from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.user import User, RoleEnum
from app.models.access_control import AccessControl
from app.services.token_service import require_role
from app.services.auth_helpers import get_token_payload
from datetime import datetime, timedelta  # 🆕 Added timedelta
from app.models.connection import Connection, ConnectionStatus
import base64
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from app.models.record import Record
from app.models.access_log import AccessLog

router = APIRouter(prefix="/access", tags=["Access Control"])

@router.post("/request", dependencies=[Depends(require_role(RoleEnum.doctor))])
def request_access(patient_id: int, db: Session = Depends(get_db), payload: dict = Depends(get_token_payload)):
    doctor_email = payload.get("sub")
    doctor = db.query(User).filter(User.email == doctor_email).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    patient = db.query(User).filter(User.id == patient_id, User.role == RoleEnum.patient).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    existing = db.query(AccessControl).filter(
        AccessControl.patient_id == patient_id,
        AccessControl.doctor_id == doctor.id
    ).first()

    if existing:
        existing.status = "pending"
        existing.updated_at = datetime.utcnow()
    else:
        access = AccessControl(patient_id=patient_id, doctor_id=doctor.id, status="pending", granted=False)
        db.add(access)

    db.commit()
    return {"message": "Access request sent to patient."}


@router.get("/requests", dependencies=[Depends(require_role(RoleEnum.patient))])
def get_requests(db: Session = Depends(get_db), payload: dict = Depends(get_token_payload)):
    patient_email = payload.get("sub")
    patient = db.query(User).filter(User.email == patient_email).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    requests = db.query(AccessControl).filter(
        AccessControl.patient_id == patient.id,
        AccessControl.status == "pending"
    ).all()

    result = []
    for req in requests:
        doctor = db.query(User).filter(User.id == req.doctor_id).first()
        result.append({
            "id": req.id,
            "doctorName": doctor.name if doctor else None,
            "doctorEmail": doctor.email if doctor else None,
            "requestedAt": req.updated_at or req.created_at
        })

    return result


@router.post("/respond", dependencies=[Depends(require_role(RoleEnum.patient))])
def respond_access(requestId: int, status: str, db: Session = Depends(get_db), payload: dict = Depends(get_token_payload)):
    patient_email = payload.get("sub")
    patient = db.query(User).filter(User.email == patient_email).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    access = db.query(AccessControl).filter(AccessControl.id == requestId, AccessControl.patient_id == patient.id).first()
    if not access:
        raise HTTPException(status_code=404, detail="Request not found")
    if status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    access.status = status
    access.granted = (status == "approved")
    access.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"Access {status} for request {requestId}"}


@router.post("/grant-key", dependencies=[Depends(require_role(RoleEnum.patient))])
def grant_record_access_key(
    data: dict = Body(..., media_type="application/json"),
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    """
    Patient grants access to a doctor for a specific record.
    Steps:
      - Decrypt AES key using patient's private key
      - Re-encrypt it for the doctor's public key
      - Store it in access_control table with EXPIRY DATE
    """
    
    print("\n================= /access/grant-key DEBUG START =================")
    print("Incoming payload:", payload)
    
    doctor_id = data.get("doctor_id")
    record_id = data.get("record_id")
    private_key_pem = data.get("private_key_pem")
    
    # 🆕 1. GET DURATION FROM FRONTEND (Default to 30 days)
    expires_in_days = data.get("expires_in_days", 30) 
    
    # 🆕 2. CALCULATE EXPIRATION DATE
    try:
        expiration_date = datetime.utcnow() + timedelta(days=int(expires_in_days))
        print(f"🕒 Access will expire on: {expiration_date} ({expires_in_days} days)")
    except ValueError:
        expiration_date = datetime.utcnow() + timedelta(days=30) # Fallback

    # Validate
    if not all([doctor_id, record_id, private_key_pem]):
        raise HTTPException(status_code=400, detail="Missing required parameters")

    # ✅ Identify patient
    patient_id = payload.get("user_id")
    patient = db.query(User).filter(User.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    # ✅ Identify doctor
    doctor = db.query(User).filter(User.id == doctor_id, User.role == RoleEnum.doctor).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # ✅ Get the record
    record = db.query(Record).filter(Record.id == record_id, Record.patient_id == patient.id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found or not owned by this patient")

    # ✅ Load patient's private key
    try:
        patient_priv = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except Exception as e:
        print("❌ Failed to load private key:", e)
        raise HTTPException(status_code=400, detail=f"Invalid private key: {str(e)}")

    # ✅ Parse record encryption bundle
    try:
        enc = record.encryption_key
        if isinstance(enc, str):
            enc = json.loads(enc)

        bundle = enc.get("patient_bundle", enc)
        wrapped_b64 = bundle["wrapped_b64"]
        nonce_b64 = bundle["nonce_b64"]
        eph_pub_spki_b64 = bundle["eph_pub_spki_b64"]
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid record encryption structure")

    # ✅ Unwrap AES key using patient's private key
    try:
        eph_pub = serialization.load_der_public_key(base64.b64decode(eph_pub_spki_b64))
        shared_secret = patient_priv.exchange(ec.ECDH(), eph_pub)
        h = hashes.Hash(hashes.SHA256()); h.update(shared_secret); kek = h.finalize()

        aes_key = AESGCM(kek).decrypt(
            base64.b64decode(nonce_b64),
            base64.b64decode(wrapped_b64),
            None
        )
    except Exception as e:
        print("❌ Failed to unwrap AES key:", e)
        raise HTTPException(status_code=500, detail=f"Failed to unwrap AES key: {str(e)}")

    # ✅ Re-encrypt AES key for doctor
    try:
        doctor_pub = serialization.load_pem_public_key(doctor.public_key.encode())
        eph_priv_for_doc = ec.generate_private_key(ec.SECP256R1())
        eph_pub_bytes_for_doc = eph_priv_for_doc.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        shared_secret_doc = eph_priv_for_doc.exchange(ec.ECDH(), doctor_pub)
        h2 = hashes.Hash(hashes.SHA256()); h2.update(shared_secret_doc); kek_doc = h2.finalize()

        nonce = os.urandom(12)
        wrapped_for_doctor = AESGCM(kek_doc).encrypt(nonce, aes_key, None)
    except Exception as e:
        print("❌ Failed during rewrap:", e)
        raise HTTPException(status_code=500, detail=f"Failed to encrypt key for doctor: {str(e)}")

    # ✅ Store or update in access_control table
    existing = db.query(AccessControl).filter(
        AccessControl.patient_id == patient.id,
        AccessControl.doctor_id == doctor.id,
        AccessControl.record_id == record.id
    ).first()

    if existing:
        print("ℹ️ Existing entry found — updating it.")
        existing.encrypted_aes_key = base64.b64encode(wrapped_for_doctor).decode()
        existing.nonce_b64 = base64.b64encode(nonce).decode()
        existing.eph_pub_b64 = base64.b64encode(eph_pub_bytes_for_doc).decode()
        existing.status = "approved"
        existing.granted = True
        existing.updated_at = datetime.utcnow()
        existing.expires_at = expiration_date # 🆕 Update Expiry
    else:
        print("🆕 Creating new access entry")
        access = AccessControl(
            patient_id=patient.id,
            doctor_id=doctor.id,
            record_id=record.id,
            encrypted_aes_key=base64.b64encode(wrapped_for_doctor).decode(),
            nonce_b64=base64.b64encode(nonce).decode(),
            eph_pub_b64=base64.b64encode(eph_pub_bytes_for_doc).decode(),
            granted=True,
            status="approved",
            updated_at=datetime.utcnow(),
            expires_at=expiration_date # 🆕 Set Expiry
        )
        db.add(access)

    db.commit()

    # 🟢 LOGGING: Mark as ROUTINE access
    log_entry = AccessLog(
        patient_id=patient.id,
        doctor_id=doctor.id,
        record_id=record.id,
        action=f"Granted access to {doctor.name} for {record.filename}",
        access_type="ROUTINE"
    )
    db.add(log_entry)
    db.commit()
    print("✅ Database commit successful")
    print("================= /access/grant-key DEBUG END =================\n")

    return {
        "message": f"Access granted to Dr. {doctor.name} for record {record.filename}",
        "doctor_id": doctor.id,
        "record_id": record.id,
        "expires_at": expiration_date.strftime("%Y-%m-%d %H:%M:%S")
    }

@router.post("/revoke")
def revoke_access(
    doctor_id: int = Query(...),
    record_id: int = Query(...),
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    """
    Revoke access for a specific doctor–record pair.
    """
    user_id = payload.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.role != RoleEnum.patient:
        raise HTTPException(status_code=403, detail="Only patients can revoke record access")

    access = (
        db.query(AccessControl)
        .filter(
            AccessControl.patient_id == user.id,
            AccessControl.doctor_id == doctor_id,
            AccessControl.record_id == record_id,
        )
        .first()
    )
    if not access:
        raise HTTPException(status_code=404, detail="Access record not found")

    db.delete(access)
    db.commit()

    # 🔴 LOGGING: Mark as REVOKE access
    log_entry = AccessLog(
        patient_id=user.id,
        doctor_id=doctor_id,
        record_id=record_id,
        action=f"Revoked access for record ID {record_id}",
        access_type="REVOKE"
    )
    db.add(log_entry)
    db.commit()

    return {"message": "Access revoked successfully for this record"}

@router.get("/check/{patient_id}", dependencies=[Depends(require_role(RoleEnum.doctor))])
def check_access(patient_id: int, db: Session = Depends(get_db), payload: dict = Depends(get_token_payload)):
    doctor_email = payload.get("sub")
    doctor = db.query(User).filter(User.email == doctor_email).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    access = db.query(AccessControl).filter(
        AccessControl.patient_id == patient_id,
        AccessControl.doctor_id == doctor.id,
        AccessControl.status == "approved",
        AccessControl.granted == True
    ).first()

    return {"access_granted": bool(access)}

@router.get("/doctor/{doctor_id}", dependencies=[Depends(require_role(RoleEnum.doctor))])
def get_doctor_access_list(doctor_id: int, db: Session = Depends(get_db)):
    all_patients = db.query(User).filter(User.role == RoleEnum.patient).all()
    access_records = db.query(AccessControl).filter(AccessControl.doctor_id == doctor_id).all()
    granted_patients = []
    granted_patient_ids = set()
    requested_patient_ids = set()

    for record in access_records:
        patient = db.query(User).filter(User.id == record.patient_id).first()
        if not patient: continue
        if record.status == "approved" and record.granted:
            granted_patients.append({"id": patient.id, "name": patient.name, "email": patient.email, "status": record.status, "granted": True})
            granted_patient_ids.add(patient.id)
        elif record.status == "pending":
            requested_patient_ids.add(patient.id)

    available_patients = [{"id": p.id, "name": p.name, "email": p.email, "status": "none", "granted": False} for p in all_patients if p.id not in granted_patient_ids and p.id not in requested_patient_ids]
    return {"granted": granted_patients, "available": available_patients}

@router.get("/patient/{patient_id}", dependencies=[Depends(require_role(RoleEnum.patient))])
def get_patient_access_list(patient_id: int, db: Session = Depends(get_db)):
    patient = db.query(User).filter(User.id == patient_id, User.role == RoleEnum.patient).first()
    if not patient: raise HTTPException(status_code=404, detail="Patient not found")
    all_doctors = db.query(User).filter(User.role == RoleEnum.doctor).all()
    access_records = db.query(AccessControl).filter(AccessControl.patient_id == patient_id).all()
    granted_doctors = []
    granted_doctor_ids = set()
    requested_doctor_ids = set()

    for record in access_records:
        doctor = db.query(User).filter(User.id == record.doctor_id).first()
        file = db.query(Record).filter(Record.id == record.record_id).first()
        if not doctor or not file: continue
        if record.status == "approved" and record.granted:
            granted_doctors.append({"id": doctor.id, "record_id": record.record_id, "file_name": file.filename, "name": doctor.name, "email": doctor.email, "grantedAt": record.updated_at or record.created_at})
            granted_doctor_ids.add(doctor.id)
        elif record.status == "pending":
            requested_doctor_ids.add(doctor.id)

    available_doctors = [{"id": d.id, "name": d.name, "email": d.email} for d in all_doctors if d.id not in granted_doctor_ids and d.id not in requested_doctor_ids]
    return {"granted": granted_doctors, "available": available_doctors}

@router.get("/authorized", dependencies=[Depends(require_role(RoleEnum.patient))])
def get_authorized_doctors(db: Session = Depends(get_db), payload: dict = Depends(get_token_payload)):
    patient_email = payload.get("sub")
    patient = db.query(User).filter(User.email == patient_email).first()
    if not patient: raise HTTPException(status_code=404, detail="Patient not found")
    access_records = db.query(AccessControl).filter(AccessControl.patient_id == patient.id, AccessControl.status == "approved", AccessControl.granted == True).all()
    authorized_doctors = []
    for record in access_records:
        doctor = db.query(User).filter(User.id == record.doctor_id).first()
        if doctor: authorized_doctors.append({"id": doctor.id, "name": doctor.name, "email": doctor.email, "grantedAt": record.updated_at or record.created_at})
    return {"count": len(authorized_doctors), "authorized_doctors": authorized_doctors}

@router.get("/authorized-patients", dependencies=[Depends(require_role(RoleEnum.doctor))])
def get_authorized_patients(db: Session = Depends(get_db), payload: dict = Depends(get_token_payload)):
    doctor_email = payload.get("sub")
    doctor = db.query(User).filter(User.email == doctor_email).first()
    if not doctor: raise HTTPException(status_code=404, detail="Doctor not found")
    access_records = db.query(AccessControl).filter(AccessControl.doctor_id == doctor.id, AccessControl.status == "approved", AccessControl.granted == True).all()
    authorized_patients = []
    for record in access_records:
        patient = db.query(User).filter(User.id == record.patient_id).first()
        if patient: authorized_patients.append({"id": patient.id, "name": patient.name, "email": patient.email, "grantedAt": record.updated_at or record.created_at})
    return {"count": len(authorized_patients), "authorized_patients": authorized_patients}

@router.get("/doctor-key/{record_id}", dependencies=[Depends(require_role(RoleEnum.doctor))])
def get_doctor_key(record_id: int, db: Session = Depends(get_db), payload: dict = Depends(get_token_payload)):
    doctor_id = payload.get("user_id")
    access = db.query(AccessControl).filter(AccessControl.doctor_id == doctor_id, AccessControl.record_id == record_id, AccessControl.status == "approved", AccessControl.granted == True).first()
    if not access: raise HTTPException(status_code=403, detail="Access not granted for this record")
    return {"encrypted_aes_key": access.encrypted_aes_key, "nonce_b64": access.nonce_b64, "eph_pub_b64": access.eph_pub_b64}

@router.get("/logs/patient/{patient_id}", dependencies=[Depends(require_role(RoleEnum.patient))])
def get_patient_access_logs(patient_id: int, db: Session = Depends(get_db)):
    patient = db.query(User).filter(User.id == patient_id, User.role == RoleEnum.patient).first()
    if not patient: raise HTTPException(status_code=404, detail="Patient not found")
    logs = db.query(AccessLog).filter(AccessLog.patient_id == patient_id).order_by(AccessLog.timestamp.desc()).all()
    result = []
    for log in logs:
        doctor = db.query(User).filter(User.id == log.doctor_id).first()
        record = db.query(Record).filter(Record.id == log.record_id).first()
        result.append({
            "id": log.id,
            "doctor_name": doctor.name if doctor else "Unknown",
            "record_name": record.filename if record else "Unknown record",
            "action": log.action,
            "access_type": getattr(log, "access_type", "ROUTINE"),
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return {"count": len(result), "logs": result}

@router.get("/logs/doctor/{doctor_id}", dependencies=[Depends(require_role(RoleEnum.doctor))])
def get_doctor_access_logs(doctor_id: int, db: Session = Depends(get_db)):
    doctor = db.query(User).filter(User.id == doctor_id, User.role == RoleEnum.doctor).first()
    if not doctor: raise HTTPException(status_code=404, detail="Doctor not found")
    logs = db.query(AccessLog).filter(AccessLog.doctor_id == doctor_id).order_by(AccessLog.timestamp.desc()).all()
    result = []
    for log in logs:
        patient = db.query(User).filter(User.id == log.patient_id).first()
        record = db.query(Record).filter(Record.id == log.record_id).first()
        result.append({
            "id": log.id,
            "patient_name": patient.name if patient else "Unknown",
            "record_name": record.filename if record else "Unknown record",
            "action": log.action,
            "access_type": getattr(log, "access_type", "ROUTINE"),
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        })
    return {"count": len(result), "logs": result}