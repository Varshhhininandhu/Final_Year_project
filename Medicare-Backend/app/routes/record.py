from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Body
from sqlalchemy import text
from sqlalchemy.orm import Session
from datetime import datetime
import base64, json, requests, io, mimetypes, os, hashlib
from fastapi.responses import StreamingResponse
from app.database.connection import get_db
from app.services.auth_helpers import get_token_payload
from app.models.user import User
from app.models.record import Record
from app.models.blockchain import Block
from app.models.access_log import AccessLog
from app.services.ipfs_service import add_bytes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec

router = APIRouter(prefix="/record", tags=["Record"])


# Decodes base64 string safely
def b64decode_str(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode())


# Extracts encryption bundle and file nonce for patients
def _pick_bundle_for_patient(enc: dict):
    if "wrapped_b64" in enc and "nonce_b64" in enc and "eph_pub_spki_b64" in enc:
        return (
            {
                "wrapped_b64": enc["wrapped_b64"],
                "nonce_b64": enc["nonce_b64"],
                "eph_pub_spki_b64": enc["eph_pub_spki_b64"],
            },
            enc.get("file_nonce_b64"),
        )

    if "patient_bundle" in enc:
        pb = enc["patient_bundle"]
        file_nonce = enc.get("file_nonce_b64") or pb.get("file_nonce_b64")
        if all(k in pb for k in ("wrapped_b64", "nonce_b64", "eph_pub_spki_b64")):
            return (
                {
                    "wrapped_b64": pb["wrapped_b64"],
                    "nonce_b64": pb["nonce_b64"],
                    "eph_pub_spki_b64": pb["eph_pub_spki_b64"],
                },
                file_nonce,
            )
    raise HTTPException(status_code=400, detail="Invalid encryption bundle structure")


# Extracts encryption bundle for doctors, with fallback to patient nonce
def _pick_bundle_for_doctor(enc: dict):
    if "doctor_bundle" in enc:
        db = enc["doctor_bundle"]
        file_nonce = (
            enc.get("file_nonce_b64")
            or db.get("file_nonce_b64")
            or enc.get("patient_bundle", {}).get("file_nonce_b64")
        )
        if all(k in db for k in ("wrapped_b64", "nonce_b64", "eph_pub_spki_b64")):
            return (
                {
                    "wrapped_b64": db["wrapped_b64"],
                    "nonce_b64": db["nonce_b64"],
                    "eph_pub_spki_b64": db["eph_pub_spki_b64"],
                },
                file_nonce,
            )
        raise HTTPException(status_code=400, detail="doctor_bundle is malformed")
    return None, None


# Uploads encrypted records to IPFS and stores metadata + a blockchain block
@router.post("/upload")
def upload_record(
    file: UploadFile = File(...),
    description: str = Form(None),
    patient_id: int = Form(None),
    file_nonce_b64: str = Form(None),
    wrapped_key: str = Form(None),
    raw_aes_key_b64: str = Form(None),
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    uploader_id = payload.get("user_id")
    if not uploader_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    uploader = db.query(User).filter(User.id == uploader_id).first()
    if not uploader:
        raise HTTPException(status_code=404, detail="Uploader not found")

    if uploader.role.value == "doctor":
        if not patient_id:
            raise HTTPException(status_code=400, detail="Patient ID required for doctor upload")
        patient = db.query(User).filter(User.id == patient_id).first()
        if not patient:
            raise HTTPException(status_code=404, detail="Target patient not found")
    else:
        patient = uploader

    if not wrapped_key or not file_nonce_b64:
        raise HTTPException(status_code=400, detail="Missing encryption data")

    file_bytes = file.file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        ipfs = add_bytes(file.filename, file_bytes)
        cid = ipfs["cid"]
        ipfs_uri = f"ipfs://{cid}"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IPFS upload failed: {str(e)}")

    try:
        wrap_data = json.loads(wrapped_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid wrapped_key JSON")

    encryption_bundle = {
        "patient_bundle": {
            "file_nonce_b64": file_nonce_b64,
            "wrapped_b64": wrap_data.get("wrappedB64"),
            "nonce_b64": wrap_data.get("nonceB64"),
            "eph_pub_spki_b64": wrap_data.get("ephPubSpkiB64"),
        },
        "scheme": "ECIES(P-256)+AES-GCM",
        "version": "1.1",
    }

    if uploader.role.value == "doctor":
        try:
            if not raw_aes_key_b64:
                wrap_data = json.loads(wrapped_key)
                raw_aes_key_b64 = wrap_data.get("wrappedB64")

            try:
                raw_aes_key = base64.b64decode(raw_aes_key_b64 + "===")
            except Exception:
                raw_aes_key = base64.urlsafe_b64decode(raw_aes_key_b64 + "===")

            doctor_pub_pem = uploader.public_key
            doctor_pub = serialization.load_pem_public_key(doctor_pub_pem.encode())

            eph_priv = ec.generate_private_key(ec.SECP256R1())
            eph_pub_bytes_doctor = eph_priv.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            shared_secret_doctor = eph_priv.exchange(ec.ECDH(), doctor_pub)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared_secret_doctor)
            kek_doctor = digest.finalize()

            wrap_iv_doctor = os.urandom(12)
            wrapped_for_doctor = AESGCM(kek_doctor).encrypt(wrap_iv_doctor, raw_aes_key, None)

            encryption_bundle["doctor_bundle"] = {
                "wrapped_b64": base64.b64encode(wrapped_for_doctor).decode(),
                "nonce_b64": base64.b64encode(wrap_iv_doctor).decode(),
                "eph_pub_spki_b64": base64.b64encode(eph_pub_bytes_doctor).decode(),
            }
        except Exception:
            # proceed with patient bundle only
            pass

    new_record = Record(
        patient_id=patient.id,
        doctor_id=uploader.id if uploader.role.value == "doctor" else None,
        filename=file.filename,
        ipfs_cid=cid,
        description=description,
        encryption_key=json.dumps(encryption_bundle),
    )
    db.add(new_record)
    db.flush()  # <-- ensure new_record.id is available

    # chain previous block per patient for clearer audit trail
    previous_block = (
        db.query(Block)
        .filter(Block.patient_id == patient.id)
        .order_by(Block.id.desc())
        .first()
    )
    previous_hash = previous_block.hash_value if previous_block else "0"

    # data hash binds important fields
    data_string = f"{cid}-{new_record.id}-{uploader.id}-{patient.id}"
    data_hash = hashlib.sha256(data_string.encode()).hexdigest()

    block = Block(
        doctor_id=uploader.id if uploader.role.value == "doctor" else 0,
        patient_id=patient.id,
        record_id=new_record.id,
        ipfs_cid=cid,
        data_hash=data_hash,
        previous_hash=previous_hash,
        hash_value=Block.generate_hash(
            uploader.id,
            patient.id,
            cid,
            previous_hash,
            data_hash
        ),
    )
    db.add(block)
    db.flush()
    new_record.block_id = block.id
    db.commit()

    return {
        "message": "Record uploaded successfully",
        "record_id": new_record.id,
        "ipfs_cid": cid,
        "ipfs_uri": ipfs_uri,
        "patient_id": patient.id,
        "block_id": block.id,
        "bundles": list(encryption_bundle.keys()),
    }


# Returns record details and encryption metadata
@router.get("/view/{record_id}")
def get_record_details(
    record_id: int,
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    user_id = payload.get("user_id")
    record = db.query(Record).filter(Record.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    if record.patient_id != user_id and record.doctor_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return {
        "record_id": record.id,
        "filename": record.filename,
        "description": record.description,
        "ipfs_cid": record.ipfs_cid,
        "uploaded_at": record.uploaded_at,
        "encryption_bundle": json.loads(record.encryption_key),
    }


# Returns all records belonging to a patient
@router.get("/my-records/{patient_id}")
def get_patient_records(
    patient_id: int,
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    user_id = payload.get("user_id")
    if user_id != patient_id:
        raise HTTPException(status_code=403, detail="Access denied")

    records = db.query(Record).filter(Record.patient_id == patient_id).order_by(Record.uploaded_at.desc()).all()

    return [
        {
            "id": r.id,
            "file_name": r.filename,
            "doctor_id": r.doctor_id,
            "uploaded_at": r.uploaded_at,
            "description": r.description,
            "ipfs_cid": r.ipfs_cid,
        }
        for r in records
    ]


# Decrypts patient’s own record using their ECC private key
@router.post("/decrypt/{record_id}")
def decrypt_record_backend(
    record_id: int,
    data: dict = Body(...),
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    user_id = payload.get("user_id")
    private_pem = data.get("private_key_pem")
    if not private_pem:
        raise HTTPException(status_code=400, detail="Private key missing")

    record = db.query(Record).filter(Record.id == record_id).first()
    if not record or record.patient_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    enc = json.loads(record.encryption_key)
    bundle, file_nonce_b64 = _pick_bundle_for_patient(enc)
    if not file_nonce_b64:
        raise HTTPException(status_code=400, detail="Missing file nonce")

    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    eph_pub = serialization.load_der_public_key(base64.b64decode(bundle["eph_pub_spki_b64"]))
    shared = private_key.exchange(ec.ECDH(), eph_pub)
    h = hashes.Hash(hashes.SHA256()); h.update(shared); kek = h.finalize()

    aes_key = AESGCM(kek).decrypt(
        base64.b64decode(bundle["nonce_b64"]),
        base64.b64decode(bundle["wrapped_b64"]),
        None
    )

    ipfs_url = f"http://127.0.0.1:8080/ipfs/{record.ipfs_cid}"
    res = requests.get(ipfs_url, timeout=30)
    plaintext = AESGCM(aes_key).decrypt(base64.b64decode(file_nonce_b64), res.content, None)

    mime_type, _ = mimetypes.guess_type(record.filename)
    return StreamingResponse(io.BytesIO(plaintext),
        media_type=mime_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{record.filename}"'}
    )


# Returns all records of a patient for a connected doctor
@router.get("/doctor/patient-records/{patient_id}")
def get_patient_records_for_doctor(
    patient_id: int,
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    user_id = payload.get("user_id")
    role = payload.get("role")
    if role != "doctor":
        raise HTTPException(status_code=403, detail="Only doctors can access this route")

    connection = db.execute(
        text(f"SELECT * FROM connections WHERE doctor_id = {user_id} AND patient_id = {patient_id} AND status IN ('active', 'accepted')")
    ).fetchone()
    if not connection:
        raise HTTPException(status_code=403, detail="No active connection with this patient")

    records = db.query(Record).filter(Record.patient_id == patient_id).order_by(Record.uploaded_at.desc()).all()

    results = []
    for r in records:
        results.append({
            "id": r.id,
            "file_name": r.filename,
            "doctor_id": r.doctor_id,
            "uploaded_at": r.uploaded_at,
            "description": r.description,
            "ipfs_cid": r.ipfs_cid,
            "self_uploaded": r.doctor_id == user_id
        })
    return results


# Allows doctor to decrypt their own or approved patient records + logs a block
@router.post("/doctor/decrypt/{record_id}")
def decrypt_record_doctor(
    record_id: int,
    data: dict = Body(...),
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    from app.models.access_control import AccessControl

    doctor_id = payload.get("user_id")
    role = payload.get("role")
    if role != "doctor":
        raise HTTPException(status_code=403, detail="Only doctors can decrypt via this route")

    private_pem = data.get("private_key_pem")
    doctor_priv = serialization.load_pem_private_key(private_pem.encode(), password=None)

    record = db.query(Record).filter(Record.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    enc = json.loads(record.encryption_key)
    bundle, file_nonce_b64 = _pick_bundle_for_doctor(enc)

    if record.doctor_id == doctor_id and bundle:
        eph_pub = serialization.load_der_public_key(base64.b64decode(bundle["eph_pub_spki_b64"]))
        shared = doctor_priv.exchange(ec.ECDH(), eph_pub)
        h = hashes.Hash(hashes.SHA256()); h.update(shared); kek = h.finalize()
        aes_key = AESGCM(kek).decrypt(
            base64.b64decode(bundle["nonce_b64"]),
            base64.b64decode(bundle["wrapped_b64"]),
            None
        )
    else:
        access = (
            db.query(AccessControl)
            .filter(
                AccessControl.doctor_id == doctor_id,
                AccessControl.record_id == record_id,
                AccessControl.status == "approved",
                AccessControl.granted == True,
            )
            .first()
        )
        if not access:
            raise HTTPException(status_code=403, detail="Access not granted for this record")
        
        # 🆕 CHECK EXPIRATION
        if access.expires_at and access.expires_at < datetime.utcnow():
            # Log the failed attempt
            log_entry = AccessLog(
                patient_id=record.patient_id,
                doctor_id=doctor_id,
                record_id=record.id,
                action="Doctor attempted to access expired record",
                access_type="ROUTINE" # Tag as routine to show in dashboard
            )
            db.add(log_entry)
            
            # (Optional) Update status to expired
            access.status = "expired"
            access.granted = False
            db.commit()

            raise HTTPException(status_code=403, detail="Access has expired.")

        eph_pub = serialization.load_der_public_key(base64.b64decode(access.eph_pub_b64))
        shared = doctor_priv.exchange(ec.ECDH(), eph_pub)
        h = hashes.Hash(hashes.SHA256()); h.update(shared); kek = h.finalize()
        aes_key = AESGCM(kek).decrypt(
            base64.b64decode(access.nonce_b64),
            base64.b64decode(access.encrypted_aes_key),
            None
        )
        _, file_nonce_b64 = _pick_bundle_for_patient(enc)

    ipfs_url = f"http://127.0.0.1:8080/ipfs/{record.ipfs_cid}"
    res = requests.get(ipfs_url, timeout=30)
    plaintext = AESGCM(aes_key).decrypt(base64.b64decode(file_nonce_b64), res.content, None)

    # chain per patient
    previous_block = (
        db.query(Block)
        .filter(Block.patient_id == record.patient_id)
        .order_by(Block.id.desc())
        .first()
    )
    previous_hash = previous_block.hash_value if previous_block else "0"

    data_string = f"{record.ipfs_cid}-{record.id}-{doctor_id}-{record.patient_id}-access"
    data_hash = hashlib.sha256(data_string.encode()).hexdigest()

    access_block = Block(
        doctor_id=doctor_id,
        patient_id=record.patient_id,
        record_id=record.id,
        ipfs_cid=record.ipfs_cid,
        data_hash=data_hash,
        previous_hash=previous_hash,
        hash_value=Block.generate_hash(
            doctor_id,
            record.patient_id,
            record.ipfs_cid,
            previous_hash,
            data_hash
        ),
    )
    db.add(access_block)
    db.commit()
    
    # 🆕 LOGGING UPDATE: Mark as ROUTINE access
    log_entry = AccessLog(
        patient_id=record.patient_id,
        doctor_id=doctor_id,
        record_id=record.id,
        action="Doctor decrypted and viewed the record",
        access_type="ROUTINE"
    )
    db.add(log_entry)
    db.commit()

    mime_type, _ = mimetypes.guess_type(record.filename)
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=mime_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{record.filename}"'}
    )
@router.get("/count/{user_id}")
def get_record_count(
    user_id: int,
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    role = payload.get("role")

    if role == "patient":
        # Count patient’s own records
        record_count = db.query(Record).filter(Record.patient_id == user_id).count()
    elif role == "doctor":
        # Count doctor’s uploaded records (to any patient)
        record_count = db.query(Record).filter(Record.doctor_id == user_id).count()
    else:
        raise HTTPException(status_code=403, detail="Invalid role")

    return {"record_count": record_count}

@router.get("/latest/doctor/{doctor_id}")
def get_latest_records_for_doctor(
    doctor_id: int,
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload)
):
    role = payload.get("role")
    if role != "doctor":
        raise HTTPException(status_code=403, detail="Only doctors can access this route")

    # Fetch 5 most recent records uploaded by the doctor
    records = (
        db.query(Record, User)
        .join(User, Record.patient_id == User.id)
        .filter(Record.doctor_id == doctor_id)
        .order_by(Record.uploaded_at.desc())
        .limit(5)
        .all()
    )

    result = []
    for record, patient in records:
        result.append({
            "id": record.id,
            "file_name": record.filename,
            "patient_name": patient.name,
            "description": record.description,
            "uploaded_at": record.uploaded_at,
        })

    return result