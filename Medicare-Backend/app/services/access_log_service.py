from sqlalchemy.orm import Session
from app.models.access_log import AccessLog
from datetime import datetime

# 🆕 Updated signature to accept access_type
def log_access(db: Session, patient_id: int, doctor_id: int, action: str, record_id: int = None, access_type: str = "ROUTINE"):
    """Add a new access log entry with context."""
    entry = AccessLog(
        patient_id=patient_id,
        doctor_id=doctor_id,
        record_id=record_id,
        action=action,
        access_type=access_type, # <--- Save it here
        timestamp=datetime.utcnow()
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

# ... (keep get_patient_logs as is, or remove it if you use the route directly)