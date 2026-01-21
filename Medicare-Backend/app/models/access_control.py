from sqlalchemy import Column, Integer, Boolean, DateTime, ForeignKey, String, Text
from datetime import datetime
from app.database.connection import Base

class AccessControl(Base):
    __tablename__ = "access_control"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doctor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    record_id = Column(Integer, ForeignKey("records.id"), nullable=True)  # new — for per-record granularity

    # Encryption sharing fields
    encrypted_aes_key = Column(Text, nullable=True)  # base64 AES key encrypted for doctor
    nonce_b64 = Column(Text, nullable=True)
    eph_pub_b64 = Column(Text, nullable=True)

    granted = Column(Boolean, default=False)
    status = Column(String(100), default="pending")  # pending, approved, rejected
    granted_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    # 🆕 NEW FIELD: Expiration Date
    # This is required for the Time-Bound Access feature
    expires_at = Column(DateTime, nullable=True)