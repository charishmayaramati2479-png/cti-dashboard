from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, Text, Boolean, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from .config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String, index=True)
    value = Column(String, index=True)
    source = Column(String)
    threat_type = Column(String, nullable=True)
    malware_family = Column(String, nullable=True)
    confidence = Column(Integer, default=50)
    cvss_score = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    anomaly = Column(Boolean, default=False)
    country = Column(String, nullable=True, index=True)
    asn = Column(String, nullable=True)
    city = Column(String, nullable=True)
    ml_probability = Column(Float, default=0.0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    tags = Column(Text, nullable=True)
    raw = Column(Text, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule = Column(String, index=True)
    severity = Column(String, index=True)   # low, medium, high, critical
    message = Column(Text)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)