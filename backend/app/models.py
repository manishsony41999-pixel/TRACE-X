"""
TRACE-X Database Models
Defines schema for Cases, EmailRecords, Investigations, Indicators, and GmailAccounts.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, DateTime, JSON, ForeignKey, Boolean, Text
)
from sqlalchemy.orm import relationship
from app.database import Base


class Case(Base):
    """Forensic Case tracking the investigation lifecycle."""
    __tablename__ = "cases"

    case_id = Column(String(50), primary_key=True, index=True)
    status = Column(String(30), default="pending")  # 'pending', 'processing', 'completed', 'failed'
    risk_level = Column(String(20), default="UNKNOWN")  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    threat_score = Column(Integer, default=0)
    source = Column(String(50), default="eml_upload")  # 'eml_upload', 'gmail_automatic'
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    email = relationship("EmailRecord", back_populates="case", uselist=False, cascade="all, delete-orphan")
    investigation = relationship("Investigation", back_populates="case", uselist=False, cascade="all, delete-orphan")
    indicators = relationship("Indicator", back_populates="case", cascade="all, delete-orphan")


class EmailRecord(Base):
    """Raw and parsed metadata of the investigated email."""
    __tablename__ = "email_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), unique=True, nullable=False)
    gmail_message_id = Column(String(100), index=True, nullable=True)
    sender = Column(String(255), nullable=True)
    recipients = Column(JSON, nullable=True)
    subject = Column(Text, nullable=True)
    received_at = Column(String(100), nullable=True)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    case = relationship("Case", back_populates="email")


class Investigation(Base):
    """Detailed forensic analysis results from all pipeline stages."""
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), unique=True, nullable=False)
    status = Column(String(30), default="processing")
    result = Column(JSON, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    case = relationship("Case", back_populates="investigation")


class Indicator(Base):
    """Extracted atomic Indicators of Compromise (IOCs)."""
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(50), ForeignKey("cases.case_id"), nullable=False)
    type = Column(String(30), nullable=False)  # 'ip', 'domain', 'url', 'hash', 'email'
    value = Column(String(500), nullable=False, index=True)
    risk = Column(String(20), default="safe")  # 'safe', 'suspicious', 'high_risk'
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    case = relationship("Case", back_populates="indicators")


class GmailAccount(Base):
    """OAuth 2.0 authorized Gmail accounts with synchronization tokens."""
    __tablename__ = "gmail_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    token_uri = Column(String(255), default="https://oauth2.googleapis.com/token")
    client_id = Column(String(255), nullable=True)
    client_secret = Column(String(255), nullable=True)
    scopes = Column(JSON, nullable=True)
    expiry = Column(DateTime, nullable=True)
    history_id = Column(String(100), nullable=True)
    watch_expiration = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
