from datetime import datetime
import enum
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from database.db import Base


class SeverityLevel(enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanStatus(enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class TriageStatus(enum.Enum):
    active = "active"
    accepted_risk = "accepted_risk"
    false_positive = "false_positive"


class CadenceType(enum.Enum):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class ScheduleStatus(enum.Enum):
    active = "active"
    paused = "paused"


class User(Base):
    """Represents an authenticated user (Google OAuth) or anonymous guest record."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    google_id = Column(String(128), unique=True, nullable=True)
    email = Column(String(320), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    picture = Column(String(2048), nullable=True)
    api_key = Column(String(128), unique=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "picture": self.picture,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Scan(Base):
    """Represents an individual audit scan execution against a target URL."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_url = Column(String(2048), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Summary severity counters for rapid reporting
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    info_count = Column(Integer, default=0, nullable=False)

    # Scanned endpoint headers captured during discovery (JSON stored)
    response_headers = Column(JSON, nullable=True)
    status_code = Column(Integer, nullable=True)

    # Auth ownership — nullable so existing guest/anonymous scans stay valid
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    guest_session_id = Column(String(100), nullable=True)

    # Relationships
    user = relationship("User", back_populates="scans")
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    reports = relationship(
        "Report", back_populates="scan", cascade="all, delete-orphan"
    )

    @property
    def subdomains(self):
        """Return list of discovered subdomains from scan recon metadata."""
        if self.response_headers and isinstance(self.response_headers, dict):
            recon = self.response_headers.get("_recon", {})
            if isinstance(recon, dict) and "ct_subdomains" in recon:
                return recon.get("ct_subdomains") or []
        return []

    @property
    def probed_subdomains(self):
        """Return list of probed subdomain dictionaries from scan recon metadata."""
        if self.response_headers and isinstance(self.response_headers, dict):
            recon = self.response_headers.get("_recon", {})
            if isinstance(recon, dict):
                if "probed_subdomains" in recon and recon["probed_subdomains"]:
                    return recon.get("probed_subdomains") or []
                ct_subs = recon.get("ct_subdomains") or []
                return [{"subdomain": s, "is_alive": True, "status": "Live", "ip_address": None} for s in ct_subs]
        return []

    def update_severity_counts(self):
        """Recalculate severity counters from associated findings."""
        counts = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 0,
            SeverityLevel.MEDIUM: 0,
            SeverityLevel.LOW: 0,
            SeverityLevel.INFO: 0,
        }
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1

        self.critical_count = counts[SeverityLevel.CRITICAL]
        self.high_count = counts[SeverityLevel.HIGH]
        self.medium_count = counts[SeverityLevel.MEDIUM]
        self.low_count = counts[SeverityLevel.LOW]
        self.info_count = counts[SeverityLevel.INFO]

    def to_dict(self, user_id=None, guest_session_id=None, mask_unowned=True):
        if mask_unowned:
            from utils.privacy import mask_scan_target
            target = mask_scan_target(self, user_id=user_id, guest_session_id=guest_session_id)
        else:
            target = self.target_url

        return {
            "id": self.id,
            "target_url": target,
            "status": self.status.value if self.status else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "severity_summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "status_code": self.status_code,
            "findings_count": len(self.findings),
            "user_id": self.user_id,
            "guest_session_id": self.guest_session_id,
        }


class Finding(Base):
    """Represents a security posture observation or missing security control."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)  # e.g., "Missing Security Header", "Cookie Configuration"
    severity = Column(Enum(SeverityLevel), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    affected_url = Column(String(2048), nullable=False)
    evidence = Column(JSON, nullable=True)  # Captured headers, missing values, etc.

    # Triage workflow columns
    triage_status = Column(
        Enum(TriageStatus),
        default=TriageStatus.active,
        nullable=False,
        server_default="active",
    )
    triage_notes = Column(Text, nullable=True)

    # Relationship
    scan = relationship("Scan", back_populates="findings")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value if self.severity else None,
            "description": self.description,
            "remediation": self.remediation,
            "affected_url": self.affected_url,
            "evidence": self.evidence,
            "triage_status": self.triage_status.value if self.triage_status else "active",
            "triage_notes": self.triage_notes,
        }


class Report(Base):
    """Tracks generated compliance/audit reports for a given scan."""

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file_path = Column(String(1024), nullable=False)
    format = Column(String(20), default="PDF", nullable=False)  # e.g., PDF, JSON, HTML
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship
    scan = relationship("Scan", back_populates="reports")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "file_path": self.file_path,
            "format": self.format,
            "generated_at": self.generated_at.isoformat()
            if self.generated_at
            else None,
        }


class SubdomainAsset(Base):
    """Represents a passively discovered subdomain asset."""

    __tablename__ = "subdomain_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    subdomain = Column(String(255), nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_scanned = Column(DateTime, default=datetime.utcnow, nullable=False)
    http_status = Column(Integer, default=200, nullable=False)
    is_alive = Column(Boolean, default=True, nullable=False)
    ip_address = Column(String(100), nullable=True)
    cname_target = Column(String(255), nullable=True)
    status = Column(String(50), default="Live", nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "subdomain": self.subdomain,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_scanned": self.last_scanned.isoformat() if self.last_scanned else None,
            "http_status": self.http_status,
            "is_alive": self.is_alive,
            "ip_address": self.ip_address,
            "cname_target": self.cname_target,
            "status": self.status,
        }


class ScheduledAudit(Base):
    """Represents a recurring automated security audit schedule."""

    __tablename__ = "scheduled_audits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target_url = Column(String(2048), nullable=False)
    cadence = Column(Enum(CadenceType), default=CadenceType.weekly, nullable=False)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, default=datetime.utcnow, nullable=False)
    alert_email = Column(String(320), nullable=True)
    webhook_url = Column(String(2048), nullable=True)
    status = Column(Enum(ScheduleStatus), default=ScheduleStatus.active, nullable=False)
    last_posture_score = Column(Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "target_url": self.target_url,
            "cadence": self.cadence.value if self.cadence else "weekly",
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "alert_email": self.alert_email,
            "webhook_url": self.webhook_url,
            "status": self.status.value if self.status else "active",
            "last_posture_score": self.last_posture_score,
        }

