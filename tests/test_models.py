import pytest
from config.config import TestingConfig
from database.db import Base, init_db, shutdown_session
from database.models import Finding, Report, Scan, ScanStatus, SeverityLevel, TriageStatus


@pytest.fixture(scope="module")
def db():
    session = init_db(TestingConfig.SQLALCHEMY_DATABASE_URI)
    yield session
    shutdown_session()


def test_create_scan_and_findings(db):
    scan = Scan(
        target_url="http://127.0.0.1:8080",
        status=ScanStatus.RUNNING,
        status_code=200,
        response_headers={"Server": "Werkzeug/3.0.3"},
    )
    db.add(scan)
    db.commit()

    finding1 = Finding(
        scan_id=scan.id,
        title="Missing Content-Security-Policy",
        category="Missing Security Header",
        severity=SeverityLevel.HIGH,
        description="The target web server does not set Content-Security-Policy.",
        remediation="Configure a Content-Security-Policy HTTP header.",
        affected_url="http://127.0.0.1:8080/",
        evidence={"header_name": "Content-Security-Policy", "present": False},
    )

    finding2 = Finding(
        scan_id=scan.id,
        title="Missing X-Frame-Options",
        category="Missing Security Header",
        severity=SeverityLevel.MEDIUM,
        description="The target web server does not set X-Frame-Options.",
        remediation="Configure X-Frame-Options header to DENY or SAMEORIGIN.",
        affected_url="http://127.0.0.1:8080/",
        evidence={"header_name": "X-Frame-Options", "present": False},
    )

    db.add_all([finding1, finding2])
    db.commit()

    scan.update_severity_counts()
    db.commit()

    retrieved = db.query(Scan).filter_by(id=scan.id).first()
    assert retrieved is not None
    assert retrieved.high_count == 1
    assert retrieved.medium_count == 1
    assert retrieved.low_count == 0
    assert len(retrieved.findings) == 2


def test_finding_triage_fields(db):
    scan = db.query(Scan).first()
    finding = Finding(
        scan_id=scan.id,
        title="Test Triage Finding",
        category="Information Disclosure",
        severity=SeverityLevel.LOW,
        description="Test description.",
        remediation="Test remediation.",
        affected_url="http://127.0.0.1:8080/",
        evidence={},
        triage_status=TriageStatus.accepted_risk,
        triage_notes="Approved by security officer on 2026-09-17.",
    )
    db.add(finding)
    db.commit()

    retrieved = db.query(Finding).filter_by(id=finding.id).first()
    assert retrieved is not None
    assert retrieved.triage_status == TriageStatus.accepted_risk
    assert retrieved.triage_notes == "Approved by security officer on 2026-09-17."

    d = retrieved.to_dict()
    assert d["triage_status"] == "accepted_risk"
    assert d["triage_notes"] == "Approved by security officer on 2026-09-17."


def test_create_report(db):
    scan = db.query(Scan).first()
    report = Report(
        scan_id=scan.id, file_path="/tmp/test_report.pdf", format="PDF"
    )
    db.add(report)
    db.commit()

    retrieved_report = db.query(Report).filter_by(id=report.id).first()
    assert retrieved_report is not None
    assert retrieved_report.scan_id == scan.id
    assert retrieved_report.format == "PDF"
