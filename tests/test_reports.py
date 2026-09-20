import json
import os
import pytest
from config.config import TestingConfig
from database.db import init_db, shutdown_session
from database.models import Finding, Scan, ScanStatus, SeverityLevel
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.pdf_report import REPORTLAB_AVAILABLE, generate_pdf_report


@pytest.fixture(scope="module")
def db_session():
    session = init_db(TestingConfig.SQLALCHEMY_DATABASE_URI)
    yield session
    shutdown_session()


@pytest.fixture
def populated_scan(db_session):
    scan = Scan(
        target_url="https://audit-target.local",
        status=ScanStatus.COMPLETED,
        status_code=200,
    )
    db_session.add(scan)
    db_session.commit()

    f1 = Finding(
        scan_id=scan.id,
        title="Missing Content Security Policy (CSP)",
        category="Security Headers",
        severity=SeverityLevel.HIGH,
        description="The web application does not set a Content-Security-Policy header.",
        remediation="Implement a CSP header specifying trusted resource domains.",
        affected_url="https://audit-target.local/",
        evidence={"header": "Content-Security-Policy", "status": "Missing"},
    )

    f2 = Finding(
        scan_id=scan.id,
        title="Cookie Missing HttpOnly Flag (session_id)",
        category="Cookie Security",
        severity=SeverityLevel.MEDIUM,
        description="The session cookie lacks the HttpOnly attribute.",
        remediation="Configure the session cookie with the HttpOnly attribute.",
        affected_url="https://audit-target.local/",
        evidence={"cookie": "session_id=abc123", "missing": "HttpOnly"},
    )

    db_session.add_all([f1, f2])
    db_session.commit()

    scan.update_severity_counts()
    db_session.commit()

    return scan


# Fixture with full passive recon metadata embedded in response_headers
SAMPLE_RECON_DATA = {
    "_recon": {
        "ct_subdomain_count": 3,
        "ct_subdomains": ["api.audit-target.local", "www.audit-target.local", "mail.audit-target.local"],
        "spf_record": "v=spf1 include:_spf.google.com ~all",
        "dmarc_record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@audit-target.local",
        "dkim_selectors_found": ["google", "default"],
        "dangling_cnames": [
            {
                "subdomain": "old.audit-target.local",
                "cname_target": "audit-target.s3.amazonaws.com",
                "status": "Does Not Resolve — Likely Dangling",
            }
        ],
        "detected_tech": [
            {"source": "Server header", "tech": "nginx/1.22.1", "label": "Nginx"},
            {"source": "x-powered-by", "tech": "PHP/8.1.0", "label": "Application Framework"},
        ],
        "tls_info": {
            "uses_tls": True,
            "http_to_https_redirect": True,
        },
        "redirect_chain": [
            {"url": "http://audit-target.local", "status_code": 301, "location": "https://audit-target.local"},
            {"url": "https://audit-target.local/", "status_code": 200, "location": ""},
        ],
    }
}


@pytest.fixture
def populated_scan_with_recon(db_session):
    """Scan fixture that includes full passive recon metadata in response_headers."""
    scan = Scan(
        target_url="https://audit-target.local",
        status=ScanStatus.COMPLETED,
        status_code=200,
        response_headers=SAMPLE_RECON_DATA,
    )
    db_session.add(scan)
    db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        title="Missing HSTS Header",
        category="Security Headers",
        severity=SeverityLevel.HIGH,
        description="HSTS header not set.",
        remediation="Add Strict-Transport-Security header.",
        affected_url="https://audit-target.local/",
        evidence={"header": "Strict-Transport-Security", "status": "Missing"},
    )
    db_session.add(finding)
    db_session.commit()
    scan.update_severity_counts()
    db_session.commit()
    return scan


# ─────────────────────────────────────────────────────────────────────────────
# Existing export tests (no recon data)
# ─────────────────────────────────────────────────────────────────────────────

def test_json_report_generation(populated_scan, tmp_path):
    output_path = str(tmp_path / "test_report.json")
    res_path = generate_json_report(populated_scan, output_path)

    assert os.path.exists(res_path)
    with open(res_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("vulnwatch_version") == "1.0.0" or data.get("webguard_version") == "1.0.0"
    assert data["scan"]["target_url"] == "https://audit-target.local"
    assert len(data["findings"]) == 2
    # Scans without recon data should NOT include the 'reconnaissance' key
    assert "reconnaissance" not in data


def test_html_report_generation(populated_scan, tmp_path):
    output_path = str(tmp_path / "test_report.html")
    res_path = generate_html_report(populated_scan, output_path)

    assert os.path.exists(res_path)
    with open(res_path, "r", encoding="utf-8") as f:
        html_str = f.read()

    assert "VulnWatch Executive Security Posture Audit" in html_str
    assert "https://audit-target.local" in html_str
    assert "Missing Content Security Policy (CSP)" in html_str


def test_pdf_report_generation(populated_scan, tmp_path):
    output_path = str(tmp_path / "test_report.pdf")
    res_path = generate_pdf_report(populated_scan, output_path)

    assert os.path.exists(res_path)
    expected_min_size = 1000 if REPORTLAB_AVAILABLE else 100
    assert os.path.getsize(res_path) > expected_min_size  # Valid non-empty PDF file generated


# ─────────────────────────────────────────────────────────────────────────────
# Recon export tests (with full recon metadata)
# ─────────────────────────────────────────────────────────────────────────────

def test_json_report_includes_reconnaissance_section(populated_scan_with_recon, tmp_path):
    """JSON export includes top-level 'reconnaissance' key with all recon sub-sections."""
    output_path = str(tmp_path / "recon_report.json")
    res_path = generate_json_report(populated_scan_with_recon, output_path)

    with open(res_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "reconnaissance" in data, "JSON must include top-level 'reconnaissance' key"

    recon = data["reconnaissance"]

    # TLS Transport
    assert "tls_transport" in recon
    tls = recon["tls_transport"]
    assert tls["https_tls_enabled"] is True
    assert tls["http_to_https_redirect"] is True
    assert tls["redirect_hop_count"] == 1
    assert "audit-target.local" in tls["final_destination"]
    assert len(tls["redirect_chain"]) == 2

    # DNS Email Security
    assert "dns_email_security" in recon
    dns = recon["dns_email_security"]
    assert dns["spf_present"] is True
    assert dns["spf_record"].startswith("v=spf1")
    assert dns["dmarc_present"] is True
    assert dns["dmarc_enforced"] is True
    assert "google" in dns["dkim_selectors_found"]

    # Technology Stack
    assert "technology_stack" in recon
    assert len(recon["technology_stack"]) == 2
    assert any(t["label"] == "Nginx" for t in recon["technology_stack"])

    # Subdomain Inventory
    assert "subdomains_discovered" in recon
    subs = recon["subdomains_discovered"]
    assert subs["total_count"] == 3
    assert "api.audit-target.local" in subs["subdomains"]
    assert subs["source"] == "Certificate Transparency Logs (crt.sh)"

    # Dangling CNAMEs
    assert "dangling_cnames" in recon
    assert len(recon["dangling_cnames"]) == 1
    assert recon["dangling_cnames"][0]["cname_target"] == "audit-target.s3.amazonaws.com"


def test_html_report_includes_recon_section(populated_scan_with_recon, tmp_path):
    """HTML export renders the Perimeter Reconnaissance & Asset Intelligence section."""
    output_path = str(tmp_path / "recon_report.html")
    res_path = generate_html_report(populated_scan_with_recon, output_path)

    with open(res_path, "r", encoding="utf-8") as f:
        html_str = f.read()

    # Section header rendered
    assert "Perimeter Reconnaissance" in html_str
    assert "Asset Intelligence" in html_str

    # TLS data present
    assert "HTTPS / TLS" in html_str
    assert "ACTIVE" in html_str

    # DNS data present
    assert "SPF Record" in html_str
    assert "DMARC" in html_str
    assert "v=spf1" in html_str

    # Tech fingerprints present
    assert "nginx/1.22.1" in html_str

    # CT subdomains present
    assert "api.audit-target.local" in html_str
    assert "3 subdomains" in html_str

    # Dangling CNAME warning present
    assert "Dangling CNAME" in html_str
    assert "audit-target.s3.amazonaws.com" in html_str


def test_pdf_report_with_recon_generates_successfully(populated_scan_with_recon, tmp_path):
    """PDF export with recon data generates a valid, non-empty PDF without errors."""
    output_path = str(tmp_path / "recon_report.pdf")
    res_path = generate_pdf_report(populated_scan_with_recon, output_path)

    assert os.path.exists(res_path)
    expected_min_size = 5000 if REPORTLAB_AVAILABLE else 100
    assert os.path.getsize(res_path) > expected_min_size

    # Verify it starts with the PDF magic bytes
    with open(res_path, "rb") as f:
        magic = f.read(4)
    assert magic == b"%PDF", "Output file must be a valid PDF"

