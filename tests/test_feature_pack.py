import pytest
from app import create_app
from database.db import get_session
from database.models import Scan, ScanStatus, ScheduledAudit, CadenceType, ScheduleStatus, SubdomainAsset
from utils.remediation import get_remediation_snippets
from scanner.subdomains import extract_base_domain, discover_subdomains
from tasks.scheduler import run_scheduled_audits, compute_next_run
from datetime import datetime, timedelta

API_HEADERS = {"X-API-Key": "testing-api-key"}


@pytest.fixture
def app_client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client


def test_remediation_utility():
    snippets = get_remediation_snippets("Missing Security Header", "Strict-Transport-Security (HSTS)")
    assert "nginx" in snippets
    assert "apache" in snippets
    assert "cloudflare" in snippets
    assert "Strict-Transport-Security" in snippets["nginx"]


def test_subdomain_extraction_and_discovery():
    base = extract_base_domain("https://sub.example.com:8080/path")
    assert base == "example.com"

    # Discovery with invalid domain returns empty list gracefully
    res = discover_subdomains("localhost", timeout=1)
    assert res == []


def test_export_report_routes(app_client):
    db = get_session()
    scan = Scan(target_url="https://test-export.com", status=ScanStatus.COMPLETED, critical_count=1, guest_session_id="guest-123")
    db.add(scan)
    db.commit()
    scan_id = scan.id

    with app_client.session_transaction() as sess:
        sess["guest_id"] = "guest-123"

    res_html = app_client.get(f"/reports/{scan_id}/export/html", headers=API_HEADERS)
    assert res_html.status_code == 200
    assert b"Audit Verification Hash:" in res_html.data

    res_pdf = app_client.get(f"/reports/{scan_id}/export/pdf", headers=API_HEADERS)
    assert res_pdf.status_code in (200, 302)


def test_schedules_and_scheduler(app_client):
    db = get_session()
    now = datetime.utcnow() - timedelta(minutes=5)
    sched = ScheduledAudit(
        target_url="https://scheduled-test.com",
        cadence=CadenceType.daily,
        next_run=now,
        status=ScheduleStatus.active,
        last_posture_score=100
    )
    db.add(sched)
    db.commit()

    executed = run_scheduled_audits()
    assert executed >= 1

    # Verify API schedule routes
    res_list = app_client.get("/schedules/", headers=API_HEADERS)
    assert res_list.status_code == 200
    data = res_list.get_json()
    assert "schedules" in data

    res_create = app_client.post(
        "/schedules/create",
        json={"target_url": "https://new-schedule.com", "cadence": "weekly"},
        headers=API_HEADERS
    )
    assert res_create.status_code == 201


def test_quick_search_api(app_client):
    res_search = app_client.get("/api/quick-search?q=test", headers=API_HEADERS)
    assert res_search.status_code == 200
    data = res_search.get_json()
    assert "results" in data
    assert "navigation" in data["results"]
    assert "audits" in data["results"]
