from unittest.mock import patch
import pytest
from app import create_app
from database.models import Scan, ScanStatus, SeverityLevel
from scanner.http import HTTPResponseData


API_HEADERS = {"X-API-Key": "testing-api-key"}


@pytest.fixture
def app_client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client


def test_dashboard_route(app_client):
    response = app_client.get("/", headers=API_HEADERS)
    assert response.status_code == 200
    assert b"Executive Audit Dashboard" in response.data

    json_response = app_client.get("/?format=json", headers=API_HEADERS)
    assert json_response.status_code == 200
    data = json_response.get_json()
    assert "total_scans" in data
    assert "severity_totals" in data
    assert "posture_score" in data
    assert "posture_tier" in data


def test_settings_routes(app_client):
    # GET settings page
    res_get = app_client.get("/settings/", headers=API_HEADERS)
    assert res_get.status_code == 200
    assert b"Platform Settings &amp; Integrations" in res_get.data or b"Platform Settings & Integrations" in res_get.data

    # POST settings save
    res_post = app_client.post(
        "/settings/",
        json={
            "scan_timeout": 15,
            "webhook_url": "https://hooks.slack.com/services/test/test/test",
            "default_modules": ["headers", "cookies"],
        },
        headers=API_HEADERS,
    )
    assert res_post.status_code == 200
    data = res_post.get_json()
    assert data["settings"]["scan_timeout"] == 15
    assert data["settings"]["webhook_url"] == "https://hooks.slack.com/services/test/test/test"

    # Generate API key
    res_key = app_client.post("/settings/generate-api-key", headers=API_HEADERS)
    assert res_key.status_code == 200
    key_data = res_key.get_json()
    assert "api_key" in key_data
    assert key_data["api_key"].startswith("wg_")


def test_scan_trigger_unauthorized(app_client):
    # Missing authorization flag should fail
    res = app_client.post(
        "/scan",
        json={"target_url": "https://8.8.8.8", "authorized": False},
        headers=API_HEADERS,
    )
    assert res.status_code == 400
    assert "Authorization Requirement Unconfirmed" in res.get_json()["error"]


def test_scan_trigger_authorized_and_triage(app_client):
    with patch("scanner.engine.HTTPClient.get") as mock_get, patch(
        "scanner.engine.HTTPClient.options"
    ) as mock_options:

        mock_get.return_value = HTTPResponseData(
            url="https://8.8.8.8/",
            status_code=200,
            headers={"Server": "TestServer/1.0"},
            raw_set_cookie_headers=[],
        )
        mock_options.return_value = HTTPResponseData(
            url="https://8.8.8.8/",
            status_code=200,
            headers={"Allow": "GET, HEAD, OPTIONS"},
        )

        res = app_client.post(
            "/scan",
            json={"target_url": "https://8.8.8.8", "authorized": True},
            headers=API_HEADERS,
        )

        assert res.status_code == 201
        data = res.get_json()
        assert data["scan"]["status"] == ScanStatus.COMPLETED.value
        assert "posture_score" in data
        assert "diff_summary" in data
        scan_id = data["scan"]["id"]

        # Test API Status Polling Endpoint
        api_res = app_client.get(f"/api/scan/{scan_id}", headers=API_HEADERS)
        assert api_res.status_code == 200
        assert api_res.get_json()["id"] == scan_id

        # Test Findings API Endpoint
        findings_res = app_client.get(f"/api/scan/{scan_id}/findings", headers=API_HEADERS)
        assert findings_res.status_code == 200
        findings = findings_res.get_json()
        assert len(findings) > 0

        # Test Finding Triage PATCH endpoint
        finding_id = findings[0]["id"]
        triage_res = app_client.patch(
            f"/reports/{scan_id}/findings/{finding_id}/triage",
            json={
                "triage_status": "false_positive",
                "triage_notes": "Tested in development environment.",
            },
            headers=API_HEADERS,
        )
        assert triage_res.status_code == 200
        triage_data = triage_res.get_json()
        assert triage_data["finding"]["triage_status"] == "false_positive"
        assert triage_data["finding"]["triage_notes"] == "Tested in development environment."

        # Test Report Download Endpoints
        json_rep = app_client.get(f"/reports/{scan_id}/json", headers=API_HEADERS)
        assert json_rep.status_code == 200
        assert json_rep.mimetype == "application/json"

        pdf_rep = app_client.get(f"/reports/{scan_id}/pdf", headers=API_HEADERS)
        assert pdf_rep.status_code == 200
        assert pdf_rep.mimetype == "application/pdf"

        html_rep = app_client.get(f"/reports/{scan_id}/html", headers=API_HEADERS)
        assert html_rep.status_code == 200
        assert html_rep.mimetype == "text/html"

        # Test Scan Deletion
        del_res = app_client.delete(f"/api/scan/{scan_id}", headers=API_HEADERS)
        assert del_res.status_code == 200


def test_queue_and_batch_scan_routes(app_client):
    # Test /queue endpoint
    queue_res = app_client.get("/queue", headers=API_HEADERS)
    assert queue_res.status_code == 200
    assert isinstance(queue_res.get_json(), list)

    # Test /scan/batch unauthorized
    batch_unauth = app_client.post(
        "/scan/batch",
        json={"targets": ["https://8.8.8.8"], "authorized": False},
        headers=API_HEADERS,
    )
    assert batch_unauth.status_code == 400

    # Test /scan/batch authorized with mocks
    with patch("scanner.engine.HTTPClient.get") as mock_get, patch(
        "scanner.engine.HTTPClient.options"
    ) as mock_options:
        mock_get.return_value = HTTPResponseData(
            url="https://8.8.8.8/",
            status_code=200,
            headers={"Server": "TestServer/1.0"},
            raw_set_cookie_headers=[],
        )
        mock_options.return_value = HTTPResponseData(
            url="https://8.8.8.8/",
            status_code=200,
            headers={"Allow": "GET, HEAD, OPTIONS"},
        )

        batch_res = app_client.post(
            "/scan/batch",
            json={
                "targets": ["https://8.8.8.8", "https://1.1.1.1"],
                "authorized": True,
            },
            headers=API_HEADERS,
        )
        assert batch_res.status_code == 201
        batch_data = batch_res.get_json()
        assert len(batch_data["results"]) == 2
        assert "Executed 2 scan(s)" in batch_data["message"]

        scan_ids = [r["scan_id"] for r in batch_data["results"]]
        ids_str = ",".join(str(i) for i in scan_ids)

        # Test GET /scanner/batch/results
        view_res = app_client.get(f"/scanner/batch/results?ids={ids_str}", headers=API_HEADERS)
        assert view_res.status_code == 200
        assert b"Executive Batch Audit Summary" in view_res.data

        # Test JSON format GET /scanner/batch/results?format=json
        json_view_res = app_client.get(f"/scanner/batch/results?ids={ids_str}&format=json", headers=API_HEADERS)
        assert json_view_res.status_code == 200
        json_data = json_view_res.get_json()
        assert "aggregate_metrics" in json_data
        assert json_data["aggregate_metrics"]["total_targets"] == 2


def test_api_docs_route(app_client):
    """Test /api/docs view returns 200 OK and renders API Documentation."""
    res = app_client.get("/api/docs")
    assert res.status_code == 200
    assert b"VulnWatch REST API Reference" in res.data
    assert b"/api/scans" in res.data


def test_login_page_renders(app_client):
    """GET /auth/login renders the login page without error."""
    res = app_client.get("/auth/login")
    assert res.status_code == 200
    assert b"VulnWatch" in res.data
    assert b"Sign In" in res.data or b"guest" in res.data.lower()


def test_logout_clears_session_and_redirects(app_client):
    """GET /auth/logout clears session and redirects to home."""
    with app_client.session_transaction() as sess:
        sess["user_id"] = 999
        sess["user"] = {"id": 999, "email": "test@test.com", "name": "Test", "picture": ""}

    res = app_client.get("/auth/logout")
    # Should redirect
    assert res.status_code in (301, 302, 303)

    with app_client.session_transaction() as sess:
        assert "user_id" not in sess
        assert "user" not in sess


def test_profile_requires_login_redirect(app_client):
    """GET /profile redirects unauthenticated users to login."""
    res = app_client.get("/profile")
    assert res.status_code in (301, 302, 303)
    location = res.headers.get("Location", "")
    assert "/auth/login" in location


def test_guest_quota_enforcement(app_client):
    """Guests are blocked once they reach the scan quota limit."""
    with patch("scanner.engine.HTTPClient.get") as mock_get, patch(
        "scanner.engine.HTTPClient.options"
    ) as mock_options:
        mock_get.return_value = HTTPResponseData(
            url="https://8.8.8.8/",
            status_code=200,
            headers={"Server": "TestServer/1.0"},
            raw_set_cookie_headers=[],
        )
        mock_options.return_value = HTTPResponseData(
            url="https://8.8.8.8/",
            status_code=200,
            headers={"Allow": "GET, HEAD, OPTIONS"},
        )

        # Simulate a guest session that has already hit the limit
        guest_id = "test-guest-exhausted-12345"
        with app_client.session_transaction() as sess:
            sess["guest_id"] = guest_id

        # Pre-seed 3 guest scans in the DB by running 3 real scans
        for _ in range(3):
            app_client.post(
                "/scan",
                json={"target_url": "https://8.8.8.8", "authorized": True},
                headers=API_HEADERS,
            )

        # 4th scan must be blocked with 403
        res = app_client.post(
            "/scan",
            json={"target_url": "https://8.8.8.8", "authorized": True},
            headers=API_HEADERS,
        )
        assert res.status_code == 403
        data = res.get_json()
        assert data.get("limit_reached") is True
        assert "Guest limit reached" in data.get("error", "")


