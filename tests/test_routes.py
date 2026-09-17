from unittest.mock import patch
import pytest
from app import create_app
from database.models import Scan, ScanStatus, SeverityLevel
from scanner.http import HTTPResponseData


@pytest.fixture
def app_client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client


def test_dashboard_route(app_client):
    response = app_client.get("/")
    assert response.status_code == 200
    assert b"Executive Audit Dashboard" in response.data

    json_response = app_client.get("/?format=json")
    assert json_response.status_code == 200
    data = json_response.get_json()
    assert "total_scans" in data
    assert "severity_totals" in data
    assert "posture_score" in data
    assert "posture_tier" in data


def test_settings_routes(app_client):
    # GET settings page
    res_get = app_client.get("/settings/")
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
    )
    assert res_post.status_code == 200
    data = res_post.get_json()
    assert data["settings"]["scan_timeout"] == 15
    assert data["settings"]["webhook_url"] == "https://hooks.slack.com/services/test/test/test"

    # Generate API key
    res_key = app_client.post("/settings/generate-api-key")
    assert res_key.status_code == 200
    key_data = res_key.get_json()
    assert "api_key" in key_data
    assert key_data["api_key"].startswith("wg_")


def test_scan_trigger_unauthorized(app_client):
    # Missing authorization flag should fail
    res = app_client.post(
        "/scan",
        json={"target_url": "http://127.0.0.1:8080", "authorized": False},
    )
    assert res.status_code == 400
    assert "Authorization Requirement Unconfirmed" in res.get_json()["error"]


def test_scan_trigger_authorized_and_triage(app_client):
    with patch("scanner.engine.HTTPClient.get") as mock_get, patch(
        "scanner.engine.HTTPClient.options"
    ) as mock_options:

        mock_get.return_value = HTTPResponseData(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={"Server": "TestServer/1.0"},
            raw_set_cookie_headers=[],
        )
        mock_options.return_value = HTTPResponseData(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={"Allow": "GET, HEAD, OPTIONS"},
        )

        res = app_client.post(
            "/scan",
            json={"target_url": "http://127.0.0.1:8080", "authorized": True},
        )

        assert res.status_code == 201
        data = res.get_json()
        assert data["scan"]["status"] == ScanStatus.COMPLETED.value
        assert "posture_score" in data
        assert "diff_summary" in data
        scan_id = data["scan"]["id"]

        # Test API Status Polling Endpoint
        api_res = app_client.get(f"/api/scan/{scan_id}")
        assert api_res.status_code == 200
        assert api_res.get_json()["id"] == scan_id

        # Test Findings API Endpoint
        findings_res = app_client.get(f"/api/scan/{scan_id}/findings")
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
        )
        assert triage_res.status_code == 200
        triage_data = triage_res.get_json()
        assert triage_data["finding"]["triage_status"] == "false_positive"
        assert triage_data["finding"]["triage_notes"] == "Tested in development environment."

        # Test Report Download Endpoints
        json_rep = app_client.get(f"/reports/{scan_id}/json")
        assert json_rep.status_code == 200
        assert json_rep.mimetype == "application/json"

        pdf_rep = app_client.get(f"/reports/{scan_id}/pdf")
        assert pdf_rep.status_code == 200
        assert pdf_rep.mimetype == "application/pdf"

        html_rep = app_client.get(f"/reports/{scan_id}/html")
        assert html_rep.status_code == 200
        assert html_rep.mimetype == "text/html"

        # Test Scan Deletion
        del_res = app_client.delete(f"/api/scan/{scan_id}")
        assert del_res.status_code == 200


def test_queue_and_batch_scan_routes(app_client):
    # Test /queue endpoint
    queue_res = app_client.get("/queue")
    assert queue_res.status_code == 200
    assert isinstance(queue_res.get_json(), list)

    # Test /scan/batch unauthorized
    batch_unauth = app_client.post(
        "/scan/batch",
        json={"targets": ["http://127.0.0.1:8080"], "authorized": False},
    )
    assert batch_unauth.status_code == 400

    # Test /scan/batch authorized with mocks
    with patch("scanner.engine.HTTPClient.get") as mock_get, patch(
        "scanner.engine.HTTPClient.options"
    ) as mock_options:
        mock_get.return_value = HTTPResponseData(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={"Server": "TestServer/1.0"},
            raw_set_cookie_headers=[],
        )
        mock_options.return_value = HTTPResponseData(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={"Allow": "GET, HEAD, OPTIONS"},
        )

        batch_res = app_client.post(
            "/scan/batch",
            json={
                "targets": ["http://127.0.0.1:8080", "http://127.0.0.1:8081"],
                "authorized": True,
            },
        )
        assert batch_res.status_code == 201
        batch_data = batch_res.get_json()
        assert len(batch_data["results"]) == 2
        assert "Executed 2 scan(s)" in batch_data["message"]

        scan_ids = [r["scan_id"] for r in batch_data["results"]]
        ids_str = ",".join(str(i) for i in scan_ids)

        # Test GET /scanner/batch/results
        view_res = app_client.get(f"/scanner/batch/results?ids={ids_str}")
        assert view_res.status_code == 200
        assert b"Executive Batch Audit Summary" in view_res.data

        # Test JSON format GET /scanner/batch/results?format=json
        json_view_res = app_client.get(f"/scanner/batch/results?ids={ids_str}&format=json")
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



