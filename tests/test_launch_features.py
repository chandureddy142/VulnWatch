import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app("testing")
    with app.test_client() as client:
        yield client


def test_privacy_policy_page(client):
    res = client.get("/privacy")
    assert res.status_code == 200
    assert b"Privacy Policy" in res.data
    assert b"Information We Collect" in res.data


def test_terms_and_conditions_page(client):
    res = client.get("/terms")
    assert res.status_code == 200
    assert b"Terms &amp; Conditions" in res.data or b"Terms & Conditions" in res.data
    assert b"User Responsibilities" in res.data


def test_robots_txt(client):
    res = client.get("/robots.txt")
    assert res.status_code == 200
    assert res.content_type == "text/plain; charset=utf-8" or "text/plain" in res.content_type
    assert b"Disallow: /reports/" in res.data
    assert b"Sitemap:" in res.data


def test_sitemap_xml(client):
    res = client.get("/sitemap.xml")
    assert res.status_code == 200
    assert "xml" in res.content_type
    assert b"<loc>" in res.data
    assert b"/privacy" in res.data
    assert b"/terms" in res.data


def test_custom_404_html(client):
    res = client.get("/nonexistent-page-xyz")
    assert res.status_code == 404
    assert b"Page Not Found" in res.data
    assert b"ERROR 404" in res.data


def test_api_404_json(client):
    res = client.get("/api/v1/nonexistent", headers={"Accept": "application/json"})
    assert res.status_code == 404
    json_data = res.get_json()
    assert json_data["error"] == "Resource Not Found"


def test_scan_honeypot_rejection(client):
    res = client.post("/scan", data={"target_url": "http://127.0.0.1:5000", "hp_website": "spam_bot_fill", "authorized": "true"})
    assert res.status_code == 400
    json_data = res.get_json()
    assert "spam" in json_data["error"].lower()


def test_guest_api_key_generation_forbidden(client):
    with client.session_transaction() as sess:
        sess["is_guest"] = True

    res = client.post("/api/keys/generate")
    assert res.status_code == 403
    json_data = res.get_json()
    assert "Google Sign-In required" in json_data["error"]


def test_guest_schedule_creation_forbidden(client):
    with client.session_transaction() as sess:
        sess["is_guest"] = True

    res = client.post("/schedules/create", data={"target_url": "https://example.com"})
    assert res.status_code == 403
    json_data = res.get_json()
    assert "Google Sign-In required" in json_data["error"]


def test_cicd_scan_unauthorized_without_key(client):
    res = client.post("/api/v1/scan", json={"target": "https://8.8.8.8"})
    assert res.status_code == 401
    json_data = res.get_json()
    assert "Unauthorized" in json_data["error"]


def test_google_user_api_key_lifecycle_and_cicd_scan(client):
    with client.session_transaction() as sess:
        sess["user_id"] = 8888
        sess["user"] = {"id": 8888, "email": "developer@example.com", "name": "Dev User"}
        sess.pop("is_guest", None)

    # 1. Generate API key as Google user
    gen_res = client.post("/api/keys/generate")
    assert gen_res.status_code == 200
    gen_data = gen_res.get_json()
    api_key = gen_data["api_key"]
    assert api_key.startswith("vw_live_")

    # 2. Schedule creation works for Google user
    sched_res = client.post("/schedules/create", json={"target_url": "https://8.8.8.8", "cadence": "weekly"})
    assert sched_res.status_code == 201

    # 3. Call CI/CD scan endpoint with Bearer token
    scan_res = client.post(
        "/api/v1/scan",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"target": "https://8.8.8.8", "fail_below_score": 70}
    )
    assert scan_res.status_code == 200
    scan_data = scan_res.get_json()
    assert scan_data["status"] in ("PASS", "FAIL")
    assert "posture_score" in scan_data
    assert "summary" in scan_data

    # 4. Revoke API key
    revoke_res = client.post("/api/keys/revoke")
    assert revoke_res.status_code == 200

    # 5. Calling CI/CD scan after revocation fails
    rev_scan_res = client.post(
        "/api/v1/scan",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"target": "https://8.8.8.8"}
    )
    assert rev_scan_res.status_code == 401
