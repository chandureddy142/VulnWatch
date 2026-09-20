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
