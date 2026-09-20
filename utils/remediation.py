"""
Remediation Catalog Utility
Provides production-ready fixes for Nginx, Apache, Cloudflare Workers, and Python/Flask.
"""
from typing import Dict, Any


def get_remediation_snippets(category: str, title: str) -> Dict[str, str]:
    """Return dictionary of remediation code snippets for Nginx, Apache, Cloudflare Workers, and Flask."""
    c = (category or "").lower()
    t = (title or "").lower()

    if "hsts" in c or "strict-transport-security" in t or "hsts" in t:
        return {
            "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "cloudflare": 'response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");',
            "flask": "@app.after_request\ndef add_hsts(resp):\n    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'\n    return resp"
        }
    elif "content-security-policy" in c or "csp" in t:
        return {
            "nginx": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; frame-ancestors \'none\';" always;',
            "apache": 'Header always set Content-Security-Policy "default-src \'self\';"',
            "cloudflare": 'response.headers.set("Content-Security-Policy", "default-src \'self\'; frame-ancestors \'none\';");',
            "flask": "@app.after_request\ndef add_csp(resp):\n    resp.headers['Content-Security-Policy'] = \"default-src 'self';\"\n    return resp"
        }
    elif "frame" in c or "x-frame-options" in t or "clickjacking" in t:
        return {
            "nginx": 'add_header X-Frame-Options "DENY" always;',
            "apache": 'Header always set X-Frame-Options "DENY"',
            "cloudflare": 'response.headers.set("X-Frame-Options", "DENY");',
            "flask": "@app.after_request\ndef add_xfo(resp):\n    resp.headers['X-Frame-Options'] = 'DENY'\n    return resp"
        }
    elif "content-type" in c or "x-content-type-options" in t or "sniff" in t:
        return {
            "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
            "apache": 'Header always set X-Content-Type-Options "nosniff"',
            "cloudflare": 'response.headers.set("X-Content-Type-Options", "nosniff");',
            "flask": "@app.after_request\ndef add_xcto(resp):\n    resp.headers['X-Content-Type-Options'] = 'nosniff'\n    return resp"
        }
    elif "cookie" in c or "cookie" in t:
        return {
            "nginx": 'proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Lax";',
            "apache": 'Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"',
            "cloudflare": 'let cookie = response.headers.get("Set-Cookie");\nif (cookie) response.headers.set("Set-Cookie", cookie + "; Secure; HttpOnly; SameSite=Lax");',
            "flask": "response.set_cookie('session', value, secure=True, httponly=True, samesite='Lax')"
        }
    else:
        return {
            "nginx": '# Apply general security header\nadd_header X-Content-Type-Options "nosniff" always;',
            "apache": '# Apply general security header\nHeader always set X-Content-Type-Options "nosniff"',
            "cloudflare": 'response.headers.set("X-Content-Type-Options", "nosniff");',
            "flask": "@app.after_request\ndef add_headers(resp):\n    resp.headers['X-Content-Type-Options'] = 'nosniff'\n    return resp"
        }
