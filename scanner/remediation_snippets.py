"""
Interactive Remediation Code Snippets Generator
Provides copy-pasteable server and framework configuration snippets
(Nginx, Apache, Python/Flask) for WebGuard security findings.
"""
from typing import Dict


def get_remediation_snippets(category: str, title: str) -> Dict[str, str]:
    """Return dict of code snippets keyed by technology ('nginx', 'apache', 'python_flask')."""
    c = (category or "").lower()
    t = (title or "").lower()

    if "content security policy" in c or "csp" in t:
        return {
            "nginx": (
                "# Nginx Configuration (http / server / location block)\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;\" always;"
            ),
            "apache": (
                "# Apache Configuration (.htaccess or httpd.conf)\n"
                "<IfModule mod_headers.c>\n"
                "    Header set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;\"\n"
                "</IfModule>"
            ),
            "python_flask": (
                "# Python / Flask Response Header Middleware\n"
                "@app.after_request\n"
                "def apply_csp(response):\n"
                "    response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self';\"\n"
                "    return response"
            ),
        }
    elif "hsts" in c or "strict-transport-security" in t or "hsts" in t:
        return {
            "nginx": (
                "# Nginx HSTS Configuration (HTTPS server block)\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
            ),
            "apache": (
                "# Apache HSTS Configuration (VirtualHost *:443)\n"
                "<IfModule mod_headers.c>\n"
                "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
                "</IfModule>"
            ),
            "python_flask": (
                "# Python / Flask Response Header Middleware\n"
                "@app.after_request\n"
                "def apply_hsts(response):\n"
                "    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'\n"
                "    return response"
            ),
        }
    elif "cookie" in c or "cookie" in t or "httponly" in t or "samesite" in t or "secure" in t:
        return {
            "nginx": (
                "# Nginx Proxy Cookie Flag Modification\n"
                "proxy_cookie_flags ~ httponly secure samesite=lax;"
            ),
            "apache": (
                "# Apache Header Edit Set-Cookie\n"
                "<IfModule mod_headers.c>\n"
                "    Header edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly; SameSite=Lax\"\n"
                "</IfModule>"
            ),
            "python_flask": (
                "# Flask Cookie Attributes\n"
                "resp = make_response(render_template('index.html'))\n"
                "resp.set_cookie('session_id', token, httponly=True, secure=True, samesite='Lax')"
            ),
        }
    elif "method" in c or "http method" in t or "verb" in t or "trace" in t or "options" in t:
        return {
            "nginx": (
                "# Nginx Limit Allowed HTTP Methods\n"
                "location / {\n"
                "    limit_except GET POST HEAD {\n"
                "        deny all;\n"
                "    }\n"
                "}"
            ),
            "apache": (
                "# Apache Limit Allowed HTTP Methods\n"
                "<LimitExcept GET POST HEAD>\n"
                "    Require all denied\n"
                "</LimitExcept>"
            ),
            "python_flask": (
                "# Flask Route Method Whitelisting\n"
                "@app.route('/api/resource', methods=['GET', 'POST'])\n"
                "def resource():\n"
                "    # Only GET and POST verbs permitted\n"
                "    return jsonify({\"status\": \"ok\"})"
            ),
        }
    elif "frame" in t or "clickjacking" in c or "x-frame-options" in t:
        return {
            "nginx": (
                "# Nginx X-Frame-Options Header\n"
                "add_header X-Frame-Options \"SAMEORIGIN\" always;"
            ),
            "apache": (
                "# Apache X-Frame-Options Header\n"
                "<IfModule mod_headers.c>\n"
                "    Header always set X-Frame-Options \"SAMEORIGIN\"\n"
                "</IfModule>"
            ),
            "python_flask": (
                "# Flask Response Header Middleware\n"
                "@app.after_request\n"
                "def apply_xfo(response):\n"
                "    response.headers['X-Frame-Options'] = 'SAMEORIGIN'\n"
                "    return response"
            ),
        }
    else:
        return {
            "nginx": (
                "# Nginx General Security Hardening\n"
                "server_tokens off;\n"
                "add_header X-Content-Type-Options \"nosniff\" always;\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
            ),
            "apache": (
                "# Apache General Security Hardening\n"
                "ServerTokens Prod\n"
                "ServerSignature Off\n"
                "Header always set X-Content-Type-Options \"nosniff\""
            ),
            "python_flask": (
                "# Flask Response Header Middleware\n"
                "@app.after_request\n"
                "def apply_security_headers(response):\n"
                "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                "    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'\n"
                "    return response"
            ),
        }
