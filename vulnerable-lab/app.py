from flask import Flask, make_response, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    resp = make_response("""
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable Test Target Lab</title></head>
    <body>
        <h1>WebGuard Local Test Target</h1>
        <p>This isolated application runs on port 5001 with deliberately missing security headers for WebGuard posture auditing.</p>
    </body>
    </html>
    """)
    # Intentionally missing CSP, HSTS, XFO, XCTO, Referrer-Policy
    # Intentionally exposing version headers
    resp.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    resp.headers['X-Powered-By'] = 'PHP/7.4.3'
    # Set permissive session cookie without HttpOnly or Secure or SameSite
    resp.set_cookie('insecure_session', 'token_123456789', path='/')
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    resp = make_response(jsonify({"status": "Login endpoint"}))
    resp.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    resp.set_cookie('auth_tracker', 'user_999', path='/')
    return resp

if __name__ == '__main__':
    import os
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5001))
    print(f"[+] Starting Vulnerable Test Target Lab on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)

