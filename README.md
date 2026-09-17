# VulnWatch — Passive VAPT & Security Posture Auditor

VulnWatch is an enterprise-grade, non-destructive web application security posture management (ASPM) and passive vulnerability assessment tool. Engineered for security engineers, DevSecOps pipelines, and penetration testers, VulnWatch evaluates perimeter attack surfaces, transport-layer security, DNS hygiene, and defensive HTTP headers without launching disruptive or weaponized payloads.

---

## Key Features

- **Non-Destructive Perimeter Auditing:** Inspects modern defensive controls including CSP, HSTS, X-Frame-Options, secure cookie attributes (`HttpOnly`, `SameSite`, `Secure`), and dangerous HTTP verbs.
- **Passive Attack Surface Mapping (ASM):**
  - **Certificate Transparency (CT) Enumeration:** Automatically queries public CT logs via `crt.sh` to map target subdomains.
  - **DNS & Mail Posture:** Audits SPF, DKIM, and DMARC enforcement policies for email spoofing exposure.
  - **Dangling CNAME Auditing:** Detects potential subdomain takeover risks pointing to decommissioned third-party cloud infrastructure.
  - **Technology Fingerprinting:** Identifies web servers, frameworks, reverse proxies, and CDN caching layers.
- **Enterprise Vulnerability Scoring & Standards:**
  - Automated CVSS v3.1 base score computation per finding.
  - Strict classification mapping to OWASP Top 10 categories, Common Weakness Enumeration (CWE), and OWASP ASVS v4.0.
- **Interactive Multi-Platform Remediation:** Generates tailored configuration snippets (Nginx, Apache, Python/Flask) directly alongside findings.
- **Batch Auditing Engine:** Run audits against multiple targets concurrently with an executive batch comparison view.
- **Multi-Format Pentest Deliverables:** Export structured assessment reports directly in PDF, Standalone HTML, and JSON formats.
- **Interactive API Documentation:** Built-in Swagger-style reference for automated CI/CD security integration.

---

## Defensive & Legal Safety Architecture

VulnWatch is explicitly designed to remain legally compliant for continuous monitoring and live SaaS deployment:
- **Zero Hostile Payloads:** Operates exclusively using standard HTTP `GET`/`HEAD` requests, public DNS lookups, and TLS handshakes.
- **SSRF Mitigation:** Evaluates target domains against private address space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) and link-local ranges before dispatching requests.
- **Identifiable User-Agent:** All outbound connections identify the scanner via a transparent `User-Agent` containing administrative abuse contact details.

---

## Tech Stack

- **Backend:** Python (Flask), SQLite, SQLAlchemy
- **Network & Security Analysis:** `dnspython`, `urllib`/`requests`, custom TLS context parsers
- **Reporting Engine:** ReportLab (PDF), Jinja2 (HTML), JSON serializers
- **Frontend:** Vanilla JS, CSS3 (Glassmorphism, High-Contrast Light/Dark themes)
- **Containerization:** Docker & Docker Compose

---

## Getting Started

### Prerequisites
- Python 3.11+
- Docker & Docker Compose (optional, for containerized runs)

### Local Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/vulnwatch.git](https://github.com/your-username/vulnwatch.git)
   cd vulnwatch
   ```

2. **Set up a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database & run:**
   ```bash
   flask run --port 5000
   ```
   Navigate to `http://localhost:5000` in your browser.

---

## Running with Docker Compose

VulnWatch includes a pre-configured local mock vulnerable lab for safe testing:

```bash
docker compose up --build -d
```

- **VulnWatch Interface:** `http://localhost:5000`
- **Mock Target Lab:** `http://localhost:5001`

---

## REST API Quick Reference

VulnWatch includes a full programmatic API for CI/CD integration. Visit `/api/docs` in the app for complete schemas and examples.

### Trigger a Single Scan
```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "[https://example.com](https://example.com)"}'
```

### Fetch Scan Details
```bash
curl -X GET http://localhost:5000/api/scans/<scan_id>
```

### Batch Scan Submission
```bash
curl -X POST http://localhost:5000/api/scans/batch \
  -H "Content-Type: application/json" \
  -d '{"targets": ["[https://example.com](https://example.com)", "[https://test.example.com](https://test.example.com)"]}'
```

---

## Testing & Quality Assurance

Run the test suite covering engine parsers, SSRF validators, CVSS computation, and passive recon modules:

```bash
python -m pytest tests/ -v
```

---

## License

Distributed under the MIT License. See `LICENSE` for more information.