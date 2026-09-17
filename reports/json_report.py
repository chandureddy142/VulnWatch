import json
import os
from typing import Any, Dict, Optional

from database.models import Scan


def _extract_recon(scan: Scan) -> Optional[Dict[str, Any]]:
    """Extract passive recon intelligence data stored in scan.response_headers['_recon'].

    Returns a structured dict suitable for JSON export, or None if no recon data exists.
    """
    if not scan.response_headers or "_recon" not in scan.response_headers:
        return None

    r = scan.response_headers["_recon"]

    tls_info = r.get("tls_info", {})
    redirect_chain = r.get("redirect_chain", [])

    return {
        "tls_transport": {
            "https_tls_enabled": tls_info.get("uses_tls", False),
            "http_to_https_redirect": tls_info.get("http_to_https_redirect"),
            "redirect_hop_count": max(0, len(redirect_chain) - 1),
            "final_destination": redirect_chain[-1]["url"] if redirect_chain else None,
            "redirect_chain": redirect_chain,
        },
        "dns_email_security": {
            "spf_record": r.get("spf_record"),
            "spf_present": bool(r.get("spf_record")),
            "dmarc_record": r.get("dmarc_record"),
            "dmarc_present": bool(r.get("dmarc_record")),
            "dmarc_enforced": (
                bool(r.get("dmarc_record"))
                and "p=none" not in (r.get("dmarc_record") or "").lower()
            ),
            "dkim_selectors_found": r.get("dkim_selectors_found", []),
        },
        "technology_stack": r.get("detected_tech", []),
        "subdomains_discovered": {
            "total_count": r.get("ct_subdomain_count", 0),
            "subdomains": r.get("ct_subdomains", []),
            "source": "Certificate Transparency Logs (crt.sh)",
        },
        "dangling_cnames": r.get("dangling_cnames", []),
    }


def generate_json_report(scan: Scan, output_path: str) -> str:
    """Serializes a WebGuard scan model and its associated findings to a JSON file.

    Includes a top-level 'reconnaissance' key with passive ASM intelligence data
    gathered during the scan (CT subdomains, DNS email security, tech fingerprints,
    TLS transport posture, and dangling CNAME records).

    Args:
        scan: Scan model instance containing results and findings.
        output_path: Absolute or relative file destination path.

    Returns:
        The output file path string.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    report_data = {
        "vulnwatch_version": "1.0.0",
        "scan": scan.to_dict(),
        "findings": [f.to_dict() for f in scan.findings],
    }

    recon = _extract_recon(scan)
    if recon is not None:
        report_data["reconnaissance"] = recon

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    return output_path
