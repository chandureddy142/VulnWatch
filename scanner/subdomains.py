"""
Passive Subdomain & Asset Discovery Module
Fetches certificate transparency logs from crt.sh to identify subdomains.
"""
from datetime import datetime
import json
import re
from typing import List, Dict, Any
from urllib.parse import urlparse
import requests


def extract_base_domain(target_url_or_host: str) -> str:
    """Extract clean domain from target URL or host (e.g. https://sub.example.com:8080 -> example.com)."""
    if not target_url_or_host:
        return ""
    host = target_url_or_host.strip()
    if "://" not in host:
        host = "https://" + host
    parsed = urlparse(host)
    hostname = parsed.hostname or ""
    # Strip port if present
    hostname = hostname.split(":")[0]
    
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def discover_subdomains(target_url_or_host: str, timeout: int = 8) -> List[Dict[str, Any]]:
    """Query CT logs via crt.sh for passive subdomain discovery with an 8-second timeout."""
    domain = extract_base_domain(target_url_or_host)
    if not domain or domain in ("localhost", "127.0.0.1") or domain.replace(".", "").isdigit():
        return []

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "VulnWatch/2.0 Passive Asset Discovery"}
    
    subdomains = set()
    results = []

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    clean_name = name.strip().lower()
                    if clean_name.startswith("*."):
                        clean_name = clean_name[2:]
                    if clean_name.endswith(domain) and re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", clean_name):
                        subdomains.add(clean_name)
    except Exception:
        # Fallback graceful behavior on network timeout or crt.sh unavailability
        pass

    now_iso = datetime.utcnow().isoformat()
    for sub in sorted(subdomains):
        results.append({
            "subdomain": sub,
            "first_seen": now_iso,
            "last_scanned": now_iso,
            "http_status": 200
        })

    return results
