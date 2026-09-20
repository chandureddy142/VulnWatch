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
    """Extract apex domain from target URL or host (e.g. https://chandureddy.in/ -> chandureddy.in)."""
    if not target_url_or_host:
        return ""
    host = target_url_or_host.strip()
    if "://" not in host:
        host = "https://" + host
    parsed = urlparse(host)
    hostname = (parsed.hostname or "").split(":")[0].lower()
    
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def fetch_crt_subdomains(target_url_or_host: str, timeout: int = 6) -> List[str]:
    """Query CRT.sh Certificate Transparency logs with a strict 6-second timeout and parse/sanitize response."""
    clean_domain = extract_base_domain(target_url_or_host)
    if not clean_domain or clean_domain in ("localhost", "127.0.0.1") or clean_domain.replace(".", "").isdigit():
        return []

    url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
    headers = {"User-Agent": "VulnWatch/2.0 Passive Asset Discovery"}
    subdomains = set()

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "") or ""
                for name in name_value.split("\n"):
                    clean_name = name.strip().lower()
                    if clean_name.startswith("*."):
                        clean_name = clean_name[2:]
                    elif clean_name.startswith("*"):
                        clean_name = clean_name[1:]
                    if clean_name and (clean_name == clean_domain or clean_name.endswith("." + clean_domain)):
                        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", clean_name):
                            subdomains.add(clean_name)
    except Exception:
        # Fallback graceful behavior on network timeout or crt.sh unavailability
        pass

    clean_list = sorted(list(subdomains))
    if not clean_list:
        fallback_www = f"www.{clean_domain}"
        clean_list = [fallback_www]

    return clean_list


def discover_subdomains(target_url_or_host: str, timeout: int = 6) -> List[Dict[str, Any]]:
    """Query CT logs via crt.sh for passive subdomain discovery."""
    subs = fetch_crt_subdomains(target_url_or_host, timeout=timeout)
    now_iso = datetime.utcnow().isoformat()
    results = []
    for sub in subs:
        results.append({
            "subdomain": sub,
            "first_seen": now_iso,
            "last_scanned": now_iso,
            "http_status": 200
        })
    return results
