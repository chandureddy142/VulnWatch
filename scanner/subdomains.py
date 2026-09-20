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


from concurrent.futures import ThreadPoolExecutor
import socket

DANGLING_PATTERNS = [
    r"\.s3\.amazonaws\.com$",
    r"\.s3-[a-z0-9-]+\.amazonaws\.com$",
    r"\.elasticbeanstalk\.com$",
    r"\.azurewebsites\.net$",
    r"\.cloudapp\.azure\.com$",
    r"\.github\.io$",
    r"\.myshopify\.com$",
    r"\.pantheonsite\.io$",
    r"\.readthedocs\.io$",
    r"\.surge\.sh$",
    r"\.netlify\.app$",
    r"\.vercel\.app$",
    r"\.firebaseapp\.com$",
    r"\.fastly\.net$",
]


def probe_subdomain(subdomain: str, timeout: float = 1.5) -> Dict[str, Any]:
    """Perform a lightweight DNS probe to test if a subdomain resolves, and check for CNAME target."""
    ip_address = None
    is_alive = False
    cname_target = None
    status = "Unresolved"

    # 1. Probe A/AAAA resolution via socket
    try:
        sock_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        addr_info = socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        socket.setdefaulttimeout(sock_timeout)

        if addr_info:
            is_alive = True
            ip_address = addr_info[0][4][0]
            status = "Live"
    except Exception:
        is_alive = False

    # 2. If unresolved, check for CNAME record and dangling cloud patterns
    if not is_alive:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            answers = resolver.resolve(subdomain, "CNAME")
            if answers:
                cname_target = str(answers[0].target).rstrip(".")
                for pattern in DANGLING_PATTERNS:
                    if re.search(pattern, cname_target, re.IGNORECASE):
                        status = "Dangling CNAME"
                        break
        except Exception:
            pass

    return {
        "subdomain": subdomain,
        "is_alive": is_alive,
        "ip_address": ip_address,
        "cname_target": cname_target,
        "status": status,
    }


def discover_subdomains(target_url_or_host: str, timeout: int = 6) -> List[Dict[str, Any]]:
    """Query CT logs via crt.sh for passive subdomain discovery and perform parallel DNS resolution probing."""
    subs = fetch_crt_subdomains(target_url_or_host, timeout=timeout)
    now_iso = datetime.utcnow().isoformat()

    # Parallel DNS probing (max 10 workers)
    with ThreadPoolExecutor(max_workers=min(10, max(1, len(subs)))) as executor:
        probe_results = list(executor.map(lambda s: probe_subdomain(s, timeout=1.5), subs))

    results = []
    for res in probe_results:
        results.append({
            "subdomain": res["subdomain"],
            "first_seen": now_iso,
            "last_scanned": now_iso,
            "http_status": 200 if res["is_alive"] else 0,
            "is_alive": res["is_alive"],
            "ip_address": res["ip_address"],
            "cname_target": res["cname_target"],
            "status": res["status"],
        })
    return results
