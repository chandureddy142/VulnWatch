"""
Privacy & Domain Masking Helpers for VulnWatch.

Provides non-destructive target URL masking for public-facing views
so that authenticated scan owners see full URLs while other viewers
see a privacy-preserving masked version.
"""

import re
from urllib.parse import urlparse


def mask_domain(target: str, is_owner: bool) -> str:
    """Return the target URL with the domain hostname partially masked when not the owner.

    Masking rule:
      - If ``is_owner`` is True: return ``target`` unchanged.
      - Otherwise: keep the first 2 characters and the TLD+1 suffix; replace
        everything in between with asterisks. TLDs like `.co.uk` are preserved.

    Examples:
        mask_domain("https://chandureddy.in/path", is_owner=False)
            -> "https://ch*******y.in/path"
        mask_domain("https://api.example.com", is_owner=False)
            -> "https://ap*****e.com"
        mask_domain("http://127.0.0.1:5001", is_owner=True)
            -> "http://127.0.0.1:5001"

    Args:
        target: Full URL or hostname string (may include path/query).
        is_owner: If True the target is returned unchanged.

    Returns:
        The (possibly masked) URL string. Never raises; falls back to the
        original value if parsing fails.
    """
    if is_owner:
        return target

    try:
        parsed = urlparse(target)
        # netloc includes port; isolate the pure hostname
        netloc = parsed.netloc or parsed.path
        # Strip port number (e.g. example.com:8080 -> example.com)
        host = netloc.split(":")[0]

        masked_host = _mask_hostname(host)

        # Reconstruct the URL with the masked hostname
        if parsed.scheme:
            # Full URL – rebuild with masked hostname (preserve port)
            port_part = ""
            if ":" in parsed.netloc:
                port_part = ":" + parsed.netloc.split(":", 1)[1]
            masked_netloc = masked_host + port_part
            result = parsed._replace(netloc=masked_netloc).geturl()
        else:
            # Bare hostname/path – just mask the host portion
            result = target.replace(host, masked_host, 1)

        return result
    except Exception:
        # Graceful degradation: return original on any parsing failure
        return target


def _mask_hostname(host: str) -> str:
    """Mask the middle section of a hostname, preserving first 2 chars and suffix."""
    # For IP addresses or very short strings – mask all but first and last char
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        # IPv4 – mask the middle two octets
        parts = host.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.***.***{parts[3]}"
        return host

    # Split by dots to find the label to mask (the leftmost label of the registered domain)
    parts = host.split(".")
    if len(parts) < 2:
        # Single label – just mask the middle
        return _mask_label(host)

    # Detect multi-level TLDs (e.g., .co.uk, .com.au)
    if len(parts) >= 3 and len(parts[-1]) <= 3 and len(parts[-2]) <= 3:
        # e.g., api.example.co.uk -> label=example, tld=.co.uk
        label_idx = len(parts) - 3
    else:
        # e.g., chandureddy.in -> label=chandureddy, tld=.in
        label_idx = len(parts) - 2

    label = parts[label_idx]
    tld_suffix = "." + ".".join(parts[label_idx + 1:])

    subdomain_prefix = ".".join(parts[:label_idx]) + "." if label_idx > 0 else ""

    return subdomain_prefix + _mask_label(label) + tld_suffix


def _mask_label(label: str) -> str:
    """Mask a single hostname label: keep first 2 chars and last char, asterisk the rest."""
    if len(label) <= 3:
        return label[0] + "*" * (len(label) - 1)
    keep_start = min(2, len(label) - 1)
    keep_end = 1
    middle_len = len(label) - keep_start - keep_end
    return label[:keep_start] + "*" * middle_len + label[-keep_end:]


def check_scan_ownership(scan, user_id=None, guest_session_id=None) -> bool:
    """Check if the active user_id or guest_session_id owns the scan."""
    if user_id is None and guest_session_id is None:
        try:
            from flask import session
            user_id = session.get("user_id")
            guest_session_id = session.get("guest_id") or session.get("guest_session_id")
        except Exception:
            pass

    if scan.user_id is not None:
        return user_id is not None and scan.user_id == user_id

    if scan.guest_session_id is not None:
        return guest_session_id is not None and scan.guest_session_id == guest_session_id

    return True


def mask_scan_target(scan, user_id=None, guest_session_id=None) -> str:
    """Return scan's target_url, masked if the current session does not own the scan."""
    is_owner = check_scan_ownership(scan, user_id=user_id, guest_session_id=guest_session_id)
    return mask_domain(scan.target_url, is_owner)

