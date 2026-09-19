import ipaddress
import re
import socket
from urllib.parse import urlparse


class TargetValidationError(Exception):
    """Custom exception raised when target URL validation fails."""

    pass


def _is_disallowed_ip(address: ipaddress._BaseAddress) -> bool:
    """Return whether an address must never be reached by scanner egress."""
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_unspecified,
            address.is_reserved,
            address.is_site_local if isinstance(address, ipaddress.IPv6Address) else False,
            not address.is_global,  # includes RFC 6598 carrier-grade NAT
        )
    )


def resolve_and_validate_hostname(hostname: str) -> list[ipaddress._BaseAddress]:
    """Resolve *all* hostname records and reject non-public destinations.

    Validating every returned address prevents a hostname with mixed public and
    private records from being used to bypass egress controls.
    """
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetValidationError(f"Unable to resolve target hostname: {hostname}") from exc

    addresses = {ipaddress.ip_address(record[4][0]) for record in records}
    if not addresses:
        raise TargetValidationError("Target hostname did not resolve to an IP address.")
    for address in addresses:
        if _is_disallowed_ip(address):
            raise TargetValidationError(
                f"Target hostname resolves to a disallowed non-public address: {address}"
            )
    return list(addresses)


def validate_target_url(url: str, allow_localhost: bool = False) -> str:
    """Validates target URL scheme, syntax, and IP target safety.

    Args:
        url: The raw URL string provided by the user.
        allow_localhost: Retained for backwards-compatible callers. Local and
            private targets are always rejected as an outbound safety boundary.

    Returns:
        Normalized URL string if valid.

    Raises:
        TargetValidationError: If URL structure is invalid or scheme is disallowed.
    """
    if not url:
        raise TargetValidationError("Target URL cannot be empty.")

    url_str = url.strip()

    # Check if a scheme is explicitly provided (e.g. scheme://...)
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):/\/", url_str)
    if not scheme_match:
        url_str = "http://" + url_str

    try:
        parsed = urlparse(url_str)
    except Exception as e:
        raise TargetValidationError(f"Invalid URL structure: {str(e)}")

    if parsed.scheme.lower() not in ("http", "https"):
        raise TargetValidationError(
            f"Disallowed scheme '{parsed.scheme}'. Only http and https are allowed."
        )

    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError("URL must include a valid hostname or IP address.")
    if parsed.username or parsed.password:
        raise TargetValidationError("URLs with embedded credentials are not allowed.")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", hostname):
        raise TargetValidationError("URL must include a valid hostname or IP address.")

    # Validate IP address format or resolve hostname safely
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        if _is_disallowed_ip(ip_obj):
            raise TargetValidationError(
                f"Target IP {hostname} is non-public or otherwise disallowed."
            )
    else:
        resolve_and_validate_hostname(hostname)

    # Reconstruct clean normalized URL
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("URL contains an invalid port.") from exc
    host_for_url = f"[{hostname}]" if ":" in hostname else hostname
    port_str = f":{port}" if port else ""
    path_str = parsed.path if parsed.path else "/"
    normalized_url = f"{parsed.scheme.lower()}://{host_for_url}{port_str}{path_str}"
    if parsed.query:
        normalized_url += f"?{parsed.query}"

    return normalized_url
