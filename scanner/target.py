import ipaddress
import re
from urllib.parse import urlparse


class TargetValidationError(Exception):
    """Custom exception raised when target URL validation fails."""

    pass


def validate_target_url(url: str, allow_localhost: bool = True) -> str:
    """Validates target URL scheme, syntax, and IP target safety.

    Args:
        url: The raw URL string provided by the user.
        allow_localhost: Flag allowing localhost auditing (default True for educational local tool).

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

    # Validate IP address format or resolve hostname safely
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
            raise TargetValidationError(
                f"Target IP {hostname} is non-routable or reserved."
            )
        if ip_obj.is_loopback and not allow_localhost:
            raise TargetValidationError("Localhost scanning is currently disabled.")
    else:
        # Basic check for localhost named targets
        if hostname.lower() in ("localhost", "localhost.localdomain"):
            if not allow_localhost:
                raise TargetValidationError("Localhost scanning is currently disabled.")

    # Reconstruct clean normalized URL
    port_str = f":{parsed.port}" if parsed.port else ""
    path_str = parsed.path if parsed.path else "/"
    normalized_url = f"{parsed.scheme.lower()}://{parsed.hostname}{port_str}{path_str}"
    if parsed.query:
        normalized_url += f"?{parsed.query}"

    return normalized_url
