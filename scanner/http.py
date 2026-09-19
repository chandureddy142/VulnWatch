from dataclasses import dataclass, field
from typing import Dict, List, Optional
import requests
from requests.exceptions import (
    ConnectionError as ReqConnectionError,
    RequestException,
    SSLError,
    Timeout as ReqTimeout,
)
from scanner.target import TargetValidationError, validate_target_url


@dataclass
class HTTPResponseData:
    """Encapsulates response data from HTTP auditing probes."""

    url: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    raw_set_cookie_headers: List[str] = field(default_factory=list)
    content_type: str = ""
    error: Optional[str] = None
    elapsed_ms: float = 0.0


class HTTPClient:
    """Wrapper around requests.Session configured with timeouts and security safeguards."""

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = "WebGuard-Security-Posture-Auditor/1.0",
        verify_ssl: bool = True,
    ):
        self.timeout = timeout
        self.timeout_tuple = (min(5, max(1, int(timeout))), max(1, int(timeout)))
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})

    def request(
        self, method: str, url: str, headers: Optional[Dict[str, str]] = None
    ) -> HTTPResponseData:
        """Executes an HTTP request with strict error handling and timeout limits."""
        req_headers = headers or {}
        try:
            # Revalidate at every egress point.  This also protects callers
            # other than ScanEngine from issuing requests to private networks.
            safe_url = validate_target_url(url)
            resp = self.session.request(
                method=method.upper(),
                url=safe_url,
                headers=req_headers,
                timeout=self.timeout_tuple,
                verify=self.verify_ssl,
                # Redirect destinations are untrusted input.  Do not follow them
                # automatically, because that would bypass target validation.
                allow_redirects=False,
            )

            # Extract raw Set-Cookie headers (requests collapses them by default in .headers dict)
            raw_cookies = []
            if hasattr(resp.raw, "headers"):
                # Handle urllib3 header retrieval
                for k, v in resp.raw.headers.items():
                    if k.lower() == "set-cookie":
                        raw_cookies.append(v)
            if not raw_cookies and "Set-Cookie" in resp.headers:
                raw_cookies = [resp.headers["Set-Cookie"]]

            return HTTPResponseData(
                url=resp.url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                raw_set_cookie_headers=raw_cookies,
                content_type=resp.headers.get("Content-Type", ""),
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
            )

        except TargetValidationError as e:
            return HTTPResponseData(url=url, error=f"Blocked unsafe target: {str(e)}")
        except SSLError as e:
            return HTTPResponseData(
                url=url, error=f"SSL/TLS Certificate error: {str(e)}"
            )
        except ReqConnectionError as e:
            return HTTPResponseData(
                url=url, error=f"Connection failed or DNS lookup error: {str(e)}"
            )
        except ReqTimeout:
            return HTTPResponseData(
                url=url, error=f"Request timed out after {self.timeout} seconds."
            )
        except RequestException as e:
            return HTTPResponseData(url=url, error=f"HTTP Request failed: {str(e)}")

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HTTPResponseData:
        return self.request("GET", url, headers)

    def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> HTTPResponseData:
        return self.request("HEAD", url, headers)

    def options(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> HTTPResponseData:
        return self.request("OPTIONS", url, headers)
