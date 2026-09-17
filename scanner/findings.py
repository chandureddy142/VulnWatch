from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from scanner.severity import SeverityLevel


# OWASP Cheat Sheet links mapped by finding category
OWASP_LINKS: Dict[str, str] = {
    "Missing Security Header": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    "Cookie Configuration": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "HTTP Methods": "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
    "Information Disclosure": "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
    "Network Connectivity": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "TLS / Transport Security": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "Content Security Policy": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "Clickjacking": "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    "Cross-Site Scripting": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "CORS": "https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html",
    "Authentication": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "Authorization": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    "Input Validation": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
}

# Fallback OWASP link when no specific category match exists
OWASP_FALLBACK = "https://cheatsheetseries.owasp.org/index.html"


def get_owasp_link(category: str) -> str:
    """Return the most relevant OWASP Cheat Sheet URL for a given finding category."""
    # Exact match first
    if category in OWASP_LINKS:
        return OWASP_LINKS[category]
    # Partial keyword match
    for key, url in OWASP_LINKS.items():
        if key.lower() in category.lower() or category.lower() in key.lower():
            return url
    return OWASP_FALLBACK


@dataclass
class RawFinding:
    """Structured data container representing a discovered security issue or observation."""

    title: str
    category: str
    severity: SeverityLevel
    description: str
    remediation: str
    affected_url: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    owasp_link: Optional[str] = None

    def __post_init__(self):
        """Auto-populate owasp_link if not explicitly provided."""
        if self.owasp_link is None:
            self.owasp_link = get_owasp_link(self.category)
        # Embed owasp_link into evidence dict for persistence in JSON column
        if self.owasp_link and "owasp_link" not in self.evidence:
            self.evidence["owasp_link"] = self.owasp_link

    def to_dict(self) -> Dict[str, Any]:
        sev_val = self.severity
        if isinstance(sev_val, type):
            sev_str = "HIGH"
        elif isinstance(sev_val, str):
            sev_str = sev_val
        elif hasattr(sev_val, "value") and isinstance(sev_val.value, str):
            sev_str = sev_val.value
        elif hasattr(sev_val, "name") and isinstance(sev_val.name, str):
            sev_str = sev_val.name
        else:
            sev_str = "HIGH"

        return {
            "title": self.title,
            "category": self.category,
            "severity": sev_str,
            "description": self.description,
            "remediation": self.remediation,
            "affected_url": self.affected_url,
            "evidence": self.evidence,
            "owasp_link": self.owasp_link,
        }
