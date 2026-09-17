import enum


class SeverityLevel(str, enum.Enum):
    """Standardized severity levels for WebGuard security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting severity (higher numeric value = higher severity)."""
        ranks = {
            SeverityLevel.INFO: 1,
            SeverityLevel.LOW: 2,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.HIGH: 4,
            SeverityLevel.CRITICAL: 5,
        }
        return ranks[self]

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.rank < other.rank
        return NotImplemented
