"""Security-layer exceptions."""


class SecurityError(Exception):
    """Base class for security failures."""


class PQCUnavailableError(SecurityError):
    """Raised when a required post-quantum primitive is unavailable."""


class NegotiationError(SecurityError):
    """Raised when peers cannot negotiate the requested protection."""


class EnvelopeError(SecurityError):
    """Raised for malformed, forged, or downgraded envelopes."""


class ReplayError(EnvelopeError):
    """Raised for replayed, expired, or implausibly dated messages."""
