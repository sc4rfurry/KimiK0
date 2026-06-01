"""Custom exception hierarchy for the cs_aggregator engine."""


class CSAggregatorError(Exception):
    """Base exception for all cs_aggregator errors."""
    pass


class PayloadError(CSAggregatorError):
    """Raised when payload input is invalid, corrupt, or unsupported."""
    pass


class PayloadTooSmallError(PayloadError):
    """Raised when the input payload is below minimum size threshold."""
    pass


class UnsupportedFormatError(PayloadError):
    """Raised when the input format is not recognized or supported."""
    pass


class ExtractionError(CSAggregatorError):
    """Raised when a segment extraction fails."""
    pass


class PEFormatError(ExtractionError):
    """Raised when PE parsing encounters a malformed or unsupported structure."""
    pass


class ConfigDecryptionError(ExtractionError):
    """Raised when configuration block decryption fails."""
    pass


class VersionDetectionError(CSAggregatorError):
    """Raised when version fingerprinting cannot determine the CS version."""
    pass


class SchemaError(CSAggregatorError):
    """Raised when a version schema file is invalid or missing required fields."""
    pass


class ManifestError(CSAggregatorError):
    """Raised when manifest generation encounters an issue."""
    pass
