class PrivacyException(Exception):
    """Base exception for privacy engine."""

class VaultError(PrivacyException):
    """Error related to the mapping vault."""

class ConfigurationError(PrivacyException):
    """Error related to privacy configuration."""

class TokenError(PrivacyException):
    """Error related to token generation or handling."""
    
class RestorationError(PrivacyException):
    """Error during token restoration."""
