class DomainException(Exception):
    """Base exception class for all domain exceptions."""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

class AuthException(DomainException):
    """Exceptions related to registration and login authentication."""
    pass

class OTPException(DomainException):
    """Exceptions related to OTP requests and verifications."""
    pass

class RateLimitException(DomainException):
    """Exception raised when rate limits are exceeded."""
    def __init__(self, message: str = "Too many requests. Please wait a few minutes and try again."):
        super().__init__(message, status_code=429)

class ScanException(DomainException):
    """Exceptions related to file or URL scanning."""
    pass
