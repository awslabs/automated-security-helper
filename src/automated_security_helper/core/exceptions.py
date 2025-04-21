class ScannerError(Exception):
    """Exception raised when scanner execution fails."""

    pass


class ASHValidationError(Exception):
    """Exception raised when an ASH component fails to validate."""

    pass


class ASHConfigValidationError(ASHValidationError):
    """Exception raised when an ASHConfig is invalid."""

    pass
