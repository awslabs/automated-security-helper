class ScannerError(Exception):
    """Exception raised when scanner execution fails."""

    pass


class ASHValidationError(Exception):
    """Exception raised when an ASH component fails to validate."""

    pass


class ASHConfigValidationError(ASHValidationError):
    """Exception raised when an AshConfig is invalid."""

    pass


class WorkspacePatternError(ASHValidationError):
    """Exception raised when a glob pattern cannot be rebased between the
    project and workspace path spaces.

    Distinct from ASHConfigValidationError so a caller can map a bad pattern to
    the workspace definition error exit code rather than reporting it as a
    general configuration failure.
    """

    pass
