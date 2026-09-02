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


class WorkspaceDefinitionError(ASHValidationError):
    """Exception raised when a workspace definition cannot be used as given.

    Covers the whole fail-closed set: a malformed or unreadable
    ``.code-workspace`` file, a folder entry that does not exist, escapes the
    workspace root, is a symlink, or overlaps another entry, and two projects
    whose scanner version pins cannot both be satisfied.

    Maps to ``WorkspaceExitCode.WORKSPACE_ERROR`` (2). Kept distinct from
    ASHConfigValidationError, which maps to ``INVALID_PROJECT_CONFIG`` (3),
    because the two route to different people: 2 means the operator's workspace
    file is wrong and nothing could run, 3 means one project is misconfigured.

    The message is expected to name every offending entry rather than the first,
    so an operator with three typos fixes three in one pass.
    """

    pass
