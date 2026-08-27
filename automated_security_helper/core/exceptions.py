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


class ShardSelectionError(ASHValidationError):
    """Exception raised when ``--shard-index``/``--shard-count`` cannot be used as given.

    Every case this covers would otherwise produce a *partial* scan that reports
    itself as a whole one, which is the worst available outcome for a security
    scanner: a lone ``--shard-index`` with no ``--shard-count`` would scan shard 0
    of an unknown total, and an index at or past the count would scan nothing at
    all and exit 0.

    Refused rather than clamped. Clamping an out-of-range index onto the last
    shard would make a pipeline with an off-by-one in its matrix expression scan
    one shard twice and another never, and the reports would look healthy.
    """

    pass


class ShardCoverageError(ASHValidationError):
    """Exception raised when a set of shard results cannot be merged into a whole.

    A merge is only meaningful if the shards it is handed reconstruct exactly one
    full scan. This is raised when they do not: a missing index (a CI job that
    failed or whose artifact never uploaded), a duplicated index, shards that
    disagree about the total count, or two shards that both claim the same
    scanner.

    The failure mode this exists to prevent is silent and severe. Merging four of
    five shards produces a valid, well-formed, confidently-empty-looking report
    for whichever scanners lived on the missing shard, and nothing in the output
    says a fifth of the scan is absent. So the merge fails loudly and names the
    specific gap instead of reporting what it happens to have.
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
