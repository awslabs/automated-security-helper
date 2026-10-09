class ScannerError(Exception):
    """Exception raised when scanner execution fails."""


class ASHValidationError(Exception):
    """Exception raised when an ASH component fails to validate."""


class ASHConfigValidationError(ASHValidationError):
    """Exception raised when an AshConfig is invalid."""


class ASHConfigSourceError(ASHConfigValidationError):
    """A config source could not be read or its ``extends`` chain resolved.

    Covers a missing or unreadable base, a cycle, a chain past its bounds, a base
    path outside the confinement root, a malformed ``patch``, and a
    ``pyproject.toml`` whose ``[tool.ash]`` table cannot be read. A subclass of
    ``ASHConfigValidationError`` so that ``resolve_config`` re-raises it rather
    than falling back to the default config: a config whose bases did not load is
    not the config the operator wrote, and scanning with the defaults instead
    would drop its suppressions and settings without failing.
    """


class ASHConfigInputNotPermittedError(ASHConfigSourceError):
    """A file in an ``extends`` chain is outside what the caller may read.

    Raised only when the caller passed a ``permit_base`` gate, which the MCP server
    does with the session's allowed config roots. A subclass of
    ``ASHConfigSourceError`` so every path that already refuses a broken chain
    refuses this one, and distinct so the MCP tools can report it as a refusal
    rather than as a malformed config. The message names the ``extends`` entry as
    written and never the resolved target, so it reads the same whether or not
    that target exists.
    """


class ASHConfigFieldDeniedError(ASHConfigValidationError):
    """A config file an MCP client delivered sets a field the session's policy denies.

    The policy is ``global_settings.mcp.runtime_overrides``' ``denied_paths`` and
    ``denied_value_patterns``, the rules a client's ``patch_ops`` and
    ``config_overrides`` are held to. A subclass of ``ASHConfigValidationError``
    so every caller that refuses an invalid config refuses this one, and distinct
    so the MCP tools can report it as a refusal naming the field.
    """


class ASHConfigPolicyUnreadableError(ASHConfigValidationError):
    """The policy a client-delivered config is checked against cannot be established.

    The profile the session bound is no longer registered, or the trusted config
    has two sections that read as the same plugin. Raised only when the config
    being resolved has a client-delivered file in its chain, so a scan that reads
    no such file is unaffected.
    """


class WorkspacePatternError(ASHValidationError):
    """Exception raised when a glob pattern cannot be rebased between the
    project and workspace path spaces.

    Distinct from ASHConfigValidationError so a caller can map a bad pattern to
    the workspace definition error exit code rather than reporting it as a
    general configuration failure.
    """


class ScannerSelectionError(ASHValidationError):
    """Exception raised when ``--scanners`` names no scanner that exists.

    The same failure mode :class:`ShardSelectionError` guards against, reached by a
    different route: a scan that ran nothing and reported itself as a clean one.
    Selection is matched against a scanner's configured name by string equality, so
    ``--scanners detect_secrets`` -- underscore, where the registered name is
    ``detect-secrets`` -- matched nothing, every scanner was recorded SKIPPED, and
    the run produced zero findings and exit 0.

    SKIPPED cannot be what gives that away. It is how sharding and
    ``--exclude-scanners`` record work a run was never meant to do, so the
    completeness gate has to tolerate it; that is what leaves an unresolvable
    allowlist with no existing gate to fall foul of.

    Raised only when *nothing* the operator asked for resolved. A partly
    unresolvable allowlist warns and continues: those runs still scan and report
    what did resolve, and a CI matrix can produce that shape legitimately when its
    runners load different plugin modules.
    """


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


class ToolDownloadIntegrityError(ASHValidationError):
    """Exception raised when a downloaded tool's bytes do not match its pinned digest.

    Raised before the download is moved into place, so a failed verification
    leaves nothing installed rather than installing the bad bytes and reporting
    the mismatch afterwards.

    The failure this exists to prevent is specific: without it, a scanner binary
    that had been substituted upstream, truncated by a proxy, or served from a
    cache poisoned in transit would be installed, found on PATH, and then trusted
    to produce the findings a security decision is made from. A digest field that
    is recorded but never compared is not a check, so this is raised on every
    mismatch and never downgraded to a warning.
    """


class ToolNotProvisionableError(ASHValidationError):
    """Exception raised when a tool cannot be installed on the current platform.

    Covers three distinct cases, all refused rather than approximated:

    * the tool has no install path in ASH at all,
    * the tool has one but publishes no asset for this platform/architecture,
    * the pinned version and the pinned digests disagree, which is what a
      half-applied version bump looks like.

    Substituting a nearby architecture would install an executable that fails at
    exec time, and that surfaces in a scan report as an execution failure rather
    than as a bad install -- the diagnosis lands on the wrong thing. An absent
    asset is a real constraint and is reported as one.
    """


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
