from enum import Enum
from typing import Optional


class ScannerToolType(str, Enum):
    """Type of scanner tool."""

    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"
    IAC = "IAC"
    SECRETS = "SECRETS"  # pragma: allowlist secret - not actually a secret, just the word "SECRETS"
    CONTAINER = "CONTAINER"
    SBOM = "SBOM"
    CUSTOM = "CUSTOM"
    UNKNOWN = "UNKNOWN"


class ScannerStatus(str, Enum):
    """Status of a scanner execution."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    MISSING = "MISSING"
    SKIPPED = "SKIPPED"


class AshLogLevel(str, Enum):
    QUIET = "QUIET"
    SIMPLE = "SIMPLE"
    ERROR = "ERROR"
    INFO = "INFO"
    VERBOSE = "VERBOSE"
    DEBUG = "DEBUG"
    TRACE = "TRACE"


class PackageManager(str, Enum):
    APT = "apt"
    PIP = "pip"
    UV = "uv"
    CONDA = "conda"
    NPM = "npm"
    BREW = "brew"
    YUM = "yum"
    CHOCO = "choco"
    CUSTOM = "custom"
    URL = "url"  # For direct URL downloads


class ExecutionPhase(str, Enum):
    """Phases of ASH execution."""

    CONVERT = "convert"
    SCAN = "scan"
    REPORT = "report"
    INSPECT = "inspect"


class ExecutionStrategy(str, Enum):
    """Strategy for executing scanners."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"


class OfflineStrategy(str, Enum):
    """Describes how a scanner behaves when network access is unavailable."""

    BUNDLED = "bundled"
    CACHE_FLAGS = "cache_flags"
    SKIP_OFFLINE = "skip_offline"
    UNKNOWN = "unknown"


class BuildTarget(str, Enum):
    NON_ROOT = "non-root"
    CI = "ci"


class RunMode(str, Enum):
    precommit = "precommit"
    container = "container"
    local = "local"
    # Runs the scan inside `nix develop`, which supplies every scanner binary pinned by
    # hash. Like container mode this is an outer wrapper: the inner run is a local scan.
    # Linux and macOS only -- native Windows Nix can fetch nothing, so Windows goes
    # through WSL2.
    nix = "nix"


class SandboxMode(str, Enum):
    """How scanner subprocesses are confined. See docs/content/docs/scanner-sandbox.md."""

    off = "off"
    auto = "auto"
    bwrap = "bwrap"
    firejail = "firejail"
    landlock = "landlock"
    sandbox_exec = "sandbox-exec"


class Transport(str, Enum):
    """A transport ``ash mcp --transport`` accepts.

    The one definition of the three spellings that used to live in the
    ``--transport`` validation tuple (``cli/mcp/__init__.py``), the known and
    networked sets (``cli/mcp/sandbox.py``) and the ``HttpCaller.transport`` values
    (``cli/mcp/http_sessions.py``). It lives here, not under ``cli/mcp``, because
    ``cli/main.py`` needs it for the ``--transport`` help text and importing
    ``cli.mcp`` loads the MCP SDK, which the lazy ``mcp`` command exists to avoid.

    A ``str`` Enum, so a member equals its wire spelling (``--transport`` and
    ``ASH_MCP_TRANSPORT`` carry the plain string). ``__str__`` returns the value so
    an f-string reads the same on every Python version: ``format()`` of a mixed-in
    Enum changed in 3.12.
    """

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"
    SSE = "sse"

    def __str__(self) -> str:
        return self.value

    @property
    def is_networked(self) -> bool:
        """True for the transports that carry callers the server does not trust."""
        return self is not Transport.STDIO

    @classmethod
    def parse(cls, value: object) -> Optional["Transport"]:
        """The member whose value is exactly ``value``, or None when none is."""
        try:
            return cls(value)
        except ValueError:
            return None


#: Every ``--transport`` spelling, in the order the help text lists them.
TRANSPORT_VALUES = tuple(member.value for member in Transport)

#: What ``--transport`` and ``ASH_MCP_TRANSPORT`` mean when unset.
DEFAULT_TRANSPORT = Transport.STDIO

#: The ``--transport`` help text, built from the members so the option and the
#: enum cannot drift. Byte-equal to the text both CLI declarations carried by hand;
#: ``tests/unit/cli/mcp/test_mcp_transport_enum.py`` pins it.
TRANSPORT_HELP = (
    f"Transport: '{Transport.STDIO.value}' (default), "
    f"'{Transport.STREAMABLE_HTTP.value}', or '{Transport.SSE.value}'."
)


class MinSeverity(str, Enum):
    """The values --min-severity accepts, laxest first, matched without regard to case.

    Not the severity ladder: there is no ``info``, ``critical`` and ``high`` rank the
    same because SARIF's ``error`` covers both, and ``none`` gates on any finding. The
    rank tables in interactions/run_ash_scan.py (``_SEVERITY_RANK``) and
    workspace/aggregation.py (``_MIN_SEVERITY_RANK``) are keyed by exactly these
    values. Only these reach those tables: ranked as ``low``, a typo would be the
    strictest gate short of ``none``.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ExportFormat(str, Enum):
    """A report format name, as --output-formats and output_formats take it.

    Each names the reporter that writes it, except aggregated, dict and
    custom: no reporter writes those, so asking for one writes nothing for it and
    logs why.
    """

    # A reporter is selected by its configured name, so every reporter ASH ships
    # needs a member with that exact value. Without one the reporter cannot be
    # named, and any list of formats switches it off.
    #
    # aggregated, dict and custom name no reporter. They stay accepted
    # rather than refused because they have been valid values of this public enum
    # and of --output-formats since v3; ReportPhase's FORMAT_NO_REPORTER message
    # tells an operator who asks for one that nothing will be written.
    # tests/unit/cli/test_output_formats_select_every_reporter.py fails for a
    # shipped reporter that has no member. (A comment rather than the docstring,
    # because a docstring becomes the description wherever this enum appears in a
    # published JSON schema.)
    AGGREGATED = "aggregated"
    TEXT = "text"
    FLAT_JSON = "flat-json"
    YAML = "yaml"
    CSV = "csv"
    HTML = "html"
    DICT = "dict"
    JUNITXML = "junitxml"
    MARKDOWN = "markdown"
    SARIF = "sarif"
    ASFF = "asff"
    OCSF = "ocsf"
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    CUSTOM = "custom"
    GITHUB_GHAS = "github-ghas"
    GITLAB_SAST = "gitlab-sast"
    GITLAB_CYCLONEDX = "gitlab-cyclonedx"
    UNUSED_SUPPRESSIONS = "unused-suppressions"
    # Reporters of the AWS plugin module. They exist in a run only when
    # ash_plugin_modules loads that module.
    AWS_SECURITY_HUB = "aws-security-hub"
    BEDROCK_SUMMARY = "bedrock-summary-reporter"
    CLOUDWATCH_LOGS = "cloudwatch-logs"
    S3 = "s3"


#: The formats no reporter writes (see ExportFormat): ``ash report --format``
#: refuses each, and a scan asked for one writes nothing for it and says why.
FORMATS_NO_REPORTER_WRITES = frozenset(
    {ExportFormat.AGGREGATED, ExportFormat.DICT, ExportFormat.CUSTOM}
)

#: The formats of the AWS plugin module's reporters, which a run has only when
#: ``ash_plugin_modules`` loads that module.
AWS_PLUGIN_MODULE_FORMATS = frozenset(
    {
        ExportFormat.AWS_SECURITY_HUB,
        ExportFormat.BEDROCK_SUMMARY,
        ExportFormat.CLOUDWATCH_LOGS,
        ExportFormat.S3,
    }
)
