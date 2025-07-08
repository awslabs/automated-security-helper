from enum import Enum


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


class ReportFormat(str, Enum):
    """Supported report formats."""

    aggregated = "aggregated"
    asff = "asff"
    csv = "csv"
    cyclonedx = "cyclonedx"
    html = "html"
    json = "flat-json"
    junitxml = "junitxml"
    markdown = "markdown"
    ocsf = "ocsf"
    sarif = "sarif"
    spdx = "spdx"
    text = "text"
    yaml = "yaml"


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


class ConfigFormat(str, Enum):
    json = "json"
    yaml = "yaml"


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


class BuildTarget(str, Enum):
    NON_ROOT = "non-root"
    CI = "ci"


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


class Phases(str, Enum):
    convert = "convert"
    scan = "scan"
    report = "report"
    inspect = "inspect"


class Strategy(str, Enum):
    parallel = "parallel"
    sequential = "sequential"


class RunMode(str, Enum):
    precommit = "precommit"
    container = "container"
    local = "local"


class ExportFormat(str, Enum):
    """Supported export formats."""

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
