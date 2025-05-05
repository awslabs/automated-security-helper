from enum import Enum


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
