import json
import logging
import os
import platform
import sys
from typing import Dict, Literal
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme
from pathlib import Path


def addLoggingLevel(levelName, levelNum, methodName=None):
    """
    Adapted from: https://stackoverflow.com/a/35804945

    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5
    """
    if not methodName:
        methodName = levelName.lower()

    # Guard against duplicate registration (e.g. module re-import)
    if hasattr(logging, levelName):
        return
    if hasattr(logging, methodName):
        return
    if hasattr(logging.getLoggerClass(), methodName):
        return

    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)

    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)


addLoggingLevel("TRACE", 5)
addLoggingLevel("VERBOSE", 15)

VERBOSE_LEVEL: int = logging._nameToLevel.get("VERBOSE", 15)  # type: ignore[attr-defined]
TRACE_LEVEL: int = logging._nameToLevel.get("TRACE", 5)  # type: ignore[attr-defined]


class ASHLogger(logging.Logger):
    """Logger subclass that adds verbose() and trace() as first-class methods."""

    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name=name, level=level)

    def verbose(self, msg, *args, **kws):
        if self.isEnabledFor(VERBOSE_LEVEL):
            self._log(VERBOSE_LEVEL, msg, args, **kws)

    def trace(self, msg, *args, **kws):
        if self.isEnabledFor(TRACE_LEVEL):
            self._log(TRACE_LEVEL, msg, args, **kws)


logging.setLoggerClass(ASHLogger)


def _detect_encoding_issues() -> bool:
    """Return True if running on Windows with an encoding that cannot represent Unicode."""
    if platform.system().lower() != "windows":
        return False

    ci_indicators = [
        "CI",
        "GITHUB_ACTIONS",
        "AZURE_PIPELINES",
        "JENKINS_URL",
        "BUILDKITE",
        "CIRCLECI",
        "TRAVIS",
        "APPVEYOR",
    ]
    is_ci = any(indicator in os.environ for indicator in ci_indicators)

    has_encoding_issues = False
    console_encoding = "utf-8"
    try:
        console_encoding = sys.stdout.encoding or "utf-8"
        has_encoding_issues = console_encoding.lower() in [
            "cp1252",
            "windows-1252",
            "cp850",
            "cp437",
            "ascii",
        ]
    except (AttributeError, TypeError):
        has_encoding_issues = True

    try:
        "✅🔴⚠️".encode(console_encoding)
    except (UnicodeEncodeError, LookupError):
        has_encoding_issues = True

    return is_ci or has_encoding_issues


def _get_default_emoji_fallback_map() -> Dict[str, str]:
    """Get the default emoji fallback mapping for Windows."""
    return {
        "✅": "[OK]",
        "🔴": "[ERROR]",
        "⚠️": "[WARNING]",
        "🚀": "[INFO]",
        "📁": "[FOLDER]",
        "📄": "[FILE]",
        "🔍": "[SEARCH]",
        "💾": "[SAVE]",
        "🔧": "[CONFIG]",
        "📊": "[STATS]",
        "🎯": "[TARGET]",
        "⏱️": "[TIME]",
        "🔒": "[SECURE]",
        "🔓": "[INSECURE]",
        "📝": "[NOTE]",
        "❌": "[FAIL]",
        "✨": "[SUCCESS]",
        "🛡️": "[SECURITY]",
        "🔎": "[SCAN]",
        "📋": "[LIST]",
        "⭐": "[STAR]",
        "🎉": "[CELEBRATE]",
        "🚨": "[ALERT]",
        "💡": "[TIP]",
        "🔄": "[REFRESH]",
        "📈": "[PROGRESS]",
        "🏁": "[FINISH]",
        "🎪": "[DEMO]",
        "🔗": "[LINK]",
        "📦": "[PACKAGE]",
        "🌟": "[FEATURE]",
        "🎨": "[STYLE]",
        "🧪": "[TEST]",
        "🔥": "[HOT]",
        "❄️": "[COLD]",
        "🌈": "[RAINBOW]",
        "🎭": "[MASK]",
        "🎲": "[DICE]",
        "🎮": "[GAME]",
        "🎸": "[MUSIC]",
        "🎤": "[MIC]",
        "🎬": "[MOVIE]",
        # Unicode warning symbol specifically (the one causing the error)
        "⚠": "[WARNING]",
        # Other common Unicode symbols
        "✓": "[CHECK]",  # ✓
        "✗": "[X]",  # ✗
        "→": "->",  # →
        "←": "<-",  # ←
        "↑": "^",  # ↑
        "↓": "v",  # ↓
    }


def _make_message_windows_safe(message: str, emoji_fallback_map: Dict[str, str]) -> str:
    """Convert a message with Unicode characters to a Windows-safe version."""
    safe_message = message
    for unicode_char, ascii_replacement in emoji_fallback_map.items():
        safe_message = safe_message.replace(unicode_char, ascii_replacement)
    return safe_message


class WindowsSafeFilter(logging.Filter):
    """Logging filter that replaces emoji/Unicode with ASCII on Windows when encoding is limited."""

    def __init__(self):
        super().__init__()
        self._active = _detect_encoding_issues()
        self._emoji_map = _get_default_emoji_fallback_map()

    def filter(self, record: logging.LogRecord) -> bool:
        if self._active and isinstance(record.msg, str):
            record.msg = _make_message_windows_safe(record.msg, self._emoji_map)
            try:
                record.msg.encode("ascii")
            except UnicodeEncodeError:
                record.msg = record.msg.encode("ascii", errors="ignore").decode("ascii")
        return True


class JsonFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings after parsing the LogRecord.

    @param dict fmt_dict: Key: logging format attribute pairs. Defaults to {"message": "message"}.
    @param str time_format: time.strftime() format string. Default: "%Y-%m-%dT%H:%M:%S"
    @param str msec_format: Microsecond formatting. Appended at the end. Default: "%s.%03dZ"
    """

    def __init__(
        self,
        fmt_dict: dict | None = None,
        time_format: str = "%Y-%m-%dT%H:%M:%S",
        msec_format: str = "%s.%03dZ",
    ):
        self.fmt_dict = fmt_dict if fmt_dict is not None else {"message": "message"}
        self.default_time_format = time_format
        self.default_msec_format = msec_format
        self.datefmt = None

    def usesTime(self) -> bool:
        """
        Overwritten to look for the attribute in the format dict values instead of the fmt string.
        """
        return "asctime" in self.fmt_dict.values()

    def formatMessage(self, record) -> dict:
        """
        Overwritten to return a dictionary of the relevant LogRecord attributes instead of a string.
        KeyError is raised if an unknown attribute is provided in the fmt_dict.
        """
        return {
            fmt_key: record.__dict__[fmt_val]
            for fmt_key, fmt_val in self.fmt_dict.items()
        }

    def format(self, record) -> str:
        """
        Mostly the same as the parent's class method, the difference being that a dict is manipulated and dumped as JSON
        instead of a string.
        """
        record.message = record.getMessage()

        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)

        message_dict = self.formatMessage(record)

        if record.exc_info:
            # Cache the traceback text to avoid converting it multiple times
            # (it's constant anyway)
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)

        if record.exc_text:
            message_dict["exc_info"] = record.exc_text

        if record.stack_info:
            message_dict["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(message_dict, default=str)


def get_logger(
    name: str = "ash",
    level: str | int | None = None,
    output_dir: Path | None = None,
    log_format: Literal["JSONL", "TABULAR", "BOTH"] = "TABULAR",
    show_progress: bool = True,
    use_color: bool = True,
    simple_format: bool = False,
    file_log_level: str | int | None = None,
    truncate_log: bool = True,
) -> "ASHLogger":
    # Disable propagation to the root logger to prevent duplicate messages
    root_logger = logging.getLogger()
    if root_logger.handlers and name != "":
        logging.getLogger(name).propagate = False

    logger: ASHLogger = logging.getLogger(name)  # type: ignore[assignment]

    # Attach the Windows-safe filter if not already present
    if not any(isinstance(f, WindowsSafeFilter) for f in logger.filters):
        logger.addFilter(WindowsSafeFilter())

    # Clear existing handlers to avoid duplicates when the function is called multiple times
    if logger.handlers:
        logger.handlers = []

    # Explicit set the logger level to TRACE/5
    # (root logger sets the lowest level depth for all attached handlers)
    logger.setLevel(logging._nameToLevel.get("TRACE", 5))  # type: ignore[attr-defined]
    level_param = {}
    if level is not None:
        level_param = {"level": level}

    logger._log(
        15,
        msg=f"Log level set to: {logging._levelToName[level] if isinstance(level, int) else level}",  # type: ignore[index]
        args=(),
    )

    logger.verbose("Logger initialized: %s", name)
    logger.verbose(
        "Logger effective level: %s",
        logging._levelToName[logger.getEffectiveLevel() or 0],  # type: ignore[index]
    )

    SHOW_DEBUG_INFO = logging._levelToName[logger.getEffectiveLevel() or 0] != "INFO"  # type: ignore[index]
    logger.info("Show debug info: %s", SHOW_DEBUG_INFO)
    # Configure console parameters with Windows-safe settings
    console_base_params = {
        "theme": Theme(
            {
                "logging.level.verbose": "magenta",
                "logging.level.warning": "yellow",
                "logging.level.trace": "green",
            }
        ),
        "highlight": use_color,
        "legacy_windows": platform.system().lower() == "windows",
        "safe_box": platform.system().lower() == "windows",
        "_environ": {},  # Prevent environment variable issues
    }

    # Set color system based on platform and encoding capabilities
    if use_color:
        if platform.system().lower() == "windows":
            console_base_params["color_system"] = "windows"
        else:
            console_base_params["color_system"] = "auto"
    else:
        console_base_params["color_system"] = None

    # Add width constraint for container environments
    if os.environ.get("ASH_IN_CONTAINER", "NO").upper() in ["YES", "1", "TRUE"]:
        console_base_params["width"] = 150

    custom_console_params = {"console": Console(**console_base_params)}
    if SHOW_DEBUG_INFO:
        handler = RichHandler(
            show_level=not simple_format,
            enable_link_path=not simple_format,
            rich_tracebacks=not simple_format,
            show_path=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
            in ["YES", "1", "TRUE"],
            tracebacks_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
            in ["YES", "1", "TRUE"],
            markup=True,
            **level_param,
            **custom_console_params,
        )
    else:
        handler = RichHandler(
            show_level=not simple_format,
            enable_link_path=False,
            show_path=False,
            tracebacks_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
            in ["YES", "1", "TRUE"],
            show_time=False,
            rich_tracebacks=not simple_format,
            markup=True,
            **level_param,
            **custom_console_params,
        )

    handler.setFormatter(logging.Formatter("%(message)s"))

    # Always add the handler unless show_progress is True
    # (show_progress means we're using a different progress display mechanism)
    if not show_progress:
        logger.addHandler(handler)

    if output_dir:
        """Add a file handler for this logger with the specified `name` (and
        store the log file under `output_dir`)."""
        # Determine file log level (default to INFO to avoid huge log files)
        final_file_log_level = (
            file_log_level if file_log_level is not None else logging.INFO
        )

        # Create JSONLines/JSONL file handler for logging to a file
        if log_format in ["JSONL", "BOTH"]:
            jsonl_log_file = Path(output_dir).joinpath(f"{name}.log.jsonl")
            jsonl_log_file.parent.mkdir(parents=True, exist_ok=True)
            # Truncate the file if requested (default), otherwise append
            if truncate_log:
                jsonl_log_file.write_text("")  # Clear the file
            else:
                jsonl_log_file.touch(
                    exist_ok=True
                )  # Create if doesn't exist, but don't truncate

            jsonl_file_handler = logging.FileHandler(jsonl_log_file.as_posix())
            logger.verbose("Logging to JSONL file: %s", jsonl_log_file.as_posix())
            jsonl_file_handler.setLevel(final_file_log_level)
            jsonl_file_handler.setFormatter(
                JsonFormatter(
                    {
                        "timestamp": "asctime",
                        "level": "levelname",
                        "filename": "filename",
                        "lineno": "lineno",
                        "message": "message",
                        "loggerName": "name",
                        "processName": "processName",
                        "processID": "process",
                        "threadName": "threadName",
                        "threadID": "thread",
                    }
                )
            )
            logger.addHandler(jsonl_file_handler)
        # Create tabular file handler for logging to a file
        if log_format in ["TABULAR", "BOTH"]:
            tab_log_file = Path(output_dir).joinpath(f"{name}.log")
            tab_log_file.parent.mkdir(parents=True, exist_ok=True)
            # Truncate the file if requested (default), otherwise append
            if truncate_log:
                tab_log_file.write_text("")  # Clear the file
            else:
                tab_log_file.touch(
                    exist_ok=True
                )  # Create if doesn't exist, but don't truncate

            tab_file_handler = logging.FileHandler(tab_log_file.as_posix())
            logger.verbose("Logging to tabular file: %s", tab_log_file.as_posix())
            tab_file_handler.setLevel(final_file_log_level)
            tab_file_handler.setFormatter(
                logging.Formatter(
                    fmt="%(asctime)s\t%(levelname)s\t%(filename)s:%(lineno)d\t%(message)s "
                )
            )
            logger.addHandler(tab_file_handler)

    return logger


ASH_LOGGER: ASHLogger = logging.getLogger("ash")  # type: ignore[assignment]
ASH_LOGGER.propagate = False
ASH_LOGGER.addFilter(WindowsSafeFilter())
