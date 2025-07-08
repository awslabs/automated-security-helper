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

    if hasattr(logging, levelName):
        raise AttributeError("{} already defined in logging module".format(levelName))
    if hasattr(logging, methodName):
        raise AttributeError("{} already defined in logging module".format(methodName))
    if hasattr(logging.getLoggerClass(), methodName):
        raise AttributeError("{} already defined in logger class".format(methodName))

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


BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# The background is set with 40 plus the number of the color, and the foreground with 30

# These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

COLORS = {
    "WARNING": YELLOW,
    "INFO": CYAN,
    "DEBUG": BLUE,
    "VERBOSE": MAGENTA,
    "TRACE": GREEN,
    "CRITICAL": YELLOW,
    "ERROR": RED,
}


def formatter_message(message, use_color=True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message


class JsonFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings after parsing the LogRecord.

    @param dict fmt_dict: Key: logging format attribute pairs. Defaults to {"message": "message"}.
    @param str time_format: time.strftime() format string. Default: "%Y-%m-%dT%H:%M:%S"
    @param str msec_format: Microsecond formatting. Appended at the end. Default: "%s.%03dZ"
    """

    def __init__(
        self,
        fmt_dict: dict = None,
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


class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color=True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = (
                COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            )
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


# Custom logger class with multiple destinations
class ASHLogger(logging.getLoggerClass()):
    def __init__(
        self,
        name: str,
        level: str | int | None = None,
    ):
        super().__init__(name=name, level=level if level is not None else logging.INFO)

    def verbose(self, msg, *args, **kws):
        self._log(logging._nameToLevel.get("VERBOSE", 15), msg, args, **kws)

    def trace(self, msg, *args, **kws):
        self._log(logging._nameToLevel.get("TRACE", 5), msg, args, **kws)


def _is_windows_with_encoding_issues() -> bool:
    """Check if we're running on Windows with potential encoding issues."""
    if platform.system().lower() != "windows":
        return False

    # Check if we're in a CI environment where encoding might be problematic
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

    # Check console encoding
    try:
        console_encoding = sys.stdout.encoding or "unknown"
        # CP1252 is the problematic encoding on Windows
        has_encoding_issues = console_encoding.lower() in ["cp1252", "windows-1252"]
    except (AttributeError, TypeError):
        has_encoding_issues = True  # Assume issues if we can't determine encoding

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
        "\u26a0": "[WARNING]",
        # Other common Unicode symbols
        "\u2713": "[CHECK]",  # ✓
        "\u2717": "[X]",  # ✗
        "\u2192": "->",  # →
        "\u2190": "<-",  # ←
        "\u2191": "^",  # ↑
        "\u2193": "v",  # ↓
    }


def _make_message_windows_safe(message: str, emoji_fallback_map: Dict[str, str]) -> str:
    """Convert a message with Unicode characters to a Windows-safe version."""
    # Replace Unicode characters with ASCII alternatives
    safe_message = message
    for unicode_char, ascii_replacement in emoji_fallback_map.items():
        safe_message = safe_message.replace(unicode_char, ascii_replacement)

    return safe_message


def configure_windows_safe_logging():
    """
    Configure logging to be Windows-safe by setting appropriate encoding.
    This should be called early in the application startup.
    """
    if platform.system().lower() != "windows":
        return

    # Check if we're in a CI environment where encoding might be problematic
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

    # Check console encoding
    try:
        console_encoding = sys.stdout.encoding or "unknown"
        has_encoding_issues = console_encoding.lower() in ["cp1252", "windows-1252"]
    except (AttributeError, TypeError):
        has_encoding_issues = True

    if not (is_ci or has_encoding_issues):
        return

    # Try to set UTF-8 encoding for stdout/stderr on Windows
    try:
        import locale

        # Try to set console to UTF-8 if possible
        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError):
                pass

        # Set locale to UTF-8 if possible
        try:
            locale.setlocale(locale.LC_ALL, "en_US.UTF-8")
        except locale.Error:
            try:
                locale.setlocale(locale.LC_ALL, "C.UTF-8")
            except locale.Error:
                pass  # Keep default locale

    except ImportError:
        pass  # codecs/locale not available


class Color:
    @staticmethod
    def red(msg) -> str:
        return "\033[91m{}\033[00m".format(msg)

    @staticmethod
    def green(msg) -> str:
        return "\033[92m{}\033[00m".format(msg)

    @staticmethod
    def yellow(msg) -> str:
        return "\033[33m{}\033[00m".format(msg)

    @staticmethod
    def lightPurple(msg) -> str:
        return "\033[94m{}\033[00m".format(msg)

    @staticmethod
    def purple(msg) -> str:
        return "\033[95m{}\033[00m".format(msg)

    @staticmethod
    def cyan(msg) -> str:
        return "\033[96m{}\033[00m".format(msg)

    @staticmethod
    def gray(msg) -> str:
        return "\033[97m{}\033[00m".format(msg)

    @staticmethod
    def black(msg) -> str:
        return "\033[98m{}\033[00m".format(msg)


# class CustomFormatter(logging.Formatter):

#     grey = "\x1b[38;20m"
#     cyan = "\x1b[36;20m"
#     yellow = "\x1b[33;20m"
#     red = "\x1b[31;20m"
#     bold_red = "\x1b[31;1m"
#     reset = "\x1b[0m"
#     format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

#     FORMATS = {
#         logging.DEBUG: cyan + format + reset,
#         logging.INFO: grey + format + reset,
#         logging.WARNING: yellow + format + reset,
#         logging.ERROR: red + format + reset,
#         logging.CRITICAL: bold_red + format + reset
#     }

#     def format(self, record):
#         log_fmt = self.FORMATS.get(record.levelno)
#         formatter = logging.Formatter(log_fmt)
#         return formatter.format(record)


def get_logger(
    name: str = "ash",
    level: str | int | None = None,
    output_dir: Path | None = None,
    log_format: Literal["JSONL", "TABULAR", "BOTH"] = "TABULAR",
    show_progress: bool = True,
    use_color: bool = True,
    simple_format: bool = False,
) -> logging.Logger:
    # Configure Windows-safe logging early
    configure_windows_safe_logging()

    # VERBOSE_FORMAT = "[%(asctime)s] [%(levelname)-18s] ($BOLD%(filename)s$RESET:%(lineno)d) %(message)s "
    # DEFAULT_FORMAT = "[%(levelname)-18s] %(message)s "

    logger: logging.Logger = logging.getLogger(name)

    # If this is the main ASH logger, enhance it with Windows-safe functionality
    if name == "ash" and not hasattr(logger, "_windows_safe_mode"):
        # Monkey patch the logger with Windows-safe functionality
        logger._windows_safe_mode = _is_windows_with_encoding_issues()
        logger._emoji_fallback_map = _get_default_emoji_fallback_map()

        # Store original _log method
        original_log = logger._log

        def _safe_log(level, msg, args, **kwargs):
            if logger._windows_safe_mode and isinstance(msg, str):
                msg = _make_message_windows_safe(msg, logger._emoji_fallback_map)

            try:
                original_log(level, msg, args, **kwargs)
            except UnicodeEncodeError:
                # Fallback: strip all non-ASCII characters
                if isinstance(msg, str):
                    ascii_msg = msg.encode("ascii", errors="ignore").decode("ascii")
                    original_log(level, f"[ENCODING_ISSUE] {ascii_msg}", args, **kwargs)
                else:
                    original_log(
                        level,
                        "[ENCODING_ISSUE] Message contained non-ASCII characters",
                        args,
                        **kwargs,
                    )

        # Replace the _log method
        logger._log = _safe_log

    # Explicit set the root logger level to TRACE/5
    # (root logger sets the lowest level depth for all attached handlers)
    logger.setLevel(logging._nameToLevel.get("TRACE", 5))
    level_param = {}
    if level is not None:
        level_param = {"level": level}

    logger._log(
        15,
        msg=f"Log level set to: {logging._levelToName[level] if isinstance(level, int) else level}",
        args=(),
    )

    logger.verbose("Logger initialized: %s", name)
    logger.verbose(
        "Logger effective level: %s",
        logging._levelToName[logger.getEffectiveLevel() or 0],
    )

    SHOW_DEBUG_INFO = logging._levelToName[logger.getEffectiveLevel() or 0] != "INFO"
    logger.info("Show debug info: %s", SHOW_DEBUG_INFO)
    custom_console_params = (
        {
            "console": Console(
                width=150,
                theme=Theme(
                    {
                        "logging.level.verbose": "magenta",
                        "logging.level.warning": "yellow",
                        "logging.level.trace": "green",
                    }
                ),
                highlight=use_color,
                color_system=(
                    "windows"
                    if platform.system() == "Windows"
                    else "auto"
                    if use_color
                    else None
                ),
            )
        }
        if os.environ.get("ASH_IN_CONTAINER", "NO").upper() in ["YES", "1", "TRUE"]
        else {
            "console": Console(
                theme=Theme(
                    {
                        "logging.level.verbose": "magenta",
                        "logging.level.warning": "yellow",
                        "logging.level.trace": "green",
                    }
                ),
                highlight=use_color,
                color_system=(
                    "windows"
                    if platform.system() == "Windows"
                    else "auto"
                    if use_color
                    else None
                ),
            )
        }
    )
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
    # if logger.level is None or logger.level > 15:
    #     COLOR_FORMAT = formatter_message(DEFAULT_FORMAT, True)
    # else:
    #     COLOR_FORMAT = formatter_message(VERBOSE_FORMAT, True)

    # color_formatter = ColoredFormatter(COLOR_FORMAT)

    handler.setFormatter(logging.Formatter("%(message)s"))

    # if logger.level == logging.DEBUG:
    #     formatter_str = "[%(asctime)s] [%(name)s] [%(filename)s:%(lineno)d] %(levelname)s: %(message)s"
    #     # formatter_str = f"{Color.cyan('[%(asctime)s]')} {Color.gray('[%(name)s]')} {Color.yellow('[%(filename)s:%(lineno)d]')} {Color.yellow('[%(levelname)s]')}: %(message)s"
    #     formatter = logging.Formatter(formatter_str)
    #     # formatter = logging.Formatter(CustomFormatter())
    # else:
    #     formatter_str = "[%(asctime)s] %(levelname)s: %(message)s"
    #     formatter = logging.Formatter(formatter_str)
    # handler.setFormatter(formatter)

    if not logger.handlers and not show_progress:
        logger.addHandler(handler)
    if output_dir:
        """Add a file handler for this logger with the specified `name` (and
        store the log file under `output_dir`)."""
        # Format for file log (use JSON Lines for easier indexing/querying)
        # fmt = '{"time": "%(asctime)s", "level": "%(levelname)s", "source": "%(filename)s:%(lineno)d", "message": "%(message)s"}'
        # fmt = "%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s "
        # json_formatter = logging.Formatter(fmt)

        # # Determine log path/file name; create output_dir if necessary
        # now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Create JSONLines/JSONL file handler for logging to a file (log all five levels)
        if log_format in ["JSONL", "BOTH"]:
            jsonl_log_file = Path(output_dir).joinpath(f"{name}.log.jsonl")
            jsonl_log_file.parent.mkdir(parents=True, exist_ok=True)
            jsonl_log_file.touch(exist_ok=True)

            jsonl_file_handler = logging.FileHandler(jsonl_log_file.as_posix())
            logger.verbose("Logging to JSONL file: %s", jsonl_log_file.as_posix())
            jsonl_file_handler.setLevel(logging.DEBUG)
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
        # Create tabular file handler for logging to a file (log all five levels)
        if log_format in ["TABULAR", "BOTH"]:
            tab_log_file = Path(output_dir).joinpath(f"{name}.log")
            tab_log_file.parent.mkdir(parents=True, exist_ok=True)
            tab_log_file.touch(exist_ok=True)

            tab_file_handler = logging.FileHandler(tab_log_file.as_posix())
            logger.verbose("Logging to tabular file: %s", tab_log_file.as_posix())
            tab_file_handler.setLevel(logging.DEBUG)
            tab_file_handler.setFormatter(
                logging.Formatter(
                    fmt="%(asctime)s\t%(levelname)s\t%(filename)s:%(lineno)d\t%(message)s "
                )
            )
            logger.addHandler(tab_file_handler)

    return logger


ASH_LOGGER = logging.getLogger("ash")

# Enhance the main ASH logger with Windows-safe functionality
if not hasattr(ASH_LOGGER, "_windows_safe_mode"):
    # Add Windows-safe functionality to the main ASH logger
    ASH_LOGGER._windows_safe_mode = _is_windows_with_encoding_issues()
    ASH_LOGGER._emoji_fallback_map = _get_default_emoji_fallback_map()

    # Store original _log method
    original_log = ASH_LOGGER._log

    def _safe_log(level, msg, args, **kwargs):
        if ASH_LOGGER._windows_safe_mode and isinstance(msg, str):
            msg = _make_message_windows_safe(msg, ASH_LOGGER._emoji_fallback_map)

        try:
            original_log(level, msg, args, **kwargs)
        except UnicodeEncodeError:
            # Fallback: strip all non-ASCII characters
            if isinstance(msg, str):
                ascii_msg = msg.encode("ascii", errors="ignore").decode("ascii")
                original_log(level, f"[ENCODING_ISSUE] {ascii_msg}", args, **kwargs)
            else:
                original_log(
                    level,
                    "[ENCODING_ISSUE] Message contained non-ASCII characters",
                    args,
                    **kwargs,
                )

    # Replace the _log method
    ASH_LOGGER._log = _safe_log

    # Add verbose and trace methods if they don't exist
    if not hasattr(ASH_LOGGER, "verbose"):

        def verbose(msg, *args, **kws):
            ASH_LOGGER._log(logging._nameToLevel.get("VERBOSE", 15), msg, args, **kws)

        ASH_LOGGER.verbose = verbose

    if not hasattr(ASH_LOGGER, "trace"):

        def trace(msg, *args, **kws):
            ASH_LOGGER._log(logging._nameToLevel.get("TRACE", 5), msg, args, **kws)

        ASH_LOGGER.trace = trace
