from datetime import datetime, timezone
import logging
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
class ColoredLogger(logging.getLoggerClass()):
    VERBOSE_FORMAT = "[%(asctime)s] [%(levelname)-18s] ($BOLD%(filename)s$RESET:%(lineno)d) %(message)s "
    DEFAULT_FORMAT = "[%(levelname)-18s] %(message)s "

    def __init__(
        self,
        name: str,
        output_dir: Path | None = None,
        level: str | int | None = None,
    ):
        super().__init__(name=name, level=logging.INFO)

        if level is None or level > 15:
            self.COLOR_FORMAT = formatter_message(self.DEFAULT_FORMAT, True)
        else:
            self.COLOR_FORMAT = formatter_message(self.VERBOSE_FORMAT, True)

        color_formatter = ColoredFormatter(self.COLOR_FORMAT)

        console = logging.StreamHandler()
        console.setFormatter(color_formatter)

        self.addHandler(console)

    def verbose(self, msg, *args, **kws):
        self._log(logging._nameToLevel.get("VERBOSE", 15), msg, args, **kws)

    def trace(self, msg, *args, **kws):
        self._log(logging._nameToLevel.get("TRACE", 5), msg, args, **kws)


# logging.setLoggerClass(ColoredLogger)


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
    name: str = "ash", level: str | int | None = None, output_dir: Path | None = None
):
    VERBOSE_FORMAT = "[%(asctime)s] [%(levelname)-18s] ($BOLD%(filename)s$RESET:%(lineno)d) %(message)s "
    DEFAULT_FORMAT = "[%(levelname)-18s] %(message)s "

    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(level)
        logger.debug(
            "Log level set to: %s",
            logging._levelToName[level] if isinstance(level, int) else level,
        )

    handler = logging.StreamHandler()
    if logger.level is None or logger.level > 15:
        COLOR_FORMAT = formatter_message(DEFAULT_FORMAT, True)
    else:
        COLOR_FORMAT = formatter_message(VERBOSE_FORMAT, True)

    color_formatter = ColoredFormatter(COLOR_FORMAT)

    handler.setFormatter(color_formatter)

    # if logger.level == logging.DEBUG:
    #     formatter_str = "[%(asctime)s] [%(name)s] [%(filename)s:%(lineno)d] %(levelname)s: %(message)s"
    #     # formatter_str = f"{Color.cyan('[%(asctime)s]')} {Color.gray('[%(name)s]')} {Color.yellow('[%(filename)s:%(lineno)d]')} {Color.yellow('[%(levelname)s]')}: %(message)s"
    #     formatter = logging.Formatter(formatter_str)
    #     # formatter = logging.Formatter(CustomFormatter())
    # else:
    #     formatter_str = "[%(asctime)s] %(levelname)s: %(message)s"
    #     formatter = logging.Formatter(formatter_str)
    # handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)
    if output_dir:
        """Add a file handler for this logger with the specified `name` (and
        store the log file under `output_dir`)."""
        # Format for file log (use JSON Lines for easier indexing/querying)
        # fmt = '{"time": "%(asctime)s", "level": "%(levelname)s", "source": "%(filename)s:%(lineno)d", "message": "%(message)s"}'
        fmt = "%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s "
        json_formatter = logging.Formatter(fmt)

        # Determine log path/file name; create output_dir if necessary
        now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        log_file = Path(output_dir).joinpath(f"{name}.{now}.log")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.touch(exist_ok=True)

        # Create file handler for logging to a file (log all five levels)
        file_handler = logging.FileHandler(log_file.as_posix())
        logger.info("Logging to file: %s", log_file.as_posix())
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(json_formatter)
        logger.addHandler(file_handler)
    return logger


ASH_LOGGER = get_logger(
    name="ash",
    # Default to debug when running scripts that only import ASH_LOGGER
    # Otherwise if running through orchestrator.py, use level passed in from caller with
    # default of INFO
    # level=logging.DEBUG,
)
