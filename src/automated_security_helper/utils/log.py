import logging
from typing import Any


BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# The background is set with 40 plus the number of the color, and the foreground with 30

# These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"


def formatter_message(message, use_color=True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message


COLORS = {
    "WARNING": YELLOW,
    "INFO": WHITE,
    "DEBUG": BLUE,
    "CRITICAL": YELLOW,
    "ERROR": RED,
}


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
class ColoredLogger(logging.Logger):
    FORMAT = "[$BOLD%(name)-5s$RESET] [%(levelname)-18s] ($BOLD%(filename)s$RESET:%(lineno)d) %(message)s "
    COLOR_FORMAT = formatter_message(FORMAT, True)

    def __init__(self, name):
        logging.Logger.__init__(self, name, logging.DEBUG)

        color_formatter = ColoredFormatter(self.COLOR_FORMAT)

        console = logging.StreamHandler()
        console.setFormatter(color_formatter)

        self.addHandler(console)
        return


logging.setLoggerClass(ColoredLogger)


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


def get_logger(name: str = "ash", level: Any = logging.INFO):
    logger = logging.getLogger(name)

    if level is not None:
        logger.setLevel(level)
        logger.debug("Logger level set to: %s", level)

    if logger.level == logging.DEBUG:
        formatter_str = "[%(asctime)s] [%(name)s] [%(filename)s:%(lineno)d] %(levelname)s: %(message)s"
        # formatter_str = f"{Color.cyan('[%(asctime)s]')} {Color.gray('[%(name)s]')} {Color.yellow('[%(filename)s:%(lineno)d]')} {Color.yellow('[%(levelname)s]')}: %(message)s"
        formatter = logging.Formatter(formatter_str)
        # formatter = logging.Formatter(CustomFormatter())
    else:
        formatter_str = "[%(asctime)s] %(levelname)s: %(message)s"
        formatter = logging.Formatter(formatter_str)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


ASH_LOGGER = get_logger(
    name="ash",
    # Default to debug when running scripts that only import ASH_LOGGER
    # Otherwise if running through orchestrator.py, use level passed in from caller with
    # default of INFO
    # level=logging.DEBUG,
)
