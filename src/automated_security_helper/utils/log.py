import logging
from typing import Any


def get_logger(name: str = "ash", level: Any = None):
    logger = logging.getLogger(name)

    if level is not None:
        logger.setLevel(level)
        logger.debug("Logger level set to: %s", level)

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(module)s - %(message)s"
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


ASH_LOGGER = get_logger(
    name="ash",
    # Default to debug when running scripts that only import ASH_LOGGER
    # Otherwise if running through orchestrator.py, use level passed in from caller with
    # default of INFO
    level=logging.DEBUG,
)
