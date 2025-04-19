from typing import Any

from automated_security_helper.utils.log import ASH_LOGGER


def clean_dict(input: Any):
    # Remove any keys with None values recursively by calling this function
    # if the value is a dictionary
    if isinstance(input, dict):
        return {k: clean_dict(v) for k, v in input.items() if v is not None}
    elif isinstance(input, list):
        return [clean_dict(i) for i in input]
    elif input is not None:
        ASH_LOGGER.verbose(f"Cleaning value: {input}")
        return input
