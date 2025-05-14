from typing import Any


def clean_dict(input: Any):
    # Remove any keys with None values recursively by calling this function
    # if the value is a dictionary or list
    if isinstance(input, dict):
        return {k: clean_dict(v) for k, v in input.items() if v is not None}
    elif isinstance(input, list):
        return [clean_dict(i) for i in input]
    elif input is not None:
        return input
