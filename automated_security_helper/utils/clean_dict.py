from typing import Any


def clean_dict(input: Any):
    # Remove any keys with None values and empty values (empty strings, lists, dicts) recursively
    if isinstance(input, dict):
        cleaned = {}
        for k, v in input.items():
            cleaned_value = clean_dict(v)
            # Only include the key if the cleaned value is not None and not empty
            if (
                cleaned_value is not None
                and cleaned_value != ""
                and cleaned_value != []
                and cleaned_value != {}
            ):
                cleaned[k] = cleaned_value
        return cleaned
    elif isinstance(input, list):
        # Clean each item in the list and filter out None and empty values
        cleaned_list = []
        for item in input:
            cleaned_item = clean_dict(item)
            if (
                cleaned_item is not None
                and cleaned_item != ""
                and cleaned_item != []
                and cleaned_item != {}
            ):
                cleaned_list.append(cleaned_item)
        return cleaned_list
    else:
        # Return the input as-is if it's not a dict or list
        return input
