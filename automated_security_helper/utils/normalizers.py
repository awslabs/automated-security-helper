# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import re

from automated_security_helper.utils.get_shortest_name import get_shortest_name


def get_normalized_filename(str_to_normalize: str | Path) -> str:
    """Returns a normalized filename for the given string.

    Args:
        str_to_normalize (str | Path): The string to normalize.

    Returns:
        str: The normalized filename.
    """
    if isinstance(str_to_normalize, Path):
        str_to_normalize = get_shortest_name(input=str_to_normalize)

    str_to_normalize = str_to_normalize.replace("/", "__").replace(".", "__")

    normalized = re.sub(
        pattern=r"\W+",
        repl="-",
        string=str_to_normalize,
        flags=re.IGNORECASE,
    ).lstrip("-")
    return normalized
