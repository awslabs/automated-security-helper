# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import fnmatch
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

    str_to_normalize = str(str_to_normalize).replace("/", "__").replace(".", "__")

    normalized = re.sub(
        pattern=r"\W+",
        repl="-",
        string=str_to_normalize,
        flags=re.IGNORECASE,
    ).lstrip("-")
    return normalized


def path_matches_pattern(path: str, pattern: str) -> bool:
    """Check if a path matches a pattern.

    .. deprecated::
        Use ``automated_security_helper.utils.suppression_matcher.file_path_matches``
        instead. This function uses fnmatch which behaves differently on macOS vs
        Linux for ``*`` matching across ``/`` separators.
    """
    from automated_security_helper.utils.suppression_matcher import file_path_matches
    return file_path_matches(path, pattern)
