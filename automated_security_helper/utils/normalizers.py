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

    Args:
        path: The path to check (may be absolute or relative)
        pattern: The pattern to match against (typically relative)

    Returns:
        True if the path matches the pattern, False otherwise
    """
    path = str(path).replace("\\", "/")
    pattern = str(pattern).replace("\\", "/")
    patterns = [
        pattern + "/**/*.*",
        pattern + "/*.*",
        pattern,
    ]

    for pat in patterns:
        if path == pat:
            return True
        elif pat in path:
            return True
        elif fnmatch.fnmatch(path, pat):
            return True

        if pat.endswith("/") and path.startswith(pat):
            return True

        # When the path is absolute and the pattern is relative, try
        # matching against the tail segments so callers that forget to
        # normalize still get correct results.
        if path.startswith("/") and not pat.startswith("/"):
            parts = path.split("/")
            depth = len(pat.split("/"))
            if len(parts) >= depth:
                tail = "/".join(parts[-depth:])
                if tail == pat or fnmatch.fnmatch(tail, pat):
                    return True

    return False
