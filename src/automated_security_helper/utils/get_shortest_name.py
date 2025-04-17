# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path


def get_shortest_name(input: str | Path):
    try:
        if input == ".":
            # Just return the input, it's already referencing the relative path to CWD
            return input
        in_path = Path(input)
        if not in_path.exists():
            # Just return the input, not an existing Path
            return input
        cwd = Path.cwd()
        input_posix = in_path.absolute().as_posix()
        cwd_posix = cwd.absolute().as_posix()
        if input_posix.startswith(cwd_posix) and input_posix != cwd_posix:
            # If input starts with the cwd, update it to the relative path
            input = in_path.relative_to(cwd)
    finally:
        return Path(input).as_posix()
