# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path


# A002 on `input` is suppressed rather than fixed: the parameter name is this
# function's published keyword. Roughly 25 call sites across 12 modules spell it
# `get_shortest_name(input=...)` (base/scanner_plugin.py, utils/normalizers.py,
# utils/cdk_nag_wrapper.py and eight scanner plugins), and one of them already
# carries a `# type: ignore[call-arg]`. This package is published to PyPI and
# exposes a plugin API, so a third-party scanner plugin can be calling it by
# keyword too -- a rename here is a breaking change for a lint nit, and a
# "silent" one, because no caller outside this repository would be updated.
#
# The A001 on the body WAS fixed: reassigning the parameter was never part of any
# contract, and the reassignment also changed the bound type (str -> Path)
# midway, which is worth removing on its own.
def get_shortest_name(input: str | Path):  # noqa: A002
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
    # Annotated because the two branches bind different types: relative_to() gives a
    # Path, while `input` is still str | Path. Without this mypy infers Path from the
    # first branch and rejects the second -- the union is the honest type here, and
    # Path() accepts either.
    shortest: str | Path
    if input_posix.startswith(cwd_posix) and input_posix != cwd_posix:
        # If input starts with the cwd, use the relative path
        shortest = in_path.absolute().relative_to(cwd)
    else:
        shortest = input
    return Path(shortest).as_posix()
