# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The down-conversion contract, stated once for the tests that check it.

``to_project_pattern`` says, for every project-relative path ``p``::

    matches(to_project_pattern(P, R, kind=k), p) == matches(P, R + "/" + p)

with ``matches`` the matcher of the pattern's kind. Three test files check it
against the real matchers and each used to hold its own copy of the loop: one
compared with ``is`` and took the converted pattern from its caller, one computed
it and compared with ``==``, and one handled both kinds. A change to the contract
(a path to probe, the other kind's matcher) had to be made three times, and the
copies had already drifted.

The probe paths stay with each file. They are chosen for the patterns that file
tests, and one shared list would change which paths each assertion reads.

This module holds no test, so it is not collected.
"""

from typing import Iterable, List, Optional

from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
)
from automated_security_helper.utils.workspace_paths import (
    IGNORE_PATH,
    SUPPRESSION,
    to_project_pattern,
)

#: Each kind of pattern is read by its own matcher.
MATCHERS = {IGNORE_PATH: ignore_path_matches, SUPPRESSION: file_path_matches}

#: Marks "the caller did not give the converted pattern": ``None`` is an answer
#: of its own (the pattern applies to nothing in the project).
_COMPUTE = object()


def disagreeing_paths(
    pattern: str,
    prefix: str,
    kind: str,
    paths: Iterable[str],
    converted: Optional[str] = _COMPUTE,  # type: ignore[assignment]
) -> List[str]:
    """The probe paths on which the two sides of the contract give different answers.

    ``converted`` is the project-relative pattern under test; left out, it is
    ``to_project_pattern(pattern, prefix, kind=kind)``. ``None`` means the
    pattern reaches nothing in the project, so its side answers ``False`` for
    every path.
    """
    if converted is _COMPUTE:
        converted = to_project_pattern(pattern, prefix, kind=kind)
    matches = MATCHERS[kind]
    return [
        path
        for path in paths
        if (False if converted is None else matches(path, converted))
        is not matches(f"{prefix}/{path}", pattern)
    ]


def assert_contract(
    pattern: str,
    prefix: str,
    kind: str,
    paths: Iterable[str],
    converted: Optional[str] = _COMPUTE,  # type: ignore[assignment]
) -> None:
    """The converted pattern reaches exactly the files the workspace one does."""
    if converted is _COMPUTE:
        converted = to_project_pattern(pattern, prefix, kind=kind)
    paths = list(paths)
    wrong = disagreeing_paths(pattern, prefix, kind, paths, converted)
    assert not wrong, (
        f"{pattern!r} over {prefix!r} -> {converted!r} ({kind}) disagrees with the "
        f"matcher at {wrong!r}"
    )
