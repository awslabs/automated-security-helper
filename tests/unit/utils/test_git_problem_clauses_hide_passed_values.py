# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The public git helpers take the run's environment values and hide them.

The redaction inside ``_rev_parse_toplevel`` and ``_first_lines`` was inert in
production: every caller inside the two utils files passed ``values=()``, and
the public entries (``git_repository_root``, ``git_repository_root_problem``,
``git_index_below``) took no values, so no caller could pass any. A git stderr
line that quotes an environment-read value (a path fragment, a ref) therefore
reached the problem clause in clear. The public entries now take a ``values``
keyword, defaulted empty, and the scan callers that know the run's values pass
them.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from automated_security_helper.utils import get_scan_set
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.scan_output_dirs import git_index_below

CANARY = "zz-ops-canary-7421"


def _failing_git(monkeypatch, stderr: bytes) -> None:
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=128, stderr=stderr, stdout=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)


def test_the_root_problem_clause_hides_a_passed_value(monkeypatch, tmp_path):
    _failing_git(monkeypatch, f"fatal: cannot use {CANARY} here\n".encode())

    assert get_scan_set.git_repository_root(tmp_path, values=(CANARY,)) is None
    problem = get_scan_set.git_repository_root_problem(tmp_path)

    assert "could not read the repository root" in problem, problem
    assert CANARY not in problem, problem


def test_the_problem_reask_passes_the_values_too(monkeypatch, tmp_path):
    """A caller that asks for the problem first (no remembered lookup) still
    gets a redacted clause: the re-ask passes the same values."""
    _failing_git(monkeypatch, f"fatal: cannot use {CANARY} here\n".encode())

    problem = get_scan_set.git_repository_root_problem(tmp_path, values=(CANARY,))

    assert "could not read the repository root" in problem, problem
    assert CANARY not in problem, problem


def test_a_value_with_a_whitespace_edge_is_hidden_at_stderrs_edge(
    monkeypatch, tmp_path
):
    """A value whose own edge is whitespace, sitting at the edge of stderr: a
    whole-text strip before the redaction shaves the value's edge off the text,
    the needle stops matching, and the remainder prints in clear."""
    edged = CANARY + " "
    _failing_git(monkeypatch, f"fatal: cannot use {edged}\n".encode())

    assert get_scan_set.git_repository_root(tmp_path, values=(edged,)) is None
    problem = get_scan_set.git_repository_root_problem(tmp_path)

    assert "could not read the repository root" in problem, problem
    assert CANARY not in problem, problem


def test_the_clause_still_quotes_gits_line_without_values(monkeypatch, tmp_path):
    """The must-not-flag control: with no values to hide, the detail is the
    stderr line, which is what makes the clause worth reading."""
    _failing_git(monkeypatch, b"fatal: a readable reason\n")

    assert get_scan_set.git_repository_root(tmp_path) is None
    problem = get_scan_set.git_repository_root_problem(tmp_path)

    assert "a readable reason" in problem, problem


def test_the_index_error_hides_a_passed_value(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def fake_spawn_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=128,
            stderr=f"fatal: cannot list {CANARY}\n".encode(),
            stdout=b"",
        )

    monkeypatch.setattr(subprocess_utils, "spawn_run", fake_spawn_run)

    answer = git_index_below(repo, values=(CANARY,))

    assert answer.error, answer
    assert "exited with status 128" in answer.error, answer.error
    assert CANARY not in answer.error, answer.error
