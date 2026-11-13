# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--staged`` outside ``--mode precommit`` is a refusal, not a full scan.

The staged scope exists for the pre-commit hook. A mode that does not apply it
must not accept it and silently scan the whole tree: the library boundary
raises, and the CLI exits with a usage error before anything runs.
"""

from __future__ import annotations

import pytest
import typer

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import run_ash_scan

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("mode", [RunMode.local, RunMode.container, RunMode.nix])
def test_run_ash_scan_refuses_staged_outside_precommit(tmp_path, mode):
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ValueError, match="precommit"):
        run_ash_scan(
            source_dir=source,
            output_dir=tmp_path / "out",
            staged=True,
            mode=mode,
        )


def test_staged_files_without_staged_is_refused_even_in_precommit(tmp_path):
    """mode=precommit, staged=False, staged_files=[...]: the list would be
    silently ignored and a whole-tree scan would run, the exact silence the
    staged refusals exist to prevent."""
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ValueError, match="staged_files is read only with staged=True"):
        run_ash_scan(
            source_dir=source,
            output_dir=tmp_path / "out",
            staged=False,
            staged_files=["app.py"],
            mode=RunMode.precommit,
        )


@pytest.mark.parametrize(
    "entry",
    ["/abs/x.py", "../x.py", "a/../../x.py", "", "C:\\x.py", "a\\b.py"],
)
def test_a_staged_files_entry_that_leaves_the_source_dir_is_refused(tmp_path, entry):
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(ValueError, match="relative to the source directory"):
        run_ash_scan(
            source_dir=source,
            output_dir=tmp_path / "out",
            staged=True,
            staged_files=[entry],
            mode=RunMode.precommit,
        )


def test_the_staged_findings_filter_set_resolves_under_the_source_dir(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import (
        _staged_findings_filter_set,
    )

    source = tmp_path / "src"
    (source / "pkg").mkdir(parents=True)
    (source / "pkg" / "app.py").write_text("x = 1\n")

    filter_set = _staged_findings_filter_set(source, ["pkg/app.py", "missing.py"])

    assert (source / "pkg" / "app.py").resolve() in filter_set
    # A name with no file still resolves to its would-be path: the filter
    # matching nothing for it is the honest answer.
    assert (source / "missing.py").resolve() in filter_set


def test_cli_refusal_is_a_usage_error_outside_precommit():
    from automated_security_helper.cli.scan import (
        _refuse_staged_outside_precommit_mode,
    )
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    with pytest.raises(typer.Exit) as refusal:
        _refuse_staged_outside_precommit_mode(
            True, RunMode.local, None, from_environment=False
        )
    assert refusal.value.exit_code == ASH_EXIT_USAGE_ERROR


def test_cli_refuses_staged_with_workspace_even_in_precommit_mode():
    from automated_security_helper.cli.scan import (
        _refuse_staged_outside_precommit_mode,
    )

    with pytest.raises(typer.Exit):
        _refuse_staged_outside_precommit_mode(
            True, RunMode.precommit, object(), from_environment=False
        )


def test_cli_accepts_staged_with_precommit_mode():
    from automated_security_helper.cli.scan import (
        _refuse_staged_outside_precommit_mode,
    )

    _refuse_staged_outside_precommit_mode(
        True, RunMode.precommit, None, from_environment=False
    )
    _refuse_staged_outside_precommit_mode(
        False, RunMode.local, None, from_environment=False
    )
