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
