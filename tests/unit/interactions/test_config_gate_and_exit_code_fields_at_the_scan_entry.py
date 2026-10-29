# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two behaviors of the scan entry's pre-run checks.

``config_base_gate`` confines the config roots of a local, single-directory
scan. Container and nix mode hand the config to a second ASH, and a workspace
run resolves each project's config without the gate, so in all three the gate
would be dropped without a word. The entry refuses it in each, as it refuses
``untrusted_config`` in each.

The exit-code fields a container run forwards (``fail_on_findings`` and
``fail_on_incomplete_scanners``) are read from the operator's config file
before the container is built. The cell pins the values the runner is handed
for a config that sets them, so the way the host loads the chain can change
without changing what the container is told.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from tests.utils.helpers import stand_in_host_ids

AshConfig.model_rebuild()


def _plan(root: Path, key: str = "app") -> WorkspacePlan:
    (root / key).mkdir(parents=True, exist_ok=True)
    return WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(root / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
        ],
    )


def test_a_config_base_gate_is_refused_with_a_workspace_plan(tmp_path, monkeypatch):
    class Started(AssertionError):
        pass

    def must_not_run(*_args, **_kwargs):
        raise Started("the workspace scan started with the config gate dropped")

    monkeypatch.setattr(ras, "_run_workspace_mode", must_not_run)

    with pytest.raises(ValueError, match="config_base_gate"):
        ras.run_ash_scan(
            source_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.local,
            workspace_plan=_plan(tmp_path),
            config_base_gate=lambda _path: True,
            progress=False,
            show_summary=False,
        )


@pytest.mark.parametrize(
    "fields",
    [
        {"fail_on_findings": False, "fail_on_incomplete_scanners": True},
        {"fail_on_findings": True, "fail_on_incomplete_scanners": False},
    ],
)
def test_a_container_run_is_handed_the_exit_code_fields_the_config_sets(
    tmp_path, monkeypatch, fields
):
    stand_in_host_ids(monkeypatch)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir()
    lines = ["project_name: t"] + [
        f"{name}: {str(value).lower()}" for name, value in fields.items()
    ]
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")

    seen: Dict[str, Any] = {}

    class Stopped(Exception):
        pass

    def record(opts, logger, **kwargs):
        seen.update(kwargs)
        raise Stopped

    monkeypatch.setattr(ras, "_run_container_mode", record)

    with pytest.raises(Stopped):
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(tmp_path / "out"),
            config=str(config),
            mode=RunMode.container,
            progress=False,
            show_summary=False,
        )

    # The scan's one record of the operator's config chain rides along with the
    # fields; it is not what this cell pins.
    reads = seen.pop("reads")
    assert type(reads).__name__ == "OperatorConfigReads"
    # Nor is the gate's answer about the image, which rides along for the
    # record repair.
    assert "image_may_differ" in seen
    seen.pop("image_may_differ")
    assert seen == {
        "resolved_fail_on_findings": fields["fail_on_findings"],
        "resolved_fail_on_incomplete_scanners": fields["fail_on_incomplete_scanners"],
    }
