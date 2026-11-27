# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the docs say the operator's ``default_scanners`` does, held to the code.

The trusted-config example on how-to/configure.md is read back from the page and
resolved as an operator config, so the effective selection is what the page says.
The other sentences are pinned with ``assert_on_page`` and a probe each. Nothing here
starts a scanner.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.interactions.run_ash_scan import (
    PRECOMMIT_MODE_SCANNERS,
    ScanOptions,
    _selection_layers,
)
from tests.unit.docs.test_page_claims import CONTENT, assert_on_page
from tests.utils.helpers import mark_git_checkout

pytestmark = [pytest.mark.unit, pytest.mark.live_tool_probes]

CONFIGURE = "how-to/configure.md"
PRE_COMMIT = "how-to/pre-commit.md"
SECTION = "## Choose which scanners run by default {#default-scanners}"


def _example() -> str:
    text = (CONTENT / CONFIGURE).read_text(encoding="utf-8")
    start = text.index(SECTION)
    block = re.search(r"```yaml\n(.*?)```", text[start:], re.DOTALL)
    assert block, "the section has no yaml example"
    return block.group(1)


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.fixture
def operator(tmp_path: Path) -> Path:
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir()
    path.write_text(_example(), encoding="utf-8")
    return path


def _allowlist(
    tmp_path: Path, config: Path | None, mode: RunMode = RunMode.local, **flags: Any
) -> List[str]:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    opts = ScanOptions(
        source_dir=source,
        output_dir=output,
        mode=mode,
        config=str(config) if config else None,
        **flags,
    )

    class _Log:
        def verbose(self, *_a: Any, **_k: Any) -> None: ...

    layers = _selection_layers(opts, _Log())
    created = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        work_dir=output / ".ash-work",
        enabled_scanners=layers.fold().names,
        selection_layers=layers,
        config_path=opts.config,
        no_cleanup=True,
    )
    return list(created.execution_engine._init_enabled_scanners)


def test_the_example_is_an_operator_selection_of_two_scanners(operator: Path) -> None:
    source = operator.parent.parent / "src"
    source.mkdir()

    config = resolve_config(config_path=operator, source_dir=source)

    assert list(config.default_scanners.only) == ["bandit", "trivy"]
    assert list(config.default_scanners.add) == []


def test_the_config_alone_selects_what_the_page_says(
    tmp_path: Path, operator: Path
) -> None:
    assert _allowlist(tmp_path, operator) == ["bandit", "trivy"]


def test_a_replacement_flag_selects_only_what_it_names(
    tmp_path: Path, operator: Path
) -> None:
    assert _allowlist(tmp_path, operator, only_scanners=["checkov"]) == ["checkov"]


def test_an_additive_flag_extends_the_configured_list(
    tmp_path: Path, operator: Path
) -> None:
    selected = _allowlist(tmp_path, operator, add_scanners=["checkov"])

    assert selected == ["checkov", "bandit", "trivy"]


def test_without_the_section_a_scan_selects_as_before(tmp_path: Path) -> None:
    config = tmp_path / "plain.yaml"
    config.write_text("project_name: plain\n", encoding="utf-8")

    assert _allowlist(tmp_path, config) == []
    assert _allowlist(tmp_path, config, scanners=["bandit"]) == ["bandit"]
    assert _allowlist(tmp_path, config, mode=RunMode.precommit) == list(
        PRECOMMIT_MODE_SCANNERS
    )


def test_only_replaces_the_default_in_precommit_and_in_local_mode(
    tmp_path: Path, operator: Path
) -> None:
    assert _allowlist(tmp_path, operator, mode=RunMode.precommit) == [
        "bandit",
        "trivy",
    ]
    assert _allowlist(tmp_path, operator, mode=RunMode.local) == ["bandit", "trivy"]


def test_add_extends_a_fixed_default_and_does_nothing_to_an_unbounded_one(
    tmp_path: Path,
) -> None:
    config = tmp_path / "add.yaml"
    config.write_text("default_scanners:\n  add: [grype]\n", encoding="utf-8")

    assert _allowlist(tmp_path, config, mode=RunMode.precommit) == [
        *PRECOMMIT_MODE_SCANNERS,
        "grype",
    ]
    assert _allowlist(tmp_path, config, mode=RunMode.local) == []


def test_a_selection_does_not_enable_a_disabled_scanner(
    tmp_path: Path, operator: Path
) -> None:
    config = tmp_path / "disabled.yaml"
    config.write_text(
        _example() + "scanners:\n  trivy:\n    enabled: false\n", encoding="utf-8"
    )
    source = tmp_path / "src"
    source.mkdir()

    resolved = resolve_config(config_path=config, source_dir=source)

    assert list(resolved.default_scanners.only) == ["bandit", "trivy"]
    assert resolved.scanners.trivy.enabled is False


def test_a_repository_config_cannot_set_it(tmp_path: Path, operator: Path) -> None:
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    (repo / ".ash.yaml").write_text(
        "default_scanners:\n  only: [checkov]\n", encoding="utf-8"
    )

    config = resolve_config(source_dir=repo)

    assert list(config.default_scanners.only) == []


def test_both_lists_at_once_are_refused() -> None:
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import DefaultScannersConfig

    with pytest.raises(ValidationError):
        DefaultScannersConfig(only=["a"], add=["b"])


@pytest.mark.parametrize(
    "sentence",
    [
        "`only` replaces the mode's default selection, and it does so in every mode",
        "in a mode that runs every scanner unrestricted, `add` has no effect.",
        "The `precommit` section is a different, narrower setting: only `--mode precommit` reads it.",
        "Naming both is refused with exit 3.",
        "A `default_scanners` in a config inside the scanned tree, or from an MCP client, is ignored with a warning",
        "Selecting a scanner does not enable it or install its tool",
        "`--only-scanners` replaces it; `--add-scanners` and the deprecated `--scanners` add to it; `--exclude-scanners` applies last",
        "Without a `default_scanners`, nothing changes.",
        "every project runs the same selection, plus every scanner the workspace policy requires",
        "A nonempty `scanners` argument of the MCP workspace tool limits every project to those scanners and does not add to the default.",
        "Container mode needs an image built from this ASH release",
        "A trusted config that `extends` a file inside a checkout keeps the selection its own files write, and ignores the one that file writes.",
        "`ashx config lint` warns about a `default_scanners` in a config inside the scanned tree, a key that is not `only` or `add` included, and still exits 0.",
        "A selection the host cannot resolve also ends the run with exit 3, before the container starts",
    ],
)
def test_the_configure_page_says(sentence: str) -> None:
    assert_on_page(CONFIGURE, sentence)


def test_the_precommit_page_places_the_operator_selection_in_the_order() -> None:
    assert_on_page(
        PRE_COMMIT,
        "The operator's `default_scanners`, in a trusted config: `only` replaces the default set and `add` adds to it",
    )


def test_the_section_is_linked_from_the_precommit_page() -> None:
    text = (CONTENT / PRE_COMMIT).read_text(encoding="utf-8")

    assert "(configure.md#default-scanners)" in text


def test_the_example_block_is_a_checked_config_example() -> None:
    text = (CONTENT / CONFIGURE).read_text(encoding="utf-8")
    start = text.index(SECTION)

    assert "<!-- doctest: config kind=ash -->" in text[start : start + 2000]
    assert yaml.safe_load(_example())["default_scanners"]["only"]
