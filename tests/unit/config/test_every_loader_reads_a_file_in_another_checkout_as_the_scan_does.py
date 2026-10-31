# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every loader that reads a chain as a scan reads it judges a file in another checkout alike.

A config file inside a git checkout other than the scanned one is never the
operator's. The scan (``resolve_config``) leaves out of such a file the options
only the operator sets (``scanners.detect-secrets.options.max_worker_output_mib``,
the Security Hub scope options) as the file is read, and a value there that the
option refuses refuses nothing. The other loaders of the same chain promise to
read it as the scan reads it: container mode and its record load, the workspace
loader, the container's sandbox-mode floor, the trusted base's own read of
ASH_CONFIG, the validator's ASH_CONFIG check and MCP ``get_config``. They built
their settings by hand with the scanned trees alone, so the same file was the
operator's for them: a value the scan took was refused with exit 3 by the host
in container mode, by ``get_config`` and by the validator, the floor read fell
to its fallback branch, and an operator file's patch pointer folded against the
wrong set of files.

``scan_repository_settings`` is the one constructor. Each test writes the same
file twice, in another checkout (``ops``) and outside every checkout (``plain``),
with a value the option refuses, and asks each loader whether it took the file:

* the file in another checkout is taken by every loader, as the scan takes it;
* the same text outside every checkout is the operator's, and every loader
  refuses the value, so a loader that skipped the confinement would pass the
  first test and fail the second.

Each test first proves the scan's own load takes the file in the checkout, so
only the loader under test can fail it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Tuple

import pytest

from automated_security_helper.config.resolve_config import (
    resolve_config,
    trusted_base_config,
)
from automated_security_helper.config.sandbox_grants import scanned_trees
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)

#: A value the option refuses: the file is loadable only when the option is left out.
REFUSED_VALUE = "zz-not-a-number"

#: A text the loaders each read a different part of: the project name, the
#: sandbox mode the floor reports, the workspace knob the workspace loader
#: answers, and the option under test.
OPERATOR_TEXT = (
    "project_name: ops\n"
    "sandbox:\n"
    "  mode: firejail\n"
    "workspace:\n"
    "  max_parallel_projects: 3\n"
    "scanners:\n"
    "  detect-secrets:\n"
    "    options:\n"
    f"      max_worker_output_mib: {REFUSED_VALUE}\n"
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    # A basetemp inside a checkout would put every file here inside it.
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _file(tmp_path: Path, where: str) -> Path:
    """The file under test: in another checkout, or outside every checkout."""
    if where == "ops":
        mark_git_checkout(tmp_path / "ops")
        return _write(tmp_path / "ops" / "ash.yaml", OPERATOR_TEXT)
    return _write(tmp_path / "plain" / "ash.yaml", OPERATOR_TEXT)


def _repository(tmp_path: Path, with_config: bool) -> Path:
    """The scanned repository, a checkout, with a config of its own when asked."""
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    if with_config:
        _write(repository / ".ash" / ".ash.yaml", "project_name: checked\n")
    return repository


def _options(tmp_path: Path, repository: Path, **fields: Any) -> Any:
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    return run_ash_scan.ScanOptions(
        source_dir=repository,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        **fields,
    )


def _takes(call: Callable[[], Any]) -> bool:
    try:
        call()
    except _REFUSED:
        return False
    return True


# Each loader: (does the chain come from ASH_CONFIG, does the test need the
# repository's own config, the loader's answer for the file as "taken").


def _scan(tmp_path: Path, repository: Path, file: Path) -> bool:
    return _takes(lambda: resolve_config(config_path=file, source_dir=repository))


def _container_mode_load(tmp_path: Path, repository: Path, file: Path) -> bool:
    from automated_security_helper.interactions import run_ash_scan

    opts = _options(tmp_path, repository, config=str(file))
    return _takes(lambda: run_ash_scan._loaded_config_file(opts))


def _record_load(tmp_path: Path, repository: Path, file: Path) -> bool:
    from automated_security_helper.interactions import run_ash_scan

    opts = _options(tmp_path, repository, config=str(file))
    return _takes(lambda: run_ash_scan._loaded_config_file(opts, for_run=True))


def _container_parse_step(tmp_path: Path, repository: Path, file: Path) -> bool:
    """The document the host resolves without building the model: the option is
    left out of it, or still there."""
    from automated_security_helper.interactions import run_ash_scan

    opts = _options(tmp_path, repository, config=str(file))
    data = run_ash_scan._parse_and_confine_config(str(file), opts).data
    options = data["scanners"]["detect-secrets"]["options"]
    return "max_worker_output_mib" not in (options or {})


def _workspace_loader(tmp_path: Path, repository: Path, file: Path) -> bool:
    from automated_security_helper.interactions import run_ash_scan

    def load() -> None:
        answer = run_ash_scan.resolve_workspace_execution_config(repository, str(file))
        assert answer.max_parallel_projects == 3

    return _takes(load)


def _container_floor(tmp_path: Path, repository: Path, file: Path) -> bool:
    """ASH_CONFIG names the file. The floor is the mode the file sets when the
    floor's own read loads it, and the fallback ("off") when that read raises."""
    from automated_security_helper.interactions import run_ash_scan

    opts = _options(tmp_path, repository)
    return run_ash_scan._sandbox_mode_without_the_config(opts) == ["firejail"]


def _trusted_base_read(tmp_path: Path, repository: Path, file: Path) -> bool:
    """ASH_CONFIG names the file, and nothing carries its load: the trusted
    base reads it itself."""
    return _takes(
        lambda: trusted_base_config(
            None,
            scanned_trees(repository),
            default_in_tree=False,
            merged_fallback=False,
        )
    )


def _validator_ash_config_check(tmp_path: Path, repository: Path, file: Path) -> bool:
    from automated_security_helper.config.config_validator import ConfigValidator

    checked = repository / ".ash" / ".ash.yaml"
    return (
        ConfigValidator.check_config_file(checked, source_dir=repository).errors == []
    )


def _get_config_search_read(tmp_path: Path, repository: Path, file: Path) -> bool:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    return mcp_get_config(search_dir=str(repository)).get("project_name") == "ops"


def _get_config_named_file(tmp_path: Path, repository: Path, file: Path) -> bool:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    checked = repository / ".ash" / ".ash.yaml"
    answer = mcp_get_config(config_path=str(checked), search_dir=str(repository))
    return answer.get("project_name") == "checked"


#: name -> (the chain comes from ASH_CONFIG, the repository has a config of its
#: own, the loader's answer). The scan's own load is the first row.
LOADERS: Dict[str, Tuple[bool, bool, Callable[[Path, Path, Path], bool]]] = {
    "the scan": (False, False, _scan),
    "container mode's host load": (False, False, _container_mode_load),
    "container mode's record load": (False, False, _record_load),
    "container mode's parse step": (False, False, _container_parse_step),
    "the workspace loader": (False, False, _workspace_loader),
    "the container sandbox floor": (True, False, _container_floor),
    "the trusted base's own read": (True, False, _trusted_base_read),
    "the validator's ASH_CONFIG check": (True, True, _validator_ash_config_check),
    "get_config's search read": (True, False, _get_config_search_read),
    "get_config's named-file pre-check": (True, True, _get_config_named_file),
}


def _premise(
    from_ash_config: bool,
    repository: Path,
    file: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scan's own load takes the file in the checkout: otherwise the test
    shows nothing about the loader under test."""
    if from_ash_config:
        monkeypatch.setenv("ASH_CONFIG", str(file))
    try:
        if from_ash_config:
            resolve_config(source_dir=repository)
        else:
            resolve_config(config_path=file, source_dir=repository)
    except _REFUSED as error:
        raise RuntimeError(
            "the scan's own load refuses, so the test shows nothing: "
            + type(error).__name__
        )


@pytest.mark.parametrize("loader", sorted(LOADERS))
def test_a_file_in_another_checkout_is_taken_as_the_scan_takes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loader: str
) -> None:
    from_ash_config, with_config, take = LOADERS[loader]
    repository = _repository(tmp_path, with_config)
    file = _file(tmp_path, "ops")
    _premise(from_ash_config, repository, file, monkeypatch)

    assert take(tmp_path, repository, file) is True, loader


@pytest.mark.parametrize("loader", sorted(LOADERS))
def test_control_the_same_text_outside_every_checkout_is_the_operators_and_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loader: str
) -> None:
    """A file outside every checkout is the operator's, so its value reaches the
    option's model and the option refuses it: each loader says so, and a loader
    that skipped the confinement altogether could not pass the test above."""
    from_ash_config, with_config, take = LOADERS[loader]
    repository = _repository(tmp_path, with_config)
    file = _file(tmp_path, "plain")
    if from_ash_config:
        monkeypatch.setenv("ASH_CONFIG", str(file))

    assert take(tmp_path, repository, file) is False, loader


def test_the_one_constructor_counts_a_file_in_any_checkout_as_the_repositorys(
    tmp_path: Path,
) -> None:
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
        scan_repository_settings,
    )

    repository = _repository(tmp_path, with_config=False)
    ops = _file(tmp_path, "ops")
    plain = _file(tmp_path, "plain")
    inside = _write(repository / "cfg.yaml", "project_name: inside\n")

    for settings in (
        scan_repository_settings(scanned_trees(repository)),
        repository_settings_for_root(repository),
        repository_settings_for_root(None),
    ):
        assert settings.is_repository_file(ops, ops) is True
        assert settings.is_repository_file(plain, plain) is False
    # With a root, its own tree counts as well; with none, no tree is known.
    assert repository_settings_for_root(repository).is_repository_file(inside, inside)


_VALUE = "a-chain-value-the-pre-check-must-keep"


def test_an_operator_pointer_folds_as_the_scan_folds_it_when_the_twin_is_in_another_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The patch folding reads ``is_repository_file``: an operator file's pointer
    folds only onto the section keys the operator's own files wrote. The twin a
    file in ANOTHER checkout writes is the repository's for the scan, so the
    pointer folds onto the operator's key; the MCP pre-check of the named file
    must read the chain the same way, and keep the value the chain read from the
    environment in its redaction set.

    The chain merge joins every spelling of one plugin's section into a single
    key, named by the later file's spelling. The twin is therefore extended first,
    so the joined section keeps the operator's own spelling and the pointer's fold
    meets the key the operator's files wrote."""
    from automated_security_helper.cli.mcp_tools import _config_pre_check

    monkeypatch.setenv("ASH_PRE_CHECK_CELL", _VALUE)
    operator = tmp_path / "operator"
    # The named config is the operator's: in a configured config root. A named
    # file the operator did not set aside is the client's to the scan, read
    # with every chain file confined (client_named_config_is_untrusted), and
    # the pre-check reads it the same way; the control below is the operator
    # read, so the file is made the operator's here.
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    source = operator / "repo"
    source.mkdir(parents=True)
    ops = operator / "ops"
    mark_git_checkout(ops)
    _write(ops / "twin.ash.yaml", "reporters:\n  ACME:\n    options: {}\n")
    _write(
        operator / "base.ash.yaml",
        "reporters:\n"
        "  acme:\n"
        "    options:\n"
        "      output_file: ${ASH_PRE_CHECK_CELL:unset}\n",
    )
    config = _write(
        operator / "ash.yaml",
        "extends:\n"
        "  - ops/twin.ash.yaml\n"
        "  - base.ash.yaml\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/Acme/options/note\n"
        "    value: pinned-by-the-test\n",
    )
    try:
        resolve_config(config_path=config, source_dir=source)
    except _REFUSED as error:
        raise RuntimeError(
            "the scan's own load refuses, so the test shows nothing: "
            + type(error).__name__
        )

    pre_check = _config_pre_check(config, source, None)

    assert pre_check.env_refusal is None
    assert pre_check.load_refusal is None
    assert _VALUE in pre_check.environment_values
