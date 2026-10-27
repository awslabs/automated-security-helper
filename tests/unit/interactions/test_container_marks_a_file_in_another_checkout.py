# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file in another git checkout is limited inside a container as on the host.

On the host a config file in a git checkout other than the scanned one cannot
grant (``config/sandbox_grants``), and an ``ASH_CONFIG`` file there still sets
what only restricts: a lowered archive extraction limit, a scanner option that
sends no usage data, and a ``network_scanners`` list as a limit
(``config/restrictions_kept``). Container mode mounts a config file outside
``/src``, where the scan inside sees it in no checkout, so the host tells the scan
inside which mounted files are in another checkout, one file at a time, with
``--config-file-from-another-checkout``. The scan inside then judges them with the
code the host uses and reads the mounted file for what it restricts. No value of
the file travels in the mark, so a mark cannot carry a grant. A file the host
could not place because the walk of the links in its name stopped is marked the
same way: the limits are the same, and no second option exists for it.

Each end-to-end cell resolves one layout twice: on the host (``resolve_config``,
or each workspace project's config), and in container mode, where
``run_ash_container`` assembles the run command against a recording runner, the
mounted files are copied under a directory outside every checkout, and the real
``ash`` command line, given the run command's arguments, resolves the mounted
config. The host's values are asserted as well, so a cell cannot pass by both
sides going wrong together.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import scan as scan_cli
from automated_security_helper.cli.main import app
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.sandbox_grants import in_any_checkout
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    _project_config_with_policy,
)
from automated_security_helper.workspace.resolver import resolve_workspace
from tests.utils.config_link_layouts import (
    LINKS_IN_ANOTHER_CHECKOUT,
    LINKS_IN_THE_SCANNED_CHECKOUT,
    LINKS_OUTSIDE_EVERY_CHECKOUT,
    config_through_links,
)
from tests.utils.container_scan import (
    RecordingContainer,
    assemble_run_command as _assemble,
    flag_values as _flags,
    inner_args as _inner_args,
    scan_inside,
)
from tests.utils.helpers import mark_git_checkout

FLAG = "--config-file-from-another-checkout"
#: An option the scan inside no longer knows: a file whose link walk stopped is
#: marked FLAG like any file in another checkout.
RETIRED_FLAG = "--config-file-walk-undecided"
TREE_FILE_FLAG = "--config-file-from-scanned-repository"
CHAIN_FLAG = "--config-from-scanned-repository"
ENV_FLAG = "--ash-config-from-host"
#: A module no environment has: a config inside the scanned tree may not add it.
UNINSTALLED = "not_installed_ash_plugins"

#: The scanned repository's own config, between the operator's lowered archive
#: limit and the default (100000), so only the operator's value caps it.
REPOSITORY = """\
project_name: repository
converters:
  archive:
    options:
      max_members: 5000
"""

#: The operator's file: a grant, the one setting that must not survive, and one
#: restriction that must. One file per restriction, so a restriction lost shows
#: in its own cell.
ARCHIVE_FILE = """\
project_name: operator
sandbox:
  extra_read_paths: [/data]
converters:
  archive:
    options:
      max_members: 10
"""
TELEMETRY_FILE = """\
project_name: operator
sandbox:
  extra_read_paths: [/data]
scanners:
  semgrep:
    options:
      metrics: "off"
"""
NETWORK_FILE = """\
project_name: operator
sandbox:
  extra_read_paths: [/data]
  network_scanners: [semgrep]
"""
WHOLE_FILE = """\
project_name: operator
sandbox:
  extra_read_paths: [/data]
  network_scanners: [semgrep]
  read_path_scanners: [zizmor]
  env_scanners: [zizmor]
converters:
  archive:
    options:
      max_members: 10
scanners:
  semgrep:
    options:
      metrics: "off"
"""
#: A base with grants, and a root that writes a sandbox section of its own.
BASE_FILE = """\
project_name: base
sandbox:
  network_scanners: [semgrep]
  read_path_scanners: [zizmor]
  env_scanners: [zizmor]
"""
ROOT_FILE = """\
project_name: root
extends: vendor/base.yaml
sandbox:
  extra_read_paths: [/opt/operator-own]
"""


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path: Path, monkeypatch) -> None:
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.fixture
def scene(tmp_path: Path) -> SimpleNamespace:
    """W/repo, a checkout holding the scanned directory W/repo/svc and its own config."""
    w = tmp_path / "W"
    mark_git_checkout(w / "repo")
    source = w / "repo" / "svc"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(REPOSITORY, encoding="utf-8")
    return SimpleNamespace(w=w, source=source, out=tmp_path / "out")


def _operator_file(w: Path, where: str, text: str) -> Path:
    """The operator's file in ``checkout`` (a git checkout beside the scanned one),
    ``scanned`` (the scanned checkout, outside the scanned directory) or
    ``outside`` (no checkout)."""
    folder = {
        "checkout": w / "envco",
        "scanned": w / "repo" / "ci",
        "outside": w / "operator",
    }[where]
    if where == "checkout":
        mark_git_checkout(folder)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "ash-env.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _facts(config) -> Dict[str, Any]:
    """What the operator's file may and may not have changed."""
    sandbox = config.sandbox
    return {
        "max_members": config.converters.archive.options.max_members,
        "semgrep.metrics": config.get_plugin_config("scanner", "semgrep")["options"][
            "metrics"
        ],
        "sandbox.extra_read_paths": list(sandbox.extra_read_paths),
        "sandbox.network_scanners": sandbox.network_scanners,
        "sandbox.network_limit": sandbox.network_limit,
        "sandbox.read_path_scanners": list(sandbox.read_path_scanners),
        "sandbox.env_scanners": list(sandbox.env_scanners),
    }


@pytest.fixture
def container(monkeypatch, tmp_path) -> RecordingContainer:
    """Run container mode against a recording runner; calling it returns the scan
    inside's facts, and ``assemble`` and ``inside`` do the two halves apart."""
    return RecordingContainer(monkeypatch, tmp_path, _scan_inside)


def _scan_inside(cmd: List[str], fs: Path, monkeypatch) -> Dict[str, Dict[str, Any]]:
    """The scan inside the container (``tests/utils/container_scan.py``), recording
    what the operator's file may and may not have changed."""
    return scan_inside(
        cmd,
        fs,
        monkeypatch,
        project=lambda planned, settings: _facts(
            _project_config_with_policy(planned, settings)
        ),
        scan=lambda kwargs: _facts(
            resolve_config(
                config_path=kwargs["config"],
                source_dir=kwargs["source_dir"],
                config_overrides=list(kwargs["config_overrides"] or []),
                untrusted_config=kwargs.get("untrusted_config", False),
            )
        ),
    )


def _ash_config_scan(monkeypatch, container, scene, where: str, text: str):
    """The operator's file at *where* as ASH_CONFIG, the scanned repository's own
    config discovered: (the file, the host's facts, the scan inside's facts)."""
    path = _operator_file(scene.w, where, text)
    monkeypatch.setenv("ASH_CONFIG", str(path))
    host = _facts(resolve_config(source_dir=scene.source))
    inside = container(source_dir=str(scene.source), output_dir=str(scene.out))
    return path, host, inside["scan"]


# --- ASH_CONFIG in another checkout: the grants go, what restricts stays ------


def test_a_lowered_archive_limit_in_an_ash_config_in_another_checkout_still_caps_the_scan_inside(
    monkeypatch, container, scene
):
    path, host, inside = _ash_config_scan(
        monkeypatch, container, scene, "checkout", ARCHIVE_FILE
    )

    assert in_any_checkout(path)
    # On the host the restriction is kept and the grant in the same file is not.
    assert host["max_members"] == 10
    assert host["sandbox.extra_read_paths"] == []
    assert inside["max_members"] == host["max_members"]
    assert inside == host


def test_a_no_usage_data_option_in_an_ash_config_in_another_checkout_still_applies_inside(
    monkeypatch, container, scene
):
    path, host, inside = _ash_config_scan(
        monkeypatch, container, scene, "checkout", TELEMETRY_FILE
    )

    assert in_any_checkout(path)
    assert host["semgrep.metrics"] == "off"
    assert host["sandbox.extra_read_paths"] == []
    assert inside["semgrep.metrics"] == host["semgrep.metrics"]
    assert inside == host


def test_a_network_list_in_an_ash_config_in_another_checkout_still_narrows_inside(
    monkeypatch, container, scene
):
    path, host, inside = _ash_config_scan(
        monkeypatch, container, scene, "checkout", NETWORK_FILE
    )

    assert in_any_checkout(path)
    # A limit, never a list: the list would replace the scanners' declared needs.
    assert host["sandbox.network_limit"] == ["semgrep"]
    assert host["sandbox.network_scanners"] is None
    assert host["sandbox.extra_read_paths"] == []
    assert inside["sandbox.network_scanners"] is None
    assert inside == host


def test_the_whole_file_is_limited_inside_as_on_the_host(monkeypatch, container, scene):
    path, host, inside = _ash_config_scan(
        monkeypatch, container, scene, "checkout", WHOLE_FILE
    )

    assert in_any_checkout(path)
    assert host["max_members"] == 10
    assert host["semgrep.metrics"] == "off"
    assert host["sandbox.network_limit"] == ["semgrep"]
    assert host["sandbox.network_scanners"] is None
    # All four grant lists the file wrote are gone.
    assert host["sandbox.extra_read_paths"] == []
    assert host["sandbox.read_path_scanners"] == []
    assert host["sandbox.env_scanners"] == []
    assert inside == host


# --- a --config or a base in another checkout cannot grant inside -------------


def test_a_config_in_another_checkout_grants_nothing_inside_in_a_one_directory_scan(
    container, scene
):
    ops = scene.w / "ops"
    mark_git_checkout(ops)
    config = ops / "ash.yaml"
    config.write_text(WHOLE_FILE, encoding="utf-8")

    host = _facts(resolve_config(config_path=config, source_dir=scene.source))
    inside = container(
        source_dir=str(scene.source), output_dir=str(scene.out), config=str(config)
    )["scan"]

    assert in_any_checkout(config)
    assert host["sandbox.extra_read_paths"] == []
    assert host["sandbox.network_scanners"] is None
    assert host["sandbox.read_path_scanners"] == []
    assert host["sandbox.env_scanners"] == []
    assert inside == host


def test_a_config_in_another_checkout_grants_nothing_inside_in_a_workspace_scan(
    container, scene
):
    ws = scene.w / "repo" / "ws"
    (ws / "bare").mkdir(parents=True)
    (ws / "bare" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (ws / "own" / ".ash").mkdir(parents=True)
    (ws / "own" / "b.py").write_text("y = 2\n", encoding="utf-8")
    (ws / "own" / ".ash" / ".ash.yaml").write_text(REPOSITORY, encoding="utf-8")
    definition = ws / "ash.code-workspace"
    definition.write_text(
        json.dumps({"folders": [{"path": "bare"}, {"path": "own"}]}), encoding="utf-8"
    )
    ops = scene.w / "ops"
    mark_git_checkout(ops)
    config = ops / "ash.yaml"
    config.write_text(WHOLE_FILE, encoding="utf-8")
    plan = resolve_workspace(definition, default_config=str(config))
    settings = ProjectScanSettings(
        output_dir=scene.out, default_config_path=str(config)
    )
    host = {
        Path(project.path).name: _facts(_project_config_with_policy(project, settings))
        for project in plan.projects
    }

    inside = container(
        source_dir=str(ws),
        output_dir=str(scene.out),
        config=str(config),
        workspace_relative_file="ash.code-workspace",
    )

    assert in_any_checkout(config)
    assert set(host) == {"bare", "own"}
    assert host["bare"]["sandbox.extra_read_paths"] == []
    assert host["bare"]["sandbox.network_scanners"] is None
    assert host["bare"]["sandbox.read_path_scanners"] == []
    assert host["bare"]["sandbox.env_scanners"] == []
    assert inside == host
    run = container.last
    assert run[run.index(FLAG) + 1] == "/ash-config/ash.yaml"


def test_a_base_in_another_checkout_grants_nothing_but_the_root_keeps_its_own_section(
    container, scene
):
    """The root is outside every checkout and keeps the sandbox settings it writes
    itself; the base it extends is in a checkout and grants nothing."""
    chain = scene.w / "chain"
    mark_git_checkout(chain / "vendor")
    (chain / "vendor" / "base.yaml").write_text(BASE_FILE, encoding="utf-8")
    config = chain / "ash.yaml"
    config.write_text(ROOT_FILE, encoding="utf-8")

    host = _facts(resolve_config(config_path=config, source_dir=scene.source))
    inside = container(
        source_dir=str(scene.source), output_dir=str(scene.out), config=str(config)
    )["scan"]

    assert in_any_checkout(chain / "vendor" / "base.yaml")
    assert not in_any_checkout(config)
    assert host["sandbox.extra_read_paths"] == ["/opt/operator-own"]
    assert host["sandbox.read_path_scanners"] == []
    assert host["sandbox.env_scanners"] == []
    assert host["sandbox.network_scanners"] is None
    assert inside == host
    run = container.last
    assert run[run.index(FLAG) + 1] == "/ash-config/vendor/base.yaml"
    assert run.count(FLAG) == 1


# --- controls: nothing changes for the other two places a file can be ---------


def test_control_the_operators_own_file_outside_every_checkout_is_unchanged_inside(
    monkeypatch, container, scene
):
    path, host, inside = _ash_config_scan(
        monkeypatch, container, scene, "outside", WHOLE_FILE
    )

    assert not in_any_checkout(path)
    # The operator's own file is the trusted base whole, grants included.
    assert host["max_members"] == 10
    assert host["semgrep.metrics"] == "off"
    assert host["sandbox.extra_read_paths"] == ["/data"]
    assert host["sandbox.network_scanners"] == ["semgrep"]
    assert host["sandbox.read_path_scanners"] == ["zizmor"]
    assert host["sandbox.env_scanners"] == ["zizmor"]
    assert inside == host
    run = container.last
    assert FLAG not in run
    assert TREE_FILE_FLAG not in run


def test_control_a_file_in_the_scanned_checkout_keeps_nothing_inside(
    monkeypatch, container, scene
):
    path, host, inside = _ash_config_scan(
        monkeypatch, container, scene, "scanned", WHOLE_FILE
    )

    assert in_any_checkout(path)
    # The scanned repository's own file: the base is the defaults.
    assert host["max_members"] == 5000
    assert host["semgrep.metrics"] == "auto"
    assert host["sandbox.network_limit"] is None
    assert host["sandbox.extra_read_paths"] == []
    assert host["sandbox.read_path_scanners"] == []
    assert host["sandbox.env_scanners"] == []
    assert inside == host
    run = container.last
    assert run[run.index(TREE_FILE_FLAG) + 1] == "/ash-env-config/ash-env.yaml"
    assert FLAG not in run


def test_control_a_delivered_config_never_reaches_a_container_scan(container, tmp_path):
    """No mark can describe a delivered file: container mode refuses to be handed
    one, so the scan inside never has a delivered class to keep restrictions from.

    Run under the recording container's stubs, so a guard that stopped refusing
    would hand the run to the recording runner and start nothing."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    (tmp_path / "src").mkdir()

    with pytest.raises(ValueError, match="untrusted_config is applied only"):
        run_ash_scan(
            source_dir=str(tmp_path / "src"),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.container,
            untrusted_config=True,
            build=False,
        )

    assert container.commands == []


# --- the host marks the file ---------------------------------------------------


@pytest.fixture
def launch(tmp_path: Path) -> Dict[str, Path]:
    """A checkout whose scan root is a subdirectory, with an operator dir beside it."""
    root = tmp_path / "repo"
    mark_git_checkout(root)
    source = root / "services" / "api"
    source.mkdir(parents=True)
    (root / "ci").mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return {
        "root": root.resolve(),
        "source": source.resolve(),
        "ci": (root / "ci").resolve(),
        "operator": operator.resolve(),
        "out": out.resolve(),
    }


def _write(path: Path, text: str = "project_name: p\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_a_config_in_another_checkout_is_marked_as_such(launch, tmp_path):
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    config = _write(ops / "ash.yaml")

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert _flags(inner, FLAG) == ["/ash-config/ash.yaml"]
    # Not the scanned tree's marks: that class keeps nothing.
    assert CHAIN_FLAG not in inner
    assert _flags(inner, TREE_FILE_FLAG) == []


def test_a_base_in_another_checkout_is_marked_and_its_root_is_not(launch, tmp_path):
    chain = tmp_path / "chain"
    mark_git_checkout(chain / "vendor")
    _write(chain / "vendor" / "base.yaml")
    config = _write(chain / "ash.yaml", "extends: vendor/base.yaml\n")

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert _flags(inner, FLAG) == ["/ash-config/vendor/base.yaml"]
    assert CHAIN_FLAG not in inner
    assert _flags(inner, TREE_FILE_FLAG) == []


def test_a_base_in_the_scanned_checkout_is_marked_once_as_the_scanned_trees(
    launch, tmp_path
):
    """An operator's file beside the checkout extends a base inside it: the base
    carries the scanned tree's mark alone. The scan inside reads that class as
    keeping nothing, so a second mark of the other class would only blur the two."""
    _write(launch["ci"] / "base.yaml")
    config = _write(tmp_path / "ash.yaml", "extends: repo/ci/base.yaml\n")

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert _flags(inner, TREE_FILE_FLAG) == ["/ash-config/repo/ci/base.yaml"]
    assert _flags(inner, FLAG) == []
    assert CHAIN_FLAG not in inner


def test_an_ash_config_in_another_checkout_is_marked_as_such(
    launch, monkeypatch, tmp_path
):
    envco = tmp_path / "envco"
    mark_git_checkout(envco)
    env = _write(envco / "env.yaml", "project_name: env\n")
    config = _write(launch["operator"] / "ash.yaml")
    monkeypatch.setenv("ASH_CONFIG", str(env))

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert inner[inner.index(ENV_FLAG) + 1] == "/ash-env-config/env.yaml"
    assert _flags(inner, FLAG) == ["/ash-env-config/env.yaml"]
    assert _flags(inner, TREE_FILE_FLAG) == []
    assert CHAIN_FLAG not in inner


def test_each_file_gets_the_mark_of_its_own_place(launch, monkeypatch, tmp_path):
    """A --config in the scanned checkout and an ASH_CONFIG file in another one."""
    config = _write(launch["ci"] / "ash.yaml")
    envco = tmp_path / "envco"
    mark_git_checkout(envco)
    env = _write(envco / "env.yaml", "project_name: env\n")
    monkeypatch.setenv("ASH_CONFIG", str(env))

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert CHAIN_FLAG in inner
    assert _flags(inner, FLAG) == ["/ash-env-config/env.yaml"]
    assert _flags(inner, TREE_FILE_FLAG) == []


@pytest.mark.parametrize("layout", LINKS_IN_ANOTHER_CHECKOUT)
def test_a_config_reached_through_a_link_in_another_checkout_is_marked_as_such(
    layout, launch, tmp_path
):
    config = config_through_links(layout, launch["root"], tmp_path)

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert _flags(inner, FLAG) == ["/ash-config/ash.yaml"]
    assert CHAIN_FLAG not in inner
    assert _flags(inner, TREE_FILE_FLAG) == []
    assert RETIRED_FLAG not in inner


@pytest.mark.parametrize("layout", LINKS_IN_THE_SCANNED_CHECKOUT)
def test_control_a_config_reached_through_a_link_in_the_scanned_checkout_keeps_its_mark(
    layout, launch, tmp_path
):
    config = config_through_links(layout, launch["root"], tmp_path)

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert CHAIN_FLAG in inner
    assert _flags(inner, FLAG) == []
    assert RETIRED_FLAG not in inner


def test_control_a_config_outside_every_checkout_is_not_marked(launch):
    config = _write(launch["operator"] / "ash.yaml")

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert _flags(inner, FLAG) == []
    assert CHAIN_FLAG not in inner
    assert _flags(inner, TREE_FILE_FLAG) == []


def test_control_a_link_chain_outside_every_checkout_is_not_marked(launch, tmp_path):
    config = config_through_links(
        LINKS_OUTSIDE_EVERY_CHECKOUT, launch["root"], tmp_path
    )

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert _flags(inner, FLAG) == []
    assert CHAIN_FLAG not in inner


def test_control_a_config_in_the_scanned_checkout_is_marked_as_the_scanned_trees(
    launch,
):
    config = _write(launch["ci"] / "ash.yaml")

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert CHAIN_FLAG in inner
    assert _flags(inner, FLAG) == []


def test_control_a_config_inside_the_source_directory_needs_no_mark(launch):
    config = _write(launch["source"] / ".ash" / "ash.yaml")

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert inner[inner.index("--config") + 1] == "/src/.ash/ash.yaml"
    assert _flags(inner, FLAG) == []
    assert CHAIN_FLAG not in inner


def test_the_launcher_spells_the_option_as_the_scan_inside_cells_do():
    """The cells below hand FLAG to the real CLI; the launcher's constant has to be
    the same word."""
    assert rac.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG == FLAG


def test_a_failed_judgment_refuses_the_scan_rather_than_send_the_file_unmarked(
    launch, monkeypatch, tmp_path
):
    """A judgment that fails after the chain was prepared for mounting refuses the
    scan: the file would otherwise arrive inside as the operator's."""
    from automated_security_helper.config import resolve_config as resolve_module

    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    config = _write(ops / "ash.yaml")

    def raising(*args, **kwargs):
        raise OSError("transient read failure")

    monkeypatch.setattr(resolve_module, "_with_any_checkout_files", raising)

    with pytest.raises(rac.ContainerInputError, match="without the mark"):
        _assemble(launch["source"], launch["out"], config=str(config))


def test_a_failed_judgment_of_the_ash_config_file_refuses_the_scan_as_well(
    launch, monkeypatch, tmp_path
):
    """The same refusal at the other call site: the file ASH_CONFIG names, with no
    --config on the command line."""
    from automated_security_helper.config import resolve_config as resolve_module

    envco = tmp_path / "envco"
    mark_git_checkout(envco)
    env = _write(envco / "env.yaml", "project_name: env\n")
    monkeypatch.setenv("ASH_CONFIG", str(env))

    def raising(*args, **kwargs):
        raise OSError("transient read failure")

    monkeypatch.setattr(resolve_module, "_with_any_checkout_files", raising)

    with pytest.raises(rac.ContainerInputError, match="without the mark"):
        _assemble(launch["source"], launch["out"])


# --- the reason the scan inside gives for a marked file -------------------------


def _reason_inside(container, monkeypatch, tmp_path: Path):
    """The reason the scan inside gives for the --config file it was handed, played
    again from the run command the host just built."""
    from automated_security_helper.config.sandbox_grants import untrusted_reason

    return scan_inside(
        container.last,
        tmp_path / "again",
        monkeypatch,
        project=lambda planned, settings: None,
        scan=lambda kwargs: untrusted_reason(
            Path(kwargs["config"]), Path(kwargs["source_dir"])
        ),
    )["scan"]


@pytest.mark.parametrize(
    "layout, in_the_scanned_checkout",
    [(layout, True) for layout in LINKS_IN_THE_SCANNED_CHECKOUT]
    + [(layout, False) for layout in LINKS_IN_ANOTHER_CHECKOUT],
)
def test_the_reason_for_a_config_reached_through_a_link_is_the_one_for_its_mark(
    layout, in_the_scanned_checkout, monkeypatch, container, scene, tmp_path
):
    """The file resolves outside every checkout: only a link on the way to it sits in
    one. The host marks it all the same (as the scanned tree's when the link is
    there, as in another checkout when it is in one), and the reason the scan inside
    gives is the one for the mark it got. The scanned tree's says the file was
    reached through a link; the one for another checkout says the host found it in,
    or reached it through a link in, such a checkout."""
    from automated_security_helper.config.sandbox_grants import (
        MARKED_ELSEWHERE_REASON,
        MARKED_REASON,
    )

    (scene.w / "repo" / "ci").mkdir()
    named = config_through_links(layout, scene.w / "repo", tmp_path)
    assert not in_any_checkout(named.resolve())

    container(
        source_dir=str(scene.source), output_dir=str(scene.out), config=str(named)
    )
    inner = _inner_args(container.last)
    if in_the_scanned_checkout:
        assert CHAIN_FLAG in inner
    else:
        assert _flags(inner, FLAG) == ["/ash-config/ash.yaml"]

    reason = _reason_inside(container, monkeypatch, tmp_path)

    expected = MARKED_REASON if in_the_scanned_checkout else MARKED_ELSEWHERE_REASON
    assert reason == expected
    if in_the_scanned_checkout:
        assert "through a link" in reason
    else:
        assert "reached it through a link in" in reason
        assert "could not rule one out" not in reason


def test_control_a_config_held_by_another_checkout_is_reported_as_found_there(
    monkeypatch, container, scene, tmp_path
):
    from automated_security_helper.config.sandbox_grants import (
        MARKED_ELSEWHERE_REASON,
    )

    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    config = _write(ops / "ash.yaml")

    container(
        source_dir=str(scene.source), output_dir=str(scene.out), config=str(config)
    )
    assert _flags(_inner_args(container.last), FLAG) == ["/ash-config/ash.yaml"]

    reason = _reason_inside(container, monkeypatch, tmp_path)

    assert reason == MARKED_ELSEWHERE_REASON
    assert "found it in, or reached it through a link in, a git checkout" in reason
    assert "other than the scanned directory" in reason


# --- the scan inside reads the mark -------------------------------------------


def test_the_inner_cli_reads_the_file_as_in_another_checkout_while_it_runs(
    monkeypatch, tmp_path
):
    from automated_security_helper.config.sandbox_grants import (
        checkout_judgment,
        confined_files,
        repository_written,
        scanned_trees,
        untrusted_reason,
    )

    source = tmp_path / "src"
    source.mkdir()
    config = _write(tmp_path / "ash-config" / "ash.yaml")
    seen: Dict[str, Any] = {}

    def run(**kwargs):
        seen["kwargs"] = kwargs
        seen["checkout"] = checkout_judgment(config).verdict
        seen["members"] = confined_files(
            [config.resolve()], scanned_trees(source), [config]
        ).members
        seen["written"] = repository_written([config.resolve()], source)
        seen["reason"] = untrusted_reason(config, source)

    monkeypatch.setattr(scan_cli, "run_ash_scan", run)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--config",
            str(config),
            FLAG,
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["checkout"] is True
    # In a checkout, not in the scanned tree: the host's two answers for it.
    assert seen["members"] == ()
    assert seen["written"] == [config.resolve()]
    assert seen["reason"] is not None
    assert seen["kwargs"].get("untrusted_config", False) is False
    # Only while the scan runs.
    assert checkout_judgment(config).verdict is False
    assert repository_written([config.resolve()], source) == []


def test_the_inner_cli_reads_the_hosts_ash_config_file_as_in_another_checkout(
    monkeypatch, tmp_path
):
    from automated_security_helper.config.sandbox_grants import checkout_judgment

    source = tmp_path / "src"
    source.mkdir()
    env = _write(tmp_path / "ash-env-config" / "env.yaml", "project_name: env\n")
    seen: Dict[str, Any] = {}

    def run(**kwargs):
        seen["checkout"] = checkout_judgment(env).verdict

    monkeypatch.setattr(scan_cli, "run_ash_scan", run)

    result = CliRunner().invoke(
        app,
        ["scan", "--source-dir", str(source), ENV_FLAG, str(env), FLAG, str(env)],
    )

    assert result.exit_code == 0, result.output
    assert seen["checkout"] is True
    assert checkout_judgment(env).verdict is False


def test_the_mark_does_not_lift_the_limits_on_a_file_inside_the_scanned_directory(
    monkeypatch, tmp_path
):
    """The host never marks a file the scan reads through /src, but the option is
    the scan inside's to take: a mark for another checkout on a file the scanned
    directory holds leaves it a member of the scanned tree, so it still cannot add
    a plugin module or grant a read path."""
    from automated_security_helper.config.sandbox_grants import (
        confined_files,
        scanned_trees,
    )

    source = tmp_path / "src"
    config = _write(
        source / ".ash" / "ash.yaml",
        f"project_name: p\nash_plugin_modules:\n  - {UNINSTALLED}\n"
        "sandbox:\n  extra_read_paths: [/data]\n",
    )
    seen: Dict[str, Any] = {}

    def run(**kwargs):
        seen["members"] = confined_files(
            [config.resolve()], scanned_trees(source), [config]
        ).members
        seen["config"] = resolve_config(
            config_path=kwargs["config"], source_dir=kwargs["source_dir"]
        )

    monkeypatch.setattr(scan_cli, "run_ash_scan", run)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--config",
            str(config),
            FLAG,
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["members"] == (config.resolve(),)
    assert seen["config"].ash_plugin_modules == []
    assert seen["config"].sandbox.extra_read_paths == []


@pytest.mark.parametrize("flag", [TREE_FILE_FLAG, FLAG])
@pytest.mark.parametrize(
    "where", ["not-in-the-chain", "not-in-the-ash-config-chain", "no-config"]
)
def test_a_file_mark_that_is_not_a_file_of_a_chain_is_refused_and_nothing_scans(
    flag, where, monkeypatch, tmp_path
):
    """A malformed mark restricts as far as it can: the scan does not start. Both
    file marks are held to the same rule, and the message is the one for the case:
    a name outside the chain of --config, outside the chain of the file ASH_CONFIG
    names, or a scan with no config for it to name a file of."""
    started: List[Any] = []
    monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: started.append(kw))
    (tmp_path / "src").mkdir()
    config = _write(tmp_path / "ash.yaml")
    env = _write(tmp_path / "env.yaml", "project_name: env\n")
    other = _write(tmp_path / "other.yaml", "project_name: o\n")
    args = ["scan", "--source-dir", str(tmp_path / "src")]
    if where == "not-in-the-chain":
        args += ["--config", str(config)]
    elif where == "not-in-the-ash-config-chain":
        args += [ENV_FLAG, str(env)]

    result = CliRunner().invoke(app, [*args, flag, str(other)])

    output = " ".join(result.output.split())
    assert result.exit_code == 3, result.output
    assert flag in output
    assert started == []
    reason = "this scan has none" if where == "no-config" else "not a file of the chain"
    assert reason in output


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_the_mark_on_any_other_scan_is_a_usage_error(mode, monkeypatch, tmp_path):
    """Refused before anything starts. The outer scan is stubbed so that a scan that
    got past the refusal would end here, not in a container runner or a Nix shell.

    The mark names the one file of the ``--config`` chain, so the chain check
    would let it through: only the mode can be what refuses."""
    started: List[Any] = []
    monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: started.append(kw))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    _write(tmp_path / "ash.yaml")

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            mode,
            "--no-build",
            "--no-progress",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            "--config",
            "ash.yaml",
            FLAG,
            "ash.yaml",
        ],
    )

    assert result.exit_code == 3, result.output
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    assert "apply only to a scan in local mode" in " ".join(result.output.split())
    assert FLAG in result.output
    assert started == []


def test_a_file_marked_both_ways_is_read_as_the_scanned_trees(monkeypatch, tmp_path):
    """Contradictory marks: the reading that keeps nothing decides."""
    from automated_security_helper.config.sandbox_grants import (
        confined_files,
        scanned_trees,
    )

    source = tmp_path / "src"
    source.mkdir()
    config = _write(tmp_path / "ash-config" / "ash.yaml")
    seen: Dict[str, Any] = {}

    def run(**kwargs):
        seen["members"] = confined_files(
            [config.resolve()], scanned_trees(source), [config]
        ).members

    monkeypatch.setattr(scan_cli, "run_ash_scan", run)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--config",
            str(config),
            TREE_FILE_FLAG,
            str(config),
            FLAG,
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["members"] == (config.resolve(),)


def test_the_registry_ends_with_the_block_and_counts_each_mark_once(tmp_path):
    from automated_security_helper.config.sandbox_grants import (
        checkout_judgment,
        confined_files,
        marked_files_in_another_checkout,
        untrusted_reason,
    )

    one = _write(tmp_path / "mounted" / "one.yaml")
    two = _write(tmp_path / "mounted" / "two.yaml")
    elsewhere = _write(tmp_path / "mounted" / "elsewhere.yaml")

    with marked_files_in_another_checkout([one, two]):
        with marked_files_in_another_checkout([one]):
            assert checkout_judgment(one).verdict is True
        # The inner block took its own mark away and no more.
        assert checkout_judgment(one).verdict is True
        assert checkout_judgment(two).verdict is True
        assert checkout_judgment(elsewhere).verdict is False
        assert untrusted_reason(one, tmp_path / "src") is not None
        assert untrusted_reason(elsewhere, tmp_path / "src") is None
        assert confined_files([one], [tmp_path / "src"], [one]).members == ()

    assert checkout_judgment(one).verdict is False
    assert checkout_judgment(two).verdict is False
    assert untrusted_reason(one, tmp_path / "src") is None


def test_the_reason_for_a_file_marked_in_another_checkout_names_that_checkout(
    tmp_path,
):
    """The mark says the host found the file in a git checkout other than the scanned
    directory, or reached it through a link in one. The reason says that and nothing
    about which ASH sent the mark, which link the host followed or which option
    carried it."""
    from automated_security_helper.config.sandbox_grants import (
        MARKED_ELSEWHERE_REASON,
        marked_files_in_another_checkout,
        untrusted_reason,
    )

    one = _write(tmp_path / "mounted" / "one.yaml")

    with marked_files_in_another_checkout([one]):
        reason = untrusted_reason(one, tmp_path / "src")

    assert reason == MARKED_ELSEWHERE_REASON
    assert reason.endswith(
        "found it in, or reached it through a link in, a git checkout other than "
        "the scanned directory"
    )
    assert "older" not in reason
    # It says a link was followed, not which one.
    assert one.as_posix() not in reason
    # The option is hidden: a warning the user reads does not name it.
    assert "--config-file" not in reason


def test_the_reason_for_a_file_marked_as_the_scanned_trees_names_the_scanned_tree(
    tmp_path,
):
    """The scanned tree's mark says the scanned directory, or the git checkout that
    holds it, has the file or a link that leads to it. It names no other sender."""
    from automated_security_helper.config.sandbox_grants import (
        MARKED_REASON,
        marked_files_repository_written,
        untrusted_reason,
    )

    one = _write(tmp_path / "mounted" / "one.yaml")

    with marked_files_repository_written([one]):
        reason = untrusted_reason(one, tmp_path / "src")

    assert reason == MARKED_REASON
    assert "git checkout that holds it" in reason
    assert "older" not in reason
    assert "any git checkout" not in reason
    # The option is hidden: a warning the user reads does not name it.
    assert "--config-file" not in reason


# --- a file whose link walk stopped ---------------------------------------------


def _walk_stopped_for(monkeypatch, *files: Path) -> None:
    """The host's checkout judgment of each of *files*, by its resolved path, is an
    unfinished walk's answer: in a checkout, with the walk not decided.

    Only the any-checkout judgment (``resolve_config._with_any_checkout_files``) is
    changed. The scanned-tree judgment the launcher makes first reads the real
    names, so these files are not the scanned tree's. No real layout reaches this
    state: that judgment reads a name whose walk stopped as the scanned tree's, so
    the launcher never gets here (see test_container_workspace_config_tier.py).
    The tests below force it to show that, were it reached, the file is marked as
    in another checkout and no other option exists for it.
    """
    from automated_security_helper.config import resolve_config as resolve_module
    from automated_security_helper.config.sandbox_grants import WalkJudgment

    real = resolve_module.checkout_judgment
    stopped = {Path(file).resolve() for file in files}

    def judged(path):
        if Path(path).resolve() in stopped:
            return WalkJudgment(verdict=True, decided=False)
        return real(path)

    monkeypatch.setattr(resolve_module, "checkout_judgment", judged)


def test_a_config_whose_walk_stopped_is_marked_as_in_another_checkout(
    launch, monkeypatch
):
    config = _write(launch["operator"] / "ash.yaml")
    _walk_stopped_for(monkeypatch, config)

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert _flags(inner, FLAG) == ["/ash-config/ash.yaml"]
    assert RETIRED_FLAG not in inner
    # Not the scanned tree's.
    assert CHAIN_FLAG not in inner
    assert _flags(inner, TREE_FILE_FLAG) == []


def test_a_base_whose_walk_stopped_is_marked_beside_a_root_found_in_another_checkout(
    launch, monkeypatch, tmp_path
):
    chain = tmp_path / "chain"
    mark_git_checkout(chain)
    base = _write(chain / "vendor" / "base.yaml")
    config = _write(chain / "ash.yaml", "extends: vendor/base.yaml\n")
    _walk_stopped_for(monkeypatch, base)

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert sorted(_flags(inner, FLAG)) == [
        "/ash-config/ash.yaml",
        "/ash-config/vendor/base.yaml",
    ]
    assert RETIRED_FLAG not in inner
    assert CHAIN_FLAG not in inner
    assert _flags(inner, TREE_FILE_FLAG) == []


def test_an_ash_config_file_whose_walk_stopped_is_marked_as_in_another_checkout(
    launch, monkeypatch, tmp_path
):
    env = _write(tmp_path / "envdir" / "env.yaml", "project_name: env\n")
    config = _write(launch["operator"] / "ash.yaml")
    monkeypatch.setenv("ASH_CONFIG", str(env))
    _walk_stopped_for(monkeypatch, env)

    inner = _inner_args(_assemble(launch["source"], launch["out"], config=str(config)))

    assert inner[inner.index(ENV_FLAG) + 1] == "/ash-env-config/env.yaml"
    assert _flags(inner, FLAG) == ["/ash-env-config/env.yaml"]
    assert RETIRED_FLAG not in inner
    assert _flags(inner, TREE_FILE_FLAG) == []


def test_the_launcher_has_no_option_for_a_stopped_walk():
    """The option was sent for a file only a stopped walk placed in another
    checkout, which no real layout produces; the constant is gone with it."""
    assert not hasattr(rac, "CONFIG_FILE_WALK_UNDECIDED_FLAG")


def test_a_stopped_walk_keeps_the_limits_of_an_ash_config_file_inside(
    monkeypatch, container, scene
):
    """The scan inside limits a file whose walk stopped as it limits one found in
    another checkout: the grant goes, what only restricts stays.

    The stopped walk is set up for the host's own facts and for the launcher that
    builds the command, and only for them. The scan inside then runs the real
    judgment from the mark alone, and its facts are compared with the host's."""
    path = _operator_file(scene.w, "outside", WHOLE_FILE)
    monkeypatch.setenv("ASH_CONFIG", str(path))
    with monkeypatch.context() as stopped:
        _walk_stopped_for(stopped, path)
        host = _facts(resolve_config(source_dir=scene.source))
        cmd = container.assemble(
            source_dir=str(scene.source), output_dir=str(scene.out)
        )

    inside = container.inside(cmd)["scan"]

    assert FLAG in cmd
    assert RETIRED_FLAG not in cmd
    assert host["max_members"] == 10
    assert host["semgrep.metrics"] == "off"
    assert host["sandbox.network_limit"] == ["semgrep"]
    assert host["sandbox.network_scanners"] is None
    assert host["sandbox.extra_read_paths"] == []
    assert host["sandbox.read_path_scanners"] == []
    assert host["sandbox.env_scanners"] == []
    assert inside == host


def test_the_inner_cli_no_longer_takes_the_stopped_walk_option(monkeypatch, tmp_path):
    """An option for a file whose walk stopped is gone: the scan inside rejects it
    with the usage error, and the usage code, of any option it does not know, and
    nothing scans."""
    started: List[Any] = []
    monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: started.append(kw))
    (tmp_path / "src").mkdir()
    config = _write(tmp_path / "ash.yaml")

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(tmp_path / "src"),
            "--config",
            str(config),
            RETIRED_FLAG,
            str(config),
        ],
    )

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert f"No such option: {RETIRED_FLAG}" in " ".join(result.output.split())
    assert started == []
