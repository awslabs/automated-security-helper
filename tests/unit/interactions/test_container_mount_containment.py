# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What of the host the scan inside the container can read and write.

The scan inside sees the host only through the mounts the runner command gives it,
and docs/content/docs/cli-reference.md ("Running a scan in a container") lists them:

- ``/src``, the source directory, read-only;
- ``/out``, the output directory, read-write;
- ``/ash-config/...``, ``--config`` and the files of its ``extends`` chain, read-only;
- ``/ash-workspace-config/...``, the workspace policy, read-only.

These tests build the command ``ash --mode container`` would run, for a plain
tree, a config chain, a chain reached through links, a workspace, and paths with
spaces and other unusual characters, and hold it to that list:

- the source directory is mounted at ``/src`` read-only, once, under its own name;
- every other mount is the output directory at ``/out`` or a file under one of
  the two config roots, read-only;
- each file of a config chain is mounted under ``/ash-config``, where the scan
  inside reads it, and is a file the host-side validation of that chain read;
- a base the host-side validation refused is not mounted at all;
- two files of a chain cannot claim the same container path.

No runner is started. ``run_cmd_direct`` is replaced by a recorder, and the tests
that only need the command call ``_assemble_run_command`` directly.
"""

from __future__ import annotations

import json
import posixpath
import shutil
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.config.config_sources import (
    default_confinement_root,
    resolve_config_document,
)
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.host_file_names import skip_unless_the_host_can_name

CONFIG_ROOT = rac.CONTAINER_CONFIG_ROOT
POLICY_ROOT = rac.CONTAINER_WORKSPACE_CONFIG_ROOT

#: Names that are legal on POSIX and that ``--mount`` carries as written: no comma,
#: double quote or line break, which the launcher refuses (see
#: test_container_mount_paths_must_be_representable.py). Windows cannot hold three of
#: them (glob, backslash and tab: tests/utils/host_file_names.py), so the tests that
#: make a directory under a name skip those there.
UNUSUAL_NAMES = [
    pytest.param("plain", id="plain"),
    pytest.param("with space", id="space"),
    pytest.param("dollar$HOME", id="dollar"),
    pytest.param("glob*?[ab]", id="glob"),
    pytest.param("semi;colon&amp", id="shell-punctuation"),
    pytest.param("quote'single", id="single-quote"),
    pytest.param("uniéü", id="non-ascii"),
    pytest.param("eq=sign", id="equals"),
    pytest.param("-leading-dash", id="leading-dash"),
    pytest.param("back\\slash", id="backslash"),
    pytest.param("tab\there", id="tab"),
]

_SCRUBBED_ENV = (
    "CI",
    "IsCI",
    "ISCI",
    "CODEBUILD_BUILD_ID",
    "ASH_IMAGE_NAME",
    "ASH_CONFIG",
    "ASH_SOURCE_DIR",
    "ASH_OUTPUT_DIR",
    "ASH_MODE",
    "ASH_WORKSPACE",
    "ASH_WORKSPACE_CONFIG",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
)


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    """No test here may start a real OCI runner; ``commands`` below records instead."""

    def refuse(cmd_list, check=True, debug=False, shell=False, env=None):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


def _assemble(source_dir: Path, output_dir: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": "automated-security-helper:non-root",
        "source_dir": source_dir,
        "output_dir": output_dir,
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
    }
    kwargs.update(overrides)
    return rac._assemble_run_command(**kwargs)


def _mount_list(cmd: List[str]) -> List[Dict[str, Any]]:
    """Every ``--mount`` in order, as its comma-separated fields."""
    found = []
    for i, arg in enumerate(cmd[:-1]):
        if arg != "--mount":
            continue
        options: Dict[str, Any] = {}
        for part in cmd[i + 1].split(","):
            key, sep, value = part.partition("=")
            options[key] = value if sep else True
        found.append(options)
    return found


def _mounts(cmd: List[str]) -> Dict[str, Dict[str, Any]]:
    """Every ``--mount``, keyed by its destination; two at one destination fail."""
    found: Dict[str, Dict[str, Any]] = {}
    for options in _mount_list(cmd):
        destination = str(options.get("destination"))
        assert destination not in found, f"two mounts at {destination}: {cmd}"
        found[destination] = options
    return found


def _flag(cmd: List[str], flag: str) -> str:
    values = [cmd[i + 1] for i, arg in enumerate(cmd[:-1]) if arg == flag]
    assert len(values) == 1, f"expected one {flag} in {cmd}"
    return values[0]


def _under(path: str, root: str) -> bool:
    return path.startswith(root + "/")


def _assert_documented_mounts(cmd: List[str], source: Path, output: Path) -> None:
    """The command's mounts are the documented ones, and nothing else."""
    mounts = _mounts(cmd)
    src = mounts.get("/src")
    assert src is not None, f"no /src mount: {cmd}"
    assert src.get("type") == "bind"
    assert src.get("source") == str(source.resolve())
    assert src.get("readonly") is True, f"/src is writable: {src}"
    out = mounts.get("/out")
    assert out is not None, f"no /out mount: {cmd}"
    assert out.get("source") == str(output.resolve())
    for destination, options in mounts.items():
        if destination in ("/src", "/out"):
            continue
        assert _under(destination, CONFIG_ROOT) or _under(destination, POLICY_ROOT), (
            f"a mount outside the documented roots: {destination} <- {options}"
        )
        assert options.get("type") == "bind"
        assert options.get("readonly") is True, f"{destination} is writable"
        assert Path(str(options["source"])).is_file(), (
            f"{destination} mounts {options['source']}, which is not a file"
        )


# ---------------------------------------------------------------------------
# The source is always read-only at /src, and nothing else is mounted
# ---------------------------------------------------------------------------


def _layout(tmp_path: Path, name: str, kind: str) -> Dict[str, Any]:
    """A tree whose every directory carries *name*, for one of the layouts below."""
    base = tmp_path / f"base {name}"
    source = base / f"project {name}"
    (source / ".ash").mkdir(parents=True)
    output = base / f"out {name}"
    operator = base / f"operator {name}"
    operator.mkdir()
    overrides: Dict[str, Any] = {}
    chain: List[Path] = []
    if kind == "config-inside":
        config = source / ".ash" / f"strict {name}.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
        overrides["config"] = str(config)
    elif kind == "config-outside-with-chain":
        (operator / f"base {name}").mkdir()
        common = operator / f"base {name}" / "common.yaml"
        common.write_text("project_name: p\n", encoding="utf-8")
        config = operator / f"ash {name}.yaml"
        # JSON, which YAML reads, so that no name needs YAML quoting rules.
        config.write_text(
            json.dumps({"extends": f"base {name}/common.yaml"}), encoding="utf-8"
        )
        overrides["config"] = str(config)
        chain = [config.resolve(), common.resolve()]
    elif kind == "output-inside-source":
        output = source / ".ash" / "ash_output"
    elif kind == "workspace-policy-outside":
        policy = operator / f"ash-workspace {name}.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")
        overrides["workspace_relative_file"] = "dev.code-workspace"
        overrides["workspace_config"] = str(policy)
    output.mkdir(parents=True, exist_ok=True)
    return {"source": source, "output": output, "overrides": overrides, "chain": chain}


class TestTheSourceIsMountedReadOnlyAndNothingElseIsShared:
    @pytest.mark.parametrize(
        "kind",
        [
            "no-config",
            "config-inside",
            "config-outside-with-chain",
            "output-inside-source",
            "workspace-policy-outside",
        ],
    )
    @pytest.mark.parametrize("name", UNUSUAL_NAMES)
    def test_the_command_mounts_only_the_documented_paths(self, kind, name, tmp_path):
        skip_unless_the_host_can_name(name)
        layout = _layout(tmp_path, name, kind)

        cmd = _assemble(
            layout["source"].resolve(),
            layout["output"].resolve(),
            **layout["overrides"],
        )

        _assert_documented_mounts(cmd, layout["source"], layout["output"])
        if layout["chain"]:
            mounted = {
                Path(str(options["source"]))
                for dest, options in _mounts(cmd).items()
                if _under(dest, CONFIG_ROOT)
            }
            assert mounted == set(layout["chain"])

    @pytest.mark.parametrize("name", UNUSUAL_NAMES)
    def test_run_ash_container_mounts_the_source_it_was_given(
        self, name, commands, tmp_path
    ):
        """Through the public entry point, which resolves the paths itself."""
        skip_unless_the_host_can_name(name)
        layout = _layout(tmp_path, name, "config-outside-with-chain")

        result = rac.run_ash_container(
            source_dir=str(layout["source"]),
            output_dir=str(layout["output"]),
            config=layout["overrides"]["config"],
            build=False,
            run=True,
        )

        assert result.returncode == 0, getattr(result, "stderr", "")
        runs = [cmd for cmd in commands if cmd[1] == "run"]
        assert len(runs) == 1, commands
        _assert_documented_mounts(runs[0], layout["source"], layout["output"])

    def test_a_source_reached_through_a_link_is_mounted_by_its_real_path(
        self, commands, tmp_path
    ):
        """The runner would resolve the link itself; the command names the target."""
        real = tmp_path / "real-project"
        real.mkdir()
        link = tmp_path / "linked-project"
        link.symlink_to(real, target_is_directory=True)

        rac.run_ash_container(
            source_dir=str(link), output_dir=str(tmp_path / "out"), build=False
        )

        run = [cmd for cmd in commands if cmd[1] == "run"][0]
        assert _mounts(run)["/src"]["source"] == str(real.resolve())
        assert _mounts(run)["/src"]["readonly"] is True


# ---------------------------------------------------------------------------
# Each file of a config chain sits under /ash-config, where the scan inside reads it
# ---------------------------------------------------------------------------


def _container_view(cmd: List[str], tmp_path: Path) -> Path:
    """Lay every config mount out under a stand-in root, as the runner would.

    Every destination, not only those under /ash-config, so that a file the command
    places anywhere else is laid out where it would be too.
    """
    root = tmp_path / "container-root"
    for destination, options in _mounts(cmd).items():
        if destination in ("/src", "/out"):
            continue
        target = root / destination.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(options["source"]), target)
    (root / "src").mkdir(parents=True, exist_ok=True)
    return root


def _operator_tree(ops: Path) -> None:
    """Directories and links the chains below reach their bases through."""
    (ops / "sub").mkdir()
    (ops / "real").mkdir()
    (ops / "x" / "y" / "z").mkdir(parents=True)
    (ops / "sub" / "b.yaml").write_text("project_name: sub\n", encoding="utf-8")
    (ops / "real" / "b2.yaml").write_text(
        "extends: c.yaml\nfail_on_findings: false\n", encoding="utf-8"
    )
    (ops / "real" / "c.yaml").write_text("project_name: c\n", encoding="utf-8")
    (ops / "sym.yaml").symlink_to(ops / "real" / "b2.yaml")
    (ops / "linked").symlink_to(ops / "real", target_is_directory=True)
    # `deep` names a directory three levels further down than its own name.
    (ops / "deep").symlink_to(ops / "x" / "y" / "z", target_is_directory=True)
    (ops / "top.yaml").write_text("project_name: top\n", encoding="utf-8")
    (ops / "src").mkdir()
    (ops / "src" / "app.py").write_text("project_name: app\n", encoding="utf-8")
    (ops / "x" / "y" / "z" / "climbs.yaml").write_text(
        "extends: ../../../top.yaml\n", encoding="utf-8"
    )
    (ops / "x" / "y" / "z" / "into-src.yaml").write_text(
        "extends: ../../../src/app.py\n", encoding="utf-8"
    )
    (ops / "x" / "y" / "z" / "one-up.yaml").write_text(
        "extends: ../near.yaml\n", encoding="utf-8"
    )
    (ops / "x" / "y" / "near.yaml").write_text("project_name: near\n", encoding="utf-8")


CHAIN_LAYOUTS = [
    pytest.param("extends: sub/b.yaml\n", id="relative-subdir"),
    pytest.param("extends: sym.yaml\n", id="symlinked-base"),
    pytest.param("extends: sub/../sub/b.yaml\n", id="dotdot-inside"),
    pytest.param("extends: linked/b2.yaml\n", id="base-in-linked-dir"),
    pytest.param("extends: deep/one-up.yaml\n", id="one-up-from-a-linked-dir"),
]

#: Entries of ``operator/ash.yaml`` whose chain the host resolves inside the config's
#: directory but whose container path, the entry followed as written from the
#: extending file's mount, is outside /ash-config: (entry, the entry in the chain
#: that leaves it).
ESCAPING_CHAINS = [
    # deep -> x/y/z, and climbs.yaml says ../../../top.yaml: /top.yaml inside.
    pytest.param(
        "deep/climbs.yaml", "../../../top.yaml", id="climbs-out-of-a-linked-dir"
    ),
    # The same climb onto a file that would sit inside the read-only /src mount.
    pytest.param("deep/into-src.yaml", "../../../src/app.py", id="climbs-into-src"),
    # Out of the config's directory and back in by its name: /operator/top.yaml.
    pytest.param(
        "../operator/top.yaml",
        "../operator/top.yaml",
        id="leaves-the-directory-and-comes-back-by-name",
    ),
]


@pytest.fixture
def tree(tmp_path) -> Dict[str, Path]:
    source = tmp_path / "project"
    (source / ".ash").mkdir(parents=True)
    output = tmp_path / "out"
    output.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    return {
        "source": source.resolve(),
        "output": output.resolve(),
        "operator": operator.resolve(),
    }


class TestEachChainFileSitsWhereTheScanInsideReadsIt:
    @pytest.mark.parametrize("body", CHAIN_LAYOUTS)
    def test_every_chain_file_is_mounted_under_ash_config(self, body, tree):
        ops = tree["operator"]
        _operator_tree(ops)
        config = ops / "ash.yaml"
        config.write_text(body, encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        _assert_documented_mounts(cmd, tree["source"], tree["output"])

    @pytest.mark.parametrize("body", CHAIN_LAYOUTS)
    def test_the_mounted_files_are_the_files_the_host_approved(self, body, tree):
        """The host validates the chain it resolves; the command mounts that chain."""
        ops = tree["operator"]
        _operator_tree(ops)
        config = ops / "ash.yaml"
        config.write_text(body, encoding="utf-8")
        approved = resolve_config_document(
            config.resolve(),
            confine_to=default_confinement_root(config.resolve(), tree["source"]),
        )

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        mounted = {
            Path(str(options["source"]))
            for dest, options in _mounts(cmd).items()
            if dest not in ("/src", "/out")
        }
        assert mounted == set(approved.chain)
        _assert_documented_mounts(cmd, tree["source"], tree["output"])

    @pytest.mark.parametrize("body", CHAIN_LAYOUTS)
    def test_the_scan_inside_resolves_the_chain_the_host_approved(
        self, body, tree, tmp_path
    ):
        ops = tree["operator"]
        _operator_tree(ops)
        config = ops / "ash.yaml"
        config.write_text(body, encoding="utf-8")
        host = resolve_config_document(config.resolve()).data

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        root = _container_view(cmd, tmp_path)
        inner = root / _flag(cmd, "--config").lstrip("/")
        inside = resolve_config_document(
            inner, confine_to=default_confinement_root(inner, root / "src")
        )
        assert inside.data == host
        real_root = root.resolve().as_posix()
        read_inside = {
            "/" + posixpath.relpath(path.as_posix(), real_root) for path in inside.chain
        }
        assert read_inside == set(_mounts(cmd)) - {"/src", "/out"}


class TestAChainThatWouldLeaveItsMountRootIsRefused:
    """The container path of a base is the lexical join of the extending file's
    container path and the entry, and the host confines the chain by real paths. A
    chain where the two disagree about how far ``..`` climbs cannot be mounted where
    the scan inside reads it, so it is refused with exit 3 before anything is
    built, naming the entry."""

    @pytest.mark.parametrize(("entry", "leaving"), ESCAPING_CHAINS)
    def test_it_is_refused_before_anything_is_mounted(self, entry, leaving, tree):
        ops = tree["operator"]
        _operator_tree(ops)
        config = ops / "ash.yaml"
        config.write_text(f"extends: {entry}\n", encoding="utf-8")

        refusal = rac.container_input_refusal(
            tree["source"], tree["output"], str(config)
        )

        assert refusal is not None
        assert f"extends: {leaving}" in refusal
        assert CONFIG_ROOT in refusal
        with pytest.raises(rac.ContainerInputError):
            _assemble(tree["source"], tree["output"], config=str(config))

    @pytest.mark.parametrize(("entry", "leaving"), ESCAPING_CHAINS)
    def test_the_run_exits_3_without_building(self, entry, leaving, tree, commands):
        ops = tree["operator"]
        _operator_tree(ops)
        config = ops / "ash.yaml"
        config.write_text(f"extends: {entry}\n", encoding="utf-8")

        result = rac.run_ash_container(
            source_dir=str(tree["source"]),
            output_dir=str(tree["output"]),
            config=str(config),
        )

        assert result.returncode == 3, result.stderr
        assert commands == []

    def test_a_chain_inside_its_directory_is_mounted(self, tree):
        """Control: one level down and back up stays under /ash-config."""
        ops = tree["operator"]
        _operator_tree(ops)
        config = ops / "ash.yaml"
        config.write_text("extends: x/y/z/one-up.yaml\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        assert _mounts(cmd)["/ash-config/x/y/near.yaml"]["source"] == str(
            ops / "x" / "y" / "near.yaml"
        )
        _assert_documented_mounts(cmd, tree["source"], tree["output"])


class TestChainFilesCannotCollide:
    def test_two_files_at_one_container_path_are_refused(self, tree):
        """``f.yaml`` is a link to ``sub/f.yaml``, so its ``b.yaml`` is ``sub/b.yaml``
        on the host but ``/ash-config/b.yaml`` inside, where the config's own
        ``b.yaml`` goes too. The scan inside would read one file for both."""
        ops = tree["operator"]
        (ops / "sub").mkdir()
        (ops / "sub" / "f.yaml").write_text("extends: b.yaml\n", encoding="utf-8")
        (ops / "sub" / "b.yaml").write_text("project_name: sub\n", encoding="utf-8")
        (ops / "b.yaml").write_text("project_name: top\n", encoding="utf-8")
        (ops / "f.yaml").symlink_to(ops / "sub" / "f.yaml")
        config = ops / "ash.yaml"
        config.write_text("extends: [f.yaml, b.yaml]\n", encoding="utf-8")

        with pytest.raises(rac.ContainerInputError, match="both be mounted"):
            _assemble(tree["source"], tree["output"], config=str(config))

    def test_one_file_reached_twice_is_mounted_once(self, tree):
        """Control: the same host file at the same container path is no collision."""
        ops = tree["operator"]
        (ops / "a.yaml").write_text("extends: c.yaml\n", encoding="utf-8")
        (ops / "b.yaml").write_text("extends: c.yaml\n", encoding="utf-8")
        (ops / "c.yaml").write_text("project_name: c\n", encoding="utf-8")
        config = ops / "ash.yaml"
        config.write_text("extends: [a.yaml, b.yaml]\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        assert sorted(d for d in _mounts(cmd) if _under(d, CONFIG_ROOT)) == [
            "/ash-config/a.yaml",
            "/ash-config/ash.yaml",
            "/ash-config/b.yaml",
            "/ash-config/c.yaml",
        ]

    def test_a_file_where_another_needs_a_directory_is_refused(self, tree):
        """``f2link.yaml`` is a link to ``sub/f2.yaml``, whose ``extends: d`` is the
        file ``sub/d`` on the host but ``/ash-config/d`` inside, where the config's
        own ``d/x.yaml`` needs a directory. The runner cannot create both."""
        ops = tree["operator"]
        (ops / "sub").mkdir()
        (ops / "d").mkdir()
        (ops / "sub" / "f2.yaml").write_text("extends: d\n", encoding="utf-8")
        (ops / "sub" / "d").write_text("project_name: q\n", encoding="utf-8")
        (ops / "d" / "x.yaml").write_text("project_name: r\n", encoding="utf-8")
        (ops / "f2link.yaml").symlink_to(ops / "sub" / "f2.yaml")
        config = ops / "ash.yaml"
        config.write_text("extends: [f2link.yaml, d/x.yaml]\n", encoding="utf-8")

        refusal = rac.container_input_refusal(
            tree["source"], tree["output"], str(config)
        )

        assert refusal is not None
        assert "/ash-config/d" in refusal and "/ash-config/d/x.yaml" in refusal
        with pytest.raises(rac.ContainerInputError):
            _assemble(tree["source"], tree["output"], config=str(config))

    @pytest.mark.parametrize("collision", ["same-path", "file-where-a-directory-goes"])
    def test_the_run_exits_3_and_starts_nothing(self, collision, tree, commands):
        ops = tree["operator"]
        if collision == "same-path":
            # x -> other/deep/dir, whose b.yaml extends ../c.yaml: other/deep/c.yaml
            # on the host, /ash-config/c.yaml inside, where the config's c.yaml goes.
            (ops / "other" / "deep" / "dir").mkdir(parents=True)
            (ops / "other" / "deep" / "dir" / "b.yaml").write_text(
                "extends: ../c.yaml\n", encoding="utf-8"
            )
            (ops / "other" / "deep" / "c.yaml").write_text(
                "project_name: deep\n", encoding="utf-8"
            )
            (ops / "c.yaml").write_text("project_name: top\n", encoding="utf-8")
            (ops / "x").symlink_to(
                ops / "other" / "deep" / "dir", target_is_directory=True
            )
            body = "extends: [x/b.yaml, c.yaml]\n"
        else:
            (ops / "sub").mkdir()
            (ops / "d").mkdir()
            (ops / "sub" / "f2.yaml").write_text("extends: d\n", encoding="utf-8")
            (ops / "sub" / "d").write_text("project_name: q\n", encoding="utf-8")
            (ops / "d" / "x.yaml").write_text("project_name: r\n", encoding="utf-8")
            (ops / "f2link.yaml").symlink_to(ops / "sub" / "f2.yaml")
            body = "extends: [f2link.yaml, d/x.yaml]\n"
        config = ops / "ash.yaml"
        config.write_text(body, encoding="utf-8")

        result = rac.run_ash_container(
            source_dir=str(tree["source"]),
            output_dir=str(tree["output"]),
            config=str(config),
        )

        assert result.returncode == 3, result.stderr
        assert commands == []


# ---------------------------------------------------------------------------
# A base the host-side validation refused is not mounted
# ---------------------------------------------------------------------------


class TestABaseOutsideTheConfigDirectoryIsNotMounted:
    """An outside config's chain is confined to the config's own directory (the
    parent of ``.ash/`` for a file there). A chain that leaves it does not resolve
    on the host, so only the config itself is mounted, and the scan inside reports
    the base it cannot reach."""

    @pytest.fixture
    def outside(self, tmp_path) -> Path:
        other = tmp_path / "unrelated" / "host-file.yaml"
        other.parent.mkdir()
        other.write_text("project_name: other\n", encoding="utf-8")
        return other.resolve()

    @pytest.mark.parametrize("how", ["dotdot", "file-link", "directory-link"])
    def test_only_the_config_is_mounted(self, how, tree, outside):
        ops = tree["operator"]
        if how == "dotdot":
            ref = "../unrelated/host-file.yaml"
        elif how == "file-link":
            (ops / "lnk.yaml").symlink_to(outside)
            ref = "lnk.yaml"
        else:
            (ops / "lnkdir").symlink_to(outside.parent, target_is_directory=True)
            ref = "lnkdir/host-file.yaml"
        config = ops / "ash.yaml"
        config.write_text(f"extends: {ref}\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        sources = [str(options["source"]) for options in _mount_list(cmd)]
        assert str(outside) not in sources
        assert {d for d in _mounts(cmd) if _under(d, CONFIG_ROOT)} == {
            "/ash-config/ash.yaml"
        }

    def test_a_config_in_dot_ash_may_reach_its_parent(self, tree):
        """Control: ``.ash/`` confines the chain to the directory above it."""
        ops = tree["operator"]
        (ops / ".ash").mkdir()
        (ops / "shared.yaml").write_text("project_name: s\n", encoding="utf-8")
        config = ops / ".ash" / ".ash.yaml"
        config.write_text("extends: ../shared.yaml\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        assert _mounts(cmd)["/ash-config/shared.yaml"]["source"] == str(
            ops / "shared.yaml"
        )


# ---------------------------------------------------------------------------
# A workspace policy linked out of the workspace, as an in-tree --config is
# ---------------------------------------------------------------------------


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in _SCRUBBED_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return seen


def _scan(*args: str):
    from automated_security_helper.cli.main import app

    return CliRunner().invoke(app, ["scan", "--no-progress", "--no-build", *args])


class TestALinkOutOfTheScannedTreeIsRefusedForEveryMountedConfig:
    """``--config`` named inside the scanned tree whose real path is outside it is
    refused with exit 3 (test_container_config_link_out_of_the_tree.py). The
    workspace policy is mounted the same way, at ``/ash-workspace-config``, and the
    host finds it inside the workspace root without being asked. These go through
    the CLI, so the policy reaches the launcher the way a scan hands it over: from
    the plan the workspace resolver built."""

    @pytest.fixture
    def workspace(self, tmp_path) -> Dict[str, Path]:
        root = tmp_path / "ws"
        (root / "api").mkdir(parents=True)
        (root / "dev.code-workspace").write_text(
            json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8"
        )
        outside = tmp_path / "elsewhere" / "settings.yaml"
        outside.parent.mkdir()
        outside.write_text("workspace: {}\n", encoding="utf-8")
        return {"root": root, "outside": outside, "out": tmp_path / "out"}

    def test_an_in_tree_config_linked_out_is_refused(self, workspace, commands):
        """The rule the policy is compared with, through the same CLI."""
        root = workspace["root"]
        (root / ".git").mkdir()
        target = workspace["outside"].parent / "operator-config.yaml"
        target.write_text("project_name: p\n", encoding="utf-8")
        (root / "ash.yaml").symlink_to(target)

        result = _scan(
            "--mode",
            "container",
            "--source-dir",
            str(root),
            "--output-dir",
            str(workspace["out"]),
            "--config",
            str(root / "ash.yaml"),
        )

        assert result.exit_code == 3, result.output
        assert "link" in result.output
        assert [cmd for cmd in commands if cmd[1] == "run"] == []

    @pytest.mark.parametrize("how", ["discovered", "named", "named-at-another-path"])
    def test_a_policy_linked_out_of_the_workspace_is_refused(
        self, how, workspace, commands
    ):
        root = workspace["root"]
        if how == "named-at-another-path":
            (root / "policies").mkdir()
            link = root / "policies" / "shared.yaml"
        else:
            link = root / "ash-workspace.yaml"
        link.symlink_to(workspace["outside"])
        extra = [] if how == "discovered" else ["--workspace-config", str(link)]

        result = _scan(
            "--mode",
            "container",
            "--workspace",
            str(root / "dev.code-workspace"),
            "--output-dir",
            str(workspace["out"]),
            *extra,
        )

        runs = [cmd for cmd in commands if cmd[1] == "run"]
        mounted = [
            str(options["source"]) for run in runs for options in _mount_list(run)
        ]
        assert str(workspace["outside"].resolve()) not in mounted
        assert result.exit_code == 3, result.output
        assert runs == []

    def test_a_library_caller_with_a_discovered_link_is_refused(
        self, workspace, commands
    ):
        """No --workspace-config: the discovered file is checked by its own name."""
        from automated_security_helper.core.enums import RunMode
        from automated_security_helper.interactions import run_ash_scan as ras
        from automated_security_helper.workspace.resolver import resolve_workspace

        root = workspace["root"]
        (root / "ash-workspace.yaml").symlink_to(workspace["outside"])
        plan = resolve_workspace(root / "dev.code-workspace")

        with pytest.raises(SystemExit) as stopped:
            ras.run_ash_scan(
                source_dir=plan.workspace_root,
                output_dir=str(workspace["out"]),
                mode=RunMode.container,
                build=False,
                workspace_plan=plan,
            )

        assert stopped.value.code == 3
        assert [cmd for cmd in commands if cmd[1] == "run"] == []

    def test_a_policy_link_inside_the_workspace_is_read_through_src(
        self, workspace, commands
    ):
        """Control: a link that stays inside the root names a file under /src."""
        root = workspace["root"]
        (root / "policies").mkdir()
        (root / "policies" / "p.yaml").write_text("workspace: {}\n", encoding="utf-8")
        (root / "ash-workspace.yaml").symlink_to("policies/p.yaml")

        _scan(
            "--mode",
            "container",
            "--workspace",
            str(root / "dev.code-workspace"),
            "--output-dir",
            str(workspace["out"]),
        )

        runs = [cmd for cmd in commands if cmd[1] == "run"]
        assert len(runs) == 1, commands
        assert _flag(runs[0], "--workspace-config") == "/src/policies/p.yaml"
        assert set(_mounts(runs[0])) == {"/src", "/out"}
        assert _mounts(runs[0])["/src"]["readonly"] is True

    def test_a_policy_kept_outside_the_workspace_is_mounted_read_only(
        self, workspace, commands
    ):
        """Control: an operator's policy outside the tree, named as itself."""
        _scan(
            "--mode",
            "container",
            "--workspace",
            str(workspace["root"] / "dev.code-workspace"),
            "--output-dir",
            str(workspace["out"]),
            "--workspace-config",
            str(workspace["outside"]),
        )

        runs = [cmd for cmd in commands if cmd[1] == "run"]
        assert len(runs) == 1, commands
        inner = _flag(runs[0], "--workspace-config")
        assert inner == "/ash-workspace-config/settings.yaml"
        assert _mounts(runs[0])[inner]["source"] == str(workspace["outside"].resolve())
        _assert_documented_mounts(runs[0], workspace["root"], workspace["out"])
