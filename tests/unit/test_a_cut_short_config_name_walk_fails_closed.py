# ONE file that both MEASURES the long-chain outcomes (facts) and ASSERTS the
# fail-closed direction for a config name whose link walk is cut short.
#
# Measuring: each cell builds a chain of operator links, assembles the
# container run command WITHOUT running a container runner (runner
# resolution is a literal path string; the oci prefix is empty; nothing is
# executed), and reads the assembled argv or the refusal. Every cell prints
# WALK|<cell>|k=v lines (run with -s) describing what the assembly did.
#
# Asserting: for the 40/41-link chains, the readlink-EACCES chain and the
# mode-000-directory chain, the outcome must be MARKED or REFUSED, never
# UNMARKED. Within-bound chains keep the same direction. Two CONTROLS pin the
# ends: the plain 1-link chain must come out MARKED, and naming the tree
# link directly must come out REFUSED. The measuring helper itself asserts
# only that the outcome class is one of REFUSED / MARKED / UNMARKED / ERROR.
#
# Layout under each cell's tmp_path (everything is built there):
#   repo/            the scanned checkout (.git/HEAD planted), source = repo/services/api, repo/ci
#   outside/ash.yaml the plain operator file the chain ends at, outside every checkout
#   repo/ci/tree.yaml   ONE repository (tree) link -> outside/ash.yaml
#   ops/l1.yaml ... ops/lN.yaml   N OPERATOR links: l_i -> l_(i+1).yaml (relative), l_N -> repo/ci/tree.yaml
# The name handed to the container runner is ops/l1.yaml. sandbox_grants._MAX_LINKS = 40 bounds the
# links the marking machinery follows; the gate _named_in_a_scanned_tree collapses a final-component
# file link outside every tree with an uncapped os.path.realpath.

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from tests.utils.helpers import mark_git_checkout

FLAG = rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG
FILE_FLAG = rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG
IMAGE = "automated-security-helper:non-root"
MAX_LINKS = getattr(sandbox_grants, "_MAX_LINKS", None)

FAIL_CLOSED = ("MARKED", "REFUSED")


def _fact(cell: str, **facts: Any) -> None:
    print("WALK|%s|%s" % (cell, "|".join("%s=%r" % (k, v) for k, v in facts.items())))


def _verdict(cell: str, outcome: str) -> None:
    print("WALK|%s|outcome=%r" % (cell, outcome))


def _fact_realpath(name) -> str:
    # Diagnostic only: realpath follows links itself and raises on one it
    # cannot read, which must not abort the cell that provoked that state.
    try:
        return os.path.realpath(name)
    except OSError:
        return "<unresolvable>"


def _assemble(source_dir: Path, output_dir: Path, config: str) -> List[str]:
    return rac._assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name=IMAGE,
        source_dir=source_dir,
        output_dir=output_dir,
        offline=False,
        debug=False,
        color=False,
        quiet=True,
        progress=False,
        verbose=False,
        simple=True,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[ExecutionPhase.SCAN],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=config,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=ExecutionStrategy.PARALLEL,
        ctx=None,
    )


def _inner_args(cmd: List[str]) -> List[str]:
    return cmd[cmd.index(IMAGE) + 1 :]


def _mount_sources(cmd: List[str]) -> List[str]:
    sources = []
    for index, item in enumerate(cmd[:-1]):
        if item == "--mount":
            fields = dict(
                field.split("=", 1)
                for field in cmd[index + 1].split(",")
                if "=" in field
            )
            sources.append(fields.get("source", ""))
    return sources


def _layout(tmp_path: Path) -> Dict[str, Path]:
    root = tmp_path / "repo"
    mark_git_checkout(root)
    source = root / "services" / "api"
    source.mkdir(parents=True)
    (root / "ci").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    real = outside / "ash.yaml"
    real.write_text("project_name: p\n", encoding="utf-8")
    tree_link = root / "ci" / "tree.yaml"
    tree_link.symlink_to(real)
    return {
        "root": root.resolve(),
        "source": source.resolve(),
        "out": out.resolve(),
        "real": real.resolve(),
        "tree_link": root.resolve() / "ci" / "tree.yaml",
    }


def _chain(
    tmp_path: Path, lay: Dict[str, Path], n: int, hidden_dir_at: Optional[int] = None
) -> Path:
    """N operator links ending at the tree link; returns the name ops/l1.yaml.

    With *hidden_dir_at* = k, link k lives in its own directory ops/d<k>/ (so the cell can later set
    that directory's mode to 000); the chain's targets are absolute for that hop.
    """
    ops = tmp_path / "ops"
    ops.mkdir()

    def where(i: int) -> Path:
        if hidden_dir_at is not None and i == hidden_dir_at:
            directory = ops / ("d%d" % i)
            directory.mkdir(exist_ok=True)
            return directory / ("l%d.yaml" % i)
        return ops / ("l%d.yaml" % i)

    for i in range(1, n + 1):
        link = where(i)
        if i == n:
            link.symlink_to(lay["tree_link"])
        elif hidden_dir_at is not None and (
            i + 1 == hidden_dir_at or i == hidden_dir_at
        ):
            link.symlink_to(where(i + 1))
        else:
            link.symlink_to("l%d.yaml" % (i + 1))
    return where(1)


def _kernel_open(name: Path) -> str:
    try:
        os.stat(name)
        return "stat-ok"
    except OSError as error:
        return "stat-%s" % errno.errorcode.get(error.errno or 0, str(error.errno))


def _measure(cell: str, lay: Dict[str, Path], name: Path) -> str:
    """Assemble for *name* and classify: REFUSED / MARKED / UNMARKED / ERROR:<class>."""
    trees = rac._scanned_tree_roots(lay["source"])
    gate_named_in_tree = None
    gate_error = None
    try:
        gate_named_in_tree = rac._named_in_a_scanned_tree(Path(name), trees)
    except Exception as error:  # noqa: BLE001 - the class is the measurement
        gate_error = "%s: %s" % (type(error).__name__, str(error)[:100])
    repository_written = None
    try:
        repository_written = rac._repository_written(Path(name), lay["source"])
    except Exception as error:  # noqa: BLE001
        repository_written = "%s: %s" % (type(error).__name__, str(error)[:100])
    try:
        links = sandbox_grants.links_followed(Path(name))
        links_followed = (len(links), links[-1].name if links else None)
    except Exception as error:  # noqa: BLE001
        links_followed = "%s: %s" % (type(error).__name__, str(error)[:100])
    gate_refusal = None
    try:
        rac._refuse_config_linked_out_of_the_tree(str(name), lay["source"])
    except rac.ContainerInputError as error:
        gate_refusal = str(error)[:100]
    except Exception as error:  # noqa: BLE001
        gate_refusal = "OTHER %s: %s" % (type(error).__name__, str(error)[:100])
    cmd = None
    refused = None
    other = None
    try:
        cmd = _assemble(lay["source"], lay["out"], str(name))
    except rac.ContainerInputError as error:
        refused = str(error)[:140]
    except Exception as error:  # noqa: BLE001
        other = "%s: %s" % (type(error).__name__, str(error)[:140])
    inner = _inner_args(cmd) if cmd is not None else []
    if refused is not None:
        outcome = "REFUSED"
    elif other is not None:
        outcome = "ERROR:%s" % other.split(":")[0]
    elif FLAG in inner:
        outcome = "MARKED"
    else:
        outcome = "UNMARKED"
    _fact(
        cell,
        outcome=outcome,
        name=str(name),
        max_links=MAX_LINKS,
        kernel_stat=_kernel_open(name),
        realpath=_fact_realpath(name),
        real_target=str(lay["real"]),
        gate_named_in_tree=gate_named_in_tree,
        gate_error=gate_error,
        gate_refusal_head=gate_refusal,
        repository_written=repository_written,
        links_followed_count_and_last=links_followed,
        refused_head=refused,
        other_error=other,
        mark_flag_in_inner=(FLAG in inner) if cmd is not None else None,
        file_mark_flags_in_inner=[
            inner[i + 1] for i, item in enumerate(inner[:-1]) if item == FILE_FLAG
        ],
        config_arg=(
            inner[inner.index("--config") + 1] if "--config" in inner else None
        ),
        argv_mount_sources=[] if cmd is None else _mount_sources(cmd),
        assembled_argv=cmd,
    )
    assert outcome in ("REFUSED", "MARKED", "UNMARKED") or outcome.startswith("ERROR:")
    return outcome


def test_control_one_operator_link_then_the_tree_link_is_marked(tmp_path):
    lay = _layout(tmp_path)
    outcome = _measure("control-1-link", lay, _chain(tmp_path, lay, 1))
    _verdict("control-1-link", outcome)
    assert outcome == "MARKED"


def test_control_naming_the_tree_link_directly_is_refused(tmp_path):
    lay = _layout(tmp_path)
    outcome = _measure("control-direct-tree-link", lay, lay["tree_link"])
    _verdict("control-direct-tree-link", outcome)
    assert outcome == "REFUSED"


@pytest.mark.parametrize("n", [2, 20, 38, 39, 40, 41])
def test_variant_a_operator_links_then_one_tree_link_fails_closed(tmp_path, n):
    lay = _layout(tmp_path)
    outcome = _measure("variant-A-n%d" % n, lay, _chain(tmp_path, lay, n))
    _verdict("variant-A-n%d" % n, outcome)
    assert outcome in FAIL_CLOSED, outcome


def test_variant_b_sim_one_link_unreadable_by_readlink_fails_closed(
    tmp_path, monkeypatch
):
    lay = _layout(tmp_path)
    name = _chain(tmp_path, lay, 40)
    victim = str(tmp_path / "ops" / "l20.yaml")
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if os.fspath(path) == victim or str(Path(os.fspath(path)).absolute()) == victim:
            raise OSError(errno.EACCES, "planted: permission denied")
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", readlink)
    outcome = _measure("variant-B-sim-l20-readlink-EACCES-n40", lay, name)
    _verdict("variant-B-sim-l20-readlink-EACCES-n40", outcome)
    assert outcome in FAIL_CLOSED, outcome


def test_variant_b_real_link_20_in_a_mode_000_directory_fails_closed(tmp_path):
    lay = _layout(tmp_path)
    name = _chain(tmp_path, lay, 40, hidden_dir_at=20)
    hidden = tmp_path / "ops" / "d20"
    hidden.chmod(0)
    try:
        outcome = _measure("variant-B-real-l20-in-mode-000-dir-n40", lay, name)
        _verdict("variant-B-real-l20-in-mode-000-dir-n40", outcome)
        assert outcome in FAIL_CLOSED, outcome
    finally:
        hidden.chmod(0o755)


@pytest.mark.skipif(
    os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs a directory the process cannot search",
)
def test_a_component_the_walk_cannot_examine_ends_it_undecided(tmp_path, request):
    """The walk alone, no gate or link test in the path: a component under a
    directory the process cannot search ends ``_walk_links`` undecided, so
    nothing downstream can treat the unseen rest of the name as settled."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    request.addfinalizer(lambda: locked.chmod(0o700))

    links, decided = sandbox_grants._walk_links(locked / "x" / "target.yaml")

    assert decided is False, (links, decided)


def test_a_provably_absent_component_keeps_the_walk_decided(tmp_path):
    """The must-not twin: a component that provably is not a link, because it
    does not exist under a searchable directory, keeps the walk decided."""
    links, decided = sandbox_grants._walk_links(tmp_path / "missing" / "target.yaml")

    assert decided is True, (links, decided)
    assert links == [], links
