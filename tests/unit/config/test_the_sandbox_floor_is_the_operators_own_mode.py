# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox-mode floor comes from the operator's own files, never the merged chain.

sandbox_grants' module docstring promises that when the operator's configuration
turns the sandbox on, an in-tree file cannot turn it off. The trusted base reads
the floor mode where that promise is kept (``trusted_base_config``): the mode an
operator-owned file of the chain writes, read from each file's own document in
chain order, with the merged chain's mode only when no owned file writes one --
an in-tree write can then only raise it. Reading the merged chain alone let a
base in the scanned checkout, later in the operator root's ``extends`` list,
turn the operator's firejail off, in the local scan and in the floor container
mode reports.

Each cell asserts the local scan's resolved mode and the container floor
(``_sandbox_mode_without_the_config``) together, so the two voices cannot
drift. Premises raise RuntimeError, so only the mode assertions can fail a
cell.
"""

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from tests.utils.helpers import mark_git_checkout

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)


def _write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _floor(tmp_path, src, trusted_config_path=None):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    opts = run_ash_scan.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        trusted_config_path=trusted_config_path,
    )
    return run_ash_scan._sandbox_mode_without_the_config(opts)


def _local_mode(src):
    try:
        return resolve_config(source_dir=src).sandbox.mode
    except _REFUSED:
        return None


def _lowered_chain(tmp_path, where, root_sets_mode=False):
    """An operator root whose own base sets firejail and whose later base, in
    the scanned checkout, writes the mode off."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    dotfiles = tmp_path / "dotfiles"
    mark_git_checkout(dotfiles)
    home = dotfiles if where == "sections-in-dotfiles" else tmp_path / "plain"
    mode_file = _write(home / "mode.yaml", {"sandbox": {"mode": "firejail"}})
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root_doc = {
        "project_name": "floor",
        "extends": [mode_file.as_posix(), lower.as_posix()],
    }
    if root_sets_mode:
        root_doc["sandbox"] = {"mode": "firejail"}
    root = _write(tmp_path / "ash-root.yaml", root_doc)
    return src, root


@pytest.mark.parametrize("where", ["sections-outside", "sections-in-dotfiles"])
def test_an_in_tree_base_after_the_operators_mode_cannot_turn_it_off(
    tmp_path, monkeypatch, where
):
    """The operator's own base sets firejail; a base in the scanned checkout,
    later in the same extends list, writes off. The local scan and the floor
    both keep the operator's mode."""
    src, root = _lowered_chain(tmp_path, where)
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    local = _local_mode(src)
    floor = _floor(tmp_path, src)
    if local is None:
        raise RuntimeError("the local scan refused, so the cell shows nothing")
    assert (local, floor) == ("firejail", ["firejail"]), (local, floor)


def test_a_sibling_files_section_rewrite_keeps_anothers_mode(tmp_path, monkeypatch):
    """One operator base sets firejail; a SIBLING operator base's own patch
    rewrites its own sandbox section without a mode; an in-tree base writes
    off. The sibling's rewrite reaches only its own document -- the merge
    keeps the other base's mode -- so the operator floor survives and the
    in-tree off cannot win through the sibling's silence."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    home = tmp_path / "ops"
    mode_file = _write(home / "mode.yaml", {"sandbox": {"mode": "firejail"}})
    grants = _write(
        home / "grants.yaml",
        {
            "patch": [
                {
                    "op": "add",
                    "path": "/sandbox",
                    "value": {"extra_read_paths": ["/opt/x"]},
                }
            ]
        },
    )
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [mode_file.as_posix(), grants.as_posix(), lower.as_posix()],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    local = _local_mode(src)
    floor = _floor(tmp_path, src)
    if local is None:
        raise RuntimeError("the local scan refused, so the cell shows nothing")
    assert (local, floor) == ("firejail", ["firejail"]), (local, floor)


def test_the_roots_own_rewrite_reaches_the_whole_chain(tmp_path, monkeypatch):
    """The control for the sibling cell above: the ROOT's own patch rewrites
    the document without a mode. The root's bases merge under it before its
    patch applies, so the rewrite drops the owned base's firejail from the
    resolved load, and the floor follows the operator's own last word: the
    root is the operator's file here, so clearing is the operator's write."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    home = tmp_path / "ops"
    mode_file = _write(home / "mode.yaml", {"sandbox": {"mode": "firejail"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [mode_file.as_posix()],
            "patch": [
                {
                    "op": "add",
                    "path": "",
                    "value": {"project_name": "rewritten", "sandbox": {}},
                }
            ],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    local = _local_mode(src)
    floor = _floor(tmp_path, src)
    if local is None:
        raise RuntimeError("the local scan refused, so the cell shows nothing")
    assert (local, floor) == ("off", ["off"]), (local, floor)


def test_the_same_lowering_through_the_operators_config_file(tmp_path, monkeypatch):
    """The same chain as the operator's --config (no ASH_CONFIG): the trusted
    base's operator branch reads the mode the same owned-files way."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src, root = _lowered_chain(tmp_path, "sections-outside")
    monkeypatch.chdir(src)
    config = resolve_config(config_path=root, source_dir=src, trusted_config_path=root)
    floor = _floor(tmp_path, src, trusted_config_path=str(root))
    assert (config.sandbox.mode, floor) == ("firejail", ["firejail"]), (
        config.sandbox.mode,
        floor,
    )


def test_control_the_roots_own_mode_is_not_lowered_by_an_in_tree_base(
    tmp_path, monkeypatch
):
    src, root = _lowered_chain(tmp_path, "sections-outside", root_sets_mode=True)
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    assert (_local_mode(src), _floor(tmp_path, src)) == ("firejail", ["firejail"])


def test_control_an_in_tree_base_before_the_operators_mode_cannot_lower_it(
    tmp_path, monkeypatch
):
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = _write(
        tmp_path / "plain" / "mode.yaml", {"sandbox": {"mode": "firejail"}}
    )
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [lower.as_posix(), mode_file.as_posix()]},
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    assert (_local_mode(src), _floor(tmp_path, src)) == ("firejail", ["firejail"])


def test_control_with_no_in_tree_base_the_operators_base_mode_holds(
    tmp_path, monkeypatch
):
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = _write(
        tmp_path / "plain" / "mode.yaml", {"sandbox": {"mode": "firejail"}}
    )
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [mode_file.as_posix()]},
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    assert (_local_mode(src), _floor(tmp_path, src)) == ("firejail", ["firejail"])


# The cells below read three voices -- the local scan, container mode's
# requested modes, and its fallback floor -- so none of them can drift from
# the others on the chains where the mode comes from an operator file's own
# ``patch`` instead of a direct ``sandbox.mode`` key.

_ROUTES = ["ash_config", "config_file", "dotfiles"]


def _voices(tmp_path, src, route, root):
    """(local, requested, floor) for one route. local is None when the scan's
    own load refuses the chain."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    if route == "config_file":
        opts = run_ash_scan.ScanOptions(
            source_dir=src,
            output_dir=tmp_path / "out",
            mode=RunMode.container,
            config=str(root),
            trusted_config_path=str(root),
        )
        try:
            local = resolve_config(
                config_path=root, source_dir=src, trusted_config_path=root
            ).sandbox.mode
        except _REFUSED:
            local = None
    else:
        opts = run_ash_scan.ScanOptions(
            source_dir=src, output_dir=tmp_path / "out", mode=RunMode.container
        )
        try:
            local = resolve_config(source_dir=src).sandbox.mode
        except _REFUSED:
            local = None
    requested = run_ash_scan._sandbox_modes_requested(opts)
    floor = run_ash_scan._sandbox_mode_without_the_config(opts)
    return local, requested, floor


def _route_setup(tmp_path, monkeypatch, route, root):
    src = tmp_path / "src"
    if route == "config_file":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
    else:
        monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    return src


def _operator_home(tmp_path, route):
    if route == "dotfiles":
        home = tmp_path / "dotfiles"
        mark_git_checkout(home)
        return home
    return tmp_path / "plain"


def _assert_kept(local, requested, floor, expected):
    if local is None:
        raise RuntimeError("the local scan refused, so the cell shows nothing")
    assert (local, requested, floor) == (expected, [expected], [expected]), (
        local,
        requested,
        floor,
    )


def _patch_mode_file(home):
    """The operator's base that sets its mode with a patch instead of a key."""
    return _write(
        home / "mode.yaml",
        {"patch": [{"op": "add", "path": "/sandbox", "value": {"mode": "firejail"}}]},
    )


@pytest.mark.parametrize("route", _ROUTES)
def test_control_an_operator_base_patch_sets_the_mode(tmp_path, monkeypatch, route):
    """Premise for the next cell: with no in-tree base, the operator's patched
    base gives firejail in every voice."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = _patch_mode_file(_operator_home(tmp_path, route))
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [mode_file.as_posix()]},
    )
    route_kind = "config_file" if route == "config_file" else "ash_config"
    _route_setup(tmp_path, monkeypatch, route_kind, root)
    _assert_kept(*_voices(tmp_path, src, route_kind, root), "firejail")


@pytest.mark.parametrize("route", _ROUTES)
def test_an_in_tree_base_cannot_lower_a_mode_the_operator_set_by_patch(
    tmp_path, monkeypatch, route
):
    """The operator's base sets firejail through its own patch; a base in the
    scanned checkout, later in the root's extends, writes off. A walk that
    reads only each owned file's direct ``sandbox.mode`` key sees no owned
    write and falls back to the merged off."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = _patch_mode_file(_operator_home(tmp_path, route))
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [mode_file.as_posix(), lower.as_posix()]},
    )
    route_kind = "config_file" if route == "config_file" else "ash_config"
    _route_setup(tmp_path, monkeypatch, route_kind, root)
    _assert_kept(*_voices(tmp_path, src, route_kind, root), "firejail")


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
@pytest.mark.parametrize("tree_mode", ["off", "bwrap"])
def test_an_operator_base_whose_own_patch_replaces_its_mode_keeps_the_patched_mode(
    tmp_path, monkeypatch, route, tree_mode
):
    """The operator's base writes mode off and its own patch replaces it with
    firejail, so the base resolves to firejail; a base in the scanned
    checkout, later in the root's extends, writes off or bwrap. A walk that
    reads the base's pre-patch key answers off, and the floor then disagrees
    with the local scan."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = _write(
        tmp_path / "plain" / "mode.yaml",
        {
            "sandbox": {"mode": "off"},
            "patch": [{"op": "replace", "path": "/sandbox/mode", "value": "firejail"}],
        },
    )
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": tree_mode}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [mode_file.as_posix(), lower.as_posix()]},
    )
    _route_setup(tmp_path, monkeypatch, route, root)
    _assert_kept(*_voices(tmp_path, src, route, root), "firejail")


@pytest.mark.parametrize("route", _ROUTES)
def test_control_a_root_patch_after_the_in_tree_base_holds(
    tmp_path, monkeypatch, route
):
    """The root's own patch applies after its bases merge, so it keeps
    firejail."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [lower.as_posix()],
            "patch": [{"op": "replace", "path": "/sandbox/mode", "value": "firejail"}],
        },
    )
    route_kind = "config_file" if route == "config_file" else "ash_config"
    _route_setup(tmp_path, monkeypatch, route_kind, root)
    _assert_kept(*_voices(tmp_path, src, route_kind, root), "firejail")


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
def test_the_operators_last_own_write_answers(tmp_path, monkeypatch, route):
    """Two operator bases (firejail, then bwrap) and a lowering in-tree base:
    the operator's own merge answers bwrap."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    first = _write(tmp_path / "plain" / "a.yaml", {"sandbox": {"mode": "firejail"}})
    second = _write(tmp_path / "plain" / "b.yaml", {"sandbox": {"mode": "bwrap"}})
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [first.as_posix(), second.as_posix(), lower.as_posix()],
        },
    )
    _route_setup(tmp_path, monkeypatch, route, root)
    _assert_kept(*_voices(tmp_path, src, route, root), "bwrap")


@pytest.mark.parametrize("route", ["ash_config", "config_file"])
def test_with_no_scanned_tree_a_checkout_base_cannot_lower_the_operators_mode(
    tmp_path, monkeypatch, route
):
    """A load that knows no tree is scanned: the any-checkout rule makes a
    base inside any checkout the repository's, so it cannot lower the mode
    the operator's base outside every checkout set."""
    co = tmp_path / "co"
    mark_git_checkout(co)
    mode_file = _write(
        tmp_path / "plain" / "mode.yaml", {"sandbox": {"mode": "firejail"}}
    )
    lower = _write(co / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [mode_file.as_posix(), lower.as_posix()]},
    )
    if route == "config_file":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        config = resolve_config(
            config_path=str(root),
            trusted_config_path=str(root),
            scanned_root=None,
            no_scanned_tree=True,
        )
    else:
        monkeypatch.setenv("ASH_CONFIG", str(root))
        config = resolve_config(scanned_root=None, no_scanned_tree=True)
    assert config.sandbox.mode == "firejail", config.sandbox.mode


@pytest.mark.parametrize("lowered", [False, True], ids=["control", "lowered"])
def test_the_floor_when_ash_config_does_not_load(tmp_path, monkeypatch, lowered):
    """The container floor's except arm (ASH_CONFIG names a file that does not
    validate) with the operator's --config. The control shows the arm is
    reached and gives the operator's mode; the lowered chain must give the
    same, not the merged mode an in-tree base wrote."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = _write(
        tmp_path / "plain" / "mode.yaml", {"sandbox": {"mode": "firejail"}}
    )
    bases = [mode_file.as_posix()]
    if lowered:
        bases.append(
            _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}}).as_posix()
        )
    root = _write(
        tmp_path / "ash-root.yaml", {"project_name": "floor", "extends": bases}
    )
    broken = _write(tmp_path / "broken" / "ash.yaml", {"sandbox": {"mode": 5}})
    monkeypatch.setenv("ASH_CONFIG", str(broken))
    monkeypatch.chdir(src)
    try:
        get_default_config()
    except _REFUSED + (OSError, ValueError):
        pass
    else:
        raise RuntimeError(
            "the broken ASH_CONFIG loaded, so the except arm is not reached"
        )
    opts = run_ash_scan.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        config=str(root),
        trusted_config_path=str(root),
    )
    assert run_ash_scan._sandbox_mode_without_the_config(opts) == ["firejail"]


def _junk_mode_chain(tmp_path, mode_document, lower_mode="off"):
    """An operator-owned base writing *mode_document* and an in-tree base
    writing *lower_mode* after it, under a root that writes nothing."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = _write(tmp_path / "plain" / "mode.yaml", mode_document)
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": lower_mode}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [mode_file.as_posix(), lower.as_posix()]},
    )
    return src, root


@pytest.mark.parametrize(
    "mode_document",
    [
        pytest.param({"sandbox": {"mode": "banana"}}, id="key-string"),
        pytest.param({"sandbox": {"mode": 5}}, id="key-non-string"),
        pytest.param(
            {
                "sandbox": {"mode": "bwrap"},
                "patch": [{"op": "replace", "path": "/sandbox/mode", "value": "melon"}],
            },
            id="own-patch",
        ),
    ],
)
def test_an_owned_write_outside_the_known_modes_refuses_the_load(
    tmp_path, monkeypatch, mode_document
):
    """The operator's base writes a mode the configuration model does not
    accept, and a base in the scanned checkout writes off after it, so the
    merged chain validates with the operator's write erased. Resolving on
    would run the scan with no sandbox although the operator's own file
    tried to set one, and the floor can never request an unknown mode of
    the container, so the load is refused whatever later files write --
    through the key and through the file's own patch alike. The container
    floor reads no mode from such a chain; the scan in the container
    refuses the same load with its own exit code."""
    src, root = _junk_mode_chain(tmp_path, mode_document)
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    with pytest.raises(ASHConfigValidationError):
        resolve_config(source_dir=src)
    assert _floor(tmp_path, src) == ["off"]


def test_an_owned_junk_mode_refuses_whatever_the_merged_mode_is(tmp_path, monkeypatch):
    """The control for the refusal's reach: the in-tree base after the junk
    write sets firejail, so the merged chain resolves to a mode that is on.
    The refusal must not hide behind the floor's off gate -- the operator's
    own write is outside the modes whatever the chain merges to."""
    src, root = _junk_mode_chain(
        tmp_path, {"sandbox": {"mode": "banana"}}, lower_mode="firejail"
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    with pytest.raises(ASHConfigValidationError):
        resolve_config(source_dir=src)


def test_the_junk_mode_refusal_names_the_file_and_not_the_value(tmp_path, monkeypatch):
    """The refusal names the file that wrote the mode, never the written
    value: a mode written as an environment reference arrives as whatever
    the variable holds, which is not the message's to show."""
    written = "a-value-the-refusal-must-not-print"
    src, root = _junk_mode_chain(tmp_path, {"sandbox": {"mode": written}})
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    with pytest.raises(ASHConfigValidationError) as refused:
        resolve_config(source_dir=src)
    message = str(refused.value)
    assert (tmp_path / "plain" / "mode.yaml").as_posix() in message, message
    assert written not in message, message


@pytest.mark.parametrize("route", _ROUTES)
def test_a_wholly_owned_chains_buried_junk_mode_refuses_the_load(
    tmp_path, monkeypatch, route
):
    """No file of the chain is in the scanned checkout, and the operator's
    own later base buries the junk write under bwrap, so the merged chain
    validates and the load skips the confinement steps. The walk that
    refuses an owned write outside the known modes runs on that path too:
    resolving on would keep a chain the same walk refuses the moment a
    repository file joins it, so whether the operator's junk write is caught
    would turn on the repository's files instead of the operator's own. The
    container floor reads no mode from such a chain."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    home = _operator_home(tmp_path, route)
    junk = _write(home / "mode.yaml", {"sandbox": {"mode": "banana"}})
    bury = _write(home / "bury.yaml", {"sandbox": {"mode": "bwrap"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [junk.as_posix(), bury.as_posix()]},
    )
    route_kind = "config_file" if route == "config_file" else "ash_config"
    _route_setup(tmp_path, monkeypatch, route_kind, root)
    if route_kind == "config_file":
        with pytest.raises(ASHConfigValidationError):
            resolve_config(config_path=root, source_dir=src, trusted_config_path=root)
        floor = _floor(tmp_path, src, trusted_config_path=str(root))
    else:
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=src)
        floor = _floor(tmp_path, src)
    assert floor == ["off"], floor


@pytest.mark.parametrize("route", _ROUTES)
def test_control_a_wholly_owned_chain_of_known_modes_loads(
    tmp_path, monkeypatch, route
):
    """The same wholly-owned shape with every write inside the known set
    loads and keeps the operator's last own write, so the refusal above is
    the junk write's, never the path's."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    home = _operator_home(tmp_path, route)
    first = _write(home / "mode.yaml", {"sandbox": {"mode": "firejail"}})
    last = _write(home / "bury.yaml", {"sandbox": {"mode": "bwrap"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {"project_name": "floor", "extends": [first.as_posix(), last.as_posix()]},
    )
    route_kind = "config_file" if route == "config_file" else "ash_config"
    _route_setup(tmp_path, monkeypatch, route_kind, root)
    _assert_kept(*_voices(tmp_path, src, route_kind, root), "bwrap")


def test_an_in_tree_member_keeps_the_buried_junk_refusal(tmp_path, monkeypatch):
    """The boundary's other side: the same buried junk with a repository
    file in the chain refuses the same way, through the confinement path,
    so the two paths cannot answer differently on one operator write."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    junk = _write(tmp_path / "plain" / "mode.yaml", {"sandbox": {"mode": "banana"}})
    bury = _write(tmp_path / "plain" / "bury.yaml", {"sandbox": {"mode": "bwrap"}})
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [junk.as_posix(), bury.as_posix(), lower.as_posix()],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    with pytest.raises(ASHConfigValidationError):
        resolve_config(source_dir=src)


def test_the_roots_patch_outranks_an_owned_bases_off_on_a_mixed_chain(
    tmp_path, monkeypatch
):
    """An owned base writes off, a base in the scanned checkout writes a mode
    of its own, and the root's own patch sets firejail: the root's patch is
    the operator's last own write, so every voice keeps firejail. A walk
    reading only the raw keys answered the owned base's off and weakened the
    floor below the mode the operator's root set."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    lowered = _write(tmp_path / "plain" / "low.yaml", {"sandbox": {"mode": "off"}})
    mid = _write(src / "cfg" / "mid.yaml", {"sandbox": {"mode": "bwrap"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [lowered.as_posix(), mid.as_posix()],
            "patch": [{"op": "replace", "path": "/sandbox/mode", "value": "firejail"}],
        },
    )
    _route_setup(tmp_path, monkeypatch, "ash_config", root)
    _assert_kept(*_voices(tmp_path, src, "ash_config", root), "firejail")


def test_an_unbuildable_chain_on_the_floor_walk_leaves_a_record(tmp_path, caplog):
    """The floor's walk runs with the reporter view's warning off, so before
    this record a chain the walk could not rebuild kept the trusted base's
    mode in silence on paths where only the floor's walk runs. The walk gets
    a chain whose file has no read, the unbuildable shape, and must say so
    at debug level; the control chain, whose read is held, says nothing."""
    import logging

    from automated_security_helper.config.resolve_config import _owned_sandbox_mode

    root = tmp_path / "ash-root.yaml"
    with caplog.at_level(logging.DEBUG):
        mode = _owned_sandbox_mode([root], [], {}, frozenset())
    if mode is not None:
        raise RuntimeError(f"premise: the walk must answer None, got {mode}")
    said = [
        record.getMessage()
        for record in caplog.records
        if "could not be rebuilt" in record.getMessage()
    ]
    assert said, caplog.text
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        mode = _owned_sandbox_mode(
            [root],
            [],
            {root.resolve(): {"sandbox": {"mode": "firejail"}}},
            frozenset(),
        )
    if mode != "firejail":
        raise RuntimeError(f"premise: the control walk must answer, got {mode}")
    assert not any(
        "could not be rebuilt" in record.getMessage() for record in caplog.records
    ), caplog.text


def _assert_plain_str(*values) -> None:
    """A mode the floor walk reads from a file's own document can come from an
    environment reference, which the loader hands over as a str subclass that
    carries the variable's name (utils/redacted_model.EnvResolvedScalar). The
    walk's answer is assigned onto the trusted model without validation, so
    the downcast every validated field performs never runs here: the floor's
    answer must already be the plain str the model contract requires (a str
    subclass has no SafeDumper representer and prints its class name where a
    message names the mode)."""
    for value in values:
        assert type(value) is str, (type(value).__name__, value)


def test_a_floor_mode_read_from_an_environment_reference_is_a_plain_str(
    tmp_path, monkeypatch
):
    """The operator's own base sets the mode through a reference the loader
    resolves; an in-tree base writes off. The floor keeps the operator's
    mode, and the kept value is a plain str, not the loader's carrier type."""
    monkeypatch.setenv("ASH_FLOOR_MODE_PROBE", "firejail")
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = tmp_path / "plain" / "mode.yaml"
    mode_file.parent.mkdir(parents=True, exist_ok=True)
    # Written by hand: the reference must stay a plain (unquoted) scalar for
    # the loader's implicit resolver to read it from the environment.
    mode_file.write_text(
        "sandbox:\n  mode: ${ASH_FLOOR_MODE_PROBE:firejail}\n", encoding="utf-8"
    )
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [mode_file.as_posix(), lower.as_posix()],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    local = _local_mode(src)
    floor = _floor(tmp_path, src)
    if (local, floor) != ("firejail", ["firejail"]):
        raise RuntimeError(f"premise: the floor must answer, got {(local, floor)}")
    _assert_plain_str(local, *floor)


def test_a_floor_mode_a_patch_sets_from_a_reference_is_a_plain_str(
    tmp_path, monkeypatch
):
    """The same contract through the walk's other arm: the operator base sets
    its mode through its own patch, with a value the loader resolves from a
    reference."""
    monkeypatch.setenv("ASH_FLOOR_MODE_PROBE", "firejail")
    src = tmp_path / "src"
    mark_git_checkout(src)
    mode_file = tmp_path / "plain" / "mode.yaml"
    mode_file.parent.mkdir(parents=True, exist_ok=True)
    # The document carries the place its own patch replaces: an add at
    # /sandbox/mode without a sandbox mapping refuses the whole chain.
    mode_file.write_text(
        "sandbox:\n"
        "  mode: bwrap\n"
        "patch:\n"
        "- op: replace\n"
        "  path: /sandbox/mode\n"
        "  value: ${ASH_FLOOR_MODE_PROBE:firejail}\n",
        encoding="utf-8",
    )
    lower = _write(src / "cfg" / "lower.yaml", {"sandbox": {"mode": "off"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [mode_file.as_posix(), lower.as_posix()],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    local = _local_mode(src)
    floor = _floor(tmp_path, src)
    if (local, floor) != ("firejail", ["firejail"]):
        raise RuntimeError(f"premise: the floor must answer, got {(local, floor)}")
    _assert_plain_str(local, *floor)


def test_an_operators_own_patch_to_off_turns_the_floor_off(tmp_path, monkeypatch):
    """A chain wholly outside the scanned checkout whose base writes firejail
    and whose root's own patch replaces it with off: off is the operator's
    own last write, so the floor follows it. A walk reading only the raw
    keys answered the base's firejail and overrode the operator's patch."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    on_file = _write(tmp_path / "plain" / "on.yaml", {"sandbox": {"mode": "firejail"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "floor",
            "extends": [on_file.as_posix()],
            "patch": [{"op": "replace", "path": "/sandbox/mode", "value": "off"}],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)
    assert (_local_mode(src), _floor(tmp_path, src)) == ("off", ["off"])


def test_each_caller_of_the_trusted_base_states_which_fallback_it_means():
    """``merged_fallback`` flips what an unowned merged mode yields: the scan's
    own resolution applies it, the container floor refuses it. Two live
    meanings behind one bool are too much to leave to a default -- a caller
    that says nothing would silently take the floor's semantics whether or
    not it meant to -- so the parameter is keyword-only with no default and
    every call site names the semantics it wants.
    """
    import inspect

    from automated_security_helper.config.resolve_config import trusted_base_config

    parameter = inspect.signature(trusted_base_config).parameters["merged_fallback"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty
