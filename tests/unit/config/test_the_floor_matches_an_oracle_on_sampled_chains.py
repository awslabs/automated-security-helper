# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox-mode floor matches an independent oracle over sampled chains.

Each cell builds one randomly generated extends chain -- a fixed seed, so
every run builds the same 84 chains: 60 mixed, plus 24 lowering chains
whose root writes nothing while an in-checkout base writes a mode beside
an operator-owned one, the shape that catches a floor reading the merged
chain -- of one to three bases plus the
operator's root, each file either operator-owned (outside the scanned
checkout, or in a dotfiles checkout of its own) or inside the scanned
checkout, and each writing the sandbox mode through any mix of a direct
``sandbox.mode`` key and its own ``patch`` operations (``/sandbox/mode``,
``/sandbox``, the whole document; add, replace, remove; valid, unknown and
non-string values, known modes in another case included; rewrites that drop
the mode). The chains also carry what the walk must pass over: ``test``
operations at the mode's place, writes beside the mode and pointers past
it.

The oracle is computed from the generator's own ground truth -- which files
it made operator-owned and what writes it put in each -- by restating the
contract: each owned base's effective mode is its direct key then its own
operations over its own document (an unset there clears only that base's
write), the last base carrying one answers, and the root is then walked over
that answer, where a remove or a modeless rewrite clears the whole chain's
mode, since the bases merge under the root before its patch applies. A chain
whose owned files write a value outside the known modes is asserted on the
refusal arm instead and never reaches this comparison. The oracle never
calls the production walk, reads no file and classifies no ownership, so the
two sides share no code path past the contract itself.

The floor (``_sandbox_mode_without_the_config``) must equal the oracle's
mode, or ``off`` when no owned file writes one, on the ``ASH_CONFIG``,
``--config`` and dotfiles routes. The resolution's own mode is pinned
beside it: the owned walk's mode where that walk turns the sandbox on,
and otherwise the whole chain's merged walk, since an in-tree file's mode
cannot turn off or replace a mode the operator's files set and applies
only when nothing else turns the sandbox on. Where the any-checkout oracle (ownership
judged with no scanned tree, so a dotfiles checkout is untrusted too) turns
the sandbox on, the ``no_scanned_tree`` resolution never answers off, and
where no untrusted file touches the sandbox section it answers exactly the
oracle's mode; chains whose any-checkout owned files write nothing leave
that arm unasserted, since the contract there is the fail-closed default,
not this oracle's subject.

Every generated chain merges to a valid document: operations are generated
against the state the file's own document guarantees at their application
point, and a chain that wrote a value outside the known modes anywhere ends
with a root operation rewriting the section to a known mode. So a chain
with no owned junk write loads, and a refusal on one that has such a write
is the walk's own, never model validation. On the matching arm a chain that
refuses to load raises RuntimeError (a premise, never the oracle's
verdict).
"""

import random

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from tests.utils.helpers import mark_git_checkout

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)

#: The modes the configuration model accepts, restated here on purpose: the
#: oracle must not read them off the model it checks.
_MODES = ("off", "auto", "bwrap", "firejail", "landlock", "sandbox-exec")
#: Values outside the known set. The case variants are deliberate: a known
#: mode in another case is not a known mode, and a walk that case-folded
#: would read one where the contract refuses it.
_UNKNOWN = ("melon", 7, "BWRAP", "Off")

_SAMPLES = 60
_LOWERING_SAMPLES = 24
_ROUTES = ("ash_config", "config_file", "dotfiles")


def _mode_value(rng, dirty):
    """A mode value to write: usually known, sometimes outside the set.

    ``dirty`` None means the caller wants known values only (the lowering
    group), so the chain needs no cleansing rewrite at its root."""
    if dirty is not None and rng.random() < 0.2:
        dirty.append(True)
        return rng.choice(_UNKNOWN)
    return rng.choice(_MODES)


def _file_spec(rng, dirty, allow_test=True):
    """One file's document: a direct ``sandbox`` section and its own ops.

    Operations are generated against the state the file's own document
    guarantees at their point -- the document merges before its operations
    apply, so a precondition met in the file's own effective state is met in
    the merged document whatever the other files wrote. Beside the writes,
    the sampled shapes carry what the walk must pass over: a ``test``
    operation at the mode's place (asserts, never writes; emitted with the
    file's own current mode so the chain still loads, and only where
    *allow_test* -- a root's patch applies to the merged document, whose
    mode other files decide), a write beside the mode
    (``/sandbox/network_scanners``) and a pointer past the mode's place
    (``/sandbox/extra_read_paths/0``)."""
    doc = {}
    section = rng.choice(("absent", "empty", "mode", "mode"))
    mode_value = None
    if section == "empty":
        doc["sandbox"] = {}
    elif section == "mode":
        mode_value = _mode_value(rng, dirty)
        doc["sandbox"] = {"mode": mode_value}
    has_sandbox = section != "absent"
    has_mode = section == "mode"
    ops = []
    for _ in range(rng.randint(0, 2)):
        kinds = ["add-sandbox"]
        if has_sandbox:
            kinds.extend(["add-mode", "sibling-grant", "deep-grant"])
        if has_mode:
            kinds.extend(["replace-mode", "remove-mode"])
            if allow_test and isinstance(mode_value, str) and mode_value in _MODES:
                kinds.append("test-mode")
        if rng.random() < 0.1:
            kinds = ["whole-doc"]
        kind = rng.choice(kinds)
        if kind == "add-sandbox":
            value = {"mode": _mode_value(rng, dirty)} if rng.random() < 0.75 else {}
            ops.append({"op": "add", "path": "/sandbox", "value": value})
            has_sandbox, has_mode = True, "mode" in value
            mode_value = value.get("mode")
        elif kind == "add-mode":
            mode_value = _mode_value(rng, dirty)
            ops.append({"op": "add", "path": "/sandbox/mode", "value": mode_value})
            has_mode = True
        elif kind == "sibling-grant":
            # A write beside the mode under the same section: never a mode.
            ops.append({"op": "add", "path": "/sandbox/network_scanners", "value": []})
        elif kind == "deep-grant":
            # A pointer past the mode's place: never a mode either.
            ops.append({"op": "add", "path": "/sandbox/extra_read_paths", "value": []})
            ops.append(
                {
                    "op": "add",
                    "path": "/sandbox/extra_read_paths/0",
                    "value": "/opt/sampled",
                }
            )
        elif kind == "test-mode":
            ops.append({"op": "test", "path": "/sandbox/mode", "value": mode_value})
        elif kind == "replace-mode":
            mode_value = _mode_value(rng, dirty)
            ops.append({"op": "replace", "path": "/sandbox/mode", "value": mode_value})
        elif kind == "remove-mode":
            ops.append({"op": "remove", "path": "/sandbox/mode"})
            has_mode = False
            mode_value = None
            break  # Nothing of this file's own may rely on the mode now.
        else:  # whole-doc
            value = {"project_name": "rewritten"}
            if rng.random() < 0.8:
                value["sandbox"] = (
                    {"mode": _mode_value(rng, dirty)} if rng.random() < 0.75 else {}
                )
            ops.append({"op": "add", "path": "", "value": value})
            sandbox = value.get("sandbox")
            has_sandbox = isinstance(sandbox, dict)
            has_mode = has_sandbox and "mode" in sandbox
            mode_value = sandbox.get("mode") if has_sandbox else None
            break  # The rewrite replaced the merged document wholesale.
    if ops:
        doc["patch"] = ops
    return doc


def _chain_spec(index):
    """(route, [(place, doc), ...bases], root doc). Fixed seed per sample."""
    rng = random.Random(f"floor-oracle-{index}")
    route = rng.choice(_ROUTES)
    dirty = []
    bases = []
    for _ in range(rng.randint(1, 3)):
        place = rng.choice(("owned", "owned", "in-tree"))
        bases.append((place, _file_spec(rng, dirty)))
    root = _file_spec(rng, dirty, allow_test=False)
    if dirty:
        root.setdefault("patch", []).append(
            {"op": "add", "path": "/sandbox", "value": {"mode": rng.choice(_MODES)}}
        )
    return route, bases, root


def _lowering_chain_spec(index):
    """A chain shaped to catch a floor that reads the merged chain: the root
    writes nothing of its own, at least one base is operator-owned and at
    least one sits in the scanned checkout and writes a mode, so whatever the
    in-checkout file wrote last is the merged answer while the oracle's is
    the owned files' alone. Known mode values only, so no cleansing rewrite
    hands the root the last word."""
    rng = random.Random(f"floor-oracle-lowering-{index}")
    route = rng.choice(_ROUTES)
    places = ["owned", "in-tree"]
    if rng.random() < 0.5:
        places.append(rng.choice(("owned", "in-tree")))
    rng.shuffle(places)
    bases = []
    for place in places:
        doc = _file_spec(rng, None)
        if place == "in-tree" and "sandbox" not in doc:
            doc["sandbox"] = {"mode": rng.choice(_MODES)}
        bases.append((place, doc))
    return route, bases, {}


def _walk_one(doc, mode=None):
    """One file's effective mode over *mode*, the state it patches.

    A BASE is walked from None: its patch reaches only its own document, so
    an unset or remove clears only this file's write, and the file then
    contributes nothing, never a clearing of a sibling file's mode, which
    the real merge keeps. The ROOT is walked from the owned bases' running
    answer, since its bases merge under it before its patch applies: a root
    remove or modeless rewrite of the place clears the whole chain's mode."""
    sandbox = doc.get("sandbox")
    if isinstance(sandbox, dict) and "mode" in sandbox:
        value = sandbox["mode"]
        if isinstance(value, str) and value in _MODES:
            mode = value
    for op in doc.get("patch", ()):
        # Only the writing operations reach the mode: a ``test`` asserts and
        # a ``move`` or ``copy`` is not read, so they set nothing here.
        if op["op"] not in ("add", "replace", "remove"):
            continue
        pointer = op["path"]
        segments = [] if pointer == "" else pointer[1:].split("/")
        if segments[:1] not in ([], ["sandbox"]) or len(segments) > 2:
            continue
        if len(segments) == 2 and segments[1] != "mode":
            continue
        if op["op"] == "remove":
            if segments:
                mode = None
            continue
        value = op.get("value")
        unset = dropped = False
        for key in ("sandbox", "mode")[len(segments) :]:
            if not isinstance(value, dict):
                dropped = True
                break
            if key not in value:
                unset = True
                break
            value = value[key]
        if dropped:
            continue
        if unset:
            mode = None
        elif isinstance(value, str) and value in _MODES:
            mode = value
    return mode


def _oracle(bases, root, owned_places):
    """Owned bases folded per file, then the root walked over the result."""
    mode = None
    for place, doc in bases:
        if place in owned_places:
            file_mode = _walk_one(doc)
            if file_mode is not None:
                mode = file_mode
    return _walk_one(root, mode)


def _writes_outside_the_modes(doc):
    """Whether the document writes a sandbox mode outside the known set,
    through its key or any of its own operations landing at the mode's
    place. The load refuses such a write in an operator-owned file,
    whatever later files write, so a chain whose owned files carry one is
    expected to refuse rather than to match the floor."""
    sandbox = doc.get("sandbox")
    if isinstance(sandbox, dict) and "mode" in sandbox:
        value = sandbox["mode"]
        if not (isinstance(value, str) and value in _MODES):
            return True
    for op in doc.get("patch", ()):
        # Mirror the walk's reach: only ``add`` and ``replace`` write a
        # value, so only they can write one outside the known set.
        if op["op"] not in ("add", "replace"):
            continue
        pointer = op["path"]
        segments = [] if pointer == "" else pointer[1:].split("/")
        if segments[:1] not in ([], ["sandbox"]) or len(segments) > 2:
            continue
        if len(segments) == 2 and segments[1] != "mode":
            continue
        value = op.get("value")
        landed = True
        for key in ("sandbox", "mode")[len(segments) :]:
            if not isinstance(value, dict) or key not in value:
                landed = False
                break
            value = value[key]
        if landed and not (isinstance(value, str) and value in _MODES):
            return True
    return False


def _touches_sandbox(doc):
    """Whether the document can reach the merged sandbox section at all."""
    if "sandbox" in doc:
        return True
    return any(
        op["path"] == "" or op["path"].startswith("/sandbox")
        for op in doc.get("patch", ())
    )


def _write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _floor(tmp_path, src, trusted_config_path=None, config=None):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    opts = run_ash_scan.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        config=config,
        trusted_config_path=trusted_config_path,
    )
    return run_ash_scan._sandbox_mode_without_the_config(opts)


def _cells():
    cells = [
        pytest.param("mixed", index, id=f"sample-{index:02d}")
        for index in range(_SAMPLES)
    ]
    cells.extend(
        pytest.param("lowering", index, id=f"lowering-{index:02d}")
        for index in range(_LOWERING_SAMPLES)
    )
    return cells


@pytest.mark.parametrize("kind,index", _cells())
def test_the_floor_matches_the_oracle_on_a_sampled_chain(
    tmp_path, monkeypatch, kind, index
):
    spec = _chain_spec if kind == "mixed" else _lowering_chain_spec
    route, bases, root_doc = spec(index)
    src = tmp_path / "src"
    mark_git_checkout(src)
    home = tmp_path / ("dotfiles" if route == "dotfiles" else "plain")
    if route == "dotfiles":
        mark_git_checkout(home)
    base_paths = []
    for position, (place, doc) in enumerate(bases):
        parent = home if place == "owned" else src / "cfg"
        base_paths.append(_write(parent / f"base-{position}.yaml", doc))
    root_doc = dict(root_doc)
    root_doc["project_name"] = "sampled"
    root_doc["extends"] = [path.as_posix() for path in base_paths]
    root = _write(tmp_path / "ash-root.yaml", root_doc)

    expected = _oracle(bases, root_doc, {"owned"}) or "off"

    # A chain whose operator-owned files (the root is always the operator's)
    # write a mode outside the known set refuses to load, whatever the rest
    # of the chain holds: with a repository file present the confinement
    # path's walk refuses it, and on a wholly operator-owned chain the
    # load's early return runs the same walk for the same refusal, so the
    # verdict on the operator's own write cannot turn on the repository's
    # files. The host-side floor probe fails closed to off either way: its
    # walk refuses the chain, so the probe reads no mode from it, and the
    # scan in the container reports its own load.
    owned_docs = [doc for place, doc in bases if place == "owned"]
    owned_docs.append(root_doc)
    if any(_writes_outside_the_modes(doc) for doc in owned_docs):
        if route == "config_file":
            monkeypatch.delenv("ASH_CONFIG", raising=False)
            monkeypatch.chdir(src)
            with pytest.raises(_REFUSED):
                resolve_config(
                    config_path=root, source_dir=src, trusted_config_path=root
                )
            floor = _floor(
                tmp_path, src, trusted_config_path=str(root), config=str(root)
            )
        else:
            monkeypatch.setenv("ASH_CONFIG", str(root))
            monkeypatch.chdir(src)
            with pytest.raises(_REFUSED):
                resolve_config(source_dir=src)
            floor = _floor(tmp_path, src)
        assert floor == ["off"], floor
        return

    if route == "config_file":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        monkeypatch.chdir(src)
        try:
            local = resolve_config(
                config_path=root, source_dir=src, trusted_config_path=root
            ).sandbox.mode
        except _REFUSED as exc:
            raise RuntimeError(f"premise: the chain must load; {exc}") from exc
        floor = _floor(tmp_path, src, trusted_config_path=str(root), config=str(root))
    else:
        monkeypatch.setenv("ASH_CONFIG", str(root))
        monkeypatch.chdir(src)
        try:
            local = resolve_config(source_dir=src).sandbox.mode
        except _REFUSED as exc:
            raise RuntimeError(f"premise: the chain must load; {exc}") from exc
        floor = _floor(tmp_path, src)

    assert floor == [expected], (floor, expected, local, route)

    # The resolution's own mode, pinned beside the floor: an in-tree file's
    # mode cannot turn off or replace a mode the operator's own files set,
    # and applies only when nothing else turns the sandbox on (the grants
    # contract's wording), so the local answer is the owned walk's mode
    # where that walk turns the sandbox on, and otherwise the whole chain's
    # merged walk. Without this arm a resolution that swapped which files
    # count as the operator's would change `local` and no cell would move.
    merged = _oracle(bases, root_doc, {"owned", "in-tree"})
    expected_local = expected if expected != "off" else (merged or "off")
    assert local == expected_local, (local, expected_local, floor, route)

    # The any-checkout arm: ownership judged with no scanned tree, so a
    # dotfiles checkout is the repository's side too. The resolution keeps
    # the merged mode -- a checkout file may raise it -- so this oracle pins
    # only what the grants contract fixes: a mode the operator's own files
    # turned on is never resolved off, and where no untrusted file touches
    # the sandbox section at all, the resolution is exactly the owned walk's
    # answer. Chains whose any-checkout owned files write nothing leave the
    # arm unasserted; the fail-closed default is not this oracle's subject.
    owned_any = {"owned"} if route != "dotfiles" else set()
    expected_any = _oracle(bases, root_doc, owned_any)
    if expected_any is None:
        return
    untrusted_touches = any(
        _touches_sandbox(doc) for place, doc in bases if place not in owned_any
    )
    if route == "config_file":
        resolved = resolve_config(
            config_path=str(root),
            trusted_config_path=str(root),
            scanned_root=None,
            no_scanned_tree=True,
        )
    else:
        resolved = resolve_config(scanned_root=None, no_scanned_tree=True)
    if expected_any != "off":
        assert resolved.sandbox.mode != "off", (expected_any, route)
    if not untrusted_touches:
        assert resolved.sandbox.mode == expected_any, (
            resolved.sandbox.mode,
            expected_any,
            route,
        )


def test_a_test_op_after_an_owned_mode_write_leaves_the_mode_standing(
    tmp_path, monkeypatch
):
    """A pinned shape the random samples can miss: in ONE owned file, a
    ``test`` operation at the mode's place FOLLOWS the operation that set
    the mode. A test asserts and writes nothing, so the walk's running
    answer must stand; a walk that treated an unread operation as clearing
    it would answer nothing for the file and the floor would fall to off.

    The chain carries an in-checkout base writing another mode on purpose:
    on a wholly owned chain the merged resolution is the floor and the
    walk's answer is discarded, so only a mixed chain makes the answer
    load-bearing -- and the in-tree mode doubles as the lowering control,
    since a floor reading the merged chain would answer it instead. The
    chain loads (the asserted precondition holds in the owned file's own
    patched document), so the resolution keeps the operator's mode too."""
    src = tmp_path / "src"
    mark_git_checkout(src)
    owned = _write(
        tmp_path / "plain" / "base.yaml",
        {
            "sandbox": {"mode": "off"},
            "patch": [
                {"op": "add", "path": "/sandbox/mode", "value": "bwrap"},
                {"op": "test", "path": "/sandbox/mode", "value": "bwrap"},
            ],
        },
    )
    in_tree = _write(src / "cfg" / "base.yaml", {"sandbox": {"mode": "landlock"}})
    root = _write(
        tmp_path / "ash-root.yaml",
        {
            "project_name": "pinned",
            "extends": [owned.as_posix(), in_tree.as_posix()],
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    monkeypatch.chdir(src)

    floor = _floor(tmp_path, src)
    local = resolve_config(source_dir=src).sandbox.mode

    assert (floor, local) == (["bwrap"], "bwrap"), (floor, local)
