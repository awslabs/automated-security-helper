# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An array op over the operator's own scalar: the view keeps the scalar.

The operator's own file writes an option as a scalar, a later patch op indexes
into that option, and the full document holds either the repository's list
(setup A) or the same scalar (setup S). The operator view is a trust filter:
an op that fits the full document but not the view is dropped from the view
alone, and the view keeps the operator's value -- never a wiped section. A
misfit in the FULL document is the operator file's own named refusal, naming
the patch entry rather than an implementation detail.
"""

import logging

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigSourceError
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

OPERATOR_REGION = "us-east-1"


def _section(config):
    return reporter_section(config, SecurityHubReporter) or {}


_OWN_SCALAR = {
    "a-string": ("tags: abc", "abc"),
    "bytes-from-a-binary-tag": ("tags: !!binary YWJj", b"abc"),
}

#: op, pointer past options/tags, value
_OPS = {
    "add-index": ("add", "/0", "v"),
    "add-dash": ("add", "/-", "v"),
    "replace-index": ("replace", "/0", "v"),
    "remove-index": ("remove", "/0", None),
}

#: Setup A: what the full document's list becomes.
_FULL_AFTER = {
    "add-index": ["v", "x", "y"],
    "add-dash": ["x", "y", "v"],
    "replace-index": ["v", "y"],
    "remove-index": ["y"],
}


def _patch_lines(op_name):
    op, tail, value = _OPS[op_name]
    lines = (
        "patch:\n"
        f"  - op: {op}\n"
        f"    path: /reporters/aws-security-hub/options/tags{tail}\n"
    )
    if value is not None:
        lines += f"    value: {value}\n"
    return lines


def _setup(tmp_path, scalar, op_name, repository_list):
    written, _value = _OWN_SCALAR[scalar]
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "reporters:\n  aws-security-hub:\n    options:\n      tags: [x, y]\n"
        if repository_list
        else "project_name: repository\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
        f"    options:\n      aws_region: {OPERATOR_REGION}\n      {written}\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends:\n  - {own.as_posix()}\n  - {repository.as_posix()}\n"
        + _patch_lines(op_name),
        encoding="utf-8",
    )
    return checkout, operator


@pytest.mark.parametrize("op_name", list(_OPS))
@pytest.mark.parametrize("scalar", list(_OWN_SCALAR))
def test_the_view_keeps_the_operator_s_scalar(tmp_path, monkeypatch, scalar, op_name):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, operator = _setup(tmp_path, scalar, op_name, repository_list=True)
    config = resolve_config(config_path=operator, source_dir=checkout)
    section = _section(config)
    options = section.get("options") or {}
    assert (section.get("enabled"), options.get("aws_region"), options.get("tags")) == (
        True,
        OPERATOR_REGION,
        _OWN_SCALAR[scalar][1],
    ), section


@pytest.mark.parametrize("op_name", list(_OPS))
@pytest.mark.parametrize("scalar", list(_OWN_SCALAR))
def test_the_full_document_applies_the_op_to_the_repository_s_list(
    tmp_path, monkeypatch, scalar, op_name
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, operator = _setup(tmp_path, scalar, op_name, repository_list=True)
    config = resolve_config(config_path=operator, source_dir=checkout)
    resolved = (
        config.get_plugin_config(plugin_type="reporter", plugin_name="aws-security-hub")
        or {}
    )
    assert (resolved.get("options") or {}).get("tags") == _FULL_AFTER[op_name], resolved


@pytest.mark.parametrize("op_name", list(_OPS))
@pytest.mark.parametrize("scalar", list(_OWN_SCALAR))
def test_the_one_warning_names_only_the_repository_s_file(
    tmp_path, monkeypatch, caplog, scalar, op_name
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, operator = _setup(tmp_path, scalar, op_name, repository_list=True)
    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        _section(config)
    ignoring = [
        record.getMessage()
        for record in caplog.records
        if "Ignoring reporters.aws-security-hub" in record.getMessage()
    ]
    assert len(ignoring) == 1 and all(
        "checkout" in line and "own.yaml" not in line and "operator.yaml" not in line
        for line in ignoring
    ), ignoring


def _corpus():
    """Every pointer under /reporters at every depth the view walk resolves,
    in "-"/"_" and case-variant spellings per section segment, crossed with
    add, replace and remove: the two resolvers below must take each to the
    same place. The case-variant section rides the plugin-section fold both
    walks share; a mid-path "-"/"_" respell (sub-map under an exact final
    key), a digit dict key, and the whole options mapping each pin a shape
    one resolver could take through a different branch than the other."""
    sections = ["aws_security_hub", "aws-security-hub", "Aws-Security-Hub"]
    options = ["some-list", "some_list"]
    deeps = ["deep-key", "deep_key"]
    pointers = []
    for sec in sections:
        pointers.append(f"/reporters/{sec}")
        pointers.append(f"/reporters/{sec}/enabled")
        pointers.append(f"/reporters/{sec}/options")
        for opt in options:
            base = f"/reporters/{sec}/options/{opt}"
            pointers.extend([base, f"{base}/0", f"{base}/1", f"{base}/-"])
        for deep in deeps:
            sub = f"/reporters/{sec}/options/sub_map/{deep}"
            pointers.extend([sub, f"{sub}/0", f"{sub}/-"])
        pointers.append(f"/reporters/{sec}/options/sub-map/plain")
        pointers.append(f"/reporters/{sec}/options/sub_map/5")
        pointers.append(f"/reporters/{sec}/options/missing-key/0")
    ops = []
    for pointer in pointers:
        for name in ("add", "replace", "remove"):
            op = {"op": name, "path": pointer}
            if name != "remove":
                op["value"] = "v"
            ops.append(op)
    for sec in sections:
        # A deeper key that happens to be named like the plugin segment: it is
        # a value's own mapping, so a case-variant child never folds on either
        # walk. Add and remove only -- a replace at a missing plain key is the
        # view's set-at-its-place against the document's refusal, a semantic
        # difference the misfit rule owns, not a spelling one.
        nested = f"/reporters/{sec}/options/reporters/Inner-Key"
        ops.append({"op": "add", "path": nested, "value": "v"})
        ops.append({"op": "remove", "path": nested})
    return ops


def _differential_view():
    return {
        "aws_security_hub": {
            "enabled": True,
            "options": {
                "some-list": ["x", "y"],
                "sub_map": {"deep-key": [1, 2], "plain": "s", "5": ["d1"]},
                "reporters": {"inner-key": "s2"},
            },
        }
    }


@pytest.mark.parametrize("op", _corpus(), ids=lambda op: f"{op['op']}:{op['path']}")
def test_the_view_walk_and_normalize_pointer_agree(op):
    """The differential pin over the pointer corpus: for every op, applying it
    through the view walk (_operator_patch_reporters) and through
    config_sources' own canonicalization (_normalize_pointer + jsonpatch on
    the same structure) must give the SAME structure, or both must drop --
    one side dropping while the other applies is exactly the drift class the
    two call sites can develop. settle here anchors on the view's own first
    spelling, as the resolve builds it from a chain whose first write
    anchored the fold."""
    import copy

    import jsonpatch

    from automated_security_helper.config.ash_config import section_fold_key
    from automated_security_helper.config.config_sources import (
        _normalize_pointer,
        deep_merge,
    )
    from automated_security_helper.config.resolve_config import (
        _operator_patch_reporters,
    )

    view = _differential_view()
    # The view walk's settle, mirrored with the production fold identity
    # (section_fold_key), so these helpers cannot drift from what the walk
    # folds.
    by_fold = {section_fold_key(key): key for key in view}

    def settled(key):
        target = by_fold.get(section_fold_key(key), key)
        by_fold.setdefault(section_fold_key(target), target)
        return target

    def folded(reporters):
        out = {}
        for key, section in reporters.items():
            target = settled(key) if isinstance(key, str) else key
            existing = out.get(target)
            out[target] = deep_merge(existing, section) if target in out else section
        return out

    via_view = _operator_patch_reporters(
        copy.deepcopy(view), [copy.deepcopy(op)], settled, folded
    )
    view_dropped = via_view == view

    document = {"reporters": copy.deepcopy(view)}
    try:
        normalized = dict(op, path=_normalize_pointer(document, op["path"]))
        via_canonical = jsonpatch.apply_patch(document, [normalized], in_place=False)[
            "reporters"
        ]
        canonical_dropped = False
    except (jsonpatch.JsonPatchException, jsonpatch.JsonPointerException, TypeError):
        via_canonical = view
        canonical_dropped = True

    assert view_dropped == canonical_dropped, (via_view, via_canonical)
    assert via_view == via_canonical, (via_view, via_canonical)


@pytest.mark.parametrize("op_name", ["add", "replace", "remove"])
def test_a_whole_reporters_op_agrees_after_the_fold(op_name):
    """The one pointer the corpus above cannot compare raw: an op at
    ``/reporters`` itself. The view folds the value's own section keys
    (fold_value), while the full document takes them as written and the
    plugin lookup folds at read time -- so the two sides are compared after
    one fold to canonical keys. A remove leaves the view ``{}`` and the full
    document without the key, the same empty mapping once read. Dict values
    only: the view maps a non-dict ``/reporters`` value to ``{}`` as its
    trust filter, a shape with no section for the fold to compare."""
    import copy

    import jsonpatch

    from automated_security_helper.config.ash_config import section_fold_key
    from automated_security_helper.config.config_sources import (
        _normalize_pointer,
        deep_merge,
    )
    from automated_security_helper.config.resolve_config import (
        _operator_patch_reporters,
    )

    op = {"op": op_name, "path": "/reporters"}
    if op_name != "remove":
        op["value"] = {"Aws-Security-Hub": {"enabled": True}}

    view = _differential_view()
    # The view walk's settle, mirrored with the production fold identity
    # (section_fold_key), so these helpers cannot drift from what the walk
    # folds.
    by_fold = {section_fold_key(key): key for key in view}

    def settled(key):
        target = by_fold.get(section_fold_key(key), key)
        by_fold.setdefault(section_fold_key(target), target)
        return target

    def folded(reporters):
        out = {}
        for key, section in reporters.items():
            target = settled(key) if isinstance(key, str) else key
            existing = out.get(target)
            out[target] = deep_merge(existing, section) if target in out else section
        return out

    via_view = _operator_patch_reporters(
        copy.deepcopy(view), [copy.deepcopy(op)], settled, folded
    )

    document = {"reporters": copy.deepcopy(view)}
    normalized = dict(op, path=_normalize_pointer(document, op["path"]))
    via_canonical = jsonpatch.apply_patch(document, [normalized], in_place=False).get(
        "reporters", {}
    )

    assert folded(via_view) == folded(via_canonical), (via_view, via_canonical)
    # The view's OWN keys already carry the settled spelling: comparing the
    # two sides only after folding both could not see the view skipping its
    # fold of the op's value (the raw key would fold away in the compare).
    if op_name == "remove":
        assert via_view == {}, via_view
    else:
        assert set(via_view) == {"aws_security_hub"}, via_view


@pytest.mark.parametrize("op_name", ["add-index", "remove-index"])
def test_the_full_document_names_the_entry_that_misfits(tmp_path, monkeypatch, op_name):
    """With the SAME scalar in the full document the patch refuses the load,
    and the refusal names the patch entry in the file's own words -- also
    where jsonpatch's misfit is a bare TypeError (a remove at an index of a
    string), which is an implementation detail no message should pass on."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, operator = _setup(tmp_path, "a-string", op_name, repository_list=False)
    with pytest.raises(ASHConfigSourceError) as caught:
        resolve_config(config_path=operator, source_dir=checkout)
    text = str(caught.value)
    assert "entry 0 in" in text and "TypeError" not in text, text


@pytest.mark.parametrize("op_name", ["remove-index", "add-index", "replace-index"])
def test_an_operator_only_scalar_under_a_removed_index_still_loads(
    tmp_path, monkeypatch, op_name
):
    """The confined-place misfit the docstring promises stays a stale-view
    fallback for every op alike: the repository's file writes an
    OPERATOR-ONLY option as a list (left out of the confined document, kept
    in the unconfined view), the operator's own file writes it as a scalar,
    and the root's op indexes into it. The op does not fit the confined
    document -- for a remove that misfit is jsonpatch's bare TypeError -- so
    it falls to the unconfined view and the file still loads, with the
    operator view keeping the operator's scalar; refusing the whole load on
    remove while add loads would split one misfit by op name."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "reporters:\n  aws-security-hub:\n    options:\n      findings_scope: [x, y]\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
        f"    options:\n      aws_region: {OPERATOR_REGION}\n"
        "      findings_scope: abc\n",
        encoding="utf-8",
    )
    op, tail, value = _OPS[op_name]
    lines = (
        "patch:\n"
        f"  - op: {op}\n"
        f"    path: /reporters/aws-security-hub/options/findings_scope{tail}\n"
    )
    if value is not None:
        lines += f"    value: {value}\n"
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends:\n  - {own.as_posix()}\n  - {repository.as_posix()}\n" + lines,
        encoding="utf-8",
    )

    config = resolve_config(config_path=operator, source_dir=checkout)

    options = _section(config).get("options") or {}
    assert options.get("findings_scope") == "abc", _section(config)


# The misfit rule across every chain that can carry a patch: the repository's
# base writes the operator-only findings_scope as a list (left out of the
# confined document), the operator's own file writes the scalar "abc", and
# the patch indexes into it. Every load answers, and no repository value
# reaches the confined document or the reporter view -- whichever chain
# carries the op: the operator's named root, the ASH_CONFIG chain (whose
# helper view reads tolerate the misfit the same way the load does), or the
# repository's own root.

import yaml as _yaml  # noqa: E402

_PLACE = "/reporters/aws-security-hub/options/findings_scope"
_TARGET = "/reporters/aws-security-hub/options/tags"
_REPOSITORY_VALUES = ("x", "y", ["x", "y"], ["y"], ["v", "x", "y"], ["x", "y", "v"])

_MISFIT_OPS = {
    "add-index": {"op": "add", "path": _PLACE + "/0", "value": "v"},
    "add-dash": {"op": "add", "path": _PLACE + "/-", "value": "v"},
    "replace-index": {"op": "replace", "path": _PLACE + "/0", "value": "v"},
    "remove-index": {"op": "remove", "path": _PLACE + "/0"},
    "test-index": {"op": "test", "path": _PLACE + "/0", "value": "x"},
}
_DISALLOWED_OPS = {
    "move-from-index": {"op": "move", "from": _PLACE + "/0", "path": _TARGET},
    "copy-from-index": {"op": "copy", "from": _PLACE + "/0", "path": _TARGET},
}
_CHAINS = ["operator", "ash-config", "repository"]


def _full_options(config):
    resolved = (
        config.get_plugin_config(plugin_type="reporter", plugin_name="aws-security-hub")
        or {}
    )
    return resolved.get("options") or {}


def _root_text(extends, op, project=None):
    document = {"extends": [p.as_posix() for p in extends], "patch": [op]}
    if project:
        document["project_name"] = project
    return _yaml.safe_dump(document, sort_keys=False)


def _misfit_load(tmp_path, monkeypatch, chain, op):
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    base = checkout / "cfg" / "repo-base.yaml"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(
        "reporters:\n  aws-security-hub:\n    options:\n      findings_scope: [x, y]\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
        f"    options:\n      aws_region: {OPERATOR_REGION}\n      findings_scope: abc\n",
        encoding="utf-8",
    )
    if chain == "operator":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        root = tmp_path / "operator.yaml"
        root.write_text(_root_text([own, base], op), encoding="utf-8")
        return resolve_config(config_path=root, source_dir=checkout)
    if chain == "ash-config":
        root = tmp_path / "operator.yaml"
        root.write_text(_root_text([own, base], op), encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(root))
        return resolve_config(source_dir=checkout)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root = checkout / ".ash" / ".ash.yaml"
    root.parent.mkdir(parents=True, exist_ok=True)
    root.write_text(_root_text([own, base], op, project="repo-root"), encoding="utf-8")
    return resolve_config(config_path=root, source_dir=tmp_path, scanned_root=checkout)


@pytest.mark.parametrize("op_name", list(_MISFIT_OPS))
@pytest.mark.parametrize("chain", _CHAINS)
def test_the_misfit_loads_and_no_repository_value_lands(
    tmp_path, monkeypatch, chain, op_name
):
    config = _misfit_load(tmp_path, monkeypatch, chain, _MISFIT_OPS[op_name])
    full = _full_options(config)
    view = _section(config).get("options") or {}
    for options in (full, view):
        assert options.get("findings_scope") not in _REPOSITORY_VALUES, (full, view)
        assert options.get("tags") not in _REPOSITORY_VALUES, (full, view)
    if chain == "operator":
        assert full.get("findings_scope") == "abc", full
        assert view.get("findings_scope") == "abc", view
    elif chain == "ash-config":
        # The ASH_CONFIG chain IS the configuration when no config file is
        # selected, so its operator files feed the reporter view the same way
        # a selected chain's do: the view holds the operator's scalar too.
        assert full.get("findings_scope") == "abc", full
        assert view.get("findings_scope") == "abc", view


@pytest.mark.parametrize("op_name", list(_DISALLOWED_OPS))
@pytest.mark.parametrize("chain", _CHAINS)
def test_a_move_or_copy_is_refused_before_any_misfit_rule(
    tmp_path, monkeypatch, chain, op_name
):
    with pytest.raises(ASHConfigSourceError) as caught:
        _misfit_load(tmp_path, monkeypatch, chain, _DISALLOWED_OPS[op_name])
    assert "uses an op that is not one of the allowed ops" in str(caught.value), str(
        caught.value
    )


_REVERSE_OPS = {
    "add-index": ({"op": "add", "path": _PLACE + "/0", "value": "v"}, ["v", "a", "b"]),
    "replace-index": (
        {"op": "replace", "path": _PLACE + "/0", "value": "v"},
        ["v", "b"],
    ),
    "remove-index": ({"op": "remove", "path": _PLACE + "/0"}, ["b"]),
}


@pytest.mark.parametrize("chain", ["operator", "ash-config"])
@pytest.mark.parametrize("op_name", list(_REVERSE_OPS))
def test_the_document_takes_an_op_the_view_refuses(
    tmp_path, monkeypatch, chain, op_name
):
    """The reverse layout: the operator's own file writes findings_scope as a
    list, the repository's base as a string (left out). The op fits the
    confined document; the unconfined view refuses it (a remove indexing into
    a string is jsonpatch's TypeError, the misfit rule's second handler), so
    the view stops being followed and the load answers with the operator's
    list patched. The ASH_CONFIG chain answers too: its helper view reads run
    under a confine, so the same misfit never refuses them."""
    op, expected = _REVERSE_OPS[op_name]
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    base = checkout / "cfg" / "repo-base.yaml"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(
        "reporters:\n  aws-security-hub:\n    options:\n      findings_scope: xyz\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
        f"    options:\n      aws_region: {OPERATOR_REGION}\n"
        "      findings_scope: [a, b]\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    root.write_text(_root_text([own, base], op), encoding="utf-8")
    if chain == "operator":
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        config = resolve_config(config_path=root, source_dir=checkout)
        assert _full_options(config).get("findings_scope") == expected, _full_options(
            config
        )
    else:
        monkeypatch.setenv("ASH_CONFIG", str(root))
        config = resolve_config(source_dir=checkout)
        # The load answering is the claim; the value then settles away,
        # never to the repository's string.
        assert _full_options(config).get("findings_scope") != "xyz", _full_options(
            config
        )


def test_an_ambiguous_section_spelling_stays_as_typed():
    """A merged document can hold two case-variant keys of an UNDECLARED
    section (deep_merge joins only "-"/"_" twins). The pointer fold then has
    no one key to land on: picking one by insertion order would put the op on
    a key the plugin does not read while the override resolver refuses the
    same spelling as ambiguous. The segment stays as typed; a single match
    still folds."""
    from automated_security_helper.config.config_sources import _normalize_pointer

    document = {
        "reporters": {
            "MyRep-X": {"enabled": True},
            "myrep_x": {"enabled": False},
            "other-rep": {"enabled": True},
        }
    }
    ambiguous = _normalize_pointer(document, "/reporters/MYREP-X/enabled")
    assert ambiguous == "/reporters/MYREP-X/enabled", ambiguous
    single = _normalize_pointer(document, "/reporters/Other-Rep/enabled")
    assert single == "/reporters/other-rep/enabled", single


def test_a_repository_twin_does_not_split_the_two_walks():
    """The operator-vs-repository differential beside a twin: the document
    holds the operator's key AND a case-variant twin only the repository's
    files wrote, which the operator view never holds. With the ownership the
    chain read builds passed into the pointer fold (``owned``), the document
    walk gives the view walk's answer: the operator's third spelling folds
    onto the operator's key -- the twin neither makes it ambiguous (the
    exactly-one match counts owned keys alone) nor captures it -- and the
    twin's own section is untouched. The ownership compare accepts an owned
    spelling and its uniform "-"/"_" swap, deep_merge's own join rule --
    deliberately not separator-blind (``_spelled_by_an_owned_write``), and a
    swap counts only while the owned spelling is not itself a document
    key."""
    import copy

    import jsonpatch

    from automated_security_helper.config.ash_config import section_fold_key
    from automated_security_helper.config.config_sources import (
        _normalize_pointer,
        deep_merge,
    )
    from automated_security_helper.config.resolve_config import (
        _operator_patch_reporters,
    )

    view = {"aws_security_hub": {"enabled": True, "options": {"aws_region": "op"}}}
    document = {
        "reporters": {
            **copy.deepcopy(view),
            "AWS-Security-Hub": {"enabled": False, "options": {"aws_region": "repo"}},
        }
    }
    owned = {"reporters": {"aws_security_hub"}}
    op = {"op": "replace", "path": "/reporters/AWSSECURITYHUB/enabled", "value": False}

    by_fold = {section_fold_key(key): key for key in view}

    def settled(key):
        target = by_fold.get(section_fold_key(key), key)
        by_fold.setdefault(section_fold_key(target), target)
        return target

    def folded(reporters):
        out = {}
        for key, section in reporters.items():
            target = settled(key) if isinstance(key, str) else key
            existing = out.get(target)
            out[target] = deep_merge(existing, section) if target in out else section
        return out

    via_view = _operator_patch_reporters(
        copy.deepcopy(view), [copy.deepcopy(op)], settled, folded
    )
    assert via_view["aws_security_hub"]["enabled"] is False, via_view

    normalized = dict(op, path=_normalize_pointer(document, op["path"], owned))
    assert normalized["path"] == "/reporters/aws_security_hub/enabled", normalized
    via_canonical = jsonpatch.apply_patch(document, [normalized], in_place=False)[
        "reporters"
    ]
    assert via_canonical["aws_security_hub"] == via_view["aws_security_hub"], (
        via_view,
        via_canonical,
    )
    assert via_canonical["AWS-Security-Hub"] == {
        "enabled": False,
        "options": {"aws_region": "repo"},
    }, via_canonical
    # A twin only the repository wrote cannot capture the pointer either:
    # with no owned key under reporters, the spelling stays as typed, exactly
    # as it does over a document holding no such section at all.
    uncaptured = _normalize_pointer(document, op["path"], {"reporters": set()})
    assert uncaptured == op["path"], uncaptured


def test_a_split_type_word_key_anchors_itself_in_the_view(tmp_path):
    """An owned file's section whose spelling folds by name onto a trusted
    section but names a different plugin (a split type word) keeps its OWN
    key in the view instead of folding onto the trusted spelling: the two
    are different fold identities, and folding them would hand the trusted
    section values that the plugin lookup never reads under the written
    spelling. The trusted section itself is untouched."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import (
        _with_operator_chain_reporters,
    )

    trusted = AshConfig.model_validate(
        {
            "reporters": {
                "bedrock-summary-reporter": {"options": {"aws_region": "us-east-1"}}
            }
        }
    )
    own = tmp_path / "own.yaml"
    own.write_text("placeholder: 1\n", encoding="utf-8")
    reads = {
        own.resolve(): {
            "reporters": {
                "Bedrock-Summary-Repo_rter": {"options": {"aws_region": "us-west-2"}}
            }
        }
    }

    view = _with_operator_chain_reporters(trusted, [own], [], reads, frozenset())

    dumped = view.model_dump().get("reporters") or {}
    assert "Bedrock-Summary-Repo_rter" in dumped, sorted(dumped)
    held = dumped.get("bedrock-summary-reporter") or {}
    assert (held.get("options") or {}).get("aws_region") == "us-east-1", held
