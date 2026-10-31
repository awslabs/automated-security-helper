# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Four readings of ``config/client_config_policy.py``.

* ``_with_own_patch``, the per-op walk the restrict-only check reads a delivered
  file's ``patch`` through: a failed ``test`` op is skipped and the walk goes
  on to the ops after it, since the walk does not read the bases the file
  extends and a ``test`` that passes in the load can fail over its starting
  document; a ``test`` that passes is
  applied without error and the walk goes on to the ops after it; and the walk
  starts from the trusted base merged with the document's own fields, so a
  ``test`` of a value the document itself sets passes here as it passes in the
  load. The walk that marks which entries are the operator's reads the other
  way (``over_report=False``): it stops at the first op that fails, so an
  entry the load never applied is not counted as the operator's.
* ``trusted_default_config`` reads ``ASH_CONFIG`` once, through
  ``get_default_config`` and its ``views`` carry, and takes the built-in
  defaults when that chain names a file under the MCP workspace root. It judges
  the file ``ASH_CONFIG`` names before it loads it, so a delivered file that
  does not parse is never read, and takes the defaults too when the load
  reports no chain for a named file.
* ``_writes_plugin_default`` forgives a denial only where the trusted base has
  no value for the option. A plugin scanner's section is a plain dict, so the
  trusted base can spell the option ``ignore-file``; the lookup reads either
  spelling, as every other option lookup here does, so a delivered file writing
  the option's default is still denied where the trusted base set a value.
* The drop handling rebuilds the config without the denied fields and keeps
  everything its load recorded (the private attributes: the values its files
  read from the environment among them), as ``apply_config_overrides`` keeps
  them for its rebuild; a rebuild that kept only the resolution warnings
  printed and recorded the environment values the file read.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import yaml

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config import default_config
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_config_policy import (
    _with_own_patch,
    _writes_plugin_default,
    apply_client_config_rules,
    trusted_default_config,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


def test_a_patch_whose_sibling_op_fails_still_shows_the_op_that_applies():
    """One op of the delivered file's patch names a place the base lacks and
    does not apply; the op beside it writes a sandbox grant. The whole patch
    failed to apply over the base, so the walk used to see the unpatched
    document and never the grant; each op is now applied on its own."""
    document = {
        "patch": [
            {"op": "remove", "path": "/no/such/place/at/all"},
            {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/etc"]},
        ]
    }

    seen = _with_own_patch(document, AshConfig())

    assert seen.get("sandbox", {}).get("extra_read_paths") == ["/etc"], seen


def test_a_failed_test_op_does_not_hide_the_grant_after_it_in_the_per_op_walk():
    """A ``test`` op that fails over the walk's own starting document does not
    end the per-op walk: the walk goes on to the ops after it and reads the
    grant one of them writes. The walk starts from the trusted base plus the
    file's own keys, not from the bases the file extends, so a ``test`` that
    passes in the load can fail here; reading on from it over-reports, which
    refuses, where ending the walk would leave the grant unjudged."""
    document = {
        "patch": [
            {"op": "remove", "path": "/no/such/place/at/all"},
            {"op": "test", "path": "/project_name", "value": "not-the-base-name"},
            {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/etc"]},
        ]
    }

    seen = _with_own_patch(document, AshConfig())

    assert seen.get("sandbox", {}).get("extra_read_paths") == ["/etc"], seen


def test_a_test_op_of_an_extended_bases_value_does_not_hide_the_grant_after_it():
    """The shape of the load: the file extends a base that sets the tested
    path, the load merges that base before it applies the patch, so the
    ``test`` op passes there and the ``add`` after it applies. The walk does not
    read the extended base, the same ``test`` op fails over its starting
    document, and the ``add`` after it must still reach the walk's judgment."""
    document = {
        "extends": "bases/sets-the-project-name.yaml",
        "patch": [
            {"op": "test", "path": "/project_name", "value": "set-by-the-base"},
            {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/etc"]},
        ],
    }
    assert AshConfig().project_name != "set-by-the-base"

    seen = _with_own_patch(document, AshConfig())

    assert seen.get("sandbox", {}).get("extra_read_paths") == ["/etc"], seen


def test_a_passing_test_op_does_not_end_the_per_op_walk():
    """The control for the failed-test case: a ``test`` op that passes over the
    base applies without error, so the walk goes on and reads the grant written
    after it. A walk that ended at any ``test`` op, passing or failing, would
    let a delivered file hide a grant behind a test it knows passes."""
    document = {
        "patch": [
            {"op": "remove", "path": "/no/such/place/at/all"},
            {"op": "test", "path": "/project_name", "value": AshConfig().project_name},
            {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/etc"]},
        ],
    }

    seen = _with_own_patch(document, AshConfig())

    assert seen.get("sandbox", {}).get("extra_read_paths") == ["/etc"], seen


def test_the_strict_walk_stops_at_the_first_op_that_fails():
    """Marking which entries are the operator's reads the same walk with
    ``over_report=False``: it keeps the ops before a failed op and drops that op
    and every op after it, where the default walk reads on."""
    document = {
        "patch": [
            {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/first"]},
            {"op": "test", "path": "/project_name", "value": "not-the-base-name"},
            {"op": "add", "path": "/sandbox/extra_write_paths", "value": ["/after"]},
        ]
    }

    strict = _with_own_patch(document, AshConfig(), over_report=False)
    reading_on = _with_own_patch(document, AshConfig())

    assert strict.get("sandbox", {}).get("extra_read_paths") == ["/first"], strict
    assert "/after" not in strict.get("sandbox", {}).get("extra_write_paths", []), (
        strict
    )
    assert reading_on.get("sandbox", {}).get("extra_write_paths") == ["/after"], (
        reading_on
    )


def _suppression() -> dict:
    return {"path": "app.py", "reason": "a suppression under test"}


def _marks_after(tmp_path: Path, test_value: str) -> list:
    """``client_supplied`` of the one suppression a delivered file supplies,
    when an operator file's patch adds the same entry behind a ``test`` op."""
    config = AshConfig.model_validate(
        {"global_settings": {"suppressions": [_suppression()]}}
    )
    operator = tmp_path / "operator.yaml"
    delivered = tmp_path / "delivered.yaml"
    documents = {
        operator: {
            "patch": [
                {"op": "test", "path": "/project_name", "value": test_value},
                {
                    "op": "add",
                    "path": "/global_settings/suppressions/-",
                    "value": _suppression(),
                },
            ]
        },
        delivered: {"global_settings": {"suppressions": [_suppression()]}},
    }

    marked = ccp._mark_client_supplied(
        config, documents, AshConfig(), lambda path: path == delivered
    )

    return [s.client_supplied for s in marked.global_settings.suppressions]


def test_an_entry_behind_a_failed_test_op_is_marked_client_supplied(
    tmp_path: Path,
):
    """The operator's patch tests a value that does not hold, so the load never
    applies the entry it adds after the test. A delivered file that supplies
    the same entry is the client's and is marked."""
    assert _marks_after(tmp_path, "not-the-base-name") == [True]


def test_control_an_entry_behind_a_passing_test_op_is_the_operators(tmp_path: Path):
    assert _marks_after(tmp_path, AshConfig().project_name) == [False]


def test_a_test_op_of_the_documents_own_value_passes_as_the_load_applies_it():
    """The walk starts from the base merged with the document's own fields, as
    the load patches the merged chain: a ``test`` of a value the delivered
    document itself sets passes here as it passes in the load, so the grant
    after it is read rather than hidden behind a test that fails over the bare
    base."""
    document = {
        "project_name": "delivered-name",
        "patch": [
            {"op": "remove", "path": "/no/such/place/at/all"},
            {"op": "test", "path": "/project_name", "value": "delivered-name"},
            {"op": "add", "path": "/sandbox/extra_read_paths", "value": ["/etc"]},
        ],
    }

    seen = _with_own_patch(document, AshConfig())

    assert seen.get("sandbox", {}).get("extra_read_paths") == ["/etc"], seen


def test_the_trusted_default_config_is_read_once(tmp_path: Path, monkeypatch):
    """The chain the server trusts is judged from the files the load itself
    read (the ``views`` carry of the one ``get_default_config`` call), not from
    a second resolution of ASH_CONFIG that a file changed in between could make
    disagree with the configuration returned. The file is rewritten the moment
    the first read returns, so any second read of it, through
    ``get_default_config`` again or through the chain readers, shows."""
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(yaml.safe_dump({"project_name": "op"}), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)

    calls = []
    first_read = default_config.get_default_config

    def one_read(*args, **kwargs):
        config = first_read(*args, **kwargs)
        calls.append(sorted(kwargs))
        operator.write_text(
            yaml.safe_dump({"project_name": "changed"}), encoding="utf-8"
        )
        return config

    def second_read(*args, **kwargs):
        raise AssertionError("ASH_CONFIG was resolved a second time")

    monkeypatch.setattr(default_config, "get_default_config", one_read)
    for reader in (
        "default_config_document",
        "default_config_chain",
        "default_config_names",
        "default_config_documents",
    ):
        monkeypatch.setattr(default_config, reader, second_read)

    trusted = trusted_default_config()

    assert trusted.project_name == "op"
    assert len(calls) == 1 and "views" in calls[0], calls


def test_an_ash_config_a_client_delivered_is_not_the_trusted_config(
    tmp_path: Path, monkeypatch
):
    """ASH_CONFIG names a file under the MCP workspace root, a client's: the
    built-in defaults are the trusted config, not that file."""
    root = tmp_path / "ash-mcp"
    delivered = root / "session-a" / "source" / "ash.yaml"
    delivered.parent.mkdir(parents=True)
    delivered.write_text(yaml.safe_dump({"project_name": "client"}), encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("ASH_CONFIG", str(delivered))

    trusted = trusted_default_config()

    assert trusted.project_name != "client"
    assert trusted.project_name == AshConfig().project_name


def test_an_ash_config_a_client_delivered_is_judged_before_it_is_parsed(
    tmp_path: Path, monkeypatch
):
    """The file ASH_CONFIG names is under the MCP workspace root, a client's, and
    holds text that does not parse. The built-in defaults are the trusted config
    without the file being read: the load is never attempted, so the client's
    text cannot make the server's own config unloadable."""
    root = tmp_path / "ash-mcp"
    delivered = root / "session-a" / "source" / "ash.yaml"
    delivered.parent.mkdir(parents=True)
    delivered.write_text("project_name: [unclosed\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("ASH_CONFIG", str(delivered))
    loads = []
    real_read = default_config.get_default_config

    def counted_read(*args, **kwargs):
        loads.append(1)
        return real_read(*args, **kwargs)

    monkeypatch.setattr(default_config, "get_default_config", counted_read)
    warnings = []

    def recorded(message, *_args, **_kwargs):
        warnings.append(message)

    monkeypatch.setattr(ASH_LOGGER, "warning", recorded)

    trusted = trusted_default_config()

    assert loads == [], "the delivered ASH_CONFIG file was loaded"
    assert trusted.project_name == AshConfig().project_name
    assert len(warnings) == 1 and "client delivered" in warnings[0], warnings


def test_an_ash_config_the_operator_owns_that_does_not_parse_still_raises(
    tmp_path: Path, monkeypatch
):
    """The control for the delivered case: a file outside the MCP workspace root
    is the operator's, and one that does not parse is still refused by the
    load, as before."""
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text("project_name: [unclosed\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)

    with pytest.raises(ASHConfigValidationError):
        trusted_default_config()


def test_an_ash_config_whose_chain_the_load_did_not_report_is_not_trusted(
    tmp_path: Path, monkeypatch
):
    """ASH_CONFIG names a file, and the load hands back a config without the
    chain it read (``views`` left empty). Nothing was judged, so the built-in
    defaults are the trusted config, not what the load returned. The warning
    says what was established, that no chain was reported, and does not say a
    client delivered the file."""
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(yaml.safe_dump({"project_name": "op"}), encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    warnings = []

    def recorded(message, *_args, **_kwargs):
        warnings.append(message)

    monkeypatch.setattr(ASH_LOGGER, "warning", recorded)

    def unreported_read(*args, **kwargs):
        return AshConfig.model_validate({"project_name": "unjudged"})

    monkeypatch.setattr(default_config, "get_default_config", unreported_read)

    trusted = trusted_default_config()

    assert trusted.project_name == AshConfig().project_name
    assert len(warnings) == 1, warnings
    assert "no chain" in warnings[0], warnings
    assert "client delivered" not in warnings[0], warnings


def test_a_kebab_spelled_trusted_option_still_denies_the_delivered_default():
    base = AshConfig.model_validate(
        {"scanners": {"trivy-repo": {"options": {"ignore-file": "/ops/.trivyignore"}}}}
    )
    document = {"scanners": {"trivy-repo": {"options": {"ignore_file": None}}}}
    denial = SimpleNamespace(
        pointer="/scanners/trivy-repo/options/ignore_file", from_patch=False
    )

    assert _writes_plugin_default(document, denial, base) is False


def test_without_a_trusted_value_the_delivered_default_is_forgiven():
    base = AshConfig()
    document = {"scanners": {"trivy-repo": {"options": {"ignore_file": None}}}}
    denial = SimpleNamespace(
        pointer="/scanners/trivy-repo/options/ignore_file", from_patch=False
    )

    assert _writes_plugin_default(document, denial, base) is True


def test_a_dropped_config_keeps_what_its_load_recorded(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(ccp, "DENIED_FIELD_HANDLING", "drop")
    root = tmp_path / "ash-mcp"
    client = root / "session-a" / "source" / "ash.yaml"
    client.parent.mkdir(parents=True)
    client.write_text("", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    document = {"project_name": "c", "fail_on_findings": False}
    config = AshConfig.model_validate(document)
    config._environment_values = ["planted-environment-value"]

    dropped = apply_client_config_rules(
        config,
        {client: document},
        rules=None,
        trusted_config_path=None,
        source_dir=None,
        permit_base=None,
    )

    assert dropped.fail_on_findings is True
    assert "planted-environment-value" in dropped._environment_values
    assert len(dropped._resolution_warnings) == 1
