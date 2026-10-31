# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``sandbox.environment``: the list of variables every sandboxed scanner is passed.

* The default is the sandbox policy's own default list, and a compose-style list is
  accepted as written.
* An entry the sandbox refuses (a credential-shaped name, ``TMPDIR``) is refused at
  validation with the variable named and no value shown.
* The setting is a grant, trust-gated like ``extra_read_paths``: a config file the
  scanned repository could have written cannot change it (the trusted list stands
  and the file is named in the warning), a delivered config may only restate entries
  the server has, and a file's own ``patch`` keeps the entries that both lists name.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.config.resolve_config import _own_grants_after_patch
from automated_security_helper.config.sandbox_grants import confine_sandbox_grants
from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.sandbox.policy import (
    CA_BUNDLE_ENV_NAMES,
    DEFAULT_ENVIRONMENT,
    PROXY_ENV_NAMES,
)

pytestmark = pytest.mark.unit


def test_the_default_list_is_the_policys_default_list():
    assert tuple(SandboxConfig().environment) == DEFAULT_ENVIRONMENT


def test_a_compose_style_list_is_accepted_as_written():
    listed = ["MY_VAR", "OTHER=1", "MY_VAR=2"]

    assert SandboxConfig(environment=listed).environment == listed


def test_an_empty_list_is_accepted_and_replaces_the_default():
    assert SandboxConfig(environment=[]).environment == []


@pytest.mark.parametrize(
    "entry, name",
    [
        ("GITHUB_TOKEN", "GITHUB_TOKEN"),
        ("DB_PASSWORD=hunter2", "DB_PASSWORD"),
        ("TMPDIR=/somewhere", "TMPDIR"),
        (OUTER_RUN_ID_ENV, OUTER_RUN_ID_ENV),
        ("A B=hunter2", "A B"),
    ],
)
def test_a_refused_entry_is_named_and_its_value_is_not_shown(entry, name):
    with pytest.raises(ValidationError) as refused:
        SandboxConfig(environment=["MY_VAR", entry])

    assert name in str(refused.value)
    assert "hunter2" not in str(refused.value)


@pytest.mark.parametrize("shape", ["MY_VAR", {"MY_VAR": "1"}])
def test_a_string_or_a_mapping_is_not_a_list(shape):
    with pytest.raises(ValidationError):
        SandboxConfig(environment=shape)


def _confine(resolved: AshConfig, trusted: AshConfig) -> None:
    confine_sandbox_grants(
        resolved.sandbox,
        trusted.sandbox,
        [Path("/zz-repository/.ash/.ash.yaml")],
        frozenset(),
        checkout_membership=True,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )


def test_a_repositorys_environment_list_is_replaced_by_the_trusted_one(caplog):
    """A NAME=value entry sets a variable in every sandboxed scanner, so a config
    file in the scanned repository must not be able to write one (LD_PRELOAD)."""
    resolved = AshConfig()
    resolved.sandbox.environment = ["LD_PRELOAD=/zz-repository/evil.so"]
    trusted = AshConfig()
    trusted.sandbox.environment = ["MY_PROXY_VAR"]

    with caplog.at_level(logging.WARNING):
        _confine(resolved, trusted)

    assert resolved.sandbox.environment == ["MY_PROXY_VAR"]
    ignored = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring sandbox.")
    ]
    assert any("sandbox.environment" in line for line in ignored), caplog.text
    assert "LD_PRELOAD" not in caplog.text


def test_control_a_list_equal_to_the_trusted_one_is_not_ignored(caplog):
    resolved = AshConfig()
    trusted = AshConfig()
    assert resolved.sandbox.environment == trusted.sandbox.environment

    with caplog.at_level(logging.WARNING):
        _confine(resolved, trusted)

    assert not [r for r in caplog.records if "sandbox.environment" in r.getMessage()]


def test_a_patch_that_rewrites_the_list_keeps_the_entries_both_lists_name():
    own = {"environment": ["A", "B=1"]}
    operations = [
        {"op": "replace", "path": "/sandbox/environment", "value": ["A", "C"]}
    ]

    limits = _own_grants_after_patch(own, operations)

    assert own["environment"] == ["A"]
    assert limits == {}


def test_a_patch_that_removes_the_list_leaves_the_trusted_list_standing():
    own = {"environment": ["A"]}

    _own_grants_after_patch(own, [{"op": "remove", "path": "/sandbox/environment"}])

    assert "environment" not in own


def test_a_list_only_the_patch_writes_is_a_limit_not_the_files_setting():
    own = {"mode": "bwrap"}
    operations = [{"op": "add", "path": "/sandbox/environment", "value": ["A"]}]

    limits = _own_grants_after_patch(own, operations)

    assert "environment" not in own
    assert limits == {"environment": ["A"]}


def _refusals(document: dict, rules: ccp.ClientConfigRules, tmp_path: Path) -> list:
    found = ccp.client_file_denials(
        {tmp_path / "delivered.yaml": document},
        rules,
        scanned_root=tmp_path,
        all_delivered=True,
    )
    return [(denial.key, denial.reason) for _, denials in found for denial in denials]


def test_a_delivered_entry_the_server_lacks_is_refused_by_variable_only(tmp_path):
    rules = ccp.rules_from(AshConfig())
    document = {"sandbox": {"environment": ["HTTP_PROXY", "LD_PRELOAD=/tmp/x.so"]}}

    refusals = _refusals(document, rules, tmp_path)

    assert [key for key, _ in refusals] == ["sandbox.environment"], refusals
    reason = refusals[0][1]
    assert "LD_PRELOAD" in reason
    assert "/tmp/x.so" not in reason
    assert "HTTP_PROXY" not in reason


def test_control_a_delivered_list_of_entries_the_server_has_is_not_refused(tmp_path):
    rules = ccp.rules_from(AshConfig())

    assert (
        _refusals({"sandbox": {"environment": ["HTTP_PROXY"]}}, rules, tmp_path) == []
    )


def test_the_scanner_reference_names_the_configurable_variables_apart():
    """The names every scanner gets exclude the ones ``sandbox.environment`` decides;
    those are named as its default, so the page stays true when a list omits them."""
    scripts = Path(__file__).resolve().parents[3] / "scripts"
    sys.path.insert(0, str(scripts))
    try:
        import generate_scanner_reference
    finally:
        sys.path.remove(str(scripts))

    text = "\n".join(generate_scanner_reference._baseline_environment())

    always = text.split("Every sandboxed scanner gets these names: ")[1].split(
        "; and names starting with"
    )[0]
    assert "`PATH`" in always
    configurable = (*CA_BUNDLE_ENV_NAMES, *sorted(PROXY_ENV_NAMES))
    for name in configurable:
        assert f"`{name}`" not in always, name
        assert f"`{name}`" in text, name
    assert "are the default of `sandbox.environment`" in text
