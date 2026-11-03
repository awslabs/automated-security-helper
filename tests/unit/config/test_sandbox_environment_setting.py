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
import yaml
from pydantic import ValidationError

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.resolve_config import (
    _own_grants_after_patch,
    _with_own_sandbox,
    apply_config_overrides,
    reset_dropped_own_sandbox_warnings,
)
from automated_security_helper.config.sandbox_grants import (
    confine_sandbox_grants,
    scanned_trees,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.sandbox.policy import (
    CA_BUNDLE_ENV_NAMES,
    DEFAULT_ENVIRONMENT,
    PROXY_ENV_NAMES,
)
from tests.utils.helpers import mark_git_checkout

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
        ("HTTPS_PROXY=http://user:hunter2@proxy:3128", "HTTPS_PROXY"),
    ],
)
def test_a_refused_entry_is_named_and_its_value_is_not_shown(entry, name):
    with pytest.raises(ValidationError) as refused:
        SandboxConfig(environment=["MY_VAR", entry])

    assert name in str(refused.value)
    assert "hunter2" not in str(refused.value)


@pytest.mark.parametrize(
    "entry",
    [
        "A B=MARKER-value",
        "MARKER-not-a-name=MARKER-value",
        "https://MARKER-user:MARKER-pw@MARKER-host/x?MARKER-key=MARKER-value",
        "MARKER+padded/ref==",
    ],
)
def test_an_entry_that_starts_with_no_name_is_named_by_position_in_the_error(entry):
    """The message of a validation error is shown wherever the config is read, and
    ``hide_input_in_errors`` does not cover message text: a value pasted without its
    name must not be in it."""
    with pytest.raises(ValidationError) as refused:
        SandboxConfig(environment=["MY_VAR", entry])

    text = str(refused.value)
    assert "number 2" in text
    assert entry.partition("=")[0] not in text
    assert "MARKER" not in text


@pytest.mark.parametrize("shape", ["MY_VAR", {"MY_VAR": "1"}])
def test_a_string_or_a_mapping_is_not_a_list(shape):
    with pytest.raises(ValidationError):
        SandboxConfig(environment=shape)


def test_the_documented_config_overrides_form_replaces_the_list():
    """``--config-overrides 'sandbox.environment=[HTTPS_PROXY,SSL_CERT_FILE,MY_VAR]'``
    is the one-run route the documentation gives; the list it writes replaces the
    default, as a list in a file does."""
    config = apply_config_overrides(
        get_default_config(),
        ["sandbox.environment=[HTTPS_PROXY,SSL_CERT_FILE,MY_VAR]"],
    )

    assert config.sandbox.environment == ["HTTPS_PROXY", "SSL_CERT_FILE", "MY_VAR"]


@pytest.mark.parametrize(
    "override, name",
    [
        ("sandbox.environment=[MY_VAR,GITHUB_TOKEN]", "GITHUB_TOKEN"),
        ('sandbox.environment=["DB_PASSWORD=MARKER-value"]', "DB_PASSWORD"),
    ],
)
def test_an_entry_the_sandbox_refuses_through_config_overrides_names_the_variable_only(
    override, name
):
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(get_default_config(), [override])

    text = f"{refused.value} {refused.value.validation_error}"
    assert name in text, text
    assert "MARKER" not in text, text


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


def _operators_file_ends_with(tmp_path, trusted, written, operations):
    """The sandbox ``_with_own_sandbox`` gives for an operator's file outside every
    checkout that writes *written* and then applies *operations*."""
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    root = tmp_path / "cfg" / "root.yaml"
    root.parent.mkdir(parents=True, exist_ok=True)
    document = {"sandbox": written, "patch": operations}
    root.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    merged, _wrote_mode = _with_own_sandbox(
        trusted, root, repo, [], scanned_trees(repo), None
    )
    return merged.sandbox


#: A patch that leaves the operator's own file with no ``environment`` list: it
#: removes the setting, or the section, or rewrites the section without it.
_LEAVES_NO_ENVIRONMENT = [
    pytest.param(
        {}, [{"op": "remove", "path": "/sandbox/environment"}], id="remove-the-list"
    ),
    pytest.param(
        {"mode": "bwrap"},
        [{"op": "remove", "path": "/sandbox"}],
        id="remove-the-section",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [
            {
                "op": "add",
                "path": "/sandbox",
                "value": {"mode": "auto", "extra_read_paths": ["/opt/a"]},
            }
        ],
        id="rewrite-the-section-without-it",
    ),
]


@pytest.mark.parametrize("written, operations", _LEAVES_NO_ENVIRONMENT)
def test_a_patch_that_leaves_no_environment_list_does_not_strip_the_default(
    tmp_path, written, operations
):
    """A missing ``environment`` is the model's default list (the proxy and CA
    names), not the empty list that a missing ``extra_read_paths`` is: reading it as
    empty would take HTTPS_PROXY and SSL_CERT_FILE from every scanner."""
    sandbox = _operators_file_ends_with(tmp_path, AshConfig(), written, operations)

    assert sandbox.environment == list(DEFAULT_ENVIRONMENT)


@pytest.mark.parametrize(
    "name", ["extra_read_paths", "read_path_scanners", "env_scanners"]
)
def test_control_a_patch_that_leaves_no_other_grant_list_still_limits_it_to_nothing(
    tmp_path, name
):
    trusted = AshConfig()
    setattr(trusted.sandbox, name, ["/opt/trusted"])

    sandbox = _operators_file_ends_with(
        tmp_path, trusted, {}, [{"op": "remove", "path": f"/sandbox/{name}"}]
    )

    assert getattr(sandbox, name) == []


def test_the_limit_for_a_missing_environment_list_is_the_default_list():
    own = {"mode": "bwrap"}

    limits = _own_grants_after_patch(
        own, [{"op": "remove", "path": "/sandbox/environment"}]
    )

    assert limits == {"environment": list(DEFAULT_ENVIRONMENT)}


def test_the_default_limit_drops_a_trusted_entry_the_default_lacks_and_says_so(
    tmp_path, caplog
):
    reset_dropped_own_sandbox_warnings()
    trusted = AshConfig()
    trusted.sandbox.environment = [*DEFAULT_ENVIRONMENT, "MY_VAR"]

    with caplog.at_level(logging.WARNING):
        sandbox = _operators_file_ends_with(
            tmp_path, trusted, {}, [{"op": "remove", "path": "/sandbox/environment"}]
        )

    assert sandbox.environment == list(DEFAULT_ENVIRONMENT)
    [warning] = [
        record.getMessage()
        for record in caplog.records
        if "root.yaml" in record.getMessage() and "environment" in record.getMessage()
    ]
    assert "leaves no list for environment" in warning, warning
    assert "default list" in warning, warning
    assert f"1 of the trusted list's {len(DEFAULT_ENVIRONMENT) + 1} entries" in warning
    assert "the entries it names" not in warning, warning
    assert "MY_VAR" not in warning, warning


def test_control_a_patch_that_leaves_no_list_over_the_default_says_nothing(
    tmp_path, caplog
):
    reset_dropped_own_sandbox_warnings()

    with caplog.at_level(logging.WARNING):
        sandbox = _operators_file_ends_with(
            tmp_path,
            AshConfig(),
            {},
            [{"op": "remove", "path": "/sandbox/environment"}],
        )

    assert sandbox.environment == list(DEFAULT_ENVIRONMENT)
    assert not [
        record for record in caplog.records if "root.yaml" in record.getMessage()
    ], caplog.text


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


def test_a_delivered_entry_that_starts_with_no_name_is_refused_by_position_only(
    tmp_path,
):
    """The denial reason is returned to the client: it names a variable, and an entry
    that does not start with one only by its place in the delivered list."""
    rules = ccp.rules_from(AshConfig())
    document = {
        "sandbox": {
            "environment": [
                "HTTP_PROXY",
                "MARKER-not-a-name=MARKER-value",
                "https://MARKER-user:MARKER-pw@MARKER-host/x?MARKER-key=MARKER-value",
                "LD_PRELOAD=MARKER-path",
                7,
            ]
        }
    }

    refusals = _refusals(document, rules, tmp_path)

    assert [key for key, _ in refusals] == ["sandbox.environment"], refusals
    reason = refusals[0][1]
    assert "entry number 2" in reason, reason
    assert "entry number 3" in reason, reason
    assert "LD_PRELOAD" in reason, reason
    assert "an entry of type int" in reason, reason
    assert "MARKER" not in reason, reason


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
