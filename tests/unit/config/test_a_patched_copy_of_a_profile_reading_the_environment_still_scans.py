# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client-patched copy of a profile that reads a denied list from the environment still scans.

``config_document_denials`` withholds the repeat exemption from a leaf the trusted
config read from the environment, and (since the list case was closed) from a
list holding such an entry. A session's client-patched profile copy is checked
with ``repeats_trusted`` against the registered profile, so the question this
pins: does an operator's profile whose default-denied entry (an ``ignore_paths``
entry, a reporter option) is written as ``${VAR}`` still scan after a client
patches an allowed key? The copy the server writes holds the reference as the
file wrote it, not the value, and the scan fills the value from the operator's
copy. The check judges the filled copy, and a leaf that holds a value the fill
read for the operator's own reference at that place is the operator's, not the
client's, so the withholding does not apply to it. The checks made before the
scan read the copy unfilled and fill it the same way. Measured, not read: the
scan resolves an AshConfig with the client's change and the operator's
environment value.

The route is ``mcp_select_profile`` with ``patch_ops`` and then the real
``_run_scan_async`` up to config resolution, as tests/unit/cli/mcp/
test_select_profile_patch_is_the_clients.py drives it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "client-one"
CANARY = "ash-canary-x35c-qzvy-ignored"


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_X35_IGN", CANARY)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"target": target, "operator": operator}
    clear_profile_registry()
    clear_all_session_state()


def _register(operator: Path, text: str) -> None:
    path = operator / "op.yaml"
    path.write_text(text, encoding="utf-8")
    set_profile_registry(register_profiles([f"op={path}"]))


def _bind(patch_ops: List[Dict[str, Any]]) -> str:
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    result = mcp_select_profile("op", session_id=SESSION, patch_ops=patch_ops)
    assert result["success"] is True, result
    bound = resolve_session_config_path(SESSION)
    assert bound == result["config_path"]
    return bound


def _scan_outcome(target: Path) -> Any:
    """What a scan of ``target`` resolves with the config the session bound: the
    AshConfig, or the exception resolution raised."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management import scan_management
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    config_path = resolve_session_config_path(SESSION)
    assert config_path is not None
    resolved: List[Any] = []
    faults: List[Exception] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> AshConfig:
        try:
            resolved.append(real(*args, **kwargs))
        except (ValueError, OSError) as refusal:
            # Only a config refusal is an outcome (ASHConfigValidationError and
            # its source, unset-variable and not-permitted kinds are ValueErrors,
            # and so is a model's validation error; an unreadable file is an
            # OSError).
            resolved.append(refusal)
        except Exception as fault:
            # Any other exception is a fault in the harness or the product. The
            # scan swallows what its resolution raises (it has to swallow the
            # exception raised below), so the fault is kept here and raised after
            # the run. Left to the scan it would surface as "the scan never
            # reached config resolution", a message that points elsewhere.
            faults.append(fault)
        raise _StopAfterResolution

    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    # The scan is the session's, as the directory tool registers it: the
    # sandbox admits the scan's own copy of the operator's profile only for a
    # scan its session holds (``session_holds_scan`` reads the registry through
    # ``scan_management``), so both bindings answer from this one registry.
    scan_id = registry.register_scan(
        directory_path=str(target),
        output_directory=str(output),
        session_id=SESSION,
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "resolve_config", recording),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        patch.object(scan_management, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=config_path,
                session_id=SESSION,
            )
        )
    if faults:
        raise faults[0]
    assert len(resolved) == 1, "the scan never reached config resolution"
    return resolved[0]


PROFILE = (
    "project_name: operator\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    "    - path: ${ASH_X35_IGN}\n"
    "      reason: environment\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
)


def test_the_patched_copy_scans_with_the_operators_environment_value(server) -> None:
    _register(server["operator"], PROFILE)
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    outcome = _scan_outcome(server["target"])

    assert isinstance(outcome, AshConfig), outcome
    assert outcome.project_name == "patched"
    assert [entry.path for entry in outcome.global_settings.ignore_paths] == [CANARY]


def test_the_copy_holds_the_reference_not_the_value(server) -> None:
    """The fact the pin rests on: the client's copy is written with the
    reference as the profile wrote it; the value never reaches the file the
    policy check reads."""
    _register(server["operator"], PROFILE)
    bound = _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    text = Path(bound).read_text(encoding="utf-8")

    assert "${ASH_X35_IGN}" in text, text
    assert CANARY not in text, text


def _resolution_raising(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    from automated_security_helper.config import resolve_config as rc

    def raising(*args: Any, **kwargs: Any) -> AshConfig:
        raise error

    monkeypatch.setattr(rc, "resolve_config", raising)


def test_a_fault_in_the_resolution_is_raised_as_itself(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The harness does not hide a fault behind its own message: the scan
    swallows what its resolution raises, so an exception that is not a config
    refusal is kept and raised after the run, as the exception it is."""
    _register(server["operator"], PROFILE)
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])
    _resolution_raising(monkeypatch, TypeError("planted fault"))

    with pytest.raises(TypeError, match="planted fault"):
        _scan_outcome(server["target"])


def test_a_config_refusal_is_the_outcome_and_not_a_fault(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a refusal of the config is what the scan resolves with, and
    is returned as the outcome."""
    _register(server["operator"], PROFILE)
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])
    refusal = ValueError("planted refusal")
    _resolution_raising(monkeypatch, refusal)

    assert _scan_outcome(server["target"]) is refusal


def _reporter_profile(region: str) -> str:
    """An operator profile whose AWS reporter section sets ``aws_region`` to ``region``."""
    return (
        "project_name: operator\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: false\n"
        "    options:\n"
        f"      aws_region: {region}\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /project_name\n"
    )


def _reporter_region(outcome: AshConfig) -> Any:
    """The ``aws_region`` option of the AWS reporter's section. The AWS reporter's
    plugin module is not loaded, so the dump holds the section as an extra one."""
    reporters = outcome.model_dump(by_alias=True)["reporters"]
    sections = {str(key).replace("-", "_"): value for key, value in reporters.items()}
    return sections["aws_security_hub"]["options"]["aws_region"]


def test_the_patched_copy_scans_with_a_denied_reporter_option_from_the_environment(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The profile reads a reporter option that the default policy denies from the
    environment, and the client patches only an allowed key. The scan resolves with
    the client's change and the operator's value."""
    monkeypatch.setenv("ASH_X35_REGION", "us-west-2")
    _register(server["operator"], _reporter_profile("${ASH_X35_REGION}"))
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    outcome = _scan_outcome(server["target"])

    assert isinstance(outcome, AshConfig), outcome
    assert outcome.project_name == "patched"
    assert _reporter_region(outcome) == "us-west-2"


def test_the_patched_copy_scans_with_a_denied_reporter_option_written_out(
    server,
) -> None:
    """The control: the same profile with the region written out in the file
    resolves with the client's change and the operator's value."""
    _register(server["operator"], _reporter_profile("us-west-2"))
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    outcome = _scan_outcome(server["target"])

    assert isinstance(outcome, AshConfig), outcome
    assert outcome.project_name == "patched"
    assert _reporter_region(outcome) == "us-west-2"


def _fixed_choice_profile(choice: str) -> str:
    """An operator profile that sets ``severity_threshold``, a fixed-choice field, to
    ``choice``, holds one suppression and denies a client any change to the
    suppressions."""
    return (
        "project_name: operator\n"
        "global_settings:\n"
        f"  severity_threshold: {choice}\n"
        "  suppressions:\n"
        "    - rule_id: B101\n"
        "      path: src/vendored.py\n"
        "      reason: vendored\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /project_name\n"
        "      denied_paths:\n"
        "        - /global_settings/suppressions\n"
    )


def test_the_patched_copy_scans_with_a_fixed_choice_field_from_the_environment(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The profile reads a fixed-choice field from the environment (the loader
    refuses a reference at a boolean field), and its own policy denies
    suppressions. The client patches only ``project_name``, and the scan resolves
    with that change, the environment's value and the operator's suppression."""
    monkeypatch.setenv("ASH_X35_SEV", "HIGH")
    _register(server["operator"], _fixed_choice_profile("${ASH_X35_SEV}"))
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    outcome = _scan_outcome(server["target"])

    assert isinstance(outcome, AshConfig), outcome
    assert outcome.project_name == "patched"
    assert outcome.global_settings.severity_threshold == "HIGH"
    assert [entry.rule_id for entry in outcome.global_settings.suppressions] == ["B101"]


def test_the_patched_copy_scans_with_a_fixed_choice_field_written_out(server) -> None:
    """The control: the same profile with the choice written out in the file
    resolves with the client's change, the operator's value and the suppression."""
    _register(server["operator"], _fixed_choice_profile("HIGH"))
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    outcome = _scan_outcome(server["target"])

    assert isinstance(outcome, AshConfig), outcome
    assert outcome.project_name == "patched"
    assert outcome.global_settings.severity_threshold == "HIGH"
    assert [entry.rule_id for entry in outcome.global_settings.suppressions] == ["B101"]


_REGION_KEY = "reporters.aws-security-hub.options.aws_region"


def _denials_before_the_scan(
    target: Path,
    *,
    references: bool = True,
    filled: Any = None,
    empty_entries: bool = False,
) -> List[Any]:
    """What ``client_file_denials`` finds in the session's bound copy, with the
    document and the rules the check made before a scan starts reads
    (``mcp_tools._client_config_denial``): the chain read as a scan reads it, and
    the rules of the profile the session bound. ``references=False`` gives the
    rules a base that holds none of the profile's environment reads. ``filled``
    is passed on as the record a scan's load passes (``client_file_denials``'s
    ``filled``); ``empty_entries`` passes the record a load that filled nothing
    makes, an empty entry for each file of the chain."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config.client_config_policy import (
        client_file_denials,
    )
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        env_refused_for,
        resolve_config_document,
    )
    from automated_security_helper.config.mcp_sandbox import (
        caller_is_remote,
        client_named_config_is_untrusted,
        config_base_gate,
    )

    path = Path(resolve_session_config_path(SESSION) or "")
    rules = mcp_tools._session_client_rules(SESSION)
    if not references:
        bare = rules.base.model_copy(deep=True)
        bare._environment_references = ()
        rules = rules.model_copy(update={"base": bare})
    document = resolve_config_document(
        path,
        confine_to=default_confinement_root(path, target),
        permit_base=config_base_gate(SESSION),
        refuse_env=env_refused_for(caller_is_remote(SESSION), SESSION),
    )
    if empty_entries:
        filled = dict.fromkeys(document.documents, ())
    return client_file_denials(
        document.documents,
        rules,
        all_delivered=client_named_config_is_untrusted(path, session_id=SESSION),
        names=document.names,
        moved_exclusions=True,
        filled=filled,
    )


def _bare_session_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """Have ``mcp_tools._session_client_rules`` answer the session's rules with a
    base that holds none of the profile's environment reads, for every check
    that reads the rules through it."""
    from automated_security_helper.cli import mcp_tools

    real = mcp_tools._session_client_rules

    def without_references(*args: Any, **kwargs: Any) -> Any:
        rules = real(*args, **kwargs)
        bare = rules.base.model_copy(deep=True)
        bare._environment_references = ()
        return rules.model_copy(update={"base": bare})

    monkeypatch.setattr(mcp_tools, "_session_client_rules", without_references)


def test_the_check_before_the_scan_accepts_a_denied_reporter_option_from_the_environment(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check a scan's start makes before the scan resolves the config reads the
    bound copy still holding the reference text. It fills the copy from the
    profile the session bound, as the scan's resolution does, so the operator's
    own value at a place the policy denies is not refused there either."""
    from automated_security_helper.cli import mcp_tools

    monkeypatch.setenv("ASH_X35_REGION", "us-west-2")
    _register(server["operator"], _reporter_profile("${ASH_X35_REGION}"))
    bound = _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])
    assert "${ASH_X35_REGION}" in Path(bound).read_text(encoding="utf-8"), bound

    assert _denials_before_the_scan(server["target"]) == []
    assert (
        mcp_tools._client_config_denial(
            bound, server["target"], SESSION, "scan_directory"
        )
        is None
    )


def test_the_check_before_the_scan_refuses_the_copy_where_it_holds_no_reference_of_the_profile(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with rules whose base holds none of the profile's environment
    reads there is nothing to fill from, so the copy is judged as it stands and
    the denied option is refused. The check a scan's start makes
    (``mcp_tools._client_config_denial``) refuses it and names the option, so
    that check does judge this copy, and the fill is what accepts it."""
    from automated_security_helper.cli import mcp_tools

    monkeypatch.setenv("ASH_X35_REGION", "us-west-2")
    _register(server["operator"], _reporter_profile("${ASH_X35_REGION}"))
    bound = _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])
    _bare_session_rules(monkeypatch)

    refused = mcp_tools._client_config_denial(
        bound, server["target"], SESSION, "scan_directory"
    )

    assert refused is not None
    assert refused["success"] is False, refused
    assert _REGION_KEY in refused["error"], refused
    found = _denials_before_the_scan(server["target"], references=False)
    keys = [denial.key for _file, denials in found for denial in denials]
    assert _REGION_KEY in keys, keys


def _validate_config(bound: str, monkeypatch, *, references: bool) -> Dict[str, Any]:
    """What ``validate_config`` answers for the bound copy, whole.
    ``references=False`` gives the check rules whose base holds none of the
    profile's environment reads."""
    from automated_security_helper.cli import mcp_tools

    if not references:
        _bare_session_rules(monkeypatch)
    return mcp_tools.mcp_validate_config(config_path=bound, session_id=SESSION)


def test_validate_config_accepts_a_denied_reporter_option_from_the_environment(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``validate_config`` judges the bound copy as the scan does, from its own read
    of the chain, so the operator's own value at a place the policy denies draws no
    refusal there either. The whole answer is checked: no error of any type, so a
    fill that fails or a reference left unread there would show."""
    monkeypatch.setenv("ASH_X35_REGION", "us-west-2")
    _register(server["operator"], _reporter_profile("${ASH_X35_REGION}"))
    bound = _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    result = _validate_config(bound, monkeypatch, references=True)

    assert result["errors"] == [], result
    assert result["valid"] is True, result


def test_validate_config_refuses_the_copy_where_it_holds_no_reference_of_the_profile(
    server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with rules whose base holds none of the profile's environment
    reads, ``validate_config`` judges the copy as it stands and refuses the denied
    option, so the check does reach this copy and the fill is what accepts it."""
    monkeypatch.setenv("ASH_X35_REGION", "us-west-2")
    _register(server["operator"], _reporter_profile("${ASH_X35_REGION}"))
    bound = _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    result = _validate_config(bound, monkeypatch, references=False)

    assert result["valid"] is False, result
    denied = [
        error["field"]
        for error in result["errors"]
        if error["type"] == "denied_by_runtime_policy"
    ]
    assert denied == [_REGION_KEY], result


@pytest.mark.parametrize(
    "empty_entries",
    [
        pytest.param(False, id="no-entry-for-the-copy"),
        pytest.param(True, id="an-empty-entry-for-each-file"),
    ],
)
def test_a_copy_the_scans_load_filled_nothing_in_is_judged_as_that_load_left_it(
    server, monkeypatch: pytest.MonkeyPatch, empty_entries: bool
) -> None:
    """A load that read the copy and filled nothing in it passes a record that
    holds nothing for it (no entry, or the empty entry each file gets from a
    load with no fill), and its documents are the ones the scan built its
    configuration from, still holding the reference text. The rules judge the
    copy as that load left it, so the denied option is refused, although the
    rules' base holds the profile's environment reads. Without a record (the
    check made before the scan) the copy is filled from those reads and
    accepted."""
    monkeypatch.setenv("ASH_X35_REGION", "us-west-2")
    _register(server["operator"], _reporter_profile("${ASH_X35_REGION}"))
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    found = _denials_before_the_scan(
        server["target"], filled={}, empty_entries=empty_entries
    )

    keys = [denial.key for _file, denials in found for denial in denials]
    assert _REGION_KEY in keys, keys
    assert _denials_before_the_scan(server["target"]) == []


def test_a_load_without_a_fill_records_an_empty_entry_for_each_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``load_config_file`` records what it filled into each file of the chain
    even when it filled nothing: an empty entry for each, so the client rules
    can tell a load that ran from none and judge each copy as it left it."""
    from automated_security_helper.config.resolve_config import load_config_file

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    (tmp_path / "base.yaml").write_text("project_name: base\n", encoding="utf-8")
    root = tmp_path / "ash.yaml"
    root.write_text("extends: base.yaml\n", encoding="utf-8")

    document, _config = load_config_file(root, confine_to=tmp_path)

    assert len(document.documents) == 2, document.documents
    assert document.filled_references == dict.fromkeys(document.documents, ())
