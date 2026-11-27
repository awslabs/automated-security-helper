"""Each reader of an override refuses a removed spelling and changes nothing else.

A runtime patch, a profile's ``override_yaml`` and a config override build a
configuration from what a caller wrote, through the models, which read an old
spelling at every release. So each of these readers refuses an old spelling
past its row's removal release itself, with the removal message naming both
spellings. It changes nothing else it reads: the canonical spelling applies at
the removal release, the old one applies before it, and an op's pointer is
applied as the caller wrote it.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest
import yaml

import automated_security_helper
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_config_policy import policy_of
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_patch,
)
from automated_security_helper.config.session_profiles import (
    clear_all_session_state,
    clear_profile_registry,
    get_session_state,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

REMOVAL_RELEASE = "4.0.0"
LIVE_RELEASE = "3.99.0"

#: An accepted write for each reader: the canonical spelling at the removal
#: release, and the old one a release before it.
_ACCEPTED = [
    pytest.param(REMOVAL_RELEASE, "expires", id="canonical-at-the-removal"),
    pytest.param(LIVE_RELEASE, "expiration", id="old-before-the-removal"),
]

#: The runtime-override policy of every profile here: open for the global
#: settings, with no denied path but those ASH always denies, so only the
#: spelling can refuse a write.
_POLICY = {
    "enabled": True,
    "replace_default_denied_paths": True,
    "allowed_paths": ["/global_settings/**"],
    "denied_paths": [],
}


@pytest.fixture
def running(monkeypatch):
    """Set the version ASH reports while the test runs."""

    def _set(version: str) -> None:
        monkeypatch.setattr(automated_security_helper, "__version__", version)

    return _set


def _suppression(key: str) -> Dict[str, Any]:
    """A suppression whose expiry is written under ``key``."""
    return {
        "rule_id": "B101",
        "path": "src/app.py",
        "reason": "reviewed",
        key: "2099-01-01",
    }


def _profile_document(**global_settings: Any) -> Dict[str, Any]:
    return {
        "project_name": "removed-spelling-readers",
        "global_settings": {
            "mcp": {"runtime_overrides": dict(_POLICY)},
            **global_settings,
        },
    }


# ---------------------------------------------------------------------------
# A runtime patch
# ---------------------------------------------------------------------------


def _added(key: str) -> Dict[str, Any]:
    return {
        "op": "add",
        "path": "/global_settings/suppressions/-",
        "value": _suppression(key),
    }


def test_a_runtime_patch_writing_the_old_spelling_is_refused_at_the_removal_release(
    running,
) -> None:
    """An op whose value writes the old spelling is refused with the removal
    message, naming both spellings."""
    running(REMOVAL_RELEASE)
    base = AshConfig.model_validate(_profile_document())

    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(base, [_added("expiration")], allowlist=policy_of(base))

    assert "'expiration'" in refused.value.rule
    assert "'expires'" in refused.value.rule


@pytest.mark.parametrize("version,key", _ACCEPTED)
def test_a_runtime_patch_is_applied_unless_it_writes_a_removed_spelling(
    running, version: str, key: str
) -> None:
    """The control: the reader refuses the removed spelling alone."""
    running(version)
    base = AshConfig.model_validate(_profile_document())

    patched = apply_runtime_patch(base, [_added(key)], allowlist=policy_of(base))

    assert [entry.expires for entry in patched.global_settings.suppressions] == [
        "2099-01-01"
    ]


def test_a_runtime_patch_pointer_in_the_old_spelling_is_applied_as_written_while_live(
    running,
) -> None:
    """Before the removal release the reader changes no op: a pointer in the old
    spelling meets a configuration dumped by field name, where no such key is."""
    running(LIVE_RELEASE)
    base = AshConfig.model_validate(
        _profile_document(suppressions=[_suppression("expires")])
    )
    op = {
        "op": "replace",
        "path": "/global_settings/suppressions/0/expiration",
        "value": "2199-12-31",
    }

    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(base, [op], allowlist=policy_of(base))

    assert refused.value.op == op
    assert "patch apply failed" in refused.value.rule


# ---------------------------------------------------------------------------
# A profile's override_yaml
# ---------------------------------------------------------------------------


@pytest.fixture
def operator_profile(tmp_path: Path, monkeypatch) -> Iterator[Path]:
    """The operator's profile ``op``, registered, with the session state the tool
    writes kept under this test's own directory."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    clear_profile_registry()
    clear_all_session_state()
    path = tmp_path / "op.yaml"
    path.write_text(
        yaml.safe_dump(_profile_document(), sort_keys=False), encoding="utf-8"
    )
    set_profile_registry(register_profiles([f"op={path}"]))
    yield path
    clear_profile_registry()
    clear_all_session_state()


def _override(key: str) -> str:
    """The profile restated with one suppression whose expiry is written under
    ``key``."""
    document = _profile_document(suppressions=[_suppression(key)])
    return yaml.safe_dump(document, sort_keys=False)


@pytest.mark.usefixtures("operator_profile")
def test_an_override_yaml_writing_the_old_spelling_is_refused_at_the_removal_release(
    running,
) -> None:
    """An override whose suppression writes the old spelling is refused, naming
    both spellings, and nothing is bound."""
    running(REMOVAL_RELEASE)

    result = mcp_select_profile(
        "op", override_yaml=_override("expiration"), session_id="override"
    )

    assert result["success"] is False, result
    assert "'expiration'" in result["error"], result["error"]
    assert "'expires'" in result["error"], result["error"]
    assert get_session_state("override") is None
    assert resolve_session_config_path("override") is None


@pytest.mark.usefixtures("operator_profile")
@pytest.mark.parametrize("version,key", _ACCEPTED)
def test_an_override_yaml_is_bound_unless_it_writes_a_removed_spelling(
    running, version: str, key: str
) -> None:
    """The control: the reader refuses the removed spelling alone, and the
    override is bound with the canonical key."""
    running(version)

    result = mcp_select_profile(
        "op", override_yaml=_override(key), session_id="override"
    )

    assert result["success"] is True, result
    state = get_session_state("override")
    assert state is not None
    assert state.bound_config is not None
    suppressions = state.bound_config.global_settings.suppressions
    assert [entry.expires for entry in suppressions] == ["2099-01-01"]


# ---------------------------------------------------------------------------
# A config override
# ---------------------------------------------------------------------------


def _config_override(key: str) -> str:
    """``global_settings.suppressions=<a list of one suppression>``, its expiry
    written under ``key``."""
    return "global_settings.suppressions=" + json.dumps([_suppression(key)])


def test_a_config_override_writing_the_old_spelling_is_refused_at_the_removal_release(
    running,
) -> None:
    """An override whose suppression writes the old spelling is refused, naming
    the override's key and both spellings."""
    running(REMOVAL_RELEASE)

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(AshConfig(), [_config_override("expiration")])

    message = str(refused.value)
    assert "global_settings.suppressions" in message
    assert "'expiration'" in message
    assert "'expires'" in message


@pytest.mark.parametrize("version,key", _ACCEPTED)
def test_a_config_override_is_applied_unless_it_writes_a_removed_spelling(
    running, version: str, key: str
) -> None:
    """The control: the reader refuses the removed spelling alone."""
    running(version)

    config = apply_config_overrides(AshConfig(), [_config_override(key)])

    assert [entry.expires for entry in config.global_settings.suppressions] == [
        "2099-01-01"
    ]
