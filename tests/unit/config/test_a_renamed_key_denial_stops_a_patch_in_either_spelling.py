"""An operator's denial of a renamed key holds in either of its spellings.

A suppression's ``expires`` was spelled ``expiration`` before 3.8.0, and the
loader still reads both. An operator who keeps runtime overrides open for the
suppressions list but denies the expiry, writing the denial in either spelling
under ``replace_default_denied_paths``, must see a runtime patch of the expiry
refused in either spelling, by that denial. A runtime patch is applied to the
configuration as dumped by field name, so it always meets ``expires``.

Red at the base: a denial written ``.../expiration`` let ``replace``, ``add``
and ``remove`` at ``.../0/expires`` through, and a denial written
``.../expires`` met an op at ``.../0/expiration`` only by accident (a failed
apply or a failed validation), never as the denial.
"""

from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_config_policy import policy_of
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_patch,
)

pytestmark = pytest.mark.unit

OLD_SPELLING_DENIAL = "/global_settings/suppressions/*/expiration"
CANONICAL_DENIAL = "/global_settings/suppressions/*/expires"


def _profile(denial: str) -> AshConfig:
    """A profile whose one denial, replacing the defaults, is ``denial``."""
    return AshConfig.model_validate(
        {
            "project_name": "renamed-key-denials",
            "global_settings": {
                "suppressions": [
                    {
                        "rule_id": "B101",
                        "path": "src/app.py",
                        "reason": "reviewed",
                        "expires": "2099-01-01",
                    }
                ],
                "mcp": {
                    "runtime_overrides": {
                        "enabled": True,
                        "replace_default_denied_paths": True,
                        "allowed_paths": ["/global_settings/**"],
                        "denied_paths": [denial],
                    }
                },
            },
        }
    )


def _patch(base: AshConfig, ops: List[Dict[str, Any]]) -> AshConfig:
    return apply_runtime_patch(base, ops, allowlist=policy_of(base))


@pytest.mark.parametrize(
    "op",
    [
        {
            "op": "replace",
            "path": "/global_settings/suppressions/0/expires",
            "value": "2199-12-31",
        },
        {
            "op": "add",
            "path": "/global_settings/suppressions/0/expires",
            "value": "2199-12-31",
        },
        {"op": "remove", "path": "/global_settings/suppressions/0/expires"},
    ],
    ids=["replace", "add", "remove"],
)
def test_a_denial_in_the_old_spelling_stops_a_write_in_the_canonical_one(
    op: Dict[str, Any],
) -> None:
    base = _profile(OLD_SPELLING_DENIAL)

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, [op])

    assert f"denied_paths entry {OLD_SPELLING_DENIAL!r}" in refused.value.rule


@pytest.mark.parametrize(
    "op",
    [
        {
            "op": "replace",
            "path": "/global_settings/suppressions/0/expiration",
            "value": "2199-12-31",
        },
        {
            "op": "add",
            "path": "/global_settings/suppressions/0/expiration",
            "value": "2199-12-31",
        },
    ],
    ids=["replace", "add"],
)
def test_a_denial_in_the_canonical_spelling_stops_a_write_in_the_old_one(
    op: Dict[str, Any],
) -> None:
    base = _profile(CANONICAL_DENIAL)

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, [op])

    # The denial is what refuses the write, not a failed apply or a failed
    # validation of the patched configuration.
    assert f"denied_paths entry {CANONICAL_DENIAL!r}" in refused.value.rule


def test_a_denial_in_the_old_spelling_still_holds_once_the_spelling_is_removed(
    monkeypatch,
) -> None:
    """At the release that stops reading ``expiration`` in a config, an
    operator's denial written that way still names the expiry it always named:
    a list nobody rewrote keeps denying, and never denies a path that can no
    longer exist."""
    import automated_security_helper

    monkeypatch.setattr(automated_security_helper, "__version__", "4.0.0")
    base = _profile(OLD_SPELLING_DENIAL)
    op = {
        "op": "replace",
        "path": "/global_settings/suppressions/0/expires",
        "value": "2199-12-31",
    }

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, [op])

    assert f"denied_paths entry {OLD_SPELLING_DENIAL!r}" in refused.value.rule


def test_a_denial_in_the_spelling_the_write_uses_still_stops_it() -> None:
    """The control: the denial and the write spelled alike, refused as always."""
    base = _profile(CANONICAL_DENIAL)
    op = {
        "op": "replace",
        "path": "/global_settings/suppressions/0/expires",
        "value": "2199-12-31",
    }

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, [op])

    assert f"denied_paths entry {CANONICAL_DENIAL!r}" in refused.value.rule


@pytest.mark.parametrize("denial", [OLD_SPELLING_DENIAL, CANONICAL_DENIAL])
def test_a_denial_of_the_expiry_leaves_the_entrys_other_keys_open(denial: str) -> None:
    """Reading both spellings as one place widens the denial to that place only."""
    base = _profile(denial)
    op = {
        "op": "replace",
        "path": "/global_settings/suppressions/0/reason",
        "value": "re-reviewed",
    }

    patched = _patch(base, [op])

    assert patched.global_settings.suppressions[0].reason == "re-reviewed"
    assert patched.global_settings.suppressions[0].expires == "2099-01-01"


GLOB_DENIAL = "/**/expiration"


def _glob_profile() -> AshConfig:
    """A profile whose one denial, replacing the defaults, is ``/**/expiration``.

    It holds a suppression and a content-database staleness override. The
    override's ``expiration`` is that model's own key, not an old spelling: the
    spelling table names a model for each row, and a glob names none.
    """
    return AshConfig.model_validate(
        {
            "project_name": "renamed-key-denials",
            "content_db_staleness_overrides": [
                {
                    "database": "grype-db",
                    "policy": "warn",
                    "expiration": "2099-01-01",
                    "reason": "upstream paused",
                }
            ],
            "global_settings": {
                "suppressions": [
                    {
                        "rule_id": "B101",
                        "path": "src/app.py",
                        "reason": "reviewed",
                        "expires": "2099-01-01",
                    }
                ],
                "mcp": {
                    "runtime_overrides": {
                        "enabled": True,
                        "replace_default_denied_paths": True,
                        "allowed_paths": [
                            "/global_settings/**",
                            "/content_db_staleness_overrides/**",
                        ],
                        "denied_paths": [GLOB_DENIAL],
                    }
                },
            },
        }
    )


def test_a_glob_denial_keeps_denying_a_model_whose_own_key_is_the_old_spelling() -> (
    None
):
    """The guard: the spellings a denial is matched under are added to the ones
    it had, never put in their place, so a glob that named a staleness
    override's ``expiration`` still names it."""
    base = _glob_profile()
    op = {
        "op": "replace",
        "path": "/content_db_staleness_overrides/0/expiration",
        "value": "2199-12-31",
    }

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, [op])

    assert f"denied_paths entry {GLOB_DENIAL!r}" in refused.value.rule


def test_a_glob_denial_in_the_old_spelling_also_stops_the_canonical_one() -> None:
    """Under a glob no model is known, so every row's spellings apply: the
    denial can refuse more than before, never less."""
    base = _glob_profile()
    op = {
        "op": "replace",
        "path": "/global_settings/suppressions/0/expires",
        "value": "2199-12-31",
    }

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, [op])

    assert f"denied_paths entry {GLOB_DENIAL!r}" in refused.value.rule
