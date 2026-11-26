"""A default ``denied_paths`` list a release shipped stays in the shipped table.

``SHIPPED_DEFAULT_DENIED_PATHS`` is the set of lists a profile may hold and still
count as using the default. ``ash config init`` writes the current default into
the profile, so a profile written by a released version holds that release's
list. If a later edit changes the table's entry for a released list in place,
that profile reads as the operator's own list, and an MCP client's delivered
suppression is refused with ``config_field_denied``.

The existing table tests check the table against itself, so an in-place edit of
a released entry passes them. These pin the v3.8.0 list from a literal kept
outside the table (``_shipped_denied_paths_v3_8_0.py``).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.client_config_policy import (
    apply_client_config_rules,
    rules_from,
)
from tests.unit.config._shipped_denied_paths_v3_8_0 import (
    V3_8_0_DEFAULT_DENIED_PATHS,
)

pytestmark = pytest.mark.unit

_SUPPRESSION = {
    "global_settings": {"suppressions": [{"path": "app.py", "reason": "delivered"}]}
}


def _profile(denied_paths) -> AshConfig:
    return AshConfig.model_validate(
        {
            "global_settings": {
                "mcp": {"runtime_overrides": {"denied_paths": list(denied_paths)}}
            }
        }
    )


def _deliver(tmp_path: Path, monkeypatch, rules):
    root = tmp_path / "ash-mcp"
    path = root / "session-a" / "source" / "ash.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    return apply_client_config_rules(
        AshConfig.model_validate(_SUPPRESSION),
        {path: _SUPPRESSION},
        rules=rules,
        trusted_config_path=None,
        source_dir=None,
        permit_base=None,
    )


# sha256 of the v3.8.0 entries, sorted and joined by newlines, computed from the
# tag's own bytes (ash_config.py's list, and the tag's table entry in
# client_config_policy.py, both give this digest). A rewrite that changes the
# fixture and the table entry together, such as a repository-wide rename of an
# option, changes the digest and fails here.
_V3_8_0_SHA256 = "d09fa5e3e8414c7fbda8b87a170fa93f2e438cef7a2f34dfcaf1b5322f16841a"


def test_the_fixture_is_the_v3_8_0_list() -> None:
    assert len(V3_8_0_DEFAULT_DENIED_PATHS) == 102
    assert len(set(V3_8_0_DEFAULT_DENIED_PATHS)) == 102
    digest = hashlib.sha256(
        "\n".join(sorted(V3_8_0_DEFAULT_DENIED_PATHS)).encode("utf-8")
    ).hexdigest()
    assert digest == _V3_8_0_SHA256


def test_the_v3_8_0_default_is_a_shipped_default() -> None:
    assert frozenset(V3_8_0_DEFAULT_DENIED_PATHS) in ccp.SHIPPED_DEFAULT_DENIED_PATHS


def test_a_profile_ash_config_init_wrote_at_v3_8_0_is_the_default() -> None:
    policy = _profile(V3_8_0_DEFAULT_DENIED_PATHS).global_settings.mcp.runtime_overrides
    assert "denied_paths" in policy.model_fields_set
    assert ccp.policy_is_default(policy)


def test_a_suppression_is_admitted_under_a_v3_8_0_profile_as_under_the_default(
    tmp_path, monkeypatch
) -> None:
    under_default = _deliver(tmp_path / "d", monkeypatch, None)
    under_v380 = _deliver(
        tmp_path / "v", monkeypatch, rules_from(_profile(V3_8_0_DEFAULT_DENIED_PATHS))
    )
    for config in (under_default, under_v380):
        [entry] = config.global_settings.suppressions
        assert entry.path == "app.py"
        assert entry.client_supplied is True


def test_the_table_comment_about_the_derived_entries_matches_the_entries() -> None:
    """The first derived entry adds ``/global_settings/exclusions`` to the entry before it.

    That entry is not the v3.8.0 list: it is that list plus the entries added
    after the release and before the exclusions did. The v3.8.0 list is its own
    entry, ahead of that one.
    """
    table = ccp.SHIPPED_DEFAULT_DENIED_PATHS
    v380 = frozenset(V3_8_0_DEFAULT_DENIED_PATHS)
    # Anchored on the entry's content, so an entry added after the next release
    # does not shift what is compared.
    at = table.index(v380)
    written_out, first_derived = table[at + 1], table[at + 2]
    assert first_derived - written_out == {"/global_settings/exclusions"}
    assert v380 < written_out
    assert table[at + 3] > first_derived
    assert table[at + 4] > table[at + 3]


def test_an_edited_v3_8_0_list_is_still_the_operators_own() -> None:
    policy = _profile(
        [*V3_8_0_DEFAULT_DENIED_PATHS, "/project_name"]
    ).global_settings.mcp.runtime_overrides
    assert not ccp.policy_is_default(policy)
    assert RuntimeOverridesConfig().denied_paths
