"""The three selections of the operator's sandbox overrides take the same entries.

Three places choose, from the operator's ``--config-overrides``, the entries that
can change the sandbox section: ``resolve_config`` replays them onto the trusted
base its sandbox grants come from, ``confine_to_trusted_base`` does the same for
``ash merge`` and its other callers, and container mode's fallback
(``interactions.run_ash_scan._sandbox_overrides``) replays them onto the trusted
floor to report the sandbox mode when the host cannot resolve the config. Each
takes an entry whose key's first part, read without the entry's operator, is
``sandbox``. A selection that left the operator on the key would miss a removal
from the whole section (``sandbox-=``), and the three must stay equal, so one
table runs through all three and each must take exactly its sandbox entries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, List

import pytest

pytestmark = pytest.mark.unit

#: Every operator at the ``sandbox.network_scanners`` key, the whole section
#: appended to and removed from, and two entries outside the section, one of them
#: a key that only starts with ``sandbox``. True marks an entry each selection
#: must take.
ENTRIES = [
    ("project_name=renamed", False),
    ("sandbox.network_scanners=[grype]", True),
    ("sandbox.network_scanners+=[grype]", True),
    ("sandbox.network_scanners-=[grype]", True),
    ('sandbox+={"mode": "bwrap"}', True),
    ('sandbox-={"mode": "bwrap"}', True),
    ("sandboxed.mode=bwrap", False),
]
OVERRIDES = [entry for entry, _ in ENTRIES]
SANDBOX_ENTRIES = [entry for entry, selected in ENTRIES if selected]


class _Replayed(Exception):
    """Raised by the stand-in apply at the first application of the overrides
    onto a base other than the run's own configuration, carrying what that
    application was given."""

    def __init__(self, overrides: List[str]) -> None:
        super().__init__(overrides)
        self.overrides = overrides


def _stand_in_apply(own_builds: List[List[str]]) -> Callable[..., Any]:
    """An ``apply_config_overrides`` that applies nothing.

    The application that builds the run's own configuration is the one that
    passes ``warn_unread_appends=True``: it is recorded in *own_builds* and gets
    its configuration back unchanged, so nothing is refused there (that build
    refuses a removal from the whole section, which holds a mapping and no list).
    Every other application replays the overrides onto another base; the first one
    raises ``_Replayed``, which ends the call before any later step reads the same
    overrides.
    """

    def apply(config: Any, overrides: List[str], **kwargs: Any) -> Any:
        if kwargs.get("warn_unread_appends"):
            own_builds.append(list(overrides))
            return config
        raise _Replayed(list(overrides))

    return apply


def test_the_three_sandbox_selections_take_the_same_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each site takes the table's sandbox entries, in order, and nothing else.

    ``_sandbox_overrides`` is called directly. The two trusted replays select
    inside larger functions, so each is read from what reaches its
    ``apply_config_overrides`` call. The stand-in above replaces the module's
    ``apply_config_overrides``, which both functions and the scan's own build look
    up there; it hands the scan's own build its configuration back unapplied, so
    that build cannot refuse an entry before the selection is reached, and it ends
    each call at its first replay, which in both functions is the sandbox replay
    (the trusted sandbox grants are confined right after it). ``resolve_config``
    runs as a scan runs it, on a repository with its own config file;
    ``confine_to_trusted_base`` is called directly, as ``ash merge`` calls it.
    """
    from automated_security_helper.config import resolve_config as module
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.interactions.run_ash_scan import (
        _sandbox_overrides,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".ash.yaml").write_text("project_name: repo\n", encoding="utf-8")
    own_builds: List[List[str]] = []
    monkeypatch.setattr(module, "apply_config_overrides", _stand_in_apply(own_builds))

    with pytest.raises(_Replayed) as resolved:
        module.resolve_config(source_dir=repository, config_overrides=OVERRIDES)
    with pytest.raises(_Replayed) as confined:
        module.confine_to_trusted_base(
            AshConfig(),
            AshConfig(),
            OVERRIDES,
            repository,
            [repository / ".ash.yaml"],
        )

    assert {
        "run_ash_scan._sandbox_overrides": _sandbox_overrides(OVERRIDES),
        "resolve_config's trusted replay": resolved.value.overrides,
        "confine_to_trusted_base's trusted replay": confined.value.overrides,
    } == {
        "run_ash_scan._sandbox_overrides": SANDBOX_ENTRIES,
        "resolve_config's trusted replay": SANDBOX_ENTRIES,
        "confine_to_trusted_base's trusted replay": SANDBOX_ENTRIES,
    }
    # The scan's own build was given every entry, once: the stand-in is the apply
    # resolve_config called, so the replay read above is its own.
    assert own_builds == [OVERRIDES]
