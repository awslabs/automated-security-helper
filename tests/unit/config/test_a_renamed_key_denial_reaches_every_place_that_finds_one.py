"""A denial of a renamed key holds in either spelling wherever a denial is found.

A suppression's ``expires`` was spelled ``expiration`` before 3.8.0, and the
loader still reads both. A runtime patch's path check is one place that finds a
denial; these pin two more. A delivered config's own ``patch`` operations are
checked against the operator's ``denied_paths`` by ``config_document_denials``,
and a ``denied_value_patterns`` key binds a regex to a place, for a runtime
patch and for a delivered file alike. Each holds whichever spelling the operator
wrote and whichever the write uses.

Only a pointer names the expiry. It lives in list entries, and a document that
sets a list writes it as one value at the list's pointer, which a denial of
anything inside the list already covers in any spelling. So every write here is
at ``/global_settings/suppressions/0/<key>``, and no pattern starts with ``**``.

Red at the base: a denial was matched over its pattern as written and with '-'
read as '_' (``runtime_patch._denial_spellings``), so ``expires`` and
``expiration`` never met. The controls (``..._spelled_as_...`` and
``..._does_not_match_...``) pass at the base too.
"""

from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_config_policy import policy_of
from automated_security_helper.config.runtime_patch import (
    DocumentDenial,
    RuntimePatchDeniedError,
    apply_runtime_patch,
    config_document_denials,
)

pytestmark = pytest.mark.unit

OLD_PATTERN = "/global_settings/suppressions/*/expiration"
CANONICAL_PATTERN = "/global_settings/suppressions/*/expires"
OLD_LEAF = "/global_settings/suppressions/0/expiration"
CANONICAL_LEAF = "/global_settings/suppressions/0/expires"

#: The regex a value pattern binds, a value it matches and one it does not.
REGEX = r"^2199-"
MATCHED = "2199-12-31"
UNMATCHED = "2099-06-30"

#: A pattern in one spelling and a write in the other, each way round.
CROSSED = [
    pytest.param(OLD_PATTERN, CANONICAL_LEAF, id="old-pattern-canonical-write"),
    pytest.param(CANONICAL_PATTERN, OLD_LEAF, id="canonical-pattern-old-write"),
]

#: A pattern and a write in the same spelling, either one.
ALIKE = [
    pytest.param(OLD_PATTERN, OLD_LEAF, id="old"),
    pytest.param(CANONICAL_PATTERN, CANONICAL_LEAF, id="canonical"),
]


def _profile(
    *,
    denied_paths: List[str],
    denied_value_patterns: Optional[Dict[str, str]] = None,
) -> AshConfig:
    """A profile with one suppression, runtime overrides open under
    ``/global_settings``, and ``denied_paths`` replacing the defaults."""
    overrides: Dict[str, Any] = {
        "enabled": True,
        "replace_default_denied_paths": True,
        "allowed_paths": ["/global_settings/**"],
        "denied_paths": denied_paths,
    }
    if denied_value_patterns is not None:
        overrides["denied_value_patterns"] = denied_value_patterns
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
                "mcp": {"runtime_overrides": overrides},
            },
        }
    )


def _op(name: str, path: str, value: str = MATCHED) -> Dict[str, Any]:
    if name == "remove":
        return {"op": name, "path": path}
    return {"op": name, "path": path, "value": value}


def _document_denials(trusted: AshConfig, op: Dict[str, Any]) -> List[DocumentDenial]:
    """The denials of a delivered document whose one write is ``op``.

    ``trusted`` gives the policy and is the trusted config, as
    ``client_config_policy.client_file_denials`` passes them, so a refusal names
    the policy's entry as the profile wrote it.
    """
    return config_document_denials(
        {"patch": [op]}, allowlist=policy_of(trusted), config=trusted
    )


def _patch(base: AshConfig, op: Dict[str, Any]) -> AshConfig:
    return apply_runtime_patch(base, [op], allowlist=policy_of(base))


# ---------------------------------------------------------------------------
# denied_paths, through a delivered document's patch op
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["replace", "add", "remove"])
@pytest.mark.parametrize("denial,pointer", CROSSED)
def test_a_document_patch_op_meets_a_denial_written_in_the_other_spelling(
    denial: str, pointer: str, name: str
) -> None:
    """A delivered file's ``patch`` op is refused by a ``denied_paths`` entry
    that names its key in the other spelling, and the refusal names the entry."""
    trusted = _profile(denied_paths=[denial])

    denials = _document_denials(trusted, _op(name, pointer))

    assert [(d.pointer, d.from_patch) for d in denials] == [(pointer, True)]
    assert f"denied_paths entry {denial!r}" in denials[0].reason


@pytest.mark.parametrize("denial,pointer", ALIKE)
def test_a_document_patch_op_spelled_as_its_denial_is_refused(
    denial: str, pointer: str
) -> None:
    """The control, refused at the base too: the profile and the document reach
    the denial when both are spelled alike."""
    trusted = _profile(denied_paths=[denial])

    denials = _document_denials(trusted, _op("replace", pointer))

    assert [(d.pointer, d.from_patch) for d in denials] == [(pointer, True)]
    assert f"denied_paths entry {denial!r}" in denials[0].reason


# ---------------------------------------------------------------------------
# denied_value_patterns, through a runtime patch and a delivered patch op
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["replace", "add"])
@pytest.mark.parametrize("pattern,pointer", CROSSED)
def test_a_value_pattern_refuses_a_runtime_write_in_the_other_spelling(
    pattern: str, pointer: str, name: str
) -> None:
    """A runtime patch whose value the regex matches is refused by a value
    pattern bound under the key's other spelling, and the refusal names it.

    The refusal is the pattern's: a write at a key the dumped entry does not
    hold can also fail to apply, or fail the patched config's validation, and
    neither of those names the pattern.
    """
    base = _profile(denied_paths=[], denied_value_patterns={pattern: REGEX})

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, _op(name, pointer))

    assert f"bound to {pattern!r}" in refused.value.rule


@pytest.mark.parametrize("pattern,pointer", ALIKE)
def test_a_value_pattern_spelled_as_the_runtime_write_refuses_it(
    pattern: str, pointer: str
) -> None:
    """The control, refused at the base too."""
    base = _profile(denied_paths=[], denied_value_patterns={pattern: REGEX})

    with pytest.raises(RuntimePatchDeniedError) as refused:
        _patch(base, _op("replace", pointer))

    assert f"bound to {pattern!r}" in refused.value.rule


@pytest.mark.parametrize(
    "pattern", [OLD_PATTERN, CANONICAL_PATTERN], ids=["old", "canonical"]
)
def test_a_value_pattern_in_either_spelling_lets_a_value_it_does_not_match_through(
    pattern: str,
) -> None:
    """The control, at the base too: a value pattern refuses by its regex, so the
    cases above are refused for their value, not for their place."""
    base = _profile(denied_paths=[], denied_value_patterns={pattern: REGEX})

    patched = _patch(base, _op("replace", CANONICAL_LEAF, UNMATCHED))

    assert patched.global_settings.suppressions[0].expires == UNMATCHED


@pytest.mark.parametrize("pattern,pointer", CROSSED)
def test_a_value_pattern_refuses_a_document_patch_op_in_the_other_spelling(
    pattern: str, pointer: str
) -> None:
    """The same through a delivered file's ``patch`` op: the profile lists no
    ``denied_paths`` entry, so the value pattern is what refuses it."""
    trusted = _profile(denied_paths=[], denied_value_patterns={pattern: REGEX})

    denials = _document_denials(trusted, _op("replace", pointer))

    assert [(d.pointer, d.from_patch) for d in denials] == [(pointer, True)]
    assert f"bound to {pattern!r}" in denials[0].reason
