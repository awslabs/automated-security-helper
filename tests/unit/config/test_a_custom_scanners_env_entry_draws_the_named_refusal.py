# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``build.custom_scanners`` entry that is an environment reference draws the
same named refusal as any other entry, and shows none of the resolved text.

The field's before-validator used to pass a list holding an environment
reference marker straight through, so that the section base's reference walk
(which names the variable) could refuse it first. The walk does not refuse an
entry slot that holds a model, so such a list went on to the scanner model's
own validation and died on the unnamed error the named refusal replaced, an
error that carries the resolved text in its ``input_value``.

These cells pin that every non-empty list, marker or not, is refused with the one
"not supported" message and never shows the resolved text. The refusal names the
variable when the value holds a reference (a mapping key is not searched, so
that shape names none). It gives no advice to write the value in the file: the
field never accepts one, so the advice would lead to a second refusal. The
rendered surfaces checked are: the
``loc``, ``msg`` and ``type`` of every error, and the text of a config-file
refusal. Two surfaces are not checked, both pydantic's by design: the raw
``str``/``repr`` of a ``ValidationError``, which appends ``input_value=...``
for a short input, and ``errors()[...]["input"]``, which keeps the raw input in
memory. Consumers render ``loc`` and ``msg`` only.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.utils.redacted_model import env_resolved_scalar

pytestmark = pytest.mark.unit

CANARY = "zz-env-entry-canary-58213"
VARIABLE = "ASH_CUSTOM_SCANNER_CANARY"


def _marker():
    return env_resolved_scalar(CANARY, VARIABLE)


#: Entries whose reference sits at a slot the refusal's search reaches (an
#: entry, or a mapping value): the message names the variable.
NAMED_SHAPES = {
    "bare-reference-entry": lambda: [_marker()],
    "reference-beside-a-literal-entry": lambda: ["literal", _marker()],
    "reference-as-a-mapping-value": lambda: [{"config": _marker()}],
}

#: A reference as a mapping key: the search does not walk keys, so the message
#: names no variable, but it is the same refusal and shows no resolved text.
UNNAMED_SHAPES = {
    "reference-as-a-mapping-key": lambda: [{_marker(): 1}],
}

SHAPES = {**NAMED_SHAPES, **UNNAMED_SHAPES}


@pytest.mark.parametrize("shape", list(SHAPES))
def test_a_reference_entry_draws_the_named_refusal_without_the_text(shape):
    from automated_security_helper.config.ash_config import BuildConfig

    with pytest.raises(ValidationError) as caught:
        BuildConfig(custom_scanners=SHAPES[shape]())

    errors = caught.value.errors()
    assert errors, "control: the refusal carries error entries"
    for err in errors:
        assert "custom_scanners" in str(err.get("loc")), err
        assert "custom_scanners is not supported" in str(err.get("msg")), err
        assert "Write the value in the file" not in str(err.get("msg")), err
        assert "Input should be a valid" not in str(err.get("msg")), err
        assert CANARY not in str(err.get("loc")), err
        assert CANARY not in str(err.get("msg")), err
        assert CANARY not in str(err.get("type")), err


@pytest.mark.parametrize("shape", list(NAMED_SHAPES))
def test_a_reference_entry_refusal_names_the_variable(shape):
    from automated_security_helper.config.ash_config import BuildConfig

    with pytest.raises(ValidationError) as caught:
        BuildConfig(custom_scanners=NAMED_SHAPES[shape]())

    errors = caught.value.errors()
    assert errors, "control: the refusal carries error entries"
    for err in errors:
        assert VARIABLE in str(err.get("msg")), err


def test_a_literal_entry_still_draws_the_same_refusal():
    """Control: the non-reference route the marker route must now match."""
    from automated_security_helper.config.ash_config import BuildConfig

    with pytest.raises(ValidationError) as caught:
        BuildConfig(custom_scanners=[{"config": {"name": CANARY}}])
    errors = caught.value.errors()
    assert errors, "control: the refusal carries error entries"
    for err in errors:
        assert "custom_scanners is not supported" in str(err.get("msg")), err
        assert CANARY not in str(err.get("msg")), err


def test_a_reference_entry_in_a_config_file_draws_the_named_refusal(
    tmp_path, monkeypatch
):
    """The file form of the mapping-value shape: every non-empty list draws
    the one "not supported" refusal whatever slot the reference sits in, and
    this value-slot reference is one the search reaches, so the refusal also
    names its variable.

    FILE-LOAD-PATH PIN: no value through the file-load path via three layers.
    L1, the marker's own text in a file load is the placeholder, never the
    value. L2, ``format_model_error`` runs ``redact_refused_input`` over the
    message. L3, ``load_config_file_for_run`` passes the document's environment
    values to ``describe_validation_error``. The cell fails only when L1 is
    bypassed and both L2 and L3 are gone; either scrubber alone covers the
    other."""
    from automated_security_helper.config.resolve_config import (
        ConfigFileRefused,
        load_config_file_for_run,
    )

    monkeypatch.setenv(VARIABLE, CANARY)
    path = tmp_path / "entry.ash.yaml"
    path.write_text(
        "project_name: entry\nbuild:\n  custom_scanners:\n"
        f"    - config: ${{{VARIABLE}}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigFileRefused) as refused:
        load_config_file_for_run(path)

    text = str(refused.value)
    assert "custom_scanners is not supported" in text, text
    assert VARIABLE in text, text
    assert CANARY not in text, text


def test_a_bare_reference_entry_in_a_config_file_draws_the_named_refusal(
    tmp_path, monkeypatch
):
    """The entry slot is a model, so a bare reference there converts, but the
    field never accepts a value: the one "not supported" refusal names the
    variable and never its value, with no advice to write the value in the
    file.

    FILE-LOAD-PATH PIN: no value through the file-load path via layers L1
    (the marker's text is the placeholder in a file load), L2
    (``redact_refused_input`` in ``format_model_error``) and L3
    (``describe_validation_error`` given the document's environment values).
    It fails only when L1 is bypassed and L2 and L3 are both gone."""
    from automated_security_helper.config.resolve_config import (
        ConfigFileRefused,
        load_config_file_for_run,
    )

    monkeypatch.setenv(VARIABLE, CANARY)
    path = tmp_path / "entry.ash.yaml"
    path.write_text(
        f"project_name: entry\nbuild:\n  custom_scanners:\n    - ${{{VARIABLE}}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigFileRefused) as refused:
        load_config_file_for_run(path)

    text = str(refused.value)
    assert "custom_scanners is not supported" in text, text
    assert "Write the value in the file" not in text, text
    assert VARIABLE in text, text
    assert CANARY not in text, text
