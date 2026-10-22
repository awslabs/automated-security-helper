# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Environment references at typed fields: refused by default, typed only
where a field opts in.

A ``${ASH_X}`` reference resolves to the variable's text, and printers show
an env-read value by its reference, never by value. An int, float or bool
field cannot carry the reference text, so a converted value would print by
value wherever its section is shown. The section base therefore refuses a
reference at a typed field, naming the field and the variable and never the
value -- opening with pydantic's own "Input should be a valid ..." phrase, so
the refusal reads the same whether this validator wrote it or a strict load's
own typing did.

A section opts a field in through ``_env_scalar_typed_fields`` only once its
printers are measured to guard the value. An opted field hands the text to
its own validation: a lax model types it as it would a plain string. A
config-file load still refuses the reference at the opted field -- strict
typing would refuse the text anyway, and the loader's context selects the
named refusal so the message names the variable instead of calling the
resolved text not-an-integer.
"""

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError


def _config(tmp_path, body: str):
    path = tmp_path / ".ash.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _without_the_files_path(text: str, path) -> str:
    """The refusal names the config file's path twice (the failure line and
    the lint advice), and a tmp path can carry any short token -- a worker
    dir's digit, a basetemp tag -- so value-absence checks run on the text
    with every spelling of the path removed."""
    for spelling in (str(path), path.as_posix(), str(path.parent)):
        text = text.replace(spelling, "")
    return text


@pytest.mark.parametrize("written", ["31744", "notanumber"], ids=["parses", "no-parse"])
def test_a_reference_at_an_int_field_is_refused_naming_field_and_variable(
    tmp_path, monkeypatch, written
):
    """Refused whether or not the text would parse: the refusal is about the
    field's printers, not the text's shape."""
    monkeypatch.setenv("ASH_TYPED_PROJECTS", written)
    path = _config(
        tmp_path,
        "project_name: typed-fields\nworkspace:\n"
        "  max_parallel_projects: ${ASH_TYPED_PROJECTS}\n",
    )
    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(path)
    text = str(refused.value)
    assert "Input should be a valid integer" in text, text
    assert "max_parallel_projects" in text, text
    assert "ASH_TYPED_PROJECTS" in text, text
    cleaned = _without_the_files_path(text, path)
    assert written not in cleaned.replace("max_parallel_projects", ""), (
        "the refusal echoed the value, which may have been read from the environment"
    )


def test_a_reference_at_a_float_field_is_refused_with_pydantics_noun(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ASH_TYPED_TIMEOUT", "2.5917")
    path = _config(
        tmp_path,
        "project_name: typed-fields\nworkspace:\n"
        "  project_timeout: ${ASH_TYPED_TIMEOUT}\n",
    )
    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(path)
    text = str(refused.value)
    assert "Input should be a valid number" in text, text
    assert "project_timeout" in text, text
    assert "ASH_TYPED_TIMEOUT" in text, text
    assert "2.5917" not in _without_the_files_path(text, path), text


def test_a_reference_at_a_bool_field_is_refused_with_pydantics_noun(
    tmp_path, monkeypatch
):
    """``bool("no")`` is True, so a converted bool could also invert what the
    operator wrote; the reference is refused like every typed field's."""
    monkeypatch.setenv("ASH_TYPED_ENABLED", "no")
    path = _config(
        tmp_path,
        "project_name: typed-fields\nscanners:\n  bandit:\n"
        "    enabled: ${ASH_TYPED_ENABLED}\n",
    )
    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(path)
    text = str(refused.value)
    assert "Input should be a valid boolean" in text, text
    assert "enabled" in text, text
    assert "ASH_TYPED_ENABLED" in text, text


def test_an_opted_field_is_typed_by_its_own_model_and_only_that_field():
    """The opt-in is per field: on one model, the named field hands the text
    to its own validation (a lax model types it), and the sibling typed
    field keeps the default refusal."""
    from typing import ClassVar, Optional

    from automated_security_helper.utils.redacted_model import (
        RedactedSection,
        env_resolved_scalar,
    )

    class Limits(RedactedSection):
        _env_scalar_typed_fields: ClassVar[frozenset] = frozenset({"limit"})
        limit: Optional[int] = None
        retries: Optional[int] = None

    typed = Limits.model_validate({"limit": env_resolved_scalar("67", "ASH_T_LIMIT")})
    assert typed.limit == 67

    with pytest.raises(Exception) as refused:
        Limits.model_validate({"retries": env_resolved_scalar("3", "ASH_T_RETRIES")})
    text = str(refused.value)
    assert "Input should be a valid integer" in text, text
    assert "retries" in text, text
    assert "ASH_T_RETRIES" in text, text


def test_an_opted_field_is_still_refused_by_a_strict_validation():
    """An opted field's text goes to the field's own validation, so a strict
    validation (the config-file load's mode) refuses it as it refuses any
    string there, with pydantic's own message."""
    from typing import ClassVar, Optional

    from automated_security_helper.utils.redacted_model import (
        RedactedSection,
        env_resolved_scalar,
    )

    class Limits(RedactedSection):
        _env_scalar_typed_fields: ClassVar[frozenset] = frozenset({"limit"})
        limit: Optional[int] = None

    with pytest.raises(Exception) as refused:
        Limits.model_validate(
            {"limit": env_resolved_scalar("67", "ASH_T_LIMIT")}, strict=True
        )
    assert "Input should be a valid integer" in str(refused.value), str(refused.value)


def test_a_config_file_refusal_of_an_opted_field_names_the_variable(
    tmp_path, monkeypatch
):
    """A config FILE load refuses an opted field's reference like any other
    typed field's: naming the field and the variable, never calling the
    resolved text not-an-integer with no source. The bare strict validation
    above keeps pydantic's own message; the loader passes the context that
    selects the named refusal."""
    monkeypatch.setenv("ASH_TYPED_SCANTIME", "424242")
    path = _config(
        tmp_path,
        "project_name: typed-fields\nscanners:\n  bandit:\n"
        "    options:\n      scan_timeout: ${ASH_TYPED_SCANTIME}\n",
    )
    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(path)
    text = str(refused.value)
    assert "Input should be a valid integer" in text, text
    assert "scan_timeout" in text, text
    assert "ASH_TYPED_SCANTIME" in text, text
    assert "424242" not in _without_the_files_path(text, path), text


def test_scanner_options_type_scan_timeout_and_refuse_other_typed_fields():
    """The one production opt-in: ScannerOptionsBase.scan_timeout, whose
    printers are measured to show the limit by reference
    (tests/unit/base/test_failure_lines_carry_no_environment_value.py). Its
    sibling bool field keeps the default refusal."""
    from automated_security_helper.base.options import ScannerOptionsBase
    from automated_security_helper.utils.redacted_model import env_resolved_scalar

    options = ScannerOptionsBase.model_validate(
        {"scan_timeout": env_resolved_scalar("67", "ASH_T_TIMEOUT")}
    )
    assert options.scan_timeout == 67

    with pytest.raises(Exception) as refused:
        ScannerOptionsBase.model_validate(
            {"offline": env_resolved_scalar("yes", "ASH_T_OFFLINE")}
        )
    text = str(refused.value)
    assert "Input should be a valid boolean" in text, text
    assert "offline" in text, text
    assert "ASH_T_OFFLINE" in text, text


def test_a_marker_nested_past_the_recursion_limit_is_downcast_iteratively():
    """The container walks run on their own stack: a reference nested deeper
    than the interpreter's recursion limit is still found and downcast,
    where a recursing walk crashed with a RecursionError."""
    import sys
    from typing import Optional

    from automated_security_helper.utils.redacted_model import (
        RedactedSection,
        EnvResolvedScalar,
        env_resolved_scalar,
    )

    class Holder(RedactedSection):
        items: Optional[list] = None

    depth = sys.getrecursionlimit() + 500
    nested = env_resolved_scalar("leaf", "ASH_T_DEEP")
    for _ in range(depth):
        nested = [nested]

    holder = Holder.model_validate({"items": nested})

    inner = holder.items
    while isinstance(inner, list):
        inner = inner[0]
    assert type(inner) is str, type(inner)
    assert not isinstance(inner, EnvResolvedScalar)
    assert inner == "leaf"
