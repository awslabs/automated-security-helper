"""A support notice holds no path on the machine that wrote it, and no command.

Why this exists
---------------
Results are shared: they are uploaded as CI artifacts, sent to CloudWatch Logs and S3,
attached to tickets and merged across machines. A notice is built from what ASH read on
the host, and a path under the user's home names the user, the interpreter and the
layout of the machine. So a notice carries tokens, ids and public sentences only, and
the command ASH builds for an upgrade path (which names the interpreter by its path)
stays on the terminal: the record has no field for it, and a key that tries to carry
one is dropped.

A text that holds a path is refused, not rewritten: a notice that quietly changed a
sentence would hide the writer's mistake from the test that should catch it.

The tests are in three groups. A path in any text field of a notice or of an upgrade
path is refused, whichever kind of path it is (the must-flag side). Ordinary text,
the register's own sentences among it, is accepted (the must-not-flag side, so a
guard that refused everything would fail). And a key a record does not declare is not
kept.
"""

import json

import pytest
from pydantic import ValidationError

from automated_security_helper.base.support_register import REGISTER
from automated_security_helper.models.asharp_model import SupportNotice
from tests.unit.models._support_notice_helpers import cpu_notice, upgrade_path

pytestmark = pytest.mark.unit

LOCAL_PATHS = {
    "an absolute path": "/home/alice/.local/share/uv/tools/ash/bin/python",
    "a macOS home": "/Users/alice/Library/Caches/uv",
    "a root path": "/root/.cache",
    "a home shorthand": "~/.cache/uv",
    "another user's home": "~alice/bin",
    "a drive path": "C:\\Users\\alice\\AppData\\Local\\uv",
    "a drive path with slashes": "c:/work/repo",
    "a network share": "\\\\fileserver\\share\\ash",
    "a file URI": "file:///home/alice/ash",
}

#: Ordinary text a notice holds, each in a spelling a path guard could get wrong.
PLAIN_TEXT = {
    "an os and architecture pair": "ASH has no trivy 0.67.2 build for windows/arm64.",
    "a version and flags": "avx2, bmi2 and fma are missing (polars-runtime-32 1.44.2).",
    "a version range": "Python 3.15.0; ASH declares >=3.11,<3.15",
    "a URL": "See https://docs.pola.rs/user-guide/installation/ for the runtime.",
    "a docs link": "how-to/supported-configurations.md#host-cpu-below-polars-runtime",
    "slashes inside words": "Linux/macOS, TCP/IP, and/or and n/a are words.",
    "spaced punctuation": "a / b, 3 ~ 4, about ~5 minutes, and Section C: the processor.",
    "a relative path": "Run ./scripts/check or ../tool/check from the project.",
}


def _fields_of_a_notice(text: str) -> dict:
    """Each text field of a notice, with ``text`` in it and the rest left right."""
    notice = cpu_notice().model_dump(mode="json")
    return {
        "id": {**notice, "id": text},
        "scope": {**notice, "scope": text},
        "dimension": {**notice, "dimension": text},
        "message": {**notice, "message": text},
        "polyfill": {**notice, "polyfill": text},
        "found": {**notice, "found": text},
        "facts value": {**notice, "facts": {"arch": text}},
        "facts name": {**notice, "facts": {text: "amd64"}},
        "docs": {**notice, "docs": text},
        "path id": {**notice, "paths": [{**notice["paths"][0], "id": text}]},
        "path summary": {**notice, "paths": [{**notice["paths"][0], "summary": text}]},
        "path docs": {**notice, "paths": [{**notice["paths"][0], "docs": text}]},
    }


FIELDS = list(_fields_of_a_notice("x"))


@pytest.mark.parametrize("path", LOCAL_PATHS.values(), ids=list(LOCAL_PATHS))
@pytest.mark.parametrize("field", FIELDS)
def test_a_local_path_in_any_text_field_is_refused(field, path):
    for text in (path, f"Python runs at {path}."):
        record = _fields_of_a_notice(text)[field]
        with pytest.raises(ValidationError) as refused:
            SupportNotice.model_validate(record)
        # The refusal names the field and quotes nothing it was given.
        assert "alice" not in str(refused.value)
        assert "fileserver" not in str(refused.value)


@pytest.mark.parametrize("text", PLAIN_TEXT.values(), ids=list(PLAIN_TEXT))
@pytest.mark.parametrize("field", ["message", "found", "path summary", "facts value"])
def test_control_ordinary_text_is_accepted(field, text):
    notice = SupportNotice.model_validate(_fields_of_a_notice(text)[field])

    assert notice.id == cpu_notice().id


def test_control_every_sentence_the_register_declares_is_accepted():
    """The guard must not refuse a word of what the register says: its reasons, its
    losses, what each stand-in replaces and each upgrade path's sentence. A sentence
    the register gained with a path in it would fail here, where it can be fixed."""
    texts: list[str] = []
    for row in REGISTER.rows:
        texts.append(row.reason)
        if row.lost is not None:
            texts.append(row.lost)
    for polyfill in REGISTER.polyfills:
        texts.append(polyfill.stands_in_for)
        if polyfill.difference is not None:
            texts.append(polyfill.difference)
    for path in REGISTER.paths:
        texts.append(path.summary)

    assert len(texts) > 40
    for text in texts:
        assert cpu_notice(message=text).message == text
        assert upgrade_path("probe", "same-os", text).summary == text


def test_a_command_attached_to_a_notice_or_a_path_is_not_kept():
    record = cpu_notice().model_dump(mode="json")
    command = "python -m uv pip install --python /home/alice/.venv/bin/python polars"
    record["command"] = command
    record["paths"][0]["command"] = command

    notice = SupportNotice.model_validate(record)
    dumped = notice.model_dump(mode="json")

    assert "command" not in dumped
    assert all("command" not in path for path in dumped["paths"])
    assert "alice" not in json.dumps(dumped)
    assert notice == cpu_notice()


def test_a_key_a_later_version_adds_is_dropped_and_the_record_still_loads():
    """The same rule from the reading side: a results file written by a newer ASH
    loads, and what the older one does not know is not carried on."""
    record = cpu_notice().model_dump(mode="json")
    record["severity_hint"] = "high"
    record["paths"][0]["rank"] = 3

    notice = SupportNotice.model_validate(record)

    assert notice == cpu_notice()
