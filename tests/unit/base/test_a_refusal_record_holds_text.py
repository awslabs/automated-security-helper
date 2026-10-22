# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter's refusal is recorded and logged as text, whatever bytes a name holds.

A name read from the filesystem or an archive can hold bytes that are not UTF-8:
os.listdir and tarfile read each such byte as a lone surrogate ("b\\udce9.tar").
That is not valid text. pydantic refuses it in a str field, a UTF-8 log or JSON
writer cannot encode it, and pytest-xdist cannot send a report whose captured log
holds one. So record_refused_input writes each lone surrogate as its escape in the
RefusedInputInfo record and in the warning. The record keeps every other character
as it is: it is data, and whatever prints it shows it for its own sink.
"""

from __future__ import annotations

import json
import logging

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.utils.scanned_tree import TreeInputRefused


@pytest.fixture
def ash_warnings():
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


@pytest.fixture
def converter(test_plugin_context):
    return ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )


def test_a_refusal_whose_names_are_not_utf_8_is_recorded_as_text(
    converter, ash_warnings
):
    converter.record_refused_input(
        TreeInputRefused("lib/b\udce9.tar", "its name holds \udce9"),
        member="secr\udce9t/m.js",
    )

    (refused,) = converter.refused_inputs
    assert refused.path == "lib/b\\udce9.tar"
    assert refused.member == "secr\\udce9t/m.js"
    assert refused.reason == "its name holds \\udce9"
    dumped = refused.model_dump_json()
    dumped.encode("utf-8")
    assert json.loads(dumped)["member"] == "secr\\udce9t/m.js"
    (warning,) = ash_warnings
    message = warning.getMessage()
    message.encode("utf-8")
    assert "secr\\udce9t/m.js" in message
    assert "lib/b\\udce9.tar" in message


@pytest.mark.parametrize(
    ("name", "stored"),
    [
        ("secr\udce9t/m.js", "secr\\udce9t/m.js"),
        ("b\udc80\udcff.js", "b\\udc80\\udcff.js"),
        ("secrét/m.js", "secrét/m.js"),
        ("secrΘt/m.js", "secrΘt/m.js"),
        ("dir\\w.js", "dir\\w.js"),
        ("plain.js", "plain.js"),
        ("a\nb.js", "a\nb.js"),
        ("a\tb.js", "a\tb.js"),
        ("a\\x41.js", "a\\x41.js"),
        ("::x.js", "::x.js"),
        ("##[x.js", "##[x.js"),
    ],
    ids=[
        "surrogate",
        "surrogates-at-both-ends-of-the-range",
        "accented",
        "cp437-read",
        "backslash",
        "plain",
        "newline",
        "tab",
        "escape-like-text",
        "ci-command-at-the-start",
        "named-hash-command",
    ],
)
def test_the_record_holds_the_name_with_only_its_surrogates_escaped(
    converter, name, stored
):
    converter.record_refused_input(
        TreeInputRefused(f"lib/{name}", f"named {name}"), member=name
    )

    (refused,) = converter.refused_inputs
    assert (refused.path, refused.member, refused.reason) == (
        f"lib/{stored}",
        stored,
        f"named {stored}",
    )
    for value in (refused.path, refused.member, refused.reason):
        assert type(value) is str
    back = json.loads(refused.model_dump_json().encode("utf-8"))
    assert (back["path"], back["member"], back["reason"]) == (
        f"lib/{stored}",
        stored,
        f"named {stored}",
    )
