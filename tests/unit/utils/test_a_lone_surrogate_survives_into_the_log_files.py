# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A DEBUG record carrying a lone surrogate reaches both log files intact.

Tool output decoded with surrogateescape carries a lone surrogate for every
byte that was not UTF-8 (a latin-1 0xE9 becomes U+DCE9), and such text is
logged as-is at the subprocess dump sites. The log files' handlers encode
strict UTF-8, which cannot write a surrogate: a record that reached them
unrespelled would be dropped by the logging module's error handling, and
ash.log would silently lose the one record that explains a failure.

The record survives through exactly one mechanism, and these cells pin it
end to end through the real handlers: the tabular formatter routes message,
exception and stack text through the shown-not-obeyed respelling, whose
escape set covers the surrogate category, so the file receives the six
printable characters that name the code point; the JSON lines formatter's
``json.dumps`` writes its own escape for the same reason. Removing the
surrogate category from the escape set loses the tabular record whole, so
the assertion is on the record's presence first, the respelled value second.
Each file is read back strict, which is itself the claim that no raw
surrogate reached the bytes on disk.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.utils.log import get_logger

#: The surrogate a surrogateescape decode of a latin-1 0xE9 byte produces.
#: Built, not spelled, so this source file stays valid UTF-8.
_SURROGATE = chr(0xDCE9)

#: The six printable characters the respelling writes for it: a backslash,
#: then the code point's escape name. Assembled so the source holds no
#: backslash-u sequence a tool could turn back into the character.
_RESPELLED = "\\" + "udce9"


@pytest.fixture
def both_log_files(tmp_path):
    """The real handler pair at DEBUG, and the two files they write.

    Yields ``(logger, read)`` where ``read()`` flushes the handlers and
    returns the tabular and JSON lines texts, read back strict so a raw
    surrogate on disk fails the cell at the read. Handlers are closed and
    detached afterwards, as the configuration tests' fixture does, so the
    throwaway logger leaks nothing into the worker.
    """
    name = "ash_test_log_surrogate"
    logger = get_logger(
        name=name,
        level="DEBUG",
        output_dir=tmp_path,
        log_format="BOTH",
        show_progress=False,
        use_color=False,
        file_log_level="DEBUG",
        truncate_log=True,
        use_stderr=True,
    )

    def read() -> tuple[str, str]:
        for handler in logger.handlers:
            handler.flush()
        tabular = (tmp_path / f"{name}.log").read_text(encoding="utf-8")
        jsonl = (tmp_path / f"{name}.log.jsonl").read_text(encoding="utf-8")
        return tabular, jsonl

    yield logger, read

    plain = logging.getLogger(name)
    for handler in list(plain.handlers):
        handler.close()
        plain.removeHandler(handler)
    plain.filters = []


def test_a_plain_debug_message_reaches_both_files(both_log_files):
    logger, read = both_log_files

    logger.debug(f"the-plain-mark Command stderr: caf{_SURROGATE} tail")

    tabular, jsonl = read()
    for text in (tabular, jsonl):
        assert "the-plain-mark" in text, (
            "the surrogate-bearing record never reached the file"
        )
        assert _RESPELLED in text, "the surrogate's value was lost, not respelled"


def test_the_argument_and_markup_shapes_reach_both_files(both_log_files):
    """The dump sites pass the value through %-args, and some records carry
    markup; both shapes meet the same respelling."""
    logger, read = both_log_files

    logger.debug("the-args-mark Command stderr: %s", f"caf{_SURROGATE} tail")
    logger.debug(f"the-markup-mark output caf{_SURROGATE} end", extra={"markup": True})

    tabular, jsonl = read()
    for text in (tabular, jsonl):
        assert "the-args-mark" in text
        assert "the-markup-mark" in text
        assert text.count(_RESPELLED) >= 2, (
            "a shape lost the surrogate's value instead of respelling it"
        )


def test_a_formatted_exception_with_a_surrogate_reaches_both_files(both_log_files):
    """formatException's text goes through the same respelling as the message,
    so a tool error quoted in a traceback survives too."""
    logger, read = both_log_files

    try:
        raise ValueError(f"caf{_SURROGATE} broke")
    except ValueError:
        logger.debug("the-exception-mark the tool failed", exc_info=True)

    tabular, jsonl = read()
    for text in (tabular, jsonl):
        assert "the-exception-mark" in text
        assert "ValueError" in text
        assert _RESPELLED in text, "the traceback's surrogate was lost"
