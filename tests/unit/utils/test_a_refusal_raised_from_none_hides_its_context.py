# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An error chain is read for redaction and rendered without a suppressed context.

Two sides of one contract. A refusal raised ``from None`` inside its handler
keeps the parser's error as ``__context__`` with ``__suppress_context__`` set,
and every renderer shipped honors the flag, so the parser's words reach no
output. And ``error_text`` keeps reading the whole chain, flag or no flag: that
walk is how a ValidationError QUOTED inside an outer message is found and its
refused inputs replaced, so honoring the flag there would unredact the quote.

Each cell carries its own hazard control that sights the canary, so a cell that
stops seeing canaries at all cannot pass. For every renderer row the control is
the same shape without ``from None``. ``error_text`` prints no member's words on
either shape, so its control is the suppressed context's own message, which
holds the canary the cell must not show; its redaction of a quoted member is
pinned separately below.
"""

from __future__ import annotations

import io
import logging
import traceback

import pytest
import yaml

from automated_security_helper.utils.error_text import error_text, traceback_text

pytestmark = pytest.mark.unit

CANARY = "Abc123canaryQ"
#: A YAML document whose parser message quotes the alias token.
UNPARSABLE = f"api_key: *{CANARY}\n"


def _raised(from_none: bool) -> ValueError:
    try:
        try:
            yaml.safe_load(UNPARSABLE)
        except yaml.YAMLError:
            if from_none:
                raise ValueError("the file could not be parsed") from None
            raise ValueError("the file could not be parsed")
    except ValueError as refusal:
        return refusal
    raise AssertionError("the document parsed")


def _rendered(error: BaseException, show_locals: bool = False) -> str:
    from rich.console import Console
    from rich.traceback import Traceback

    sink = io.StringIO()
    Console(file=sink, width=200, color_system=None).print(
        Traceback.from_exception(
            type(error), error, error.__traceback__, show_locals=show_locals
        )
    )
    return sink.getvalue()


def _logged(error: BaseException) -> str:
    from rich.console import Console
    from rich.logging import RichHandler

    sink = io.StringIO()
    handler = RichHandler(
        console=Console(file=sink, width=200, color_system=None),
        rich_tracebacks=True,
        tracebacks_show_locals=False,
    )
    logger = logging.getLogger("test-chain-rendering")
    logger.handlers[:] = [handler]
    logger.propagate = False
    try:
        raise error
    except ValueError:
        logger.exception("refused")
    return sink.getvalue()


def _console_handled(error: BaseException) -> str:
    """ASH's own console handler, as get_logger attaches it."""
    from rich.console import Console

    from automated_security_helper.utils.log import ConsoleHandler

    sink = io.StringIO()
    handler = ConsoleHandler(
        console=Console(file=sink, width=200, color_system=None),
        rich_tracebacks=True,
        tracebacks_show_locals=False,
    )
    logger = logging.getLogger("test-chain-console-handler")
    logger.handlers[:] = [handler]
    logger.propagate = False
    try:
        raise error
    except ValueError:
        logger.exception("refused")
    return sink.getvalue()


def _record_of(error: BaseException) -> logging.LogRecord:
    return logging.LogRecord(
        "ash",
        logging.ERROR,
        __file__,
        1,
        "refused",
        (),
        (type(error), error, error.__traceback__),
    )


def _text_file_formatted(error: BaseException) -> str:
    """ash.log's tabular formatter."""
    from automated_security_helper.utils.log import TextFileFormatter

    return TextFileFormatter("%(message)s").format(_record_of(error))


def _json_formatted(error: BaseException) -> str:
    """ash.log.jsonl's formatter."""
    from automated_security_helper.utils.log import JsonFormatter

    return JsonFormatter({"message": "message"}).format(_record_of(error))


def _unexpectedly_logged(error: BaseException) -> str:
    """error_text's own logger for an error nothing expected."""
    from automated_security_helper.utils.error_text import log_unexpected_error

    sink = io.StringIO()
    handler = logging.StreamHandler(sink)
    logger = logging.getLogger("test-chain-unexpected")
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    log_unexpected_error(logger, error)
    return sink.getvalue()


RENDERERS = {
    "error_text": lambda e: error_text(e),
    "traceback_text": lambda e: traceback_text(e),
    "format_exception": lambda e: "".join(traceback.format_exception(e)),
    "logging-formatException": lambda e: logging.Formatter().formatException(
        (type(e), e, e.__traceback__)
    ),
    "rich-handler": _logged,
    "rich-traceback": lambda e: _rendered(e),
    "rich-traceback-locals": lambda e: _rendered(e, show_locals=True),
    "ash-console-handler": _console_handled,
    "ash-text-file-formatter": _text_file_formatted,
    "ash-json-formatter": _json_formatted,
    "ash-log-unexpected-error": _unexpectedly_logged,
}


@pytest.mark.parametrize("renderer", sorted(RENDERERS))
def test_a_refusal_raised_from_none_renders_without_its_context(renderer):
    read = RENDERERS[renderer]
    # The hazard: without from None, a renderer that walks the context shows
    # the parser's words. error_text reads only the outer message on either
    # shape, so its control is the suppressed context's own message, which
    # does hold the canary this cell must not show.
    if renderer == "error_text":
        assert CANARY in str(_raised(from_none=True).__context__)
    else:
        assert CANARY in read(_raised(from_none=False)), renderer

    assert CANARY not in read(_raised(from_none=True)), renderer


def test_error_text_redacts_a_quote_of_a_suppressed_context():
    """The chain is read past ``__suppress_context__``: a message that quotes a
    ValidationError raised ``from None`` still has the quote's inputs replaced
    (utils/error_text.py's ``_chain``)."""
    from pydantic import BaseModel

    class Model(BaseModel):
        count: int

    try:
        try:
            Model.model_validate({"count": CANARY})
        except Exception as inner:
            raise ValueError(f"refused: {inner}") from None
    except ValueError as outer:
        refusal = outer

    # The hazard: the message itself holds the input.
    assert CANARY in str(refusal)
    described = error_text(refusal)
    assert CANARY not in described, described
    assert "count" in described, described
