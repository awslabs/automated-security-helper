"""Regression tests: Rich markup must not destroy diagnostic output.

The bug these cover: ASH logs a failing command and that command's own output
through a ``RichHandler`` built with ``markup=True`` (see
``utils/log.py::setup_logging``). Rich parses ``[...]`` in the *message* as
markup, so bracketed text arriving from a subprocess is interpreted instead of
printed -- and it is interpreted precisely when a scan has failed and the output
is the only thing explaining why.

There are two failure modes, and they need separate coverage because only one of
them raises:

* A bracketed span whose body starts with ``/`` reads as a *closing* tag.
  ``rich.markup.render`` raises ``MarkupError``, ``RichHandler.emit`` does not
  catch it, and ``logging.Handler.handle`` does not either -- so the exception
  replaces the report being formatted. Worse, it escapes before the file
  handlers registered later in ``setup_logging`` ever see the record, so the
  message is absent from ``*.log.jsonl`` too. Observed in CI job 105289559888,
  where the destroyed traceback was the one explaining a failed container build.

* A bracketed span whose body starts with a lowercase letter, ``#`` or ``@``
  reads as an *opening* tag. Nothing raises; Rich simply consumes the span as a
  style name and the text disappears from the output. ``semgrep --exclude
  [node_modules]`` logs as ``semgrep --exclude``. A silently truncated command
  line is harder to notice than a crash.

Rich's tag pattern is ``\\[([a-z#/@][^[]*?)]``, so ``[0]``, ``[B404]`` and
``['/bin/bash', '-c']`` (a Python argv repr -- the quote is not in that class)
are all inert. Only the four leading characters above matter, which is why the
fixtures below use real strings from a real failure rather than invented ones.

The fix is at the sink, with an opt-in for the few messages that style
themselves:

* The console handler is built with ``markup=False`` (utils/log.py), so every
  record is text unless it passes ``extra=MARKUP``. ``RichHandler.render_message``
  reads ``getattr(record, "markup", self.markup)``. ``extra=NO_MARKUP`` still
  works and changes nothing. The message string is never rewritten, so the JSONL
  and tabular file logs stay byte-exact, which ``test_file_log_is_not_rewritten``
  guards.
* Messages that do style part of themselves pass ``extra=MARKUP`` and escape
  only the untrusted value, so the styling still renders; the file handlers
  write such a record as the text it shows.

The fixture below builds the handlers get_logger builds (ConsoleHandler, the
tabular TextFileFormatter), not a RichHandler with markup on, so these tests
exercise the production sink. TestEachMarkupSiteUnderTheRealSink logs through
each extra=MARKUP site with "[/x]" in its path, rule and reason.
"""

import io
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    ConsoleHandler,
    TextFileFormatter,
)


# The exact line podman/buildah writes to stderr while building the ASH image.
# buildah renders the Dockerfile SHELL directive's argv as a Go slice, which is
# where the brackets come from -- ASH never formatted a command this way.
BUILDAH_SHELL_WARNING = (
    'time="2026-09-17T16:41:18Z" level=warning msg="SHELL is not supported for '
    'OCI image format, [/bin/bash -c] will be ignored. Must use `docker` format"'
)
CLOSING_TAG_PAYLOAD = "[/bin/bash -c]"

# A scanner argument that reads as an opening tag.
OPEN_TAG_PAYLOAD = "[node_modules]"


@pytest.fixture(autouse=True)
def _unresolved_names_reach_the_mocked_spawn(monkeypatch):
    """Hand names that resolve nowhere to the mocked spawn on every platform.

    These tests replace the process boundary and pass it programs that are not
    installed. On Windows ASH refuses such a name before spawning it
    (subprocess_utils._refuse_unresolved_on_windows); these tests are about what
    happens after the spawn, so that decision is set aside here.
    """
    from automated_security_helper.utils import subprocess_utils as _subprocess_utils

    monkeypatch.setattr(_subprocess_utils, "_refuse_unresolved_on_windows", False)


@pytest.fixture
def rich_capture(tmp_path):
    """Capture ASH_LOGGER through the handler stack ``setup_logging`` builds.

    Both handler kinds are attached, and the Rich one first, so the ordering
    matches production: an exception raised while rendering to the console stops
    the file handler from running.
    """
    console_buffer = io.StringIO()
    rich_handler = ConsoleHandler(
        # color_system=None keeps assertions on plain text; with colors on, Rich
        # interleaves escape sequences inside a word and a substring check on the
        # payload fails even when the payload survived.
        console=ash_console(file=console_buffer, width=250, color_system=None),
        markup=False,
        show_time=False,
        show_path=False,
    )
    rich_handler.setFormatter(logging.Formatter("%(message)s"))

    log_file = tmp_path / "ash.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(TextFileFormatter("%(message)s"))

    saved_handlers = list(ASH_LOGGER.handlers)
    saved_level = ASH_LOGGER.level
    ASH_LOGGER.handlers = [rich_handler, file_handler]
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield console_buffer, log_file
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.setLevel(saved_level)
        file_handler.close()


def _completed(returncode=1, stdout="", stderr=""):
    """A CompletedProcess stand-in for a patched plain runner (``_run_plain``)."""
    import subprocess

    return subprocess.CompletedProcess(
        args=["scanner"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestClosingTagInSubprocessOutput:
    """A subprocess's own bracketed output must not abort the log record."""

    def test_run_command_survives_closing_tag_in_stderr(self, rich_capture):
        from automated_security_helper.utils import subprocess_utils

        console_buffer, _ = rich_capture

        with patch.object(
            subprocess_utils,
            "_run_plain",
            return_value=_completed(stderr=BUILDAH_SHELL_WARNING),
        ):
            # Before the fix this raises MarkupError out of the logging call
            # rather than returning, so the caller never sees the exit code
            # either.
            result = subprocess_utils.run_command(["podman", "build", "."])

        assert result.returncode == 1
        assert CLOSING_TAG_PAYLOAD in console_buffer.getvalue()

    def test_run_command_survives_closing_tag_in_the_command_itself(self, rich_capture):
        from automated_security_helper.utils import subprocess_utils

        console_buffer, _ = rich_capture

        # A path segment that reads as a closing tag. Contrived-looking, but it
        # is the same shape as the podman warning and it exercises the cmd_str
        # sites rather than the stderr ones.
        args = ["semgrep", "--config", "/rules/[/legacy]/all.yml"]
        with patch.object(
            subprocess_utils, "_run_plain", return_value=_completed(returncode=0)
        ):
            subprocess_utils.run_command(args)

        assert "[/legacy]" in console_buffer.getvalue()


class TestOpeningTagIsNotSilentlyDropped:
    """The quiet half of the bug: no exception, the text just vanishes."""

    def test_command_argument_reading_as_open_tag_is_preserved(self, rich_capture):
        from automated_security_helper.utils import subprocess_utils

        console_buffer, _ = rich_capture

        args = ["semgrep", "--exclude", OPEN_TAG_PAYLOAD, "--config", "p/ci"]
        with patch.object(
            subprocess_utils, "_run_plain", return_value=_completed(returncode=0)
        ):
            subprocess_utils.run_command(args)

        output = console_buffer.getvalue()
        assert OPEN_TAG_PAYLOAD in output, (
            "Rich consumed the bracketed argument as a style tag and dropped it "
            f"from the logged command line: {output!r}"
        )

    def test_stderr_reading_as_open_tag_is_preserved(self, rich_capture):
        from automated_security_helper.utils import subprocess_utils

        console_buffer, _ = rich_capture

        stderr = f"error: cannot read {OPEN_TAG_PAYLOAD}/pkg: permission denied"
        with patch.object(
            subprocess_utils,
            "_run_plain",
            return_value=_completed(stderr=stderr),
        ):
            subprocess_utils.run_command(["npm", "audit"])

        assert OPEN_TAG_PAYLOAD in console_buffer.getvalue()


class TestFileLogIsNotRewritten:
    """Guards the fix mechanism, not just its effect.

    Escaping the message string would also make the console assertions above
    pass, while writing ``\\[/bin/bash -c\\]`` into the log file operators read.
    """

    def test_file_log_keeps_the_payload_verbatim(self, rich_capture):
        from automated_security_helper.utils import subprocess_utils

        _, log_file = rich_capture

        with patch.object(
            subprocess_utils,
            "_run_plain",
            return_value=_completed(stderr=BUILDAH_SHELL_WARNING),
        ):
            subprocess_utils.run_command(["podman", "build", "."])

        written = Path(log_file).read_text()
        assert CLOSING_TAG_PAYLOAD in written
        assert "\\[" not in written, (
            "the message string was escaped rather than the record marked "
            f"non-markup, so the file log now carries escape characters: {written!r}"
        )


class TestIntentionalStylingStillWorks:
    """Where a message does style itself, only the untrusted value is escaped."""

    def test_suppression_reason_keeps_styling_and_untrusted_rule_id(self, rich_capture):
        from automated_security_helper.models.core import AshSuppression
        from automated_security_helper.models.flat_vulnerability import (
            FlatVulnerability,
        )
        from automated_security_helper.utils.sarif_utils import (
            _apply_config_suppression,
        )
        from automated_security_helper.schemas.sarif_schema_model import (
            Message,
            Result,
        )

        console_buffer, _ = rich_capture

        # A file path that reads as a closing tag, on the suppression log line
        # that wraps its reason in [yellow].
        file_path = "src/[/vendor]/foo.py"
        result = Result(ruleId="B108", message=Message(text="msg"))
        suppression = AshSuppression(
            rule_id="B108", path=file_path, reason="accepted risk"
        )
        flat = FlatVulnerability(
            id="abc",
            title="t",
            description="d",
            severity="MEDIUM",
            scanner="test",
            scanner_type="SAST",
            rule_id="B108",
            file_path=file_path,
        )

        applied = _apply_config_suppression(result, [suppression], flat, set())

        assert applied is True
        output = console_buffer.getvalue()
        assert "[/vendor]" in output
        # The styling tag must have been consumed as markup, not printed.
        assert "[yellow]" not in output
        assert "accepted risk" in output


def _assert_logged_as_text(console_buffer, log_file, expected: str) -> None:
    """The console shows *expected* styled, the file writes it plain; neither shows
    a tag or an escape."""
    shown = " ".join(console_buffer.getvalue().split())
    written = Path(log_file).read_text(encoding="utf-8")
    assert " ".join(expected.split()) in shown, shown
    assert expected in written, written
    for output in (shown, written):
        assert "[yellow]" not in output, output
        assert "\\[" not in output, output


class TestEachMarkupSiteUnderTheRealSink:
    """Each extra=MARKUP log call, with "[/x]" in what it quotes, under the real sink.

    Dropping a site's extra=MARKUP prints its [yellow] tags; dropping one of its
    escape_markup calls raises MarkupError or drops text. Both fail here.
    """

    def test_a_config_suppression(self, rich_capture):
        from automated_security_helper.models.core import AshSuppression
        from automated_security_helper.models.flat_vulnerability import (
            FlatVulnerability,
        )
        from automated_security_helper.schemas.sarif_schema_model import (
            Message,
            Result,
        )
        from automated_security_helper.utils.sarif_utils import (
            _apply_config_suppression,
        )

        console_buffer, log_file = rich_capture
        rule, path, reason = "B[/x]108", "src/[/x]/foo.py", "accepted [/x] risk"
        result = Result(ruleId=rule, message=Message(text="msg"))
        # The suppression's rule id is a glob, where "[/x]" is a character class.
        suppression = AshSuppression(rule_id="B*", path=path, reason=reason)
        flat = FlatVulnerability(
            id="abc",
            title="t",
            description="d",
            severity="MEDIUM",
            scanner="test",
            scanner_type="SAST",
            rule_id=rule,
            file_path=path,
        )

        assert _apply_config_suppression(result, [suppression], flat, set()) is True
        _assert_logged_as_text(
            console_buffer,
            log_file,
            f"Suppressing rule '{rule}' on location '{path}' based on suppression "
            f"rule: {reason}",
        )

    def test_an_inline_suppression(self, rich_capture, tmp_path):
        from automated_security_helper.schemas.sarif_schema_model import (
            Message,
            Result,
        )
        from automated_security_helper.utils.sarif_utils import (
            _apply_inline_suppression,
        )

        console_buffer, log_file = rich_capture
        source = tmp_path / "source"
        (source / "pkg[" / "x]").mkdir(parents=True)
        uri = "pkg[/x]/app.py"
        (source / uri).write_text(
            "value = 1  # ash-ignore: B108 accepted [/x] risk\n", encoding="utf-8"
        )
        result = Result(ruleId="B108", message=Message(text="msg"))

        assert _apply_inline_suppression(result, uri, source, 1, {}) is True
        _assert_logged_as_text(
            console_buffer,
            log_file,
            f"Suppressing rule 'B108' at line 1 in '{uri}' via inline comment: "
            "accepted [/x] risk",
        )

    def test_an_ignore_path(self, rich_capture, tmp_path):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.models.core import IgnorePathWithReason
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Location,
            Message,
            PhysicalLocation2,
            Region,
            Result,
            Run,
            SarifReport,
            Tool,
            ToolComponent,
        )
        from automated_security_helper.utils.sarif_utils import (
            apply_suppressions_to_sarif,
        )

        console_buffer, log_file = rich_capture
        uri, rule, reason = "vendor[/x]/lib.py", "RULE[/x]-1", "vendored [/x] code"
        sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="Test Scanner", version="1")),
                    results=[
                        Result(
                            ruleId=rule,
                            message=Message(text="finding"),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(uri=uri),
                                        region=Region(startLine=1, endLine=1),
                                    )
                                )
                            ],
                        )
                    ],
                )
            ],
        )
        (tmp_path / "source").mkdir()
        (tmp_path / "output").mkdir()
        config = AshConfig(
            project_name="p",
            global_settings={
                "ignore_paths": [
                    IgnorePathWithReason(path="vendor[/x]/**", reason=reason)
                ]
            },
        )
        context = PluginContext(
            source_dir=tmp_path / "source",
            output_dir=tmp_path / "output",
            config=config,
        )

        filtered = apply_suppressions_to_sarif(sarif, context)

        assert filtered.runs[0].results == [], filtered.runs[0].results
        _assert_logged_as_text(
            console_buffer,
            log_file,
            f"Ignoring finding on rule '{rule}' file location '{uri}' based on "
            f"ignore_path match with global reason: {reason}",
        )
