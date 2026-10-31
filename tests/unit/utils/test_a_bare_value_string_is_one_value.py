# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``values`` argument given as one string is one value, wherever it is taken.

The run's environment values are passed as ``values: Iterable[str]``, and a
str is an iterable of strings too: one per character. Every function that
turned them into a tuple or a list, iterated them or unpacked them, split a
value given on its own into its characters. Each character is shorter than
any band config_validator.redact_values replaces outside quotes, so the value
then printed whole, and nothing said redaction had stopped.

Each cell gives one function the value as a bare string, and the same value in
a tuple, and pins that both give the same text, which holds no value. One cell
per place the values are materialized, so dropping the one guard there turns
its own cell red.
"""

import logging
import re
import subprocess

import pytest

from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

#: Long enough, and holding a "-", that redaction replaces it anywhere: the
#: cells measure how the value is taken, not the band a short value falls in.
CANARY = "ENVCANARY-bare-9q7x"


@pytest.fixture(autouse=True, scope="module")
def _config_package_imported():
    """The process's first redacting call imports the config package, whose
    plugin registration logs its own lines. Whichever cell made that call saw
    them in its captured records, so the first bare-vs-tuple comparison in a
    worker failed. One warmup here, before any cell, keeps every cell's
    records its own."""
    from automated_security_helper.utils.error_text import text_without_values

    text_without_values("warmup", ("warmup-not-a-value",))


@pytest.fixture
def records():
    """Every record ASH_LOGGER logs during the cell, at any level."""
    collected = []

    class _Collect(logging.Handler):
        def emit(self, record):
            collected.append(record.getMessage())

    handler = _Collect(level=1)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        yield collected
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _raised(error):
    """*error*, raised and caught, so it has a traceback."""
    try:
        raise error
    except Exception as caught:  # noqa: BLE001 -- the cell's own error
        return caught


def _same_as_in_a_tuple(give):
    """``give(values)`` for the bare value and for it in a tuple: the two agree
    and hold no value. The tuple form is the control: it is redacted."""
    bare = give(CANARY)
    in_a_tuple = give((CANARY,))
    assert CANARY not in str(in_a_tuple), in_a_tuple
    assert bare == in_a_tuple, (bare, in_a_tuple)
    return bare


# ---------------------------------------------------------------------------
# The redaction functions themselves
# ---------------------------------------------------------------------------


def test_redact_values_takes_a_bare_value_as_one():
    from automated_security_helper.config.config_validator import redact_values

    _same_as_in_a_tuple(lambda values: redact_values(f"cannot read {CANARY}", values))


def test_text_without_values_takes_a_bare_value_as_one():
    from automated_security_helper.utils.error_text import text_without_values

    _same_as_in_a_tuple(
        lambda values: text_without_values(f"cannot read {CANARY}", values)
    )


def test_error_text_takes_a_bare_value_as_one():
    from automated_security_helper.utils.error_text import error_text

    _same_as_in_a_tuple(
        lambda values: error_text(RuntimeError(f"cannot read {CANARY}"), values)
    )


def test_traceback_text_takes_a_bare_value_as_one():
    from automated_security_helper.utils.error_text import traceback_text

    error = _raised(RuntimeError(f"cannot read {CANARY}"))

    _same_as_in_a_tuple(lambda values: traceback_text(error, values))


def test_log_unexpected_error_takes_a_bare_value_as_one():
    from automated_security_helper.utils.error_text import log_unexpected_error

    error = _raised(RuntimeError(f"cannot read {CANARY}"))

    def logged(values):
        lines = []

        class _Logger:
            def error(self, message, **kwargs):
                lines.append(str(message))

            def debug(self, message, **kwargs):
                lines.append(str(message))

        log_unexpected_error(_Logger(), error, "Error in the cell", values=values)
        return lines

    lines = _same_as_in_a_tuple(logged)
    # The control: the error was logged.
    assert any("Error in the cell" in line for line in lines), lines


def test_pattern_error_text_takes_a_bare_value_as_one():
    from automated_security_helper.utils.error_text import pattern_error_text

    pattern = f"{CANARY}["
    with pytest.raises(re.error) as excinfo:
        re.compile(pattern)

    text = _same_as_in_a_tuple(
        lambda values: pattern_error_text(excinfo.value, pattern, values)
    )
    assert text.startswith("re.error"), text


def test_timeout_limit_token_takes_a_bare_value_as_one():
    """A limit typed from the one value ("067" loads as 67) names the option.
    Split into "0", "6" and "7", no value typed to it, and the number printed."""
    from automated_security_helper.utils.error_text import timeout_limit_token

    assert timeout_limit_token(67, "067") == "the configured scan_timeout"
    assert timeout_limit_token(67, ("067",)) == "the configured scan_timeout"


def test_a_carried_bare_value_is_one():
    from automated_security_helper.utils.error_text import (
        carry_environment_values,
        error_text,
    )

    def carried(values):
        error = RuntimeError(f"cannot read {CANARY}")
        carry_environment_values(error, values)
        return error_text(error)

    _same_as_in_a_tuple(carried)


def test_a_section_given_a_bare_value_redacts_it_as_one():
    from automated_security_helper.utils.redacted_model import (
        RedactedSection,
        carry_environment_values,
    )

    class _Section(RedactedSection):
        path: str = ""

    def shown(values):
        section = _Section(path=CANARY)
        carry_environment_values(section, values)
        return repr(section)

    _same_as_in_a_tuple(shown)


def test_environment_strings_take_a_bare_value_as_one():
    """The readers of a values attribute: a bare string there is one value too,
    not none (which redacted nothing) and not its characters."""
    from automated_security_helper.utils.error_text import config_environment_values
    from automated_security_helper.utils.redacted_model import environment_strings

    class _Config:
        _environment_values = CANARY

    assert environment_strings(CANARY) == (CANARY,)
    assert config_environment_values(_Config()) == (CANARY,)


def test_a_path_of_environment_values_is_one_value(monkeypatch, records):
    """A path value is a value too: a bare ``os.PathLike`` is one value
    (``os.fspath``), and a PathLike entry inside an iterable is converted
    rather than filtered out. An environment-chosen directory is the common
    value a command line and a report both print."""
    from pathlib import Path

    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.error_text import text_without_values
    from automated_security_helper.utils.redacted_model import environment_strings

    path_value = Path(f"/scans/{CANARY}-dir")

    # The normalizer's contract.
    assert environment_strings(path_value) == (str(path_value),)
    assert environment_strings([path_value, "kept-value"]) == (
        str(path_value),
        "kept-value",
    )

    # A report printer.
    for values in (path_value, [path_value]):
        redacted = text_without_values(f"wrote report under {path_value}", values)
        assert CANARY not in redacted, redacted
        assert "<value>" in redacted, redacted

    # The run_command line.
    def _fails(args, **kwargs):
        return subprocess.CompletedProcess(args, 2, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _fails)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    for values in (path_value, [path_value]):
        records.clear()
        subprocess_utils.run_command(
            ["stub-tool", "--output", str(path_value)], values=values
        )
        lines = [line for line in records if "Running command:" in line]
        assert lines, records
        assert all(CANARY not in line for line in lines), lines


def test_the_normalizer_takes_any_iterable_and_filters_junk():
    """Pins of the normalizer's handling, one per arm: an iterable that is not
    a list or tuple still yields its values (a generator here), and entries
    that cannot be needles (empty strings, non-strings) are dropped."""
    from automated_security_helper.utils.redacted_model import environment_strings

    assert environment_strings(value for value in (CANARY, "second-value")) == (
        CANARY,
        "second-value",
    )
    assert environment_strings((CANARY, "", 7, None)) == (CANARY,)
    assert environment_strings(7) == ()


def test_a_path_that_will_not_fspath_still_redacts(monkeypatch, records):
    """A PathLike whose ``__fspath__`` raises, or gives bytes, is still a value:
    its text is taken another way rather than the entry being dropped, which
    printed it in clear."""
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.redacted_model import environment_strings

    raising_text = f"/scans/{CANARY}-raising/keys.toml"
    bytes_text = f"/scans/{CANARY}-bytes/keys.toml"

    class _RaisingPath:
        def __fspath__(self):
            raise OSError("cannot spell this path")

        def __str__(self):
            return raising_text

    class _BytesPath:
        def __fspath__(self):
            return bytes_text.encode()

    import os

    assert isinstance(_RaisingPath(), os.PathLike)

    # The normalizer's contract, bare and inside an iterable.
    assert environment_strings(_RaisingPath()) == (raising_text,)
    assert environment_strings(_BytesPath()) == (bytes_text,)
    assert environment_strings([_RaisingPath(), _BytesPath()]) == (
        raising_text,
        bytes_text,
    )

    # The run_command line, where the dropped entry printed in clear.
    def _fails(args, **kwargs):
        return subprocess.CompletedProcess(args, 2, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _fails)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    for value, text in ((_RaisingPath(), raising_text), (_BytesPath(), bytes_text)):
        records.clear()
        subprocess_utils.run_command(["stub-tool", text], values=value)
        lines = [line for line in records if "Running command:" in line]
        assert lines, records
        assert all(CANARY not in line for line in lines), lines


def test_a_path_with_no_text_at_all_is_dropped_and_nothing_raises():
    """``__fspath__`` and ``__str__`` both raise: there is no text to redact
    with, so the entry is dropped, and the normalizer still returns, because
    its callers are printers."""
    import os

    from automated_security_helper.utils.redacted_model import environment_strings

    class _Unspellable:
        def __fspath__(self):
            raise OSError("cannot spell this path")

        def __str__(self):
            raise RuntimeError("cannot show this path")

    assert isinstance(_Unspellable(), os.PathLike)
    assert environment_strings(_Unspellable()) == ()
    # Beside a value that has text, only that value is kept.
    assert environment_strings([_Unspellable(), CANARY]) == (CANARY,)


# ---------------------------------------------------------------------------
# The places a caller's values are taken before they reach those functions
# ---------------------------------------------------------------------------


def test_the_runners_lines_take_a_bare_value_as_one(tmp_path, monkeypatch, records):
    from automated_security_helper.utils import subprocess_utils

    def _fails(args, **kwargs):
        return subprocess.CompletedProcess(
            args, 2, stdout="", stderr=f"cannot read {CANARY}"
        )

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _fails)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    def logged(values):
        records.clear()
        subprocess_utils.run_command_with_output_handling(
            ["stub-tool", "--config", CANARY], results_dir=tmp_path, values=values
        )
        return list(records)

    lines = _same_as_in_a_tuple(logged)
    # The control: the runner logged the command it ran.
    assert any("Running:" in line and "--config" in line for line in lines), lines


def test_run_command_s_lines_take_a_bare_value_as_one(monkeypatch, records):
    """``run_command(values=...)`` is a public redaction parameter too, and its
    eight logged lines read the caller's values the same way: a bare string is
    one value on the "Running command" line and on the stderr line, never
    characters."""
    from automated_security_helper.utils import subprocess_utils

    def _fails(args, **kwargs):
        return subprocess.CompletedProcess(
            args, 2, stdout="", stderr=f"cannot read {CANARY}"
        )

    monkeypatch.setattr(subprocess_utils, "_runner", lambda sandboxed: _fails)
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)

    def logged(values):
        records.clear()
        subprocess_utils.run_command(["stub-tool", "--config", CANARY], values=values)
        return list(records)

    lines = _same_as_in_a_tuple(logged)
    # The controls: both logged lines are present, with the value replaced.
    assert any("Running command:" in line and "--config" in line for line in lines), (
        lines
    )
    assert any("Command stderr:" in line for line in lines), lines


def test_the_uv_runner_takes_a_bare_value_as_one(monkeypatch):
    from automated_security_helper.utils import uv_tool_runner

    def _spawn_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    monkeypatch.setattr(uv_tool_runner, "spawn_run", _spawn_run)
    runner = uv_tool_runner.UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True

    for values in ("067", ("067",)):
        result = runner.run_tool(
            "stub-tool", args=["--scan"], timeout=67, values=values
        )
        assert "Command timed out after the configured scan_timeout" in result.error, (
            values,
            result.error,
        )


def test_the_dependency_refusal_takes_a_bare_value_as_one():
    from automated_security_helper.cli.dependencies import _refusal_reason

    class _Refusing:
        def missing_dependency_reason(self):
            return f"cannot read {CANARY}"

    reason = _same_as_in_a_tuple(lambda values: _refusal_reason(_Refusing(), values))
    # The control: the plugin's own words are quoted.
    assert reason and "cannot read" in reason, reason


def test_a_failed_container_takes_a_bare_value_as_one():
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    error = _raised(RuntimeError(f"cannot read {CANARY}"))

    def recorded(values):
        container = ScanResultsContainer(scanner_name="stub-scanner")
        container.set_exception(error, values)
        return (container.exception, container.errors)

    exception, errors = _same_as_in_a_tuple(recorded)
    # The control: the error was recorded.
    assert "cannot read" in exception, exception


class _BedrockClient:
    """A Bedrock control-plane client with one active text model, "other-model"."""

    def __init__(self, fails=False):
        self._fails = fails

    def list_inference_profiles(self):
        if self._fails:
            raise RuntimeError(f"cannot list for {CANARY}")
        return {"inferenceProfileSummaries": []}

    def list_foundation_models(self):
        return {
            "modelSummaries": [
                {
                    "modelId": "other-model",
                    "modelLifecycle": {"status": "ACTIVE"},
                    "inputModalities": ["TEXT"],
                    "outputModalities": ["TEXT"],
                    "inferenceTypesSupported": ["ON_DEMAND"],
                }
            ]
        }


def test_the_bedrock_model_list_takes_a_bare_value_as_one(records):
    from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
        get_available_models,
    )

    def logged(values):
        records.clear()
        get_available_models(_BedrockClient(fails=True), values)
        return list(records)

    lines = _same_as_in_a_tuple(logged)
    # The control: the failure was logged.
    assert any("Unexpected error getting available models" in line for line in lines)


def test_the_bedrock_model_check_takes_a_bare_value_as_one():
    from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
        validate_bedrock_model,
    )

    valid, message = _same_as_in_a_tuple(
        lambda values: validate_bedrock_model(_BedrockClient(), CANARY, values=values)
    )
    # The control: the model was not found, and the message says so.
    assert valid is False and "not found" in message, message


def test_the_bedrock_client_takes_a_bare_value_as_one():
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
        BedrockModelClient,
    )

    def redacted(values):
        client = BedrockModelClient(
            bedrock_runtime=None,
            model_id=CANARY,
            temperature=0.0,
            max_tokens=1,
            top_p=1.0,
            values=values,
        )
        return client._redacted(f"*Error invoking {CANARY}*")

    _same_as_in_a_tuple(redacted)


def test_grype_s_path_spellings_take_a_bare_value_as_one():
    from pathlib import Path

    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        _with_path_spellings,
    )

    assert _with_path_spellings(CANARY) == [CANARY]
    # Path() writes the collapsed spelling natively: the same string as the
    # POSIX one off Windows, backslashes on it.
    assert _with_path_spellings("cfg/./grype.yaml") == list(
        dict.fromkeys(
            [
                "cfg/./grype.yaml",
                "cfg/grype.yaml",
                str(Path("cfg/./grype.yaml")),
            ]
        )
    )


def test_a_shard_s_message_takes_a_bare_value_as_one():
    from automated_security_helper.cli.merge import _redact_values

    _same_as_in_a_tuple(lambda values: _redact_values(f"cannot read {CANARY}", values))


def test_the_plugin_loader_takes_a_bare_value_as_one(tmp_path, monkeypatch):
    """An env-read module entry, named in the shown form, whose import raises
    quoting its own dotted name: the loader widens the values with the
    module's path spellings, and the bare value is one of them."""
    import sys

    from automated_security_helper.plugins.loader import load_additional_plugin_modules

    # A top-level package ending in "_ash_plugins" is in the plugin namespace.
    package = "envcanaryq7x9_ash_plugins"
    module = f"{package}.mod"
    (tmp_path / package).mkdir()
    (tmp_path / package / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / package / "mod.py").write_text(
        'raise RuntimeError("cannot load " + __name__)\n', encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    def recorded(values):
        for name in (module, package):
            sys.modules.pop(name, None)
        record = {}
        load_additional_plugin_modules(
            [module], shown={module: "<value>"}, record=record, values=values
        )
        return record[module].recorded

    try:
        text = recorded(module)
        in_a_tuple = recorded((module,))
    finally:
        for name in (module, package):
            sys.modules.pop(name, None)

    # The control: the import's own error is the recorded text.
    assert "cannot load" in in_a_tuple, in_a_tuple
    assert module not in in_a_tuple, in_a_tuple
    assert text == in_a_tuple, (text, in_a_tuple)
