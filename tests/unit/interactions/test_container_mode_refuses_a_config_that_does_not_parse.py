# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode refuses a config file that does not parse before anything starts.

A local scan refuses a config file that does not parse with exit 3, naming the
file. Container mode read the file only inside the container: the host started
the runner (an image build, minutes of work), and the run ended with the
runner's exit code, never naming the file. The host now parse-checks the file
the inner scan would load (the ``--config`` file, else the discovered one; the
file ASH_CONFIG names is handed over separately, as the scan's base, and its
own checks refuse it with their own message) before the runner is resolved:
syntax only, so a file that parses and does not validate is still the
container's to refuse.

Each cell patches ``run_ash_container`` and checks that the refusal exits 3,
names the file, and starts no runner. The refusal gives the error's type and
place, never the parser's own text, which can quote the file's tokens.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

BAD_YAML = "project_name: [unclosed\n"


def _make_opts(tmp_path, **update):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    opts = ScanOptions(source_dir=src, output_dir=out, mode=RunMode.container)
    return opts.model_copy(update=update) if update else opts


def _refused(opts, capsys, name: str):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanRefusedExit,
        _run_container_mode,
    )

    runner = MagicMock()
    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        runner,
    ):
        with pytest.raises(ScanRefusedExit) as refused:
            _run_container_mode(opts, MagicMock())

    assert refused.value.code == 3
    assert runner.call_count == 0, "the runner was started for a refused config"
    output = capsys.readouterr().out
    assert name in output, output
    return output


def test_a_config_named_with_dash_dash_config(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "broken.yaml"
    config.write_text(BAD_YAML, encoding="utf-8")
    opts = _make_opts(tmp_path, config=str(config))

    _refused(opts, capsys, "broken.yaml")


def test_a_config_that_cannot_be_read_is_described_as_unread(
    tmp_path, monkeypatch, capsys
):
    """The pre-parse's read failure says the file could not be read, never that
    it could not be parsed: a reader sent to fix the syntax finds nothing wrong
    with it."""
    import os as _os

    if _os.name == "nt" or (hasattr(_os, "geteuid") and _os.geteuid() == 0):
        pytest.skip("needs POSIX permission bits, which root reads past")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "unreadable.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")
    config.chmod(0)
    opts = _make_opts(tmp_path, config=str(config))

    try:
        output = _refused(opts, capsys, "unreadable.yaml")
    finally:
        config.chmod(0o600)

    assert "could not be read" in output, output
    assert "parsed" not in output, output


def test_a_file_ash_config_names_is_not_the_pre_check_s(tmp_path, monkeypatch, capsys):
    """The pre-check parses what the inner scan loads as its config, the
    --config file else the discovered one, never the file ASH_CONFIG names.
    That file is still refused with exit 3 -- it is mounted as the scan's
    base, and a file whose variables cannot be read cannot be handed over --
    but by the input handoff, whose message says the variables could not be
    read, not by this pre-check, whose message gives a parse error's type and
    place."""
    from automated_security_helper.interactions.run_ash_scan import (
        _run_container_mode,
    )

    config = tmp_path / "operator-broken.yaml"
    config.write_text(BAD_YAML, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))
    opts = _make_opts(tmp_path)

    runner = MagicMock()
    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        new=runner,
    ):
        with pytest.raises(SystemExit) as refused:
            _run_container_mode(opts, MagicMock())

    assert refused.value.code == 3
    assert runner.call_count == 0
    message = capsys.readouterr().err
    assert "Could not read the variables" in message, message
    assert "could not be parsed" not in message, message


def test_the_cli_reads_ash_config_as_the_config_option_and_refuses(
    tmp_path, monkeypatch
):
    """At the CLI, ``--config`` reads ASH_CONFIG when the flag is absent, so a
    broken ASH_CONFIG becomes the --config file there: ``ash scan --mode
    container`` refuses it with exit 3, naming the file, before any runner is
    resolved. The cell above holds at the layer below, where ASH_CONFIG is not
    routed into the options."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    config = tmp_path / "operator-broken.yaml"
    config.write_text(BAD_YAML, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out"

    runner = MagicMock()
    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        runner,
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--mode",
                "container",
                "--source-dir",
                str(src),
                "--output-dir",
                str(out),
            ],
        )

    assert result.exit_code == 3, result.output
    assert "operator-broken.yaml" in result.output, result.output
    assert runner.call_count == 0, "the runner was started for a refused config"


def test_the_discovered_file_is_checked_even_with_ash_config_set(
    tmp_path, monkeypatch, capsys
):
    """With ASH_CONFIG set, the pre-check still parses
    the discovered file, since that is the one the inner scan loads."""
    valid = tmp_path / "valid.yaml"
    valid.write_text("project_name: t\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(valid))
    opts = _make_opts(tmp_path)
    nested = Path(opts.source_dir) / ".ash"
    nested.mkdir()
    (nested / ".ash.yaml").write_text(BAD_YAML, encoding="utf-8")

    _refused(opts, capsys, ".ash.yaml")


def test_a_discovered_config(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _make_opts(tmp_path)
    nested = Path(opts.source_dir) / ".ash"
    nested.mkdir()
    (nested / ".ash.yaml").write_text(BAD_YAML, encoding="utf-8")

    _refused(opts, capsys, ".ash.yaml")


def test_the_refusal_quotes_no_token_of_the_file(tmp_path, monkeypatch, capsys):
    """The parser's own problem text can quote a token of the file (an alias,
    a tag), so the refusal gives the error's type and place instead."""
    import secrets

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    canary = "ashv" + secrets.token_hex(12)
    config = tmp_path / "aliased.yaml"
    config.write_text(f"project_name: *{canary}\n", encoding="utf-8")
    opts = _make_opts(tmp_path, config=str(config))

    output = _refused(opts, capsys, "aliased.yaml")

    assert canary not in output, "the refusal quotes the file's token"


def test_no_run_skips_the_parse_check(tmp_path, monkeypatch):
    """With --no-run the container never starts and the inner scan
    never loads the config, so the pre-check gates on ``opts.run`` like every
    other container pre-check instead of refusing a file the run never reads."""
    from automated_security_helper.interactions.run_ash_scan import (
        _refuse_a_container_config_that_does_not_parse,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "broken.yaml"
    config.write_text(BAD_YAML, encoding="utf-8")
    opts = _make_opts(tmp_path, config=str(config), run=False)

    # Returns instead of raising ScanRefusedExit.
    _refuse_a_container_config_that_does_not_parse(opts)


def test_no_run_skips_the_container_input_refusal(tmp_path, monkeypatch):
    """A build-only run (--no-run) mounts nothing and reads no config, so the
    container-input pre-check gates on ``opts.run`` as the parse check above
    does: ASH_CONFIG naming a missing file refuses a scan, never an image
    build."""
    import subprocess

    from automated_security_helper.interactions.run_ash_scan import (
        _run_container_mode,
    )

    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "missing.yaml"))
    opts = _make_opts(tmp_path, run=False)

    runner = MagicMock(
        return_value=subprocess.CompletedProcess(
            args=["build"], returncode=0, stdout="", stderr=""
        )
    )
    with patch(
        "automated_security_helper.interactions.run_ash_scan.run_ash_container",
        runner,
    ):
        with pytest.raises(SystemExit) as finished:
            _run_container_mode(opts, MagicMock())

    assert finished.value.code == 0
    assert runner.call_count == 1, "the image build was refused over a scan input"
    assert runner.call_args.kwargs["run"] is False


def test_a_config_that_is_not_utf8_is_refused_at_the_byte_offset(
    tmp_path, monkeypatch, capsys
):
    """The pre-check speaks the shared refusal's words for a file that is
    not UTF-8, "(not UTF-8 at byte offset N)", never the decoder's type alone
    and never its message, which prints the byte's value."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "latin1.yaml"
    config.write_bytes("project_name: café\n".encode("latin-1"))
    opts = _make_opts(tmp_path, config=str(config))

    output = _refused(opts, capsys, "latin1.yaml")

    assert "could not be parsed" in output, output
    assert "not UTF-8 at byte offset" in output, output
    assert "UnicodeDecodeError" not in output, output
    assert "can't decode" not in output, output


@pytest.mark.parametrize(
    "name,content",
    [
        ("broken.yaml", BAD_YAML),
        ("broken.json", '{"project_name": ,}\n'),
    ],
    ids=["yaml", "json"],
)
def test_the_refusal_is_the_shared_formatter_s_sentence(
    tmp_path, monkeypatch, capsys, name, content
):
    """The pre-check's wording is unparsed_config_reason's, computed from
    the same parse it runs, so every surface describes an unparsed config in
    the same words."""
    import json as json_module

    import yaml

    from automated_security_helper.config.config_sources import unparsed_config_reason

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / name
    config.write_text(content, encoding="utf-8")
    expected = ""
    try:
        if name.endswith(".json"):
            json_module.loads(content)
        else:
            yaml.compose(content)
    except json_module.JSONDecodeError as error:
        # The exact parenthetical from the error's own fields, not through the
        # formatter: an identity computed through the formatter would also
        # accept whatever a changed formatter adds between the type and the
        # place.
        expected = (
            f"{config} could not be parsed (JSONDecodeError: {error.msg} "
            f"at line {error.lineno}, column {error.colno})"
        )
    except yaml.YAMLError as error:
        expected = unparsed_config_reason(config, error)
    assert expected, "the fixture content must not parse"
    opts = _make_opts(tmp_path, config=str(config))

    output = _refused(opts, capsys, name)

    assert expected in output, (expected, output)


def test_a_toml_config_that_does_not_parse_is_refused(tmp_path, monkeypatch, capsys):
    """The TOML arm of the pre-check: a syntax error is refused with exit 3,
    naming the file, like the YAML and JSON arms."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "broken.toml"
    config.write_text('project_name = "demo\n[[broken\n', encoding="utf-8")
    opts = _make_opts(tmp_path, config=str(config))

    _refused(opts, capsys, "broken.toml")


def test_a_toml_config_with_a_byte_order_mark_reaches_the_runner(tmp_path, monkeypatch):
    """The scan's own TOML reader drops a leading UTF-8 byte order mark
    (config_sources._read_toml_text), which tomllib rejects, so the pre-check
    parses the text that reader hands the parser: a marked file the scan
    loads is not refused on the host, and the runner starts."""
    from automated_security_helper.interactions.run_ash_scan import (
        _run_container_mode,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # Inside the source directory: container mode refuses a --config outside
    # it (the mounts are /src and /out only), and this cell measures the
    # byte-order-mark parse, not that refusal.
    config = tmp_path / "src" / "with-mark.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    mark = chr(0xFEFF)  # ZERO WIDTH NO-BREAK SPACE, the byte order mark
    config.write_text(mark + 'project_name = "demo"\n', encoding="utf-8")
    opts = _make_opts(tmp_path, config=str(config))
    results_file = Path(opts.output_dir) / "ash_aggregated_results.json"

    def fake_run_ash_container(**kwargs):
        results_file.write_text('{"sarif": null, "scanners": []}', encoding="utf-8")
        done = MagicMock()
        done.returncode = 0
        return done

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            side_effect=fake_run_ash_container,
        ) as runner,
        patch(
            "automated_security_helper.interactions.run_ash_scan"
            ".AshAggregatedResults.model_validate_json",
            return_value=MagicMock(),
        ),
    ):
        _run_container_mode(opts, MagicMock())

    assert runner.call_count == 1


def test_control_a_config_that_parses_reaches_the_runner(tmp_path, monkeypatch):
    """Syntax only: a file that parses, valid or not, is the container's to
    judge, and the runner starts."""
    from automated_security_helper.interactions.run_ash_scan import (
        _run_container_mode,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # Inside the source directory, as the byte-order-mark cell above: this
    # cell measures the syntax-only rule, not the mount-rule refusal.
    config = tmp_path / "src" / "parses.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("project_name: demo\n", encoding="utf-8")
    opts = _make_opts(tmp_path, config=str(config))
    results_file = Path(opts.output_dir) / "ash_aggregated_results.json"

    def fake_run_ash_container(**kwargs):
        results_file.write_text('{"sarif": null, "scanners": []}', encoding="utf-8")
        done = MagicMock()
        done.returncode = 0
        return done

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            side_effect=fake_run_ash_container,
        ) as runner,
        patch(
            "automated_security_helper.interactions.run_ash_scan"
            ".AshAggregatedResults.model_validate_json",
            return_value=MagicMock(),
        ),
    ):
        _run_container_mode(opts, MagicMock())

    assert runner.call_count == 1


def test_control_no_config_found_reaches_the_runner(tmp_path, monkeypatch):
    """With nothing to check, the pre-parse refuses nothing."""
    from automated_security_helper.interactions.run_ash_scan import (
        _run_container_mode,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _make_opts(tmp_path)
    results_file = Path(opts.output_dir) / "ash_aggregated_results.json"

    def fake_run_ash_container(**kwargs):
        results_file.write_text('{"sarif": null, "scanners": []}', encoding="utf-8")
        done = MagicMock()
        done.returncode = 0
        return done

    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            side_effect=fake_run_ash_container,
        ) as runner,
        patch(
            "automated_security_helper.interactions.run_ash_scan"
            ".AshAggregatedResults.model_validate_json",
            return_value=MagicMock(),
        ),
    ):
        _run_container_mode(opts, MagicMock())

    assert runner.call_count == 1
