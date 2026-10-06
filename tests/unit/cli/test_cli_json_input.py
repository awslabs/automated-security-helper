# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--cli-json-input`` and ``--generate-cli-skeleton`` (issue #290).

The scan tests drive the real ``ashx`` Typer app through ``CliRunner`` with
``run_ash_scan`` patched out, so what is asserted is the value the scan command
would have handed to the scan, after click has parsed, cast and defaulted it.
That is the only place a precedence bug or a skipped type check is visible.

The drift tests build a throwaway Typer app with the same command class, so
they show that a parameter nobody wrote JSON-input code for is still accepted,
validated and listed in the skeleton.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest
import typer
import typer.utils
from typer.testing import CliRunner

from automated_security_helper.cli.json_input import CliJsonInputCommand
from automated_security_helper.cli.main import app
from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.core.enums import ExecutionStrategy, RunMode

RUN_ASH_SCAN = "automated_security_helper.cli.scan.run_ash_scan"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _write(tmp_path: Path, payload: object, name: str = "params.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _scan_kwargs(mock_run) -> dict:
    assert mock_run.call_count == 1, "the scan was not invoked"
    return mock_run.call_args.kwargs


class TestScanJsonInput:
    def test_json_only_invocation(self, runner, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        params = _write(
            tmp_path,
            {
                "source_dir": src.as_posix(),
                "output_dir": (tmp_path / "out").as_posix(),
                "scanners": ["bandit", "semgrep"],
                "strategy": "sequential",
                "offline": True,
                "mode": "local",
            },
        )
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app, ["scan", "--cli-json-input", f"file://{params}"]
            )
        assert result.exit_code == 0, result.output
        kwargs = _scan_kwargs(mock_run)
        assert kwargs["source_dir"] == src.as_posix()
        assert kwargs["output_dir"] == (tmp_path / "out").as_posix()
        assert list(kwargs["scanners"]) == ["bandit", "semgrep"]
        # Cast through the click type exactly as the flag would be: an enum, not
        # the string that was in the file.
        assert kwargs["strategy"] == ExecutionStrategy.SEQUENTIAL
        assert kwargs["offline"] is True
        assert kwargs["mode"] == RunMode.local

    def test_plain_path_is_accepted_as_well_as_file_uri(self, runner, tmp_path):
        params = _write(tmp_path, {"offline": True})
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(params)])
        assert result.exit_code == 0, result.output
        assert _scan_kwargs(mock_run)["offline"] is True

    def test_flag_spelling_keys_are_accepted(self, runner, tmp_path):
        params = _write(
            tmp_path,
            {"--strategy": "sequential", "--python-only": True, "--formats": ["sarif"]},
        )
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(params)])
        assert result.exit_code == 0, result.output
        kwargs = _scan_kwargs(mock_run)
        assert kwargs["strategy"] == ExecutionStrategy.SEQUENTIAL
        assert kwargs["python_based_plugins_only"] is True
        assert [f.value for f in kwargs["output_formats"]] == ["sarif"]

    def test_explicit_flags_override_json(self, runner, tmp_path):
        params = _write(
            tmp_path,
            {
                "strategy": "sequential",
                "scanners": ["bandit", "semgrep"],
                "offline": True,
                "config_overrides": ["global_settings.severity_threshold=LOW"],
            },
        )
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--cli-json-input",
                    str(params),
                    "--strategy",
                    "parallel",
                    "--scanners",
                    "checkov",
                    "--no-offline",
                ],
            )
        assert result.exit_code == 0, result.output
        kwargs = _scan_kwargs(mock_run)
        assert kwargs["strategy"] == ExecutionStrategy.PARALLEL
        # A list flag on the command line replaces the JSON list; it does not
        # extend it.
        assert list(kwargs["scanners"]) == ["checkov"]
        assert kwargs["offline"] is False
        # Keys the command line did not mention still come from the file.
        assert kwargs["config_overrides"] == ["global_settings.severity_threshold=LOW"]

    def test_flag_order_relative_to_json_flag_does_not_matter(self, runner, tmp_path):
        params = _write(tmp_path, {"strategy": "sequential"})
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                ["scan", "--strategy", "parallel", "--cli-json-input", str(params)],
            )
        assert result.exit_code == 0, result.output
        assert _scan_kwargs(mock_run)["strategy"] == ExecutionStrategy.PARALLEL

    def test_json_overrides_environment_variable(self, runner, tmp_path):
        src = tmp_path / "from-json"
        src.mkdir()
        params = _write(tmp_path, {"source_dir": src.as_posix()})
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                ["scan", "--cli-json-input", str(params)],
                env={"ASH_SOURCE_DIR": (tmp_path / "from-env").as_posix()},
            )
        assert result.exit_code == 0, result.output
        assert _scan_kwargs(mock_run)["source_dir"] == src.as_posix()

    def test_environment_variable_still_applies_to_keys_json_omits(
        self, runner, tmp_path
    ):
        env_src = tmp_path / "from-env"
        env_src.mkdir()
        params = _write(tmp_path, {"offline": True})
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                ["scan", "--cli-json-input", str(params)],
                env={"ASH_SOURCE_DIR": env_src.as_posix()},
            )
        assert result.exit_code == 0, result.output
        assert _scan_kwargs(mock_run)["source_dir"] == env_src.as_posix()

    def test_null_value_means_not_provided(self, runner, tmp_path):
        params = _write(tmp_path, {"strategy": None, "offline": True})
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(params)])
        assert result.exit_code == 0, result.output
        assert _scan_kwargs(mock_run)["strategy"] == ExecutionStrategy.PARALLEL

    def test_stdin_input(self, runner):
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                ["scan", "--cli-json-input", "-"],
                input=json.dumps({"strategy": "sequential", "offline": True}),
            )
        assert result.exit_code == 0, result.output
        kwargs = _scan_kwargs(mock_run)
        assert kwargs["strategy"] == ExecutionStrategy.SEQUENTIAL
        assert kwargs["offline"] is True


class TestScanJsonInputErrors:
    def _invoke(self, runner, tmp_path, payload):
        params = _write(tmp_path, payload)
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(params)])
        return result, mock_run

    def test_unknown_key_names_the_key_and_valid_ones(self, runner, tmp_path):
        result, mock_run = self._invoke(runner, tmp_path, {"sauce_dir": "x"})
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'sauce_dir'" in result.output
        assert "source_dir" in result.output
        assert "output_dir" in result.output

    def test_wrong_enum_value_points_at_the_key(self, runner, tmp_path):
        result, mock_run = self._invoke(runner, tmp_path, {"strategy": "sideways"})
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'strategy'" in result.output
        assert "sideways" in result.output

    def test_wrong_int_value_points_at_the_key(self, runner, tmp_path):
        result, mock_run = self._invoke(
            runner, tmp_path, {"shard_index": "zero", "shard_count": 2}
        )
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'shard_index'" in result.output

    def test_list_for_scalar_parameter_is_rejected(self, runner, tmp_path):
        # A string parameter would otherwise accept str(['a', 'b']).
        result, mock_run = self._invoke(runner, tmp_path, {"source_dir": ["a", "b"]})
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'source_dir'" in result.output

    def test_scalar_for_list_parameter_is_rejected(self, runner, tmp_path):
        result, mock_run = self._invoke(runner, tmp_path, {"scanners": "bandit"})
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'scanners'" in result.output

    def test_boolean_for_non_boolean_parameter_is_rejected(self, runner, tmp_path):
        # int(True) == 1, so without this check `true` would become shard 1.
        result, mock_run = self._invoke(
            runner, tmp_path, {"shard_index": True, "shard_count": 2}
        )
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'shard_index'" in result.output

    def test_object_for_parameter_is_rejected(self, runner, tmp_path):
        result, mock_run = self._invoke(runner, tmp_path, {"config": {"a": 1}})
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'config'" in result.output

    def test_same_parameter_under_two_spellings_is_rejected(self, runner, tmp_path):
        result, mock_run = self._invoke(
            runner, tmp_path, {"strategy": "parallel", "--strategy": "sequential"}
        )
        assert result.exit_code == 2
        assert not mock_run.called
        assert "strategy" in result.output

    def test_top_level_must_be_an_object(self, runner, tmp_path):
        result, mock_run = self._invoke(runner, tmp_path, ["strategy", "parallel"])
        assert result.exit_code == 2
        assert not mock_run.called
        assert "object" in result.output

    def test_duplicate_key_in_document_is_rejected(self, runner, tmp_path):
        path = tmp_path / "dup.json"
        path.write_text('{"strategy": "parallel", "strategy": "sequential"}')
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(path)])
        assert result.exit_code == 2
        assert not mock_run.called
        assert "strategy" in result.output

    def test_malformed_json_is_rejected(self, runner, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(path)])
        assert result.exit_code == 2
        assert not mock_run.called
        assert "JSON" in result.output

    def test_missing_file_is_rejected(self, runner, tmp_path):
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app, ["scan", "--cli-json-input", str(tmp_path / "absent.json")]
            )
        assert result.exit_code == 2
        assert not mock_run.called
        assert "absent.json" in result.output

    def test_meta_options_cannot_be_set_from_json(self, runner, tmp_path):
        result, mock_run = self._invoke(
            runner, tmp_path, {"cli_json_input": "other.json"}
        )
        assert result.exit_code == 2
        assert not mock_run.called
        assert "'cli_json_input'" in result.output

    def test_no_environment_expansion_in_values(self, runner, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_TEST_290", "expanded")
        params = _write(tmp_path, {"source_dir": "$ASH_TEST_290"})
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(params)])
        assert result.exit_code == 0, result.output
        assert _scan_kwargs(mock_run)["source_dir"] == "$ASH_TEST_290"


class TestSkeleton:
    def test_skeleton_lists_every_scan_parameter_by_name(self, runner):
        result = runner.invoke(app, ["scan", "--generate-cli-skeleton"])
        assert result.exit_code == 0, result.output
        skeleton = json.loads(result.stdout)
        expected = {
            name
            for name, meta in typer.utils.get_params_from_function(
                run_ash_scan_cli_command
            ).items()
            if meta.annotation is not typer.Context
        }
        assert set(skeleton) == expected

    def test_skeleton_does_not_run_the_scan(self, runner):
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--generate-cli-skeleton"])
        assert result.exit_code == 0, result.output
        assert not mock_run.called

    def test_skeleton_values_are_defaults(self, runner):
        skeleton = json.loads(
            runner.invoke(app, ["scan", "--generate-cli-skeleton"]).stdout
        )
        assert skeleton["strategy"] == "parallel"
        assert skeleton["source_dir"] is None
        assert skeleton["progress"] is True

    def test_skeleton_round_trips_into_cli_json_input(self, runner, tmp_path):
        skeleton = runner.invoke(app, ["scan", "--generate-cli-skeleton"]).stdout
        path = tmp_path / "skeleton.json"
        path.write_text(skeleton, encoding="utf-8")

        with patch(RUN_ASH_SCAN) as from_skeleton:
            via_json = runner.invoke(app, ["scan", "--cli-json-input", str(path)])
        with patch(RUN_ASH_SCAN) as from_flags:
            via_flags = runner.invoke(app, ["scan"])

        assert via_json.exit_code == 0, via_json.output
        assert via_flags.exit_code == 0, via_flags.output
        assert _scan_kwargs(from_skeleton) == _scan_kwargs(from_flags)

    def test_edited_skeleton_round_trips(self, runner, tmp_path):
        skeleton = json.loads(
            runner.invoke(app, ["scan", "--generate-cli-skeleton"]).stdout
        )
        skeleton["strategy"] = "sequential"
        skeleton["scanners"] = ["bandit"]
        path = _write(tmp_path, skeleton)
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--cli-json-input", str(path)])
        assert result.exit_code == 0, result.output
        kwargs = _scan_kwargs(mock_run)
        assert kwargs["strategy"] == ExecutionStrategy.SEQUENTIAL
        assert list(kwargs["scanners"]) == ["bandit"]


@pytest.mark.parametrize("command", ["scan", "build-image", "report", "merge"])
def test_commands_expose_both_options(runner, command):
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0, result.output
    # Rich styles each dash-separated segment of a flag separately.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    assert "--cli-json-input" in plain
    assert "--generate-cli-skeleton" in plain


@pytest.mark.parametrize("command", ["build-image", "report", "merge"])
def test_other_commands_produce_a_skeleton(runner, command):
    result = runner.invoke(app, [command, "--generate-cli-skeleton"])
    assert result.exit_code == 0, result.output
    assert isinstance(json.loads(result.stdout), dict)


class TestNoDrift:
    """A parameter added to a command needs no JSON-input code of its own."""

    @staticmethod
    def _app(captured: dict) -> typer.Typer:
        demo = typer.Typer()

        @demo.command(cls=CliJsonInputCommand)
        def run(
            target: str = typer.Argument("here"),
            brand_new_flag: int = typer.Option(7, "--brand-new-flag"),
            names: list[str] = typer.Option([], "--name"),
        ):
            captured.update(target=target, brand_new_flag=brand_new_flag, names=names)

        @demo.command()
        def other():  # a second command, so `run` is addressed by name
            pass

        return demo

    def test_new_parameter_appears_in_skeleton(self, runner):
        demo = self._app({})
        result = runner.invoke(demo, ["run", "--generate-cli-skeleton"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == {
            "target": "here",
            "brand_new_flag": 7,
            "names": [],
        }

    def test_new_parameter_is_accepted_and_cast(self, runner, tmp_path):
        captured: dict = {}
        params = _write(
            tmp_path, {"target": "there", "brand_new_flag": "9", "--name": ["a", "b"]}
        )
        result = runner.invoke(
            self._app(captured), ["run", "--cli-json-input", str(params)]
        )
        assert result.exit_code == 0, result.output
        assert captured == {"target": "there", "brand_new_flag": 9, "names": ["a", "b"]}

    def test_new_parameter_is_validated_by_its_click_type(self, runner, tmp_path):
        captured: dict = {}
        params = _write(tmp_path, {"brand_new_flag": "nine"})
        result = runner.invoke(
            self._app(captured), ["run", "--cli-json-input", str(params)]
        )
        assert result.exit_code == 2
        assert captured == {}
        assert "'brand_new_flag'" in result.output

    def test_positional_argument_on_command_line_overrides_json(self, runner, tmp_path):
        captured: dict = {}
        params = _write(tmp_path, {"target": "there"})
        result = runner.invoke(
            self._app(captured),
            ["run", "--cli-json-input", str(params), "argv-wins"],
        )
        assert result.exit_code == 0, result.output
        assert captured["target"] == "argv-wins"
