# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for .github/actions/validate-mcp/compare_tool_surface.py.

The script is the only writer and the only wire-side reader of the MCP golden, and
it gates CI, so the properties that keep it from passing vacuously are pinned
here rather than trusted: a missing golden, a golden that predates a surface, an
empty capture and an empty golden all fail; every surface's differences are
reported; and only ``tools/list`` runs with ``--strict`` or accepts exit 6.

No inspector or Node runtime is needed. ``subprocess.run`` is replaced where a
test is about how the inspector is invoked, and ``capture`` is replaced where a
test drives ``main`` end to end.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT = REPO_ROOT / ".github" / "actions" / "validate-mcp" / "compare_tool_surface.py"


def _load() -> ModuleType:
    name = "compare_tool_surface_under_unit_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cts = _load()


def _replies() -> Dict[str, Dict[str, Any]]:
    """One plausible list reply per surface, shaped as the inspector prints it."""
    return {
        "tools/list": {
            "tools": [
                {
                    "name": "scan",
                    "description": "Scan.\n\n    Indented body.\n    ",
                    "inputSchema": {
                        "type": "object",
                        "required": ["b", "a"],
                        "properties": {"level": {"enum": ["LOW", "HIGH"]}},
                    },
                }
            ]
        },
        "resources/list": {
            "resources": [
                {
                    "uri": "ash://help",
                    "name": "get_help",
                    "description": "Help.",
                    "mimeType": "text/plain",
                }
            ]
        },
        "resources/templates/list": {"resourceTemplates": []},
        "prompts/list": {
            "prompts": [
                {
                    "name": "run",
                    "title": "Run",
                    "description": "Run a scan.",
                    "arguments": [{"name": "source_dir", "required": False}],
                }
            ]
        },
    }


def _live() -> Dict[str, Dict[str, Any]]:
    replies = _replies()
    return {s.key: cts.live_surface(replies[s.method], s) for s in cts.SURFACES}


class TestSurfaceTable:
    def test_the_four_list_methods_are_covered(self) -> None:
        assert [s.method for s in cts.SURFACES] == [
            "tools/list",
            "resources/list",
            "resources/templates/list",
            "prompts/list",
        ]

    def test_only_resource_templates_may_be_empty(self) -> None:
        assert {s.key for s in cts.SURFACES if s.may_be_empty} == {"resourceTemplates"}

    def test_only_tools_runs_strict(self) -> None:
        assert [s.key for s in cts.SURFACES if s.strict] == ["tools"]


class TestNormalization:
    def test_entries_are_keyed_by_the_identity_a_client_uses(self) -> None:
        live = _live()
        assert set(live["tools"]) == {"scan"}
        assert set(live["resources"]) == {"ash://help"}
        assert set(live["prompts"]) == {"run"}
        # The identity is the key and is not repeated inside the entry.
        assert "uri" not in live["resources"]["ash://help"]
        assert live["resources"]["ash://help"]["name"] == "get_help"

    def test_descriptions_are_cleandoc_for_every_surface(self) -> None:
        live = _live()
        assert live["tools"]["scan"]["description"] == "Scan.\n\nIndented body."
        prompt = {"name": "p", "description": "  Lead.\n\n    Body.\n"}
        assert (
            cts.normalize_entries([prompt], cts.PROMPTS)["p"]["description"]
            == "Lead.\n\nBody."
        )

    def test_set_valued_schema_arrays_are_sorted_and_positional_ones_are_not(
        self,
    ) -> None:
        tool = {
            "name": "t",
            "inputSchema": {
                "required": ["z", "a"],
                "enum": ["b", "a"],
                "prefixItems": [{"type": "string"}, {"type": "integer"}],
            },
        }
        schema = cts.normalize_tools([tool])["t"]["inputSchema"]
        assert schema["required"] == ["a", "z"]
        assert schema["enum"] == ["a", "b"]
        assert schema["prefixItems"] == [{"type": "string"}, {"type": "integer"}]

    def test_prompt_arguments_keep_their_order(self) -> None:
        prompt = {
            "name": "p",
            "arguments": [{"name": "z"}, {"name": "a", "required": True}],
        }
        args = cts.normalize_entries([prompt], cts.PROMPTS)["p"]["arguments"]
        assert [a["name"] for a in args] == ["z", "a"]

    def test_an_entry_without_its_identity_is_refused(self) -> None:
        with pytest.raises(SystemExit, match="has no uri"):
            cts.normalize_entries([{"name": "x"}], cts.RESOURCES)

    def test_a_duplicate_identity_is_refused(self) -> None:
        with pytest.raises(SystemExit, match="two prompts"):
            cts.normalize_entries([{"name": "p"}, {"name": "p"}], cts.PROMPTS)


class TestLiveSurfaceRefusesVacuousCaptures:
    @pytest.mark.parametrize("surface", [cts.TOOLS, cts.RESOURCES, cts.PROMPTS])
    def test_an_empty_reply_is_refused(self, surface) -> None:
        with pytest.raises(SystemExit, match="returned no"):
            cts.live_surface({surface.key: []}, surface)

    def test_an_empty_resource_template_list_is_accepted(self) -> None:
        assert cts.live_surface({"resourceTemplates": []}, cts.RESOURCE_TEMPLATES) == {}

    @pytest.mark.parametrize("surface", list(cts.SURFACES))
    def test_a_reply_without_the_array_is_refused(self, surface) -> None:
        with pytest.raises(SystemExit, match="has no"):
            cts.live_surface({"error": "nope"}, surface)


class TestLoadGolden:
    def test_the_committed_golden_has_every_surface(self) -> None:
        golden = cts.load_golden(cts.DEFAULT_GOLDEN)
        assert set(golden) == {s.key for s in cts.SURFACES}
        assert len(golden["tools"]) >= 14
        assert set(golden["resources"]) == {
            "ash://schema/config",
            "ash://schema/suppression",
            "ash://exit-codes",
            "ash://status",
            "ash://help",
        }
        assert set(golden["prompts"]) == {
            "run_ash_security_scan",
            "analyze_security_findings",
        }

    def test_a_missing_golden_fails_and_is_not_created(self, tmp_path) -> None:
        path = tmp_path / "golden.json"
        with pytest.raises(SystemExit, match="missing"):
            cts.load_golden(path)
        assert not path.exists()

    def test_a_golden_written_before_a_surface_existed_fails(self, tmp_path) -> None:
        """A tools-only golden -- the shape before this script covered resources."""
        path = tmp_path / "golden.json"
        path.write_text(json.dumps({"tools": _live()["tools"]}), encoding="utf-8")
        with pytest.raises(SystemExit, match="no 'resources' key"):
            cts.load_golden(path)

    @pytest.mark.parametrize("key", ["tools", "resources", "prompts"])
    def test_an_empty_surface_fails(self, tmp_path, key) -> None:
        document = cts.golden_document(_live())
        document[key] = {}
        path = tmp_path / "golden.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(SystemExit, match="names no"):
            cts.load_golden(path)

    def test_write_then_load_round_trips_every_surface(self, tmp_path) -> None:
        live = _live()
        path = tmp_path / "golden.json"
        cts.write_golden(path, live)
        assert cts.load_golden(path) == live
        assert cts.compare_all(live, cts.load_golden(path)) == []


class TestCompare:
    def test_a_changed_resource_mime_type_is_reported_with_a_diff(self) -> None:
        golden = _live()
        live = _live()
        live["resources"]["ash://help"]["mimeType"] = "text/markdown"
        problems = cts.compare_all(live, golden)
        assert len(problems) == 1
        assert problems[0].startswith("resource ash://help: mimeType changed.")
        assert '+"text/markdown"' in problems[0]
        assert "golden/resources/ash://help.mimeType" in problems[0]

    def test_a_vanished_prompt_and_a_new_template_are_reported(self) -> None:
        golden = _live()
        live = _live()
        del live["prompts"]["run"]
        live["resourceTemplates"]["ash://scan/{id}"] = {"name": "scan"}
        problems = cts.compare_all(live, golden)
        assert any(
            p.startswith("PROMPT(S) GONE FROM THE WIRE SURFACE: run") for p in problems
        )
        assert any(
            p.startswith(
                "NEW RESOURCE TEMPLATE(S) ON THE WIRE SURFACE: ash://scan/{id}"
            )
            for p in problems
        )

    def test_a_tool_problem_keeps_its_original_label(self) -> None:
        golden = _live()
        live = _live()
        live["tools"]["scan"]["description"] = "Different."
        problems = cts.compare(live["tools"], golden["tools"])
        assert problems[0].startswith("scan: description changed.")

    def test_a_gained_and_a_lost_field_are_named(self) -> None:
        golden = _live()
        live = _live()
        live["prompts"]["run"].pop("title")
        live["resources"]["ash://help"]["title"] = "Help"
        problems = cts.compare_all(live, golden)
        assert (
            "resource ash://help: gained a title the golden does not record."
            in problems
        )
        assert "prompt run: lost the title the golden records." in problems


class TestCapture:
    def _run(self, monkeypatch, surface, returncode: int, stdout: str):
        calls: List[List[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, returncode, stdout, "")

        monkeypatch.setattr(cts.subprocess, "run", fake_run)
        result = cts.capture("inspector", "ash", ["--x"], surface)
        return calls[0], result

    def test_tools_list_runs_strict_with_the_target_before_the_method(
        self, monkeypatch
    ) -> None:
        cmd, _ = self._run(monkeypatch, cts.TOOLS, 0, '{"tools": []}')
        assert cmd == [
            "inspector",
            "--cli",
            "ash",
            "mcp",
            "--method",
            "tools/list",
            "--strict",
            "--x",
        ]

    @pytest.mark.parametrize(
        "surface", [cts.RESOURCES, cts.RESOURCE_TEMPLATES, cts.PROMPTS]
    )
    def test_the_other_methods_run_without_strict(self, monkeypatch, surface) -> None:
        cmd, _ = self._run(monkeypatch, surface, 0, "{}")
        assert "--strict" not in cmd
        assert cmd[cmd.index("--method") + 1] == surface.method

    def test_exit_6_is_a_capture_for_tools_list(self, monkeypatch) -> None:
        _, (payload, code, _) = self._run(monkeypatch, cts.TOOLS, 6, '{"tools": []}')
        assert code == 6 and payload == {"tools": []}

    def test_exit_6_is_a_failure_for_prompts_list(self, monkeypatch) -> None:
        with pytest.raises(SystemExit, match="exited 6 on prompts/list"):
            self._run(monkeypatch, cts.PROMPTS, 6, '{"prompts": []}')

    def test_no_output_is_a_failure(self, monkeypatch) -> None:
        with pytest.raises(SystemExit, match="printed no resources/list reply"):
            self._run(monkeypatch, cts.RESOURCES, 0, "  \n")

    def test_non_json_output_is_a_failure(self, monkeypatch) -> None:
        with pytest.raises(SystemExit, match="is not JSON"):
            self._run(monkeypatch, cts.RESOURCES, 0, "not json")


class TestMain:
    """``main`` end to end, with ``capture`` replaced by the canned replies."""

    def _main(self, monkeypatch, tmp_path, replies, *args: str) -> int:
        def fake_capture(inspector, ash, extra_args=None, surface=cts.TOOLS):
            return replies[surface.method], 0, ""

        monkeypatch.setattr(cts, "capture", fake_capture)
        executable = tmp_path / "exe"
        executable.write_text("", encoding="utf-8")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "compare_tool_surface.py",
                "--golden",
                str(tmp_path / "golden.json"),
                "--inspector",
                str(executable),
                "--ash",
                str(executable),
                *args,
            ],
        )
        return cts.main()

    def test_update_writes_every_surface_and_check_then_passes(
        self, monkeypatch, tmp_path, capsys
    ) -> None:
        replies = _replies()
        assert self._main(monkeypatch, tmp_path, replies, "--update") == 0
        written = json.loads((tmp_path / "golden.json").read_text(encoding="utf-8"))
        assert {"tools", "resources", "resourceTemplates", "prompts"} <= set(written)

        assert self._main(monkeypatch, tmp_path, replies) == 0
        assert "MCP wire surface matches the golden." in capsys.readouterr().out

    def test_check_fails_on_a_changed_prompt_and_never_writes(
        self, monkeypatch, tmp_path, capsys
    ) -> None:
        replies = _replies()
        self._main(monkeypatch, tmp_path, replies, "--update")
        before = (tmp_path / "golden.json").read_text(encoding="utf-8")
        capsys.readouterr()

        replies["prompts/list"]["prompts"][0]["description"] = "Run a different scan."
        assert self._main(monkeypatch, tmp_path, replies) == 1

        out = capsys.readouterr().out
        assert "MCP WIRE SURFACE MISMATCH -- 1 difference(s)" in out
        assert "prompt run: description changed." in out
        assert "-Run a scan." in out and "+Run a different scan." in out
        assert (tmp_path / "golden.json").read_text(encoding="utf-8") == before

    def test_check_fails_when_the_golden_is_missing(
        self, monkeypatch, tmp_path
    ) -> None:
        with pytest.raises(SystemExit, match="missing"):
            self._main(monkeypatch, tmp_path, _replies())
        assert not (tmp_path / "golden.json").exists()
