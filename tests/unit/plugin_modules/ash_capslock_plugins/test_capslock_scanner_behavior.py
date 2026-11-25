# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CapslockScanner: invocation, output conversion, severity and failure handling.

The JSON documents below are written by hand from the protobuf schema Capslock
prints (proto/capability.proto, rendered by protojson: lowerCamelCase names,
int64 as strings, enums by name). No Capslock binary was run to produce them, so
they pin this plugin's reading of the documented schema, not captured output.
The subprocess is replaced by a fake, so the tests run on every platform.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_capslock_plugins import (
    ASH_REPORTERS,
    ASH_SCANNERS,
    capslock_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_capslock_plugins.capslock_scanner import (
    CapslockScanner,
    CapslockScannerConfig,
    convert_capslock_output,
    find_go_modules,
)
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

POSITIVE: Dict[str, Any] = {
    "capabilityInfo": [
        {
            "packageName": "example.com/app/server",
            "capabilityName": "CAPABILITY_NETWORK",
            "capability": "CAPABILITY_NETWORK",
            "depPath": "example.com/app/server.Serve net/http.ListenAndServe",
            "path": [
                {
                    "name": "example.com/app/server.Serve",
                    "site": {
                        "filename": "/ABS/server/serve.go",
                        "line": "12",
                        "column": "5",
                    },
                    "package": "example.com/app/server",
                },
                {"name": "net/http.ListenAndServe", "package": "net/http"},
            ],
            "packageDir": "/ABS/server",
            "capabilityType": "CAPABILITY_TYPE_DIRECT",
        },
        {
            "packageName": "example.com/app/util",
            "capabilityName": "CAPABILITY_EXEC",
            "depPath": "example.com/app/util.Run os/exec.Command",
            "path": [{"name": "example.com/app/util.Run"}],
            "capabilityType": "CAPABILITY_TYPE_TRANSITIVE",
        },
    ],
    "moduleInfo": [{"path": "example.com/app"}],
}
NEGATIVE: Dict[str, Any] = {"moduleInfo": [{"path": "example.com/app"}]}


def _positive_text(root: Path) -> str:
    return json.dumps(POSITIVE).replace("/ABS", root.as_posix())


class FakeCapslock:
    """Stands in for _run_subprocess; records every call."""

    def __init__(
        self,
        stdout: str = "",
        exit_code: int = 0,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout, self.exit_code, self.stderr = stdout, exit_code, stderr
        self.timed_out = timed_out
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **kw):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            }

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> CapslockScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return CapslockScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=CapslockScannerConfig(enabled=True),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "server").mkdir(parents=True)
    (src / "go.mod").write_text("module example.com/app\n\ngo 1.22\n")
    (src / "server" / "serve.go").write_text("package server\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(target=Path(scanner.context.source_dir), target_type="source")


def _rows(report) -> List[tuple]:
    out = []
    for r in report.get_all_results():
        phys = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                phys.artifactLocation.uri,
                phys.region.startLine if phys.region else None,
            )
        )
    return out


class TestCommunityPlugin:
    def test_module_exports_the_scanner(self):
        assert ASH_SCANNERS == [CapslockScanner]
        assert ASH_REPORTERS == []

    def test_enabled_once_its_module_is_listed(self):
        assert CapslockScannerConfig().enabled is True
        assert CapslockScannerConfig().name == "capslock"

    def test_class_declarations(self):
        assert CapslockScanner.success_exit_codes == {0}
        assert CapslockScanner.python_only is False
        assert CapslockScanner.offline_strategy.value != "unknown"


class TestInvocation:
    def test_every_fixed_flag_and_working_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCapslock(json.dumps(NEGATIVE))
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert len(fake.calls) == 1
        call = fake.calls[0]
        assert call["argv"] == [
            "capslock",
            "-packages=./...",
            "-output=json",
            "-force_local_module",
        ]
        assert Path(call["cwd"]) == tree
        assert call["env"]["GOFLAGS"] == "-mod=readonly"

    @pytest.mark.parametrize(
        "flag",
        ["-capability_map", "-disable_builtin", "-noisy", "-output=compare"],
    )
    def test_flags_that_read_the_tree_or_change_the_mode_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, flag
    ):
        fake = FakeCapslock(json.dumps(NEGATIVE))
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not any(a.startswith(flag) for a in fake.calls[0]["argv"])

    def test_the_temp_module_fallback_is_always_disabled(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCapslock(json.dumps(NEGATIVE))
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert "-force_local_module" in fake.calls[0]["argv"]

    def test_one_run_per_module_each_in_its_own_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "tools").mkdir()
        (tree / "tools" / "go.mod").write_text("module example.com/tools\n")
        (tree / "vendor" / "x").mkdir(parents=True)
        (tree / "vendor" / "x" / "go.mod").write_text("module x\n")
        fake = FakeCapslock(json.dumps(NEGATIVE))
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert [Path(c["cwd"]) for c in fake.calls] == [tree, tree / "tools"]

    def test_find_go_modules_skips_vendor_and_testdata(self, tree):
        for d in ("vendor", "testdata", "node_modules"):
            (tree / d).mkdir()
            (tree / d / "go.mod").write_text("module x\n")
        assert find_go_modules(tree) == [tree]

    def test_no_go_mod_is_a_skip_not_a_run(self, tmp_path, on_path, monkeypatch):
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text("print(1)\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeCapslock(json.dumps(POSITIVE))
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert report.get_all_results() == []

    def test_global_ignore_paths_keep_a_module_from_being_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        from automated_security_helper.models.core import IgnorePathWithReason

        (tree / "vendored").mkdir()
        (tree / "vendored" / "go.mod").write_text("module example.com/v\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeCapslock(json.dumps(NEGATIVE))
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(
            target=tree,
            target_type="source",
            global_ignore_paths=[IgnorePathWithReason(path="vendored/", reason="t")],
        )
        assert [c["cwd"] for c in fake.calls] == [tree]

    def test_every_module_ignored_runs_nothing(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        from automated_security_helper.models.core import IgnorePathWithReason

        scanner = _scanner(tree, tmp_path)
        fake = FakeCapslock(json.dumps(NEGATIVE))
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        report = scanner.scan(
            target=tree,
            target_type="source",
            global_ignore_paths=[IgnorePathWithReason(path="go.mod", reason="t")],
        )
        assert fake.calls == []
        assert report.get_all_results() == []

    def test_a_missing_target_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "nothing"
        scanner = _scanner(src, tmp_path)
        fake = FakeCapslock(json.dumps(POSITIVE))
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert report.get_all_results() == []

    def test_scan_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.config.options.scan_timeout = 77
        fake = FakeCapslock(json.dumps(NEGATIVE))
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["timeout"] == 77


class TestReport:
    def test_happy_path_findings_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCapslock(_positive_text(tree))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _rows(report) == [
            ("CAPSLOCK-NETWORK", "none", "INFO", "server/serve.go", 12),
            # No site in the path: located at the module's go.mod.
            ("CAPSLOCK-EXEC", "none", "INFO", "go.mod", None),
        ]
        first = report.get_all_results()[0]
        assert "can interact with the network" in first.message.root.text
        assert "net/http.ListenAndServe" in first.message.root.text

    def test_severity_and_level_agree_on_every_result(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeCapslock(_positive_text(tree)), monkeypatch
        )
        for r in report.get_all_results():
            assert r.properties.issue_severity == cs.CAPSLOCK_SEVERITY == "INFO"
            assert r.level.value == cs.CAPSLOCK_LEVEL == "none"
            assert r.kind.value == "informational"

    def test_negative_control_clean_module_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeCapslock(json.dumps(NEGATIVE)), monkeypatch
        )
        assert report.get_all_results() == []

    def test_module_subdirectory_prefixes_the_uri(self, tmp_path):
        target = tmp_path / "t"
        module = target / "svc"
        doc = json.loads(_positive_text(module))
        results = convert_capslock_output(doc, module, target)
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "svc/server/serve.go"
        assert loc["region"] == {"startLine": 12, "startColumn": 5}

    def test_a_site_outside_the_target_falls_back_to_go_mod(self, tmp_path):
        target = tmp_path / "t"
        doc = json.loads(json.dumps(POSITIVE).replace("/ABS", "/elsewhere"))
        results = convert_capslock_output(doc, target, target)
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"] == {
            "uri": "go.mod"
        }

    @pytest.mark.parametrize("name", ["CAPABILITY_FILES", "FILES", "capability_files"])
    def test_capability_names_are_normalised(self, name):
        assert cs.capability_name(name) == "FILES"


class TestFailures:
    @pytest.mark.parametrize(
        "kwargs, needle",
        [
            ({"exit_code": 2, "stderr": "No packages matching ./..."}, "exited 2"),
            ({"exit_code": 1, "stdout": "{}"}, "exited 1"),
            ({"exit_code": 137}, "exited 137"),
            ({"timed_out": True}, "timed out after"),
            ({"stdout": ""}, "wrote no report"),
            ({"stdout": "not JSON"}, "not JSON"),
            ({"stdout": "[1, 2]"}, "not a JSON object"),
            ({"stdout": '{"capabilityInfo": {"a": 1}}'}, "not a list"),
            ({"stdout": '{"capabilityInfo": [{"packageName": "p"}]}'}, "no capability"),
        ],
    )
    def test_failure_cases_fail_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, kwargs, needle
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.config.options.scan_timeout = 5
        with pytest.raises(ScannerError) as raised:
            _run(scanner, FakeCapslock(**kwargs), monkeypatch)
        assert needle in str(raised.value)

    def test_failure_message_names_the_module(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "tools").mkdir()
        (tree / "tools" / "go.mod").write_text("module example.com/tools\n")
        with pytest.raises(ScannerError) as raised:
            _run(_scanner(tree, tmp_path), FakeCapslock(exit_code=2), monkeypatch)
        assert "the target root module" in str(raised.value)


class TestDependencyCheck:
    def test_tool_absent_skips_the_scan_with_the_install_hint(
        self, tree, tmp_path, monkeypatch, caplog
    ):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        fake = FakeCapslock(json.dumps(POSITIVE))
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []

    def test_tool_present(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_the_install_hint_is_the_go_install_command(self):
        assert (
            cs.INSTALL_COMMAND
            == "go install github.com/google/capslock/cmd/capslock@latest"
        )

    def test_no_install_commands_are_declared(self, tree, tmp_path):
        # Capslock has no release assets; the user installs it with go.
        assert not _scanner(tree, tmp_path).custom_install_commands
