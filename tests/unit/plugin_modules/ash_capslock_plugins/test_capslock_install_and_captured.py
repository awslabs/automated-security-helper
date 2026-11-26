# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The go install build, and the converter over real captured Capslock runs.

``tests/test_data/scanners/capslock/captured/`` holds what ``capslock -output=json``
v0.3.4 printed for the three committed input modules (see its README). The
conversion tests read those files, so the location rules are pinned over output
the tool produced, not over a hand-built document.

The installer's go commands are replaced by a fake that answers as the go command
does, so no toolchain runs, nothing is downloaded and the tests run on every
platform. What the real go command did is recorded in the captured README.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_capslock_plugins import (
    capslock_install as ci,
)
from automated_security_helper.plugin_modules.ash_capslock_plugins.capslock_scanner import (
    capslock_sarif_document,
    convert_capslock_output,
    read_module_path,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import download_utils as du
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "capslock"
    / "captured"
)

#: (report, input module) for every captured run with results.
CAPTURES = (("positive", "pos"), ("dependency", "dep"))


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------


def test_the_module_digest_holds_one_sha256_and_round_trips():
    digest = ci.module_sum_hex()
    assert len(digest) == 64 and int(digest, 16) >= 0
    assert "h1:" + base64.b64encode(bytes.fromhex(digest)).decode() == (
        ci.CAPSLOCK_MODULE_SUM
    )


@pytest.mark.parametrize(
    "bad",
    ["", "eS3/PLl++R96+Ub8b7uIDgCWzQh8CsY1CzVQbnt+Vhs=", "h1:", "h1:!!!!", "h1:AAAA"],
)
def test_a_digest_that_is_not_one_h1_sha256_is_refused(bad):
    with pytest.raises(ValueError):
        ci.module_sum_hex(bad)


def test_the_install_command_is_the_pinned_package_at_the_pinned_version():
    assert ci.INSTALL_COMMAND == (
        "go install github.com/google/capslock/cmd/capslock@v0.3.4"
    )
    assert ci.CAPSLOCK_PACKAGE == f"{ci.CAPSLOCK_MODULE}/cmd/capslock"
    assert ci.MINIMUM_GO == (1, 26, 0)


@pytest.mark.parametrize(
    "text,parsed",
    [
        ("go1.26.11", (1, 26, 11)),
        ("go1.26", (1, 26, 0)),
        ("go1.27rc1", (1, 27, 0)),
        ("devel go1.27-0123abcd", (1, 27, 0)),
        ("", None),
        ("unknown", None),
    ],
)
def test_go_versions_are_read_as_the_go_command_prints_them(text, parsed):
    assert ci.parse_go_version(text) == parsed


def test_the_build_environment_fixes_what_shapes_the_build_and_keeps_the_rest():
    base = {
        "GOFLAGS": "-mod=mod",
        "GOOS": "windows",
        "GOARCH": "386",
        "GOBIN": "/elsewhere",
        "GOWORK": "/w/go.work",
        "GOTOOLCHAIN": "auto",
        "GOPROXY": "https://mirror.example/",
        "GOPATH": "/home/me/go",
        "GOPRIVATE": "example.com/*",
    }
    env = ci.go_environment(base, Path("/staging/bin"))
    assert env["GOFLAGS"] == "" and env["GOWORK"] == "off"
    assert env["GOTOOLCHAIN"] == "local" and env["GOBIN"] == str(Path("/staging/bin"))
    assert "GOOS" not in env and "GOARCH" not in env
    for kept in ("GOPROXY", "GOPATH", "GOPRIVATE"):
        assert env[kept] == base[kept]


def test_the_install_table_covers_every_go_platform(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = ci.capslock_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(
        ci.GO_PLATFORMS
    )
    assert set(ci.GO_PLATFORMS) == {
        (p, a) for p in ("linux", "darwin", "windows") for a in ("amd64", "arm64")
    }


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = ci.capslock_install_commands()
    (command,) = table["linux"]["amd64"]
    assert "install_capslock" not in " ".join(command.args)
    assert du.NO_BIN_DIRECTORY in command.args


# ---------------------------------------------------------------------------
# install_capslock, with the go command faked
# ---------------------------------------------------------------------------


class FakeGo:
    """Answers the installer's go commands; records them; never runs a process."""

    def __init__(
        self,
        version: str = "go1.26.11",
        host: tuple = ("linux", "amd64"),
        module_sum: str = ci.CAPSLOCK_MODULE_SUM,
        built_module: Optional[List[str]] = None,
        built_for: Optional[tuple] = None,
    ):
        self.version, self.host, self.module_sum = version, host, module_sum
        self.built_module = built_module or [
            ci.CAPSLOCK_MODULE,
            ci.CAPSLOCK_VERSION,
            ci.CAPSLOCK_MODULE_SUM,
        ]
        self.built_for = built_for or host
        self.calls: List[List[str]] = []
        self.envs: List[Dict[str, str]] = []

    def __call__(self, go, args, cwd, env, timeout):
        self.calls.append(list(args))
        self.envs.append(dict(env))
        out = ""
        if args[:1] == ["env"]:
            out = f"{self.version}\n{self.host[0]}\n{self.host[1]}\n"
        elif args[:2] == ["mod", "download"]:
            out = json.dumps(
                {
                    "Path": ci.CAPSLOCK_MODULE,
                    "Version": ci.CAPSLOCK_VERSION,
                    "Sum": self.module_sum,
                }
            )
        elif args[:1] == ["install"]:
            built = Path(env["GOBIN"]) / ci.install_name()
            built.write_bytes(b"capslock binary built by the fake go\n")
            built.chmod(0o755)
        elif args[:2] == ["version", "-m"]:
            module = "\t".join(self.built_module)
            out = (
                f"{args[2]}: {self.version}\n"
                f"\tpath\t{ci.CAPSLOCK_PACKAGE}\n"
                f"\tmod\t{module}\n"
                "\tdep\tgolang.org/x/tools\tv0.51.0\th1:abc=\n"
                f"\tbuild\tGOOS={self.built_for[0]}\n"
                f"\tbuild\tGOARCH={self.built_for[1]}\n"
            )
        return subprocess.CompletedProcess([go, *args], 0, out, "")

    def ran(self, verb: str) -> bool:
        return any(call[:1] == [verb] for call in self.calls)


@pytest.fixture
def installer(tmp_path, monkeypatch):
    """A home for receipts, a bin directory, a go on PATH, online, and the fake."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(du, "is_offline_mode", lambda: False)
    monkeypatch.setattr(
        subprocess_utils, "find_executable", lambda name: f"/usr/local/go/bin/{name}"
    )
    fake = FakeGo()
    monkeypatch.setattr(ci, "_run_go", fake)
    bin_dir = tmp_path / "bin"
    return bin_dir, fake


def _leftovers(bin_dir: Path) -> List[str]:
    return sorted(p.name for p in bin_dir.iterdir()) if bin_dir.exists() else []


def test_a_build_checks_the_module_then_installs_and_records_it(installer):
    bin_dir, fake = installer
    target = ci.install_capslock(bin_dir)
    assert target == bin_dir.absolute() / ci.install_name()
    assert target.read_bytes() == b"capslock binary built by the fake go\n"
    assert [call[:2] for call in fake.calls] == [
        ["env", "GOVERSION"],
        ["mod", "download"],
        ["install", f"{ci.CAPSLOCK_PACKAGE}@{ci.CAPSLOCK_VERSION}"],
        ["version", "-m"],
    ]
    assert fake.calls[1] == [
        "mod",
        "download",
        "-json",
        f"{ci.CAPSLOCK_MODULE}@{ci.CAPSLOCK_VERSION}",
    ]
    for env in fake.envs:
        assert env["GOTOOLCHAIN"] == "local" and env["GOFLAGS"] == ""
    receipt = du.read_receipt(bin_dir.absolute(), ci.install_name())
    assert receipt["url"] == ci.INSTALL_COMMAND
    assert receipt["sha256"] == ci.module_sum_hex()
    assert receipt["module_sum"] == ci.CAPSLOCK_MODULE_SUM
    assert receipt["installed_sha256"] == du.sha256_file(target)
    assert receipt["go_version"] == "go1.26.11"
    # The staging directory is gone; only the executable is left.
    assert _leftovers(bin_dir) == [ci.install_name()]


def test_a_second_install_of_the_same_bytes_builds_nothing(installer):
    bin_dir, fake = installer
    ci.install_capslock(bin_dir)
    fake.calls.clear()
    ci.install_capslock(bin_dir)
    assert fake.calls == []


def test_a_changed_executable_is_built_again(installer):
    bin_dir, fake = installer
    target = ci.install_capslock(bin_dir)
    target.write_bytes(b"something else\n")
    fake.calls.clear()
    ci.install_capslock(bin_dir)
    assert fake.ran("install")


def test_offline_nothing_is_downloaded_or_built(installer, monkeypatch):
    bin_dir, fake = installer
    monkeypatch.setattr(du, "is_offline_mode", lambda: True)
    with pytest.raises(ToolNotProvisionableError, match="offline"):
        ci.install_capslock(bin_dir)
    assert fake.calls == []


def test_without_a_go_command_the_install_says_how_to_get_one(installer, monkeypatch):
    bin_dir, fake = installer
    monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
    with pytest.raises(ToolNotProvisionableError, match="no `go` on PATH"):
        ci.install_capslock(bin_dir)
    assert fake.calls == []


def test_an_older_go_is_refused_with_its_version_before_any_download(
    installer, monkeypatch
):
    bin_dir, _ = installer
    old = FakeGo(version="go1.25.4")
    monkeypatch.setattr(ci, "_run_go", old)
    with pytest.raises(ToolNotProvisionableError, match="go1.25.4") as refused:
        ci.install_capslock(bin_dir)
    assert "1.26.0 or later" in str(refused.value)
    assert not old.ran("mod") and not old.ran("install")
    assert _leftovers(bin_dir) == []


def test_a_module_with_another_digest_is_refused_before_the_build(
    installer, monkeypatch
):
    bin_dir, _ = installer
    other = FakeGo(module_sum="h1:" + base64.b64encode(b"\0" * 32).decode())
    monkeypatch.setattr(ci, "_run_go", other)
    with pytest.raises(ToolNotProvisionableError, match="nothing was built"):
        ci.install_capslock(bin_dir)
    assert not other.ran("install")
    assert _leftovers(bin_dir) == []


def test_an_executable_built_from_another_module_is_not_installed(
    installer, monkeypatch
):
    bin_dir, _ = installer
    other = FakeGo(built_module=[ci.CAPSLOCK_MODULE, "v0.3.3", ci.CAPSLOCK_MODULE_SUM])
    monkeypatch.setattr(ci, "_run_go", other)
    with pytest.raises(ToolNotProvisionableError, match="not installed"):
        ci.install_capslock(bin_dir)
    assert _leftovers(bin_dir) == []


def test_an_executable_for_another_platform_is_not_installed(installer, monkeypatch):
    bin_dir, _ = installer
    other = FakeGo(built_for=("windows", "amd64"))
    monkeypatch.setattr(ci, "_run_go", other)
    with pytest.raises(ToolNotProvisionableError, match="windows/amd64"):
        ci.install_capslock(bin_dir)
    assert _leftovers(bin_dir) == []


def test_a_failing_go_command_is_reported_with_its_words(tmp_path, monkeypatch):
    def failed(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "go: no network\n")

    monkeypatch.setattr(ci.subprocess, "run", failed)
    with pytest.raises(ToolNotProvisionableError) as refused:
        ci._run_go("/usr/local/go/bin/go", ["env", "GOVERSION"], tmp_path, {}, 5)
    assert "exited 1" in str(refused.value) and "go: no network" in str(refused.value)


def test_a_go_command_that_runs_too_long_is_reported(tmp_path, monkeypatch):
    def late(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

    monkeypatch.setattr(ci.subprocess, "run", late)
    with pytest.raises(ToolNotProvisionableError, match="did not finish in 5 seconds"):
        ci._run_go("/usr/local/go/bin/go", ["install", "x@v1"], tmp_path, {}, 5)


def test_the_go_command_runs_with_no_input_and_the_given_directory(
    tmp_path, monkeypatch
):
    seen: Dict[str, object] = {}

    def record(argv, **kwargs):
        seen.update(kwargs, argv=argv)
        return subprocess.CompletedProcess(argv, 0, "go1.26.11\n", "")

    monkeypatch.setattr(ci.subprocess, "run", record)
    ci._run_go("/usr/local/go/bin/go", ["env", "GOVERSION"], tmp_path, {"A": "b"}, 7)
    assert seen["argv"] == ["/usr/local/go/bin/go", "env", "GOVERSION"]
    assert seen["cwd"] == str(tmp_path) and seen["env"] == {"A": "b"}
    assert seen["stdin"] is subprocess.DEVNULL and seen["timeout"] == 7
    assert "shell" not in seen


# ---------------------------------------------------------------------------
# Conversion over the captured runs
# ---------------------------------------------------------------------------


def _report(name: str) -> dict:
    return json.loads((CAPTURED / f"{name}.json").read_text(encoding="utf-8"))


def _converted(report: str, module: str) -> List[dict]:
    module_dir = CAPTURED / "in" / module
    return convert_capslock_output(
        _report(report), module_dir, module_dir, read_module_path(module_dir / "go.mod")
    )


def _rows(results: List[dict]) -> List[tuple]:
    rows = []
    for r in results:
        physical = r["locations"][0]["physicalLocation"]
        region = physical.get("region", {})
        rows.append(
            (
                r["ruleId"],
                physical["artifactLocation"]["uri"],
                region.get("startLine"),
                region.get("startColumn"),
                r["properties"]["capslock_type"],
            )
        )
    return rows


def test_the_positive_capture_is_converted_row_by_row():
    assert _rows(_converted("positive", "pos")) == [
        ("CAPSLOCK-FILES", "store/load.go", 8, 20, "DIRECT"),
        ("CAPSLOCK-NETWORK", "server/serve.go", 8, 28, "DIRECT"),
        # The module root's own package: the file is at the root.
        ("CAPSLOCK-READ_SYSTEM_STATE", "app.go", 8, 18, "DIRECT"),
        # util.FirstByte is itself the capability: one step, no site.
        ("CAPSLOCK-UNSAFE_POINTER", "go.mod", None, None, "DIRECT"),
        ("CAPSLOCK-EXEC", "internal/exe/start.go", 8, 21, "DIRECT"),
        # The call inside util.Run, not the later call in internal/exe.
        ("CAPSLOCK-EXEC", "util/run.go", 8, 18, "TRANSITIVE"),
    ]


def test_every_named_file_and_line_exists_in_the_captured_input():
    for report, module in CAPTURES:
        for rule, uri, line, column, _ in _rows(_converted(report, module)):
            source = CAPTURED / "in" / module / uri
            assert source.is_file(), (rule, uri)
            if line is not None:
                text = source.read_text(encoding="utf-8").splitlines()[line - 1]
                # The column is the call's opening parenthesis (tabs count as one).
                assert text[column - 1] == "(", (rule, uri, line, column, text)


def test_a_closure_the_function_creates_has_no_site_and_is_located_at_go_mod():
    rows = _rows(_converted("dependency", "dep"))
    assert rows == [
        ("CAPSLOCK-FILES", "go.mod", None, None, "DIRECT"),
        ("CAPSLOCK-FILES", "read.go", 14, 24, "DIRECT"),
    ]
    first = _report("dependency")["capabilityInfo"][0]["path"]
    assert [step["name"] for step in first] == [
        "example.com/dep.Read",
        "example.com/dep.Read$1",
        "os.ReadFile",
    ]
    assert "site" not in first[1]


def test_the_report_carries_dependency_versions_apart_from_the_entries():
    report = _report("dependency")
    assert report["moduleInfo"] == [{"path": "golang.org/x/sync", "version": "v0.23.0"}]
    for entry in report["capabilityInfo"]:
        assert not {"version", "moduleVersion"} & set(entry)


def test_positions_are_strings_in_the_real_report():
    site = _report("positive")["capabilityInfo"][0]["path"][1]["site"]
    assert site == {"column": "20", "filename": "load.go", "line": "8"}


def test_the_negative_capture_lists_packages_and_has_no_results():
    report = _report("negative")
    assert "capabilityInfo" not in report
    assert report["packageInfo"] == [{"path": "example.com/clean/add"}]
    neg = CAPTURED / "in" / "neg"
    assert (
        convert_capslock_output(report, neg, neg, read_module_path(neg / "go.mod"))
        == []
    )


def test_severity_and_level_agree_on_every_captured_result():
    for report, module in CAPTURES:
        for result in _converted(report, module):
            assert result["properties"]["issue_severity"] == "INFO"
            assert (result["level"], result["kind"]) == ("none", "informational")


@pytest.mark.parametrize("report,module", CAPTURES)
def test_the_committed_sarif_is_what_the_converter_writes(report, module):
    committed = json.loads((CAPTURED / f"{report}.sarif").read_text(encoding="utf-8"))
    written = capslock_sarif_document(_converted(report, module))
    assert committed == written
    SarifReport.model_validate(committed)


#: Each recording in transcripts.json, and the committed corpus SARIF its report
#: converts to (None: the run found no capability, so there is no SARIF file).
RECORDINGS = {
    "capslock-0.3.4-positive": "positive.sarif",
    "capslock-0.3.4-dependency": "dependency.sarif",
    "capslock-0.3.4-negative": None,
}


def _recordings():
    from automated_security_helper.core.plugin_conformance import (
        discover_transcript_files,
        transcripts_of,
    )

    return transcripts_of("capslock", discover_transcript_files(CAPTURED.parent))


def _read_through_the_prep(transcript, base: Path) -> list:
    from automated_security_helper.core.plugin_conformance import PREPS

    (entry,) = transcript.results
    return [
        result
        for _report, results in PREPS["capslock"](transcript, base, base / entry.path)
        for result in results
    ]


def test_ash_plugin_verify_reads_each_recording_as_the_committed_sarif():
    """``ash plugin verify`` judges the facets over transcripts.json, reading each
    recording through the registered prep; that reading is the committed corpus SARIF,
    result for result, so the promotion bar and the register gate see one corpus."""
    recordings = _recordings()
    assert sorted(t.id for _base, t in recordings) == sorted(RECORDINGS)
    for base, transcript in recordings:
        assert transcript.adapter_prep == "capslock", transcript.id
        assert transcript.tool.version == ci.CAPSLOCK_VERSION, transcript.id
        read = _read_through_the_prep(transcript, base)
        sarif = RECORDINGS[transcript.id]
        if sarif is None:
            assert read == [], transcript.id
            continue
        committed = SarifReport.model_validate(
            json.loads((CAPTURED / sarif).read_text(encoding="utf-8"))
        )
        expected = [r for run in committed.runs or [] for r in run.results or []]
        assert expected and read == expected, transcript.id


def test_a_recording_that_names_no_single_module_is_not_read():
    """Capslock names a call site's file by base name only, so the prep needs the
    module the run was over; a recording without exactly one is refused, not guessed."""
    base, transcript = next(
        item for item in _recordings() if item[1].id == "capslock-0.3.4-positive"
    )
    for tree in (
        None,
        transcript.fixture_tree.model_copy(update={"paths": ("a", "b")}),
    ):
        planted = transcript.model_copy(update={"fixture_tree": tree})
        with pytest.raises(ValueError, match="one module it ran over"):
            _read_through_the_prep(planted, base)


def test_the_captured_readme_names_the_tool_and_toolchain_that_ran():
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    for fact in (
        "capslock version v0.3.4",
        "go1.26.11",
        ci.CAPSLOCK_MODULE_SUM,
        "capslock -packages=./... -output=json -force_local_module",
    ):
        assert fact in readme, fact


def test_the_inputs_are_three_modules_and_nothing_else_is_a_module():
    modules = sorted(
        p.parent.relative_to(CAPTURED / "in").as_posix()
        for p in (CAPTURED / "in").rglob("go.mod")
    )
    assert modules == ["dep", "neg", "pos"]
    assert os.path.isfile(CAPTURED / "in" / "dep" / "go.sum")
