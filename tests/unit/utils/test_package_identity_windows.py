# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Package identity must be the same string on Windows as on POSIX.

On the Windows CI leg grype reports a lockfile as the scan root joined to a
backslashed relative path, for example
``D:/a/repo/repo/\\deploy\\cdk\\package-lock.json``. The grype converter built
``package_path`` from that URI before anything relativized it, and
``install_path`` only swapped backslashes and stripped a leading ``/``, so the
drive and the scan root survived:
``D:/a/repo/repo/deploy/cdk/node_modules/aws-cdk-lib/node_modules/brace-expansion``.
A suppression's ``package_path`` is written relative to the scan root, so the
three bundled brace-expansion findings stayed actionable on Windows only.

A POSIX host cannot produce such a URI by itself, so these tests hand the code
Windows semantics directly: a ``PureWindowsPath`` scan root selects Windows path
parsing, exactly as a real ``WindowsPath`` root does on Windows. Disk reads are
redirected to a lockfile under ``tmp_path``.
"""

import json
import ntpath
import posixpath
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
)
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
from automated_security_helper.utils import package_identity
from automated_security_helper.utils.path_matching import _path_pattern_matches
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

BUNDLED_KEY = "node_modules/aws-cdk-lib/node_modules/brace-expansion"
TOP_KEY = "node_modules/brace-expansion"
WIN_ROOT = PureWindowsPath("D:/a/repo/repo")
# The exact shape grype produced in the Windows CI leg: forward-slashed root,
# then a separator, then the backslashed relative path.
WIN_URI = "D:/a/repo/repo/\\deploy\\cdk\\package-lock.json"
EXPECTED = f"deploy/cdk/{BUNDLED_KEY}"


def _lockfile(tmp_path: Path) -> Path:
    project = tmp_path / "deploy" / "cdk"
    project.mkdir(parents=True)
    packages = {
        "": {"name": "p", "version": "1.0.0"},
        "node_modules/aws-cdk-lib": {"version": "2.272.0"},
        BUNDLED_KEY: {"version": "5.0.9", "inBundle": True},
        TOP_KEY: {"version": "1.1.18"},
    }
    lock = project / "package-lock.json"
    lock.write_text(
        json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2) + "\n"
    )
    return lock


def _grype_result(version: str, uri: str) -> Result:
    return Result(
        ruleId="GHSA-6j4f-fj2g-mc7p-brace-expansion",
        message=Message(
            text=(
                f"A high vulnerability in npm package: brace-expansion, version "
                f"{version} was found at: {uri}"
            )
        ),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=1, startColumn=1, endLine=1, endColumn=1),
                )
            )
        ],
    )


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(tool=Tool(driver=ToolComponent(name="grype")), results=list(results))
        ],
    )


def _props(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


@pytest.fixture
def lockfile_on_disk(tmp_path, monkeypatch):
    """Any read of a package-lock.json is served from the one under tmp_path.

    This stands in for the file existing on the Windows runner's disk; it does
    not care how the caller spelled the path, so the old code (which joined the
    root to an absolute URI) reads the lockfile exactly as it did on Windows.
    """
    lock = _lockfile(tmp_path)
    real = package_identity.load_npm_lock_entries

    def load(path):
        if PureWindowsPath(str(path)).name == "package-lock.json":
            return real(lock)
        return None

    monkeypatch.setattr(package_identity, "load_npm_lock_entries", load)
    return lock


class TestGrypeConverterOnWindows:
    def test_package_path_is_relative_posix(
        self, test_plugin_context, lockfile_on_disk
    ):
        scanner = GrypeScanner(context=test_plugin_context)
        out = scanner._post_process_sarif(
            _report(_grype_result("5.0.9", WIN_URI)), [], WIN_ROOT
        )
        props = _props(out.runs[0].results[0])
        assert props["package_name"] == "brace-expansion"
        assert props["package_version"] == "5.0.9"
        assert props["package_path"] == EXPECTED

    def test_matches_the_config_entry_as_written(
        self, test_plugin_context, lockfile_on_disk
    ):
        """The entry in .ash/.ash.yaml, unchanged: no ``**``, no widening."""
        scanner = GrypeScanner(context=test_plugin_context)
        out = scanner._post_process_sarif(
            _report(_grype_result("5.0.9", WIN_URI)), [], WIN_ROOT
        )
        path = _props(out.runs[0].results[0])["package_path"]
        assert _path_pattern_matches(path, EXPECTED)

    def test_uri_outside_the_scan_root_claims_no_path(
        self, test_plugin_context, lockfile_on_disk
    ):
        scanner = GrypeScanner(context=test_plugin_context)
        uri = "E:/elsewhere/\\deploy\\cdk\\package-lock.json"
        out = scanner._post_process_sarif(
            _report(_grype_result("5.0.9", uri)), [], WIN_ROOT
        )
        props = _props(out.runs[0].results[0])
        assert props["package_version"] == "5.0.9"
        assert "package_path" not in props


class TestScanRelativePath:
    @pytest.mark.parametrize(
        "uri",
        [
            WIN_URI,
            "D:\\a\\repo\\repo\\deploy\\cdk\\package-lock.json",
            "d:/A/Repo/repo/deploy/cdk/package-lock.json",  # Windows is case-insensitive
            "\\deploy\\cdk\\package-lock.json",  # rooted, no drive
            "deploy\\cdk\\package-lock.json",
            "deploy/cdk/package-lock.json",
        ],
    )
    def test_windows_spellings(self, uri):
        rel = package_identity.scan_relative_path(uri, WIN_ROOT)
        assert rel == "deploy/cdk/package-lock.json"

    @pytest.mark.parametrize(
        "uri",
        [
            "E:/other/deploy/cdk/package-lock.json",
            "D:/a/repo/repo/../escape/package-lock.json",
            "..\\escape\\package-lock.json",
        ],
    )
    def test_windows_outside_root_is_none(self, uri):
        assert package_identity.scan_relative_path(uri, WIN_ROOT) is None

    @pytest.mark.parametrize(
        "uri",
        [
            "/src/deploy/cdk/package-lock.json",
            # grype's POSIX convention: scan-root-relative with a leading slash.
            "/deploy/cdk/package-lock.json",
            "deploy/cdk/package-lock.json",
        ],
    )
    def test_posix_spellings(self, uri):
        rel = package_identity.scan_relative_path(uri, PurePosixPath("/src"))
        assert rel == "deploy/cdk/package-lock.json"

    def test_posix_backslash_is_a_filename_character(self):
        """On POSIX a backslash is legal in a name; it must not become a separator."""
        rel = package_identity.scan_relative_path(
            "a\\b/package-lock.json", PurePosixPath("/src")
        )
        assert rel == "a\\b/package-lock.json"


class TestMatchTimeNormalization:
    def _context(self, source_dir, output_dir, *suppressions):
        config = AshConfig(
            project_name="p", global_settings={"suppressions": list(suppressions)}
        )
        return PluginContext(
            source_dir=source_dir, output_dir=output_dir, config=config
        )

    def test_absolute_package_path_under_source_dir_matches(
        self, test_source_dir, test_output_dir
    ):
        """SARIF written by a converter that did not relativize (or by an older
        ASH) still compares in scan-root-relative form."""
        absolute = f"{Path(test_source_dir).resolve().as_posix()}/{EXPECTED}"
        result = _grype_result("5.0.9", "deploy/cdk/package-lock.json")
        result.properties = {
            "package_name": "brace-expansion",
            "package_version": "5.0.9",
            "package_path": absolute,
        }
        supp = AshSuppression(
            rule_id="GHSA-6j4f-fj2g-mc7p*",
            path="deploy/cdk/package-lock.json",
            package_name="brace-expansion",
            package_version="5.0.9",
            package_path=EXPECTED,
            reason="bundled",
        )
        out = apply_suppressions_to_sarif(
            _report(result), self._context(test_source_dir, test_output_dir, supp)
        )
        assert out.runs[0].results[0].suppressions

    def test_absolute_package_path_outside_source_dir_does_not_match(
        self, test_source_dir, test_output_dir
    ):
        result = _grype_result("5.0.9", "deploy/cdk/package-lock.json")
        result.properties = {
            "package_name": "brace-expansion",
            "package_version": "5.0.9",
            "package_path": f"/somewhere/else/{EXPECTED}",
        }
        supp = AshSuppression(
            rule_id="GHSA-6j4f-fj2g-mc7p*",
            path="deploy/cdk/package-lock.json",
            package_path=EXPECTED,
            reason="bundled",
        )
        out = apply_suppressions_to_sarif(
            _report(result), self._context(test_source_dir, test_output_dir, supp)
        )
        assert not out.runs[0].results[0].suppressions

    # fnmatch.fnmatch runs both sides through os.path.normcase, which on Windows
    # turns "/" into "\" and on POSIX does nothing, so the same pattern and path
    # compared differently per platform. Each case is run under both normcase
    # implementations and must give the same answer under each.
    @pytest.mark.parametrize("normcase", [posixpath.normcase, ntpath.normcase])
    @pytest.mark.parametrize(
        "path, pattern, expected",
        [
            (EXPECTED, EXPECTED, True),
            (
                EXPECTED,
                "deploy\\cdk\\node_modules\\aws-cdk-lib\\node_modules\\brace-expansion",
                True,
            ),
            ("deploy\\cdk\\" + BUNDLED_KEY.replace("/", "\\"), EXPECTED, True),
            (EXPECTED, "deploy/cdk/node_modules/*/node_modules/brace-expansion", True),
            (
                EXPECTED,
                "deploy\\cdk\\node_modules\\*\\node_modules\\brace-expansion",
                True,
            ),
            (f"deploy/cdk/{TOP_KEY}", EXPECTED, False),
            (f"deploy/cdk-constructs/{BUNDLED_KEY}", EXPECTED, False),
        ],
    )
    def test_same_answer_on_every_platform(
        self, monkeypatch, normcase, path, pattern, expected
    ):
        import os

        monkeypatch.setattr(os.path, "normcase", normcase)
        assert _path_pattern_matches(path, pattern) is expected
