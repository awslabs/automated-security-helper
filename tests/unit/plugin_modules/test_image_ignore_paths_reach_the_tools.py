# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ignore_paths`` reach the image tools as excludes, as well as the report.

An ignore path always filtered an image scan's findings after the fact. The
three tools that read images can also be told to leave paths unread (trivy
``--skip-files``, syft and grype ``--exclude``; the measurements are in
``utils/image_ignore_paths``), so the argv now carries them. The report filter
is unchanged and still runs, so these rows pin only what the tools are handed.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.image_ignore_paths import (
    MAX_EXCLUDE_GLOBS,
    image_exclude_globs,
)

pytestmark = pytest.mark.unit

IMAGE_REF = "registry.example.com/team/app:1.2.3"


def _ignore(*paths: str):
    return [IgnorePathWithReason(path=path, reason="test") for path in paths]


class TestTranslation:
    def test_a_bare_path_is_the_file_and_its_subtree(self):
        excludes = image_exclude_globs(_ignore("/usr/share/doc"))
        assert excludes.globs == ["/usr/share/doc", "/usr/share/doc/**"]
        assert excludes.left_to_the_filter == []

    def test_a_trailing_slash_is_the_directory_only(self):
        excludes = image_exclude_globs(_ignore("/usr/share/doc/"))
        assert excludes.globs == ["/usr/share/doc/**"]

    def test_a_glob_is_passed_as_written(self):
        excludes = image_exclude_globs(_ignore("/srv/*/creds.txt", "**/vendor/**"))
        assert excludes.globs == ["/srv/*/creds.txt", "**/vendor/**"]

    def test_backslashes_are_separators_as_the_matcher_reads_them(self):
        assert image_exclude_globs(_ignore("\\opt\\skip\\")).globs == ["/opt/skip/**"]

    @pytest.mark.parametrize(
        "path",
        [
            "vendor/",  # relative: anchored at a reported path, no tool glob says so
            "node_modules/**",
            "/usr/*/doc/",  # a glob ending in "/": files below directories
            "",
            ".",
            "./",
            "/",
            "/a\nb",  # a line break splits trivy's list
        ],
    )
    def test_what_no_tool_glob_can_say_is_left_to_the_filter(self, path):
        excludes = image_exclude_globs(_ignore(path))
        assert excludes.globs == []
        assert excludes.left_to_the_filter == [path]

    def test_a_repeated_glob_is_given_once(self):
        excludes = image_exclude_globs(_ignore("/opt/x/", "/opt/x/**"))
        assert excludes.globs == ["/opt/x/**"]

    def test_no_entries_is_nothing(self):
        assert image_exclude_globs(None).globs == []
        assert image_exclude_globs([]).left_to_the_filter == []

    def test_the_count_given_to_a_tool_is_bounded(self):
        many = _ignore(*(f"/data/dir{i}/" for i in range(MAX_EXCLUDE_GLOBS + 25)))
        excludes = image_exclude_globs(many)
        assert len(excludes.globs) == MAX_EXCLUDE_GLOBS
        assert len(excludes.left_to_the_filter) == 25


def _context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _archive(tmp_path) -> Path:
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(name="manifest.json")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"[]"))
    return path


IGNORES = _ignore("/opt/skipme/", "/srv/*/creds.txt", "relative/dir/")


class TestTrivy:
    def _scanner(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
            TrivyScanner,
            TrivyScannerConfig,
        )

        return TrivyScanner(context=_context(tmp_path), config=TrivyScannerConfig())

    def test_the_ignore_paths_become_skip_files_before_the_target(self, tmp_path):
        scanner = self._scanner(tmp_path)
        scanner._image_ignore_paths = list(IGNORES)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_archive=_archive(tmp_path))
        )
        assert "--skip-files=/opt/skipme/**" in argv
        assert "--skip-files=/srv/*/creds.txt" in argv
        # trivy's --skip-dirs removed nothing from an image in measurement.
        assert not any(token.startswith("--skip-dirs") for token in argv)
        assert not any("relative" in token for token in argv)
        target = next(token for token in argv if token.startswith("--input="))
        assert argv.index("--skip-files=/opt/skipme/**") < argv.index(target)

    def test_no_ignore_path_adds_no_skip_flag(self, tmp_path):
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_archive=_archive(tmp_path))
        )
        assert not any(token.startswith("--skip-files") for token in argv)
        assert not any(token.startswith("--skip-dirs") for token in argv)


class TestGrype:
    def _scanner(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )

        return GrypeScanner(context=_context(tmp_path), config=GrypeScannerConfig())

    def test_each_glob_is_one_exclude(self, tmp_path):
        scanner = self._scanner(tmp_path)
        scanner._image_ignore_paths = list(IGNORES)
        argv, _results, _env = scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        values = [argv[i + 1] for i, token in enumerate(argv) if token == "--exclude"]
        assert values == ["/opt/skipme/**", "/srv/*/creds.txt"]

    def test_the_directory_scan_is_not_given_the_image_excludes(self, tmp_path):
        scanner = self._scanner(tmp_path)
        scanner._image_ignore_paths = list(IGNORES)
        source = Path(scanner.context.source_dir)
        argv, _results, _env = scanner._execute_scan(source, "source", [])
        assert "/opt/skipme/**" not in argv


class TestSyft:
    def test_the_image_dispatch_stores_the_ignore_paths(self, tmp_path, monkeypatch):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
            SyftScannerConfig,
        )

        monkeypatch.setenv("ASH_OFFLINE", "true")
        monkeypatch.setattr(
            "automated_security_helper.core.container_engine.DOCKER_DEFAULT_SOCKET",
            str(tmp_path / "absent.sock"),
        )
        monkeypatch.setattr(
            "automated_security_helper.core.container_engine.PODMAN_SYSTEM_SOCKET",
            str(tmp_path / "absent-podman.sock"),
        )
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        scanner = SyftScanner(context=_context(tmp_path), config=SyftScannerConfig())
        # Offline with no engine ends in the clean skip, after the paths are kept.
        scanner.scan_image(ImageLocator(ref=IMAGE_REF), global_ignore_paths=IGNORES)
        assert [entry.path for entry in scanner._image_ignore_paths] == [
            entry.path for entry in IGNORES
        ]
        assert scanner._image_exclude_globs() == [
            "/opt/skipme/**",
            "/srv/*/creds.txt",
        ]

    def test_the_base_dispatch_stores_them_too(self, tmp_path, monkeypatch):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
            TrivyScanner,
            TrivyScannerConfig,
        )

        monkeypatch.setenv("ASH_OFFLINE", "true")
        monkeypatch.setattr(
            "automated_security_helper.core.container_engine.DOCKER_DEFAULT_SOCKET",
            str(tmp_path / "absent.sock"),
        )
        monkeypatch.setattr(
            "automated_security_helper.core.container_engine.PODMAN_SYSTEM_SOCKET",
            str(tmp_path / "absent-podman.sock"),
        )
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        scanner = TrivyScanner(context=_context(tmp_path), config=TrivyScannerConfig())
        scanner.scan_image(ImageLocator(ref=IMAGE_REF), global_ignore_paths=IGNORES)
        assert len(scanner._image_ignore_paths) == len(IGNORES)
