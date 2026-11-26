# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The exact image-mode argv per wired scanner, with the filesystem control.

The C9 argv rows: no tool runs here. ``_execute_image_scan`` is called
directly (the executor's seam), the engine detection is pointed at paths this
suite owns, and each row asserts the one translation the design names --
stereoscope schemes for grype (and syft, whose shared translation
``utils/image_tool_targets.stereoscope_target`` is pinned per shape), the
``image`` subcommand with ``--image-src`` or ``--input`` for trivy -- plus the
control: the image dispatch leaves the filesystem argv exactly as it was.

The engine rows that bind a real AF_UNIX socket are skipped where CPython has
none (Windows), and every bind uses a relative name from inside the socket's
directory: an AF_UNIX path holds about 100 bytes, and a deep basetemp (a CI
runner's, a macOS ``/private/var/folders`` one) makes the full path too long
for the bind.
"""

from __future__ import annotations

import io
import socket
import tarfile
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.core.container_engine import (
    ContainerEngine,
    detect_container_engine,
)
from automated_security_helper.utils.image_tool_targets import (
    archive_scheme,
    stereoscope_target,
)

pytestmark = pytest.mark.unit

IMAGE_REF = "registry.example.com/team/app:1.2.3"

needs_af_unix = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="binding a unix socket needs AF_UNIX, which this platform lacks",
)


def _context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _tar_with(tmp_path, names, file_name="image.tar") -> Path:
    path = tmp_path / file_name
    with tarfile.open(path, "w") as archive:
        for name in names:
            info = tarfile.TarInfo(name=name)
            info.size = 2
            archive.addfile(info, io.BytesIO(b"[]"))
    return path


def _archive(tmp_path) -> Path:
    return _tar_with(tmp_path, ["manifest.json"])


def _docker_archive(tmp_path) -> Path:
    """What ``podman save`` (and docker save before 25) writes: no index.json."""
    return _tar_with(tmp_path, ["manifest.json"], "docker-image.tar")


def _oci_archive(tmp_path) -> Path:
    """A tar holding an OCI layout, as newer ``docker save`` writes."""
    return _tar_with(tmp_path, ["oci-layout", "index.json"], "oci-image.tar")


def _layout(tmp_path) -> Path:
    layout = tmp_path / "layout"
    layout.mkdir(exist_ok=True)
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    return layout


def _no_engine(monkeypatch, tmp_path):
    """Point every default socket into this test's own empty tree."""
    import automated_security_helper.core.container_engine as engine_module

    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("CONTAINER_HOST", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(
        engine_module, "DOCKER_DEFAULT_SOCKET", str(tmp_path / "absent-docker.sock")
    )
    monkeypatch.setattr(
        engine_module, "PODMAN_SYSTEM_SOCKET", str(tmp_path / "absent-podman.sock")
    )


def _docker_engine(monkeypatch, tmp_path):
    """A real unix socket, bound by a RELATIVE name (the AF_UNIX path cap)."""
    _no_engine(monkeypatch, tmp_path)
    sock_dir = tmp_path / "sock"
    sock_dir.mkdir(exist_ok=True)
    server = socket.socket(socket.AF_UNIX)
    monkeypatch.chdir(sock_dir)
    server.bind("docker.sock")
    monkeypatch.setenv("DOCKER_HOST", f"unix://{sock_dir / 'docker.sock'}")
    return server


class TestEngineDetection:
    def test_no_socket_is_none(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        assert detect_container_engine() == ContainerEngine.NONE

    @needs_af_unix
    def test_a_docker_host_unix_socket_is_docker(self, monkeypatch, tmp_path):
        server = _docker_engine(monkeypatch, tmp_path)
        try:
            assert detect_container_engine() == ContainerEngine.DOCKER
        finally:
            server.close()

    def test_a_dead_unix_docker_host_is_none(self, monkeypatch, tmp_path):
        # A leftover variable naming a removed socket is not an engine: a
        # local path is still stat'ed, unlike a declared remote daemon.
        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv("DOCKER_HOST", f"unix://{tmp_path / 'gone.sock'}")
        assert detect_container_engine() == ContainerEngine.NONE

    @pytest.mark.parametrize(
        "value",
        [
            "tcp://docker:2375",
            "ssh://build@ci-daemon",
            "npipe:////./pipe/docker_engine",
        ],
    )
    def test_a_declared_remote_docker_host_is_docker(
        self, monkeypatch, tmp_path, value
    ):
        # GitLab docker-in-docker, ssh daemons and Docker Desktop on Windows
        # declare the daemon in DOCKER_HOST; a dead one behind the declaration
        # is the tool's own error, as a dead local socket's daemon is.
        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv("DOCKER_HOST", value)
        assert detect_container_engine() == ContainerEngine.DOCKER

    def test_a_declared_container_host_is_podman(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv(
            "CONTAINER_HOST",
            "ssh://core@localhost:2222/run/user/1000/podman/podman.sock",
        )
        assert detect_container_engine() == ContainerEngine.PODMAN

    @needs_af_unix
    def test_a_podman_runtime_socket_is_podman(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        runtime = tmp_path / "runtime"
        (runtime / "podman").mkdir(parents=True)
        server = socket.socket(socket.AF_UNIX)
        # Bound by a relative name from inside the directory: an AF_UNIX path
        # holds about 100 bytes, and a deep basetemp (a CI runner's, a lane's)
        # makes the full path too long for the bind.
        monkeypatch.chdir(runtime / "podman")
        server.bind("podman.sock")
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
        try:
            assert detect_container_engine() == ContainerEngine.PODMAN
        finally:
            server.close()


class TestArchiveScheme:
    def test_an_oci_layout_tar_is_oci_archive(self, tmp_path):
        assert archive_scheme(_oci_archive(tmp_path)) == "oci-archive"

    def test_a_manifest_only_tar_is_docker_archive(self, tmp_path):
        # podman save's default, and docker save before 25: stereoscope's
        # oci-archive provider cannot read these, its docker-archive one can
        # (measured on syft 1.57.2 and grype 0.122.1: a docker-save tarball
        # given as oci-archive: is refused).
        assert archive_scheme(_docker_archive(tmp_path)) == "docker-archive"

    def test_a_save_that_holds_both_listings_is_docker_archive(self, tmp_path):
        # A recent `docker save` writes manifest.json and an OCI index;
        # docker-archive: reads that.
        tar = _tar_with(
            tmp_path, ["index.json", "oci-layout", "manifest.json"], "both.tar"
        )
        assert archive_scheme(tar) == "docker-archive"

    def test_a_dot_slash_member_name_is_read(self, tmp_path):
        tar = _tar_with(tmp_path, ["./manifest.json"], "dot.tar")
        assert archive_scheme(tar) == "docker-archive"

    def test_a_markerless_tar_is_the_documented_shape(self, tmp_path):
        # Neither marker: named docker-archive, the documented shape, so the
        # tool reports what is wrong with the bytes itself.
        tar = _tar_with(tmp_path, ["something-else.json"], "odd.tar")
        assert archive_scheme(tar) == "docker-archive"

    def test_an_archive_that_cannot_be_walked_is_the_documented_shape(self, tmp_path):
        not_tar = tmp_path / "not-a.tar"
        not_tar.write_bytes(b"PK\x03\x04 definitely a zip")
        assert archive_scheme(not_tar) == "docker-archive"
        assert archive_scheme(tmp_path / "absent.tar") == "docker-archive"


class TestStereoscopeTargets:
    def test_an_oci_archive_needs_no_engine(self, tmp_path):
        archive = _oci_archive(tmp_path)
        locator = ImageLocator(oci_archive=archive)
        assert stereoscope_target(locator, ContainerEngine.NONE) == (
            f"oci-archive:{archive.absolute().as_posix()}"
        )

    def test_a_docker_archive_gets_its_own_scheme(self, tmp_path):
        archive = _docker_archive(tmp_path)
        locator = ImageLocator(oci_archive=archive)
        assert stereoscope_target(locator, ContainerEngine.NONE) == (
            f"docker-archive:{archive.absolute().as_posix()}"
        )

    def test_a_layout_needs_no_engine(self, tmp_path):
        layout = _layout(tmp_path)
        locator = ImageLocator(oci_layout=layout)
        assert stereoscope_target(locator, ContainerEngine.NONE) == (
            f"oci-dir:{layout.absolute().as_posix()}"
        )

    def test_a_ref_prefers_the_daemon(self):
        locator = ImageLocator(ref=IMAGE_REF)
        assert (
            stereoscope_target(locator, ContainerEngine.DOCKER) == f"docker:{IMAGE_REF}"
        )
        assert (
            stereoscope_target(locator, ContainerEngine.PODMAN) == f"podman:{IMAGE_REF}"
        )

    def test_a_ref_with_no_engine_is_the_registry_client(self):
        locator = ImageLocator(ref=IMAGE_REF)
        assert (
            stereoscope_target(locator, ContainerEngine.NONE) == f"registry:{IMAGE_REF}"
        )


class TestGrypeImageArgv:
    def _scanner(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )

        return GrypeScanner(context=_context(tmp_path), config=GrypeScannerConfig())

    def test_a_ref_with_no_engine_is_a_registry_target(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        argv, results_file, _env = scanner._execute_image_scan(
            ImageLocator(ref=IMAGE_REF)
        )
        assert f"registry:{IMAGE_REF}" in argv
        assert not any(str(value).startswith("dir:") for value in argv)
        assert results_file.parent.name == "image"

    @needs_af_unix
    def test_a_ref_with_a_daemon_is_a_docker_target(self, monkeypatch, tmp_path):
        server = _docker_engine(monkeypatch, tmp_path)
        try:
            scanner = self._scanner(tmp_path)
            argv, _results, _env = scanner._execute_image_scan(
                ImageLocator(ref=IMAGE_REF)
            )
        finally:
            server.close()
        assert f"docker:{IMAGE_REF}" in argv

    def test_the_detected_engine_is_read_once_per_target(self, monkeypatch, tmp_path):
        # scan_image detects once and the argv build reads that one answer
        # (_image_engine), so the skip decision and the target cannot disagree
        # when a socket appears or vanishes between two reads.
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        scanner._image_engine = ContainerEngine.PODMAN
        argv, _results, _env = scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert f"podman:{IMAGE_REF}" in argv

    def test_an_oci_archive_is_an_oci_archive_target(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        archive = _oci_archive(tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_archive=archive)
        )
        assert f"oci-archive:{archive.absolute().as_posix()}" in argv

    def test_a_saved_docker_archive_is_a_docker_archive_target(
        self, monkeypatch, tmp_path
    ):
        _no_engine(monkeypatch, tmp_path)
        archive = _docker_archive(tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_archive=archive)
        )
        assert f"docker-archive:{archive.absolute().as_posix()}" in argv

    def test_a_layout_is_an_oci_dir_target(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        layout = _layout(tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_layout=layout)
        )
        assert f"oci-dir:{layout.absolute().as_posix()}" in argv

    def test_the_filesystem_argv_is_unchanged(self, monkeypatch, tmp_path):
        # The control, whole-argv: the image dispatch leaves the dir: scan's
        # resolution exactly as it was, no token added, dropped or moved.
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        source = Path(scanner.context.source_dir)
        before, _results, _env = scanner._execute_scan(source, "source", [])
        scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        scanner._image_scan_in_progress = False
        after, _results2, _env2 = scanner._execute_scan(source, "source", [])
        assert after == before
        import os

        assert f"dir:{Path(os.path.abspath(source)).as_posix()}" in before


class TestTrivyImageArgv:
    def _scanner(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
            TrivyScanner,
            TrivyScannerConfig,
        )

        return TrivyScanner(context=_context(tmp_path), config=TrivyScannerConfig())

    def test_a_ref_with_no_engine_scans_remote(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        argv, results_file, _env = scanner._execute_image_scan(
            ImageLocator(ref=IMAGE_REF)
        )
        assert argv[:2] == ["trivy", "image"]
        assert "--image-src=remote" in argv
        # The tool's own flags (the output file) may follow the target; what
        # matters is that the engine selection precedes it.
        assert argv.index("--image-src=remote") < argv.index(IMAGE_REF)
        assert results_file.parent.name == "image"

    @needs_af_unix
    def test_a_ref_with_a_daemon_scans_through_it_then_remote(
        self, monkeypatch, tmp_path
    ):
        # The daemon's store first, the registry second: trivy's engine
        # sources never pull, so a single-source value made every
        # not-yet-pulled reference an ERROR on any host with a socket.
        server = _docker_engine(monkeypatch, tmp_path)
        try:
            scanner = self._scanner(tmp_path)
            argv, _results, _env = scanner._execute_image_scan(
                ImageLocator(ref=IMAGE_REF)
            )
        finally:
            server.close()
        assert argv.index("--image-src=docker,remote") < argv.index(IMAGE_REF)

    def test_an_archive_goes_through_input(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        archive = _docker_archive(tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_archive=archive)
        )
        assert argv[:2] == ["trivy", "image"]
        assert f"--input={archive.absolute().as_posix()}" in argv
        assert IMAGE_REF not in argv
        assert not any(str(value).startswith("--image-src") for value in argv)

    def test_a_layout_goes_through_input_too(self, monkeypatch, tmp_path):
        # trivy's --input reads an OCI image-layout directory as well as a
        # saved tar (its container_image target docs), so a layout is scanned,
        # not skipped.
        _no_engine(monkeypatch, tmp_path)
        layout = _layout(tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_layout=layout)
        )
        assert f"--input={layout.absolute().as_posix()}" in argv
        assert (
            scanner._unsupported_image_shape_reason(ImageLocator(oci_layout=layout))
            is None
        )

    def test_the_filesystem_argv_is_unchanged(self, monkeypatch, tmp_path):
        # The control, whole-argv: the image resolution swaps the subcommand
        # for itself only and leaves the fs resolution untouched.
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        source = Path(scanner.context.source_dir)
        before, _results, _env = scanner._execute_scan(source, "source", [])
        scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        scanner._image_scan_in_progress = False
        after, _results2, _env2 = scanner._execute_scan(source, "source", [])
        assert after == before
        assert scanner.subcommands == ["fs"]


class TestSyftImageDispatch:
    def test_syft_overrides_the_whole_image_dispatch(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
        )

        # syft's result is a CycloneDX document, which the base image template
        # would grade as SARIF, so the override must be the whole dispatch.
        assert "scan_image" in vars(SyftScanner)

    @pytest.mark.parametrize("engine_present", [False, True])
    def test_an_offline_ref_is_a_reported_clean_skip(
        self, monkeypatch, tmp_path, engine_present
    ):
        # Offline gates the PULL path too: an engine asked for an image it
        # does not hold pulls it, so a reference is skipped offline whether or
        # not a daemon is present (a payload is not).
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
            SyftScannerConfig,
        )

        _no_engine(monkeypatch, tmp_path)
        if engine_present:
            monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2375")
        monkeypatch.setenv("ASH_OFFLINE", "true")
        scanner = SyftScanner(context=_context(tmp_path), config=SyftScannerConfig())
        result = scanner.scan_image(ImageLocator(ref=IMAGE_REF))
        assert result is True
        assert scanner._nothing_scanned_reason is not None
        assert "offline" in scanner._nothing_scanned_reason
        assert "archive" in scanner._nothing_scanned_reason
