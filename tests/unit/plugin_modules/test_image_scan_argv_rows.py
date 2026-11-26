# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The exact image-mode argv per wired scanner, with the filesystem control.

The C9 argv rows: no tool runs here. ``_execute_image_scan`` is called
directly (the executor's seam), the engine detection is pointed at paths this
suite owns, and each row asserts the one translation the design names --
stereoscope schemes for grype (and syft, whose shared translation
``utils/image_tool_targets.stereoscope_target`` is pinned per shape), the
``image`` subcommand with ``--image-src`` or ``--input`` for trivy -- plus the
control: the filesystem argv is byte-for-byte what it was.
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

#: A row that binds an engine socket of its own: a Python without
#: socket.AF_UNIX (Windows' CPython) cannot, and the probe it exercises only
#: finds unix sockets, so the row does not apply there.
needs_unix_sockets = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="no socket.AF_UNIX (Windows), so no unix-socket engine can be faked",
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


def _archive(tmp_path) -> Path:
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(name="manifest.json")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"[]"))
    return path


def _layout(tmp_path) -> Path:
    layout = tmp_path / "layout"
    layout.mkdir(exist_ok=True)
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    return layout


def _no_engine(monkeypatch, tmp_path):
    """Point every default socket into this test's own empty tree."""
    import automated_security_helper.core.container_engine as engine_module

    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(
        engine_module, "DOCKER_DEFAULT_SOCKET", str(tmp_path / "absent-docker.sock")
    )
    monkeypatch.setattr(
        engine_module, "PODMAN_SYSTEM_SOCKET", str(tmp_path / "absent-podman.sock")
    )


def _docker_engine(monkeypatch, tmp_path):
    _no_engine(monkeypatch, tmp_path)
    sock_path = tmp_path / "docker.sock"
    server = socket.socket(socket.AF_UNIX)
    # Bound by a relative name from inside the directory, as the podman row
    # does: an AF_UNIX path holds about 100 bytes, and a deep basetemp (the
    # macOS runners' tmp_path, or xdist's per-worker one) makes the full path
    # too long for the bind. The probe only stats DOCKER_HOST's full path,
    # which has no such limit.
    try:
        with monkeypatch.context() as scoped:
            scoped.chdir(tmp_path)
            server.bind(sock_path.name)
    except BaseException:
        server.close()
        raise
    monkeypatch.setenv("DOCKER_HOST", f"unix://{sock_path}")
    return server


class TestEngineDetection:
    def test_no_socket_is_none(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        assert detect_container_engine() == ContainerEngine.NONE

    @needs_unix_sockets
    def test_a_docker_host_unix_socket_is_docker(self, monkeypatch, tmp_path):
        server = _docker_engine(monkeypatch, tmp_path)
        try:
            assert detect_container_engine() == ContainerEngine.DOCKER
        finally:
            server.close()

    def test_a_tcp_docker_host_is_not_probed(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
        assert detect_container_engine() == ContainerEngine.NONE

    @needs_unix_sockets
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


class TestStereoscopeTargets:
    def test_a_docker_save_archive_needs_no_engine(self, tmp_path):
        # The submitted shape is a `docker save` tarball: it holds manifest.json
        # and stereoscope reads it as docker-archive (measured: syft and grype
        # refuse it as oci-archive).
        archive = _archive(tmp_path)
        locator = ImageLocator(oci_archive=archive)
        assert stereoscope_target(locator, ContainerEngine.NONE) == (
            f"docker-archive:{archive.absolute().as_posix()}"
        )

    def test_an_oci_layout_tarball_is_an_oci_archive(self, tmp_path):
        archive = tmp_path / "layout.tar"
        with tarfile.open(archive, "w") as saved:
            for name, data in (("oci-layout", b"{}"), ("index.json", b"{}")):
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                saved.addfile(info, io.BytesIO(data))
        assert archive_scheme(archive) == "oci-archive"
        assert stereoscope_target(
            ImageLocator(oci_archive=archive), ContainerEngine.NONE
        ) == (f"oci-archive:{archive.absolute().as_posix()}")

    def test_a_save_that_holds_both_listings_is_docker_archive(self, tmp_path):
        # A recent `docker save` writes manifest.json and an OCI index.
        archive = tmp_path / "both.tar"
        with tarfile.open(archive, "w") as saved:
            for name in ("index.json", "oci-layout", "manifest.json"):
                info = tarfile.TarInfo(name=name)
                info.size = 2
                saved.addfile(info, io.BytesIO(b"{}"))
        assert archive_scheme(archive) == "docker-archive"

    def test_a_dot_slash_member_name_is_read(self, tmp_path):
        archive = tmp_path / "dot.tar"
        with tarfile.open(archive, "w") as saved:
            info = tarfile.TarInfo(name="./manifest.json")
            info.size = 2
            saved.addfile(info, io.BytesIO(b"[]"))
        assert archive_scheme(archive) == "docker-archive"

    def test_an_archive_that_cannot_be_walked_is_the_documented_shape(self, tmp_path):
        broken = tmp_path / "broken.tar"
        broken.write_bytes(b"not a tar" * 100)
        assert archive_scheme(broken) == "docker-archive"
        assert archive_scheme(tmp_path / "absent.tar") == "docker-archive"

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

    @needs_unix_sockets
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

    def test_a_docker_save_archive_is_a_docker_archive_target(
        self, monkeypatch, tmp_path
    ):
        _no_engine(monkeypatch, tmp_path)
        archive = _archive(tmp_path)
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
        # The control: the dir: scan's target spelling is byte-for-byte what
        # it was, whatever the image dispatch added beside it.
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        source = Path(scanner.context.source_dir)
        argv, _results, _env = scanner._execute_scan(source, "source", [])
        import os

        assert f"dir:{Path(os.path.abspath(source)).as_posix()}" in argv


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

    @needs_unix_sockets
    def test_a_ref_with_a_daemon_scans_through_it(self, monkeypatch, tmp_path):
        server = _docker_engine(monkeypatch, tmp_path)
        try:
            scanner = self._scanner(tmp_path)
            argv, _results, _env = scanner._execute_image_scan(
                ImageLocator(ref=IMAGE_REF)
            )
        finally:
            server.close()
        assert argv.index("--image-src=docker") < argv.index(IMAGE_REF)

    def test_an_archive_goes_through_input(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        archive = _archive(tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_archive=archive)
        )
        assert argv[:2] == ["trivy", "image"]
        assert f"--input={archive.absolute().as_posix()}" in argv
        assert not any(token.startswith("--image-src") for token in argv)
        assert IMAGE_REF not in argv
        assert not any(value.startswith("--image-src") for value in argv)

    def test_a_layout_is_a_reported_clean_skip(self, tmp_path):
        scanner = self._scanner(tmp_path)
        layout = _layout(tmp_path)
        reason = scanner._unsupported_image_shape_reason(
            ImageLocator(oci_layout=layout)
        )
        assert reason is not None
        assert "OCI image-layout" in reason

    def test_the_filesystem_subcommand_is_unchanged(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        # The image resolution swaps the subcommand for itself only.
        scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert scanner.subcommands == ["fs"]


class TestSyftImageDispatch:
    def test_syft_overrides_the_whole_image_dispatch(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
        )

        # syft's result is a CycloneDX document, which the base image template
        # would grade as SARIF, so the override must be the whole dispatch.
        assert "scan_image" in vars(SyftScanner)

    def test_an_offline_ref_with_no_engine_is_a_reported_clean_skip(
        self, monkeypatch, tmp_path
    ):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
            SyftScannerConfig,
        )

        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv("ASH_OFFLINE", "true")
        scanner = SyftScanner(context=_context(tmp_path), config=SyftScannerConfig())
        result = scanner.scan_image(ImageLocator(ref=IMAGE_REF))
        assert result is True
        assert scanner._nothing_scanned_reason is not None
        assert "no container engine" in scanner._nothing_scanned_reason
        assert "offline" in scanner._nothing_scanned_reason
