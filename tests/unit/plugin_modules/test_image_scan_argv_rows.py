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
import os
import re
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


#: One run's own tool-config directory: every _execute_scan writes its
#: neutralizing config files into a fresh directory (utils/tool_config_dir
#: gives each run its own, removed with the run), so two resolutions of one
#: target differ in that one path component BY CONSTRUCTION. The filesystem
#: controls mask it and assert whole-argv equality on everything else.
_PER_RUN_CONFIG_DIR = re.compile(r"(ash-tool-config-)[0-9A-Za-z_]+")


def _per_run_dirs_masked(argv) -> list:
    return [_PER_RUN_CONFIG_DIR.sub(r"\1X", str(token)) for token in argv]


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

    def test_a_declared_remote_daemon_is_a_schemeless_ref(self):
        # The tool's own client honors the declared daemon, and the schemeless
        # form keeps stereoscope's source fallback; NONE is unaffected.
        locator = ImageLocator(ref=IMAGE_REF)
        assert (
            stereoscope_target(locator, ContainerEngine.DOCKER, remote_daemon=True)
            == IMAGE_REF
        )
        assert (
            stereoscope_target(locator, ContainerEngine.NONE, remote_daemon=True)
            == f"registry:{IMAGE_REF}"
        )

    @pytest.mark.parametrize(
        "engine, expected",
        [
            (ContainerEngine.DOCKER, ["docker", "registry"]),
            (ContainerEngine.PODMAN, ["podman", "registry"]),
        ],
    )
    def test_a_schemeless_target_names_its_sources(self, engine, expected):
        # Schemeless, grype and syft try their LOCAL sources first: measured on
        # syft 1.57.2 and grype 0.122.1 with DOCKER_HOST=tcp://, "/abs/dir"
        # and a valid reference that is also a directory in the tool's working
        # directory ("app" beside ./app) were each cataloged as a directory.
        # Naming the sources (--from) keeps the declared daemon and then the
        # registry, the fallback the schemeless form was chosen for, and no
        # local file or directory source.
        from automated_security_helper.utils.image_tool_targets import (
            stereoscope_sources,
        )

        locator = ImageLocator(ref=IMAGE_REF)
        assert stereoscope_sources(locator, engine, remote_daemon=True) == expected

    def test_every_schemed_target_names_no_sources(self, tmp_path):
        from automated_security_helper.utils.image_tool_targets import (
            stereoscope_sources,
        )

        ref = ImageLocator(ref=IMAGE_REF)
        layout = ImageLocator(oci_layout=_layout(tmp_path))
        archive = ImageLocator(oci_archive=_docker_archive(tmp_path))
        assert stereoscope_sources(ref, ContainerEngine.DOCKER) == []
        assert stereoscope_sources(ref, ContainerEngine.PODMAN) == []
        assert stereoscope_sources(ref, ContainerEngine.NONE, remote_daemon=True) == []
        for payload in (layout, archive):
            assert (
                stereoscope_sources(payload, ContainerEngine.DOCKER, remote_daemon=True)
                == []
            )

    @pytest.mark.parametrize(
        "engine, remote",
        [
            (ContainerEngine.DOCKER, True),
            (ContainerEngine.PODMAN, True),
            (ContainerEngine.DOCKER, False),
            (ContainerEngine.NONE, False),
        ],
    )
    @pytest.mark.parametrize("value", ["/etc", "../app", "-x"])
    def test_a_non_reference_never_becomes_a_target(self, engine, remote, value):
        # A locator built without validation (model_construct) is the shape no
        # surface makes; the target is still refused rather than handed over.
        locator = ImageLocator.model_construct(ref=value)
        with pytest.raises(ValueError, match="not an image reference"):
            stereoscope_target(locator, engine, remote_daemon=remote)


DIGEST = "sha256:" + "ab" * 32


class TestARegistryResolvedTagIsPulledByDigest:
    """What the tools pull is what the ids key on (the digest-vs-scanned row).

    A tag-only reference whose digest the REGISTRY named is handed to the
    tools as ``repo@<digest>``: a tag moved between the resolution and the
    pull cannot make the report describe bytes nobody keyed. An ENGINE-named
    digest pins nothing (it may be the config-blob Id, which no registry
    serves), and a pinned reference is already itself.
    """

    PINNED = f"registry.example.com/team/app@{DIGEST}"

    def _registry_resolved(self, ref=IMAGE_REF):
        return ImageLocator(ref=ref, resolved_digest=DIGEST, resolved_from="registry")

    def test_the_stereoscope_target_is_digest_pinned(self):
        assert stereoscope_target(self._registry_resolved(), ContainerEngine.NONE) == (
            f"registry:{self.PINNED}"
        )
        assert stereoscope_target(
            self._registry_resolved(), ContainerEngine.DOCKER
        ) == (f"docker:{self.PINNED}")

    def test_a_port_carrying_registry_keeps_its_port(self):
        pinned = ImageLocator(
            ref="registry.example.com:5000/team/app:1.2",
            resolved_digest=DIGEST,
            resolved_from="registry",
        ).pulled_ref()
        assert pinned == f"registry.example.com:5000/team/app@{DIGEST}"

    def test_an_engine_named_digest_pins_nothing(self):
        # The engine's answer may be the config-blob Id: not a registry
        # lookup key, and the engine's store is already one copy.
        locator = ImageLocator(
            ref=IMAGE_REF, resolved_digest=DIGEST, resolved_from="engine"
        )
        assert locator.pulled_ref() == IMAGE_REF
        assert (
            stereoscope_target(locator, ContainerEngine.DOCKER) == f"docker:{IMAGE_REF}"
        )

    def test_a_pinned_ref_is_left_as_written(self):
        locator = ImageLocator(
            ref=self.PINNED, resolved_digest=DIGEST, resolved_from="registry"
        )
        assert locator.pulled_ref() == self.PINNED

    @pytest.mark.parametrize("digest", ["latest", "sha256:abc", "md5:" + "0" * 32])
    def test_a_digest_that_is_not_one_pins_nothing(self, digest):
        # A locator built without validation is the shape no surface makes;
        # its digest is still read before it reaches an argv, so the tools
        # are never handed name@latest.
        locator = ImageLocator.model_construct(
            ref=IMAGE_REF, resolved_digest=digest, resolved_from="registry"
        )
        assert locator.pulled_ref() == IMAGE_REF
        assert stereoscope_target(locator, ContainerEngine.NONE) == (
            f"registry:{IMAGE_REF}"
        )

    def test_trivys_target_is_digest_pinned(self, monkeypatch, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
            TrivyScanner,
            TrivyScannerConfig,
        )

        _no_engine(monkeypatch, tmp_path)
        scanner = TrivyScanner(context=_context(tmp_path), config=TrivyScannerConfig())
        argv, _results, _env = scanner._execute_image_scan(self._registry_resolved())
        assert self.PINNED in argv
        assert IMAGE_REF not in argv

    def test_grypes_target_is_digest_pinned(self, monkeypatch, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )

        _no_engine(monkeypatch, tmp_path)
        scanner = GrypeScanner(context=_context(tmp_path), config=GrypeScannerConfig())
        argv, _results, _env = scanner._execute_image_scan(self._registry_resolved())
        assert f"registry:{self.PINNED}" in argv


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
        # (_image_engine plus its socket), so the skip decision and the target
        # cannot disagree when a socket appears or vanishes between two reads.
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        scanner._image_engine = ContainerEngine.PODMAN
        scanner._image_engine_socket = str(tmp_path / "podman.sock")
        argv, _results, _env = scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert f"podman:{IMAGE_REF}" in argv

    def test_a_declared_remote_daemon_keeps_the_source_fallback(
        self, monkeypatch, tmp_path
    ):
        # A tcp:// DOCKER_HOST counts as a daemon, but stereoscope gets the
        # SCHEMELESS ref: its own client honors the declaration AND its source
        # order still reaches the registry when the declaration is stale, where
        # a pinned docker: scheme flipped every scan to an ERROR.
        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2375")
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert IMAGE_REF in argv
        assert f"docker:{IMAGE_REF}" not in argv
        assert f"registry:{IMAGE_REF}" not in argv

    @pytest.mark.parametrize(
        "variable, value, engine",
        [
            ("DOCKER_HOST", "tcp://docker:2375", "docker"),
            ("CONTAINER_HOST", "ssh://core@localhost:2222/run/podman.sock", "podman"),
        ],
    )
    def test_a_declared_remote_daemon_reads_no_local_source(
        self, monkeypatch, tmp_path, variable, value, engine
    ):
        # The schemeless ref with its sources named, before the target: the
        # declared daemon, then the registry, and never a local path that
        # happens to spell the reference.
        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv(variable, value)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        target = argv.index(IMAGE_REF)
        flags = [index for index, token in enumerate(argv) if token == "--from"]
        assert [argv[index + 1] for index in flags] == [engine, "registry"]
        assert all(index < target for index in flags)

    def test_a_local_daemon_names_no_sources(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        scanner._image_engine = ContainerEngine.DOCKER
        scanner._image_engine_socket = str(tmp_path / "docker.sock")
        argv, _results, _env = scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert f"docker:{IMAGE_REF}" in argv
        assert "--from" not in argv

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
        # The control, whole-argv modulo the per-run config directory: the
        # image dispatch leaves the dir: scan's resolution exactly as it was,
        # no token added, dropped or moved. Nothing resets the in-progress
        # flag by hand: a resolution-only image call must not set it (and the
        # assertion below would name the leak if it did).
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        source = Path(scanner.context.source_dir)
        before, _results, _env = scanner._execute_scan(source, "source", [])
        scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert scanner._image_scan_in_progress is False
        after, _results2, _env2 = scanner._execute_scan(source, "source", [])
        assert _per_run_dirs_masked(after) == _per_run_dirs_masked(before)
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

    def test_the_reference_is_an_operand_after_the_end_of_options(
        self, monkeypatch, tmp_path
    ):
        # trivy reads its target slot as a positional with no scheme, so the
        # reference goes last, after "--": nothing it holds can be read as an
        # option, and every option (the output file included) precedes it.
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert argv[-2:] == ["--", IMAGE_REF]
        assert argv.count("--") == 1
        assert argv.count(IMAGE_REF) == 1
        assert argv.index("--output") < argv.index("--")

    def test_a_payload_needs_no_end_of_options(self, monkeypatch, tmp_path):
        _no_engine(monkeypatch, tmp_path)
        archive = _docker_archive(tmp_path)
        scanner = self._scanner(tmp_path)
        argv, _results, _env = scanner._execute_image_scan(
            ImageLocator(oci_archive=archive)
        )
        assert "--" not in argv

    @pytest.mark.parametrize("value", ["--help", "/etc", "../app"])
    def test_a_non_reference_never_reaches_the_argv(self, monkeypatch, tmp_path, value):
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        with pytest.raises(ValueError, match="not an image reference"):
            scanner._execute_image_scan(ImageLocator.model_construct(ref=value))

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
        # The control, whole-argv modulo the per-run config directory: the
        # image resolution swaps the subcommand for itself only and leaves the
        # fs resolution untouched. Nothing resets the in-progress flag by
        # hand: a resolution-only image call must not set it.
        _no_engine(monkeypatch, tmp_path)
        scanner = self._scanner(tmp_path)
        source = Path(scanner.context.source_dir)
        before, _results, _env = scanner._execute_scan(source, "source", [])
        scanner._execute_image_scan(ImageLocator(ref=IMAGE_REF))
        assert scanner._image_scan_in_progress is False
        after, _results2, _env2 = scanner._execute_scan(source, "source", [])
        assert _per_run_dirs_masked(after) == _per_run_dirs_masked(before)
        assert scanner.subcommands == ["fs"]


class TestSyftImageDispatch:
    def test_syft_overrides_the_whole_image_dispatch(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
        )

        # syft's result is a CycloneDX document, which the base image template
        # would grade as SARIF, so the override must be the whole dispatch.
        assert "scan_image" in vars(SyftScanner)

    def test_a_declared_remote_daemon_reads_no_local_source(
        self, monkeypatch, tmp_path
    ):
        # syft builds its image argv inside scan_image, so the row stops the
        # run at the spawn and reads the argv it was about to start.
        from automated_security_helper.core.exceptions import ScannerError
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
            SyftScannerConfig,
        )

        _no_engine(monkeypatch, tmp_path)
        monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2375")
        scanner = SyftScanner(context=_context(tmp_path), config=SyftScannerConfig())
        seen = {}

        class _Stop(Exception):
            pass

        def _spawn(command, **_kwargs):
            seen["argv"] = list(command)
            raise _Stop

        def _pre_scan(**_kwargs):
            scanner.dependencies_satisfied = True
            return True

        monkeypatch.setattr(scanner, "_pre_scan", _pre_scan)
        monkeypatch.setattr(scanner, "_run_subprocess", _spawn)
        with pytest.raises(ScannerError):
            scanner.scan_image(ImageLocator(ref=IMAGE_REF))
        argv = seen["argv"]
        target = argv.index(IMAGE_REF)
        flags = [index for index, token in enumerate(argv) if token == "--from"]
        assert [argv[index + 1] for index in flags] == ["docker", "registry"]
        assert all(index < target for index in flags)

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
