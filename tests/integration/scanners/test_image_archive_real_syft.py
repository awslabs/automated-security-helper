# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A real syft catalog of a saved image: the target scheme and the excludes.

What this covers, with the real pinned syft over images built from nothing
(tests/utils/image_archive_fixture.py), no engine and no registry:

- a ``docker save`` tarball is catalogued (``docker-archive:``; given as
  ``oci-archive:`` syft refuses it, the defect ``archive_scheme`` fixes);
- an ignore path reaches syft as ``--exclude`` and the packages under it are
  absent from the SBOM (an absolute in-image glob; the ``./`` form matches
  nothing on an image, which is why the translation never writes it).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
)
from automated_security_helper.utils.config_trust import record_provenance
from tests.utils.image_archive_fixture import build_image_archive
from tests.utils.trivy_fixture import host_arch, host_platform

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]


@pytest.fixture(scope="session")
def syft_bin_dir(tmp_path_factory) -> Path:
    """The pinned syft, installed through ASH's own verified installer, once."""
    import shutil

    from automated_security_helper.utils.download_utils import install_pinned_tool

    on_path = shutil.which("syft")
    if on_path:
        return Path(on_path).parent
    bin_dir = tmp_path_factory.mktemp("syft-bin")
    try:
        install_pinned_tool("syft", host_platform(), host_arch(), bin_dir)
    except Exception as exc:  # pragma: no cover - network-dependent
        pytest.fail(f"could not provision syft through the pinned installer ({exc})")
    return bin_dir


@pytest.fixture
def syft_on_path(syft_bin_dir, monkeypatch) -> Path:
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setenv("PATH", f"{syft_bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    return syft_bin_dir


def _package(name: str) -> bytes:
    return json.dumps({"name": name, "version": "1.0.0", "license": "MIT"}).encode()


def _image(tmp_path: Path) -> Path:
    return build_image_archive(
        tmp_path / "packages.tar",
        {
            "app/node_modules/kept-app/package.json": _package("kept-app"),
            "srv/keep/node_modules/kept-srv/package.json": _package("kept-srv"),
            "opt/skipme/deep/node_modules/skipped-pkg/package.json": _package(
                "skipped-pkg"
            ),
        },
    )


def _catalog(tmp_path: Path, archive: Path, ignore_paths=None) -> set:
    source = tmp_path / "anchor"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    config = AshConfig()
    record_provenance(config, in_tree=[])
    scanner = SyftScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=SyftScannerConfig(),
    )
    report = scanner.scan_image(
        ImageLocator(oci_archive=archive), global_ignore_paths=ignore_paths
    )
    assert report not in (True, False), "syft produced no SBOM"
    components = json.loads(report.model_dump_json(exclude_unset=True)).get(
        "components", []
    )
    return {component["name"] for component in components}


def test_a_docker_save_tarball_is_catalogued(tmp_path, syft_on_path):
    names = _catalog(tmp_path, _image(tmp_path))
    assert {"kept-app", "kept-srv", "skipped-pkg"} <= names


@pytest.mark.parametrize("path", ["/opt/skipme/", "/opt/skipme", "/opt/**/deep/"])
def test_an_ignore_path_keeps_syft_from_cataloguing_what_is_under_it(
    tmp_path, syft_on_path, path
):
    names = _catalog(
        tmp_path,
        _image(tmp_path),
        [IgnorePathWithReason(path=path, reason="test")],
    )
    if path.endswith("/") and "*" in path:
        # A glob ending in "/" is the report filter's alone (no tool glob says it).
        assert "skipped-pkg" in names
    else:
        assert "skipped-pkg" not in names
    assert {"kept-app", "kept-srv"} <= names
