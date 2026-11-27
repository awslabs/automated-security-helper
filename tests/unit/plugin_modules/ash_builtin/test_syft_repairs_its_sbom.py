"""An SBOM with one part CycloneDX 1.6 does not define keeps every component.

syft is asked for CycloneDX 1.6 and ``CycloneDXReport`` refuses any key outside it,
so one component with a key a newer syft writes, an external reference of a type
added after 1.6, or a number where the model wants text refused the whole SBOM and
every component with it. Each of those parts is now repaired where the scanner
reads the SBOM, counted on the scanner's record with the place it was at (field
names and list positions, never a value), and said once in the log. A component
whose type or name cannot be read still refuses the SBOM, as before.

The directory scan and the image scan read the SBOM in two places, so every case
runs through both.
"""

from __future__ import annotations

import io
import json
import logging
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

pytestmark = pytest.mark.unit

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "snapshot_fixture"
    / "scanner_outputs"
    / "syft.cdx.json"
)

#: Values the record and the log must never carry.
_CATALOGER = "python-installed-package-cataloger"
_NEW_REFERENCE_TYPE = "homepage-x"


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")


def _sbom() -> dict[str, Any]:
    """A fresh copy of the SBOM syft's snapshot fixture holds: two components."""
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _repairable_sbom() -> dict[str, Any]:
    """The fixture with the three parts of the brief: a key CycloneDX 1.6 does not
    define on one component, an external reference of a type it does not define
    beside one it does, and a purl that is a number."""
    document = _sbom()
    document["components"][0]["foundBy"] = _CATALOGER
    document["components"][0]["externalReferences"] = [
        {"type": _NEW_REFERENCE_TYPE, "url": "https://example.com/a"},
        {"type": "website", "url": "https://example.com/b"},
    ]
    document["components"][1]["purl"] = 5
    return document


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    return context


def _archive(tmp_path: Path) -> Path:
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(name="manifest.json")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"[]"))
    return path


def _syft_writes(document: Any):
    """What the subprocess does: writes *document* where syft was told to."""

    def run(command, **kwargs):
        (value,) = [a for a in command if str(a).startswith("cyclonedx-json@")]
        destination = Path(str(value).split("=", 1)[1])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(document), encoding="utf-8")
        return {"returncode": 0}

    return run


def _scanner(tmp_path: Path) -> SyftScanner:
    scanner = SyftScanner(context=_context(tmp_path), config=SyftScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


@pytest.fixture(params=["directory", "image"])
def scan(request, tmp_path):
    """Run the scanner over the SBOM syft wrote, through the named scan."""
    scanner = _scanner(tmp_path)
    archive = _archive(tmp_path)

    def run(document: Any):
        with (
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(scanner, "_post_scan"),
            patch.object(
                scanner, "_run_subprocess", side_effect=_syft_writes(document)
            ),
        ):
            if request.param == "directory":
                return scanner.scan(
                    target=Path(scanner.context.source_dir), target_type="source"
                )
            return scanner.scan_image(ImageLocator(oci_archive=archive))

    return SimpleNamespace(scanner=scanner, run=run, kind=request.param)


def _components(report: CycloneDXReport) -> list[dict[str, Any]]:
    return report.model_dump(mode="json", exclude_none=True)["components"]


def _noted(scanner: SyftScanner) -> list[tuple[str, str, str]]:
    summary = scanner.output_ingest_record
    assert summary is not None
    return sorted(
        (element["action"], element["code"], element["pointer"])
        for element in summary["elements"]
    )


# --- one part at a time ---------------------------------------------------------


def test_a_component_with_a_key_cyclonedx_does_not_define_keeps_the_sbom(scan):
    document = _sbom()
    document["components"][0]["foundBy"] = _CATALOGER

    report = scan.run(document)

    assert isinstance(report, CycloneDXReport)
    components = _components(report)
    assert [component["name"] for component in components] == ["requests", "python"]
    assert "foundBy" not in components[0]
    assert components[0]["purl"] == "pkg:pypi/requests@2.19.1"
    assert _noted(scan.scanner) == [("dropped", "unknown_key", "components/0/*")]


def test_an_external_reference_of_a_type_added_after_1_6_is_left_out_alone(scan):
    document = _sbom()
    document["components"][0]["externalReferences"] = [
        {"type": _NEW_REFERENCE_TYPE, "url": "https://example.com/a"},
        {"type": "website", "url": "https://example.com/b"},
    ]

    report = scan.run(document)

    references = _components(report)[0]["externalReferences"]
    assert [reference["type"] for reference in references] == ["website"]
    assert references[0]["url"] == "https://example.com/b"
    assert _noted(scan.scanner) == [
        (
            "dropped",
            "externalReferences_entry_unreadable",
            "components/0/externalReferences/0",
        )
    ]


def test_a_purl_that_is_a_number_is_written_as_text(scan):
    document = _sbom()
    document["components"][1]["purl"] = 5

    report = scan.run(document)

    components = _components(report)
    assert components[1]["purl"] == "5"
    assert components[0]["purl"] == "pkg:pypi/requests@2.19.1"
    assert _noted(scan.scanner) == [
        ("rewritten", "number_as_text", "components/1/purl")
    ]


# --- all three, and what is said about them --------------------------------------


def test_every_repair_is_counted_and_no_component_is_lost(scan):
    report = scan.run(_repairable_sbom())

    assert [component["name"] for component in _components(report)] == [
        "requests",
        "python",
    ]
    summary = scan.scanner.output_ingest_record
    assert summary is not None
    assert (summary["results_read"], summary["repaired"], summary["left_out"]) == (
        2,
        3,
        0,
    )
    assert sorted((c["action"], c["code"], c["count"]) for c in summary["changes"]) == [
        ("dropped", "externalReferences_entry_unreadable", 1),
        ("dropped", "unknown_key", 1),
        ("rewritten", "number_as_text", 1),
    ]
    assert _noted(scan.scanner) == [
        (
            "dropped",
            "externalReferences_entry_unreadable",
            "components/0/externalReferences/0",
        ),
        ("dropped", "unknown_key", "components/0/*"),
        ("rewritten", "number_as_text", "components/1/purl"),
    ]


def test_the_record_holds_no_value_from_the_sbom(scan):
    scan.run(_repairable_sbom())

    written = json.dumps(scan.scanner.output_ingest_record)

    assert _CATALOGER not in written
    assert _NEW_REFERENCE_TYPE not in written
    assert "foundBy" not in written
    assert "example.com" not in written


def test_the_repairs_are_said_once_in_the_log_without_a_value(scan, caplog):
    with caplog.at_level(logging.WARNING):
        scan.run(_repairable_sbom())

    said = [
        record.getMessage()
        for record in caplog.records
        if "ASH repaired" in record.getMessage()
    ]
    assert len(said) == 1
    assert "3 parts of syft's report that CycloneDX does not allow" in said[0]
    assert _CATALOGER not in caplog.text
    assert _NEW_REFERENCE_TYPE not in caplog.text


# --- what is not changed ----------------------------------------------------------


def test_a_clean_sbom_is_read_as_the_model_reads_it_and_says_nothing(scan, caplog):
    with caplog.at_level(logging.WARNING):
        report = scan.run(_sbom())

    assert report == CycloneDXReport.model_validate(_sbom())
    assert scan.scanner.output_ingest_record is None
    assert "ASH repaired" not in caplog.text


def test_a_component_type_cyclonedx_does_not_define_still_refuses_the_sbom(scan):
    """The type of a component is what it is: guessing at one would invent a
    component, so the SBOM is refused as before, with the error count only."""
    document = _sbom()
    document["components"][0]["type"] = "unknown-type"

    with pytest.raises(ScannerError, match="not CycloneDX ASH can read") as refusal:
        scan.run(document)

    assert "unknown-type" not in str(refusal.value)
    assert scan.scanner.output_ingest_record is None


def test_a_component_with_no_name_still_refuses_the_sbom(scan):
    document = _sbom()
    del document["components"][1]["name"]

    with pytest.raises(ScannerError, match="not CycloneDX ASH can read"):
        scan.run(document)

    assert scan.scanner.output_ingest_record is None


# --- one record per target --------------------------------------------------------


def test_a_scan_does_not_carry_the_previous_scans_record(scan):
    scan.run(_repairable_sbom())
    assert scan.scanner.output_ingest_record is not None

    scan.run(_sbom())

    assert scan.scanner.output_ingest_record is None


def test_a_target_with_nothing_to_scan_starts_a_new_record(tmp_path):
    scanner = _scanner(tmp_path)
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(
            scanner, "_run_subprocess", side_effect=_syft_writes(_repairable_sbom())
        ),
    ):
        scanner.scan(target=Path(scanner.context.source_dir), target_type="source")
        assert scanner.output_ingest_record is not None
        empty = tmp_path / "empty"
        empty.mkdir()

        assert scanner.scan(target=empty, target_type="source") is True

    assert scanner.output_ingest_record is None
