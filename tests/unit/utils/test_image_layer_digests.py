# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An image scan's results carry the layer that put them there.

trivy's SARIF names no layer; its JSON report does. The tests join a real
captured pair (a secret in the committed archive) and a vulnerability-shaped
pair written to trivy's documented JSON schema, and pin the one case where the
join must stay silent: a key two layers disagree on.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.image_layer_digests import (
    attach_layer_digests,
    json_argv,
    layer_index,
    read_layer_index,
)

pytestmark = pytest.mark.unit

CAPTURED = Path(__file__).resolve().parents[2] / "test_data" / "images" / "captured"
LAYER = "sha256:9fd2968b2b1e3dfa271598db3b56fb431faf5827450d945c04c335b51ae4c077"
DIFF_ID = "sha256:1d22db9c2a74a638d7ce577905a5ea8943518f004a81dbce6251a68809df2b2a"


def _package_of(message):
    first = (message or "").split("\n")[0]
    return first[len("Package: ") :] if first.startswith("Package: ") else None


def _captured_sarif() -> SarifReport:
    return SarifReport.model_validate_json(
        (CAPTURED / "trivy-0.76.2-secret-image.sarif").read_text(encoding="utf-8")
    )


def _layer_of(report: SarifReport) -> list:
    return [
        getattr(r.properties, "layerDigest", None)
        for run in report.runs
        for r in run.results or []
    ]


def test_the_sarif_alone_carries_no_layer():
    assert _layer_of(_captured_sarif()) == [None]


def test_the_captured_secret_gets_its_layer_digest():
    report = _captured_sarif()
    index = read_layer_index(CAPTURED / "trivy-0.76.2-secret-image.json")
    assert attach_layer_digests(report, index, _package_of) == 1
    assert _layer_of(report) == [LAYER]


def _vuln_report(*, second_layer: str | None = None):
    entries = [
        {
            "VulnerabilityID": "CVE-2024-0001",
            "PkgName": "openssl",
            "Layer": {"Digest": LAYER, "DiffID": DIFF_ID},
        },
        {
            "VulnerabilityID": "CVE-2024-0002",
            "PkgName": "zlib",
            "Layer": {"DiffID": DIFF_ID},
        },
    ]
    if second_layer is not None:
        entries.append(
            {
                "VulnerabilityID": "CVE-2024-0001",
                "PkgName": "openssl",
                "Layer": {"Digest": second_layer},
            }
        )
    return {
        "Results": [
            {"Target": "alpine 3.19", "Class": "os-pkgs", "Vulnerabilities": entries}
        ]
    }


def _vuln_sarif() -> SarifReport:
    def result(cve: str, package: str) -> dict:
        return {
            "ruleId": cve,
            "message": {
                "text": f"Package: {package}\nInstalled Version: 1.0\nVulnerability {cve}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "library/alpine"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }

    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Trivy"}},
                    "results": [
                        result("CVE-2024-0001", "openssl"),
                        result("CVE-2024-0002", "zlib"),
                        result("CVE-2024-0003", "busybox"),
                    ],
                }
            ],
        }
    )


def test_a_vulnerability_joins_on_cve_and_package_and_prefers_the_blob_digest():
    report = _vuln_sarif()
    attach_layer_digests(report, layer_index(_vuln_report()), _package_of)
    # The second entry names only a DiffID, which is what is used when it is
    # all the report has; the third finding is in no report entry.
    assert _layer_of(report) == [LAYER, DIFF_ID, None]


def test_a_key_two_layers_disagree_on_stays_empty():
    report = _vuln_sarif()
    index = layer_index(_vuln_report(second_layer="sha256:" + "b" * 64))
    attach_layer_digests(report, index, _package_of)
    assert _layer_of(report) == [None, DIFF_ID, None]


def test_a_key_two_layers_agree_on_is_kept():
    report = _vuln_sarif()
    attach_layer_digests(
        report, layer_index(_vuln_report(second_layer=LAYER)), _package_of
    )
    assert _layer_of(report)[0] == LAYER


@pytest.mark.parametrize(
    "document", [None, [], {}, {"Results": None}, {"Results": [3]}]
)
def test_a_report_without_findings_indexes_nothing(document):
    assert layer_index(document) == {}


def test_an_unreadable_report_indexes_nothing(tmp_path):
    broken = tmp_path / "layers.json"
    broken.write_text("{not json", encoding="utf-8")
    assert read_layer_index(broken) == {}
    assert read_layer_index(tmp_path / "absent.json") == {}


def test_an_empty_index_writes_nothing():
    report = _captured_sarif()
    assert attach_layer_digests(report, {}, _package_of) == 0
    assert _layer_of(report) == [None]


class TestJsonArgv:
    def test_two_token_options_are_replaced_and_the_rest_kept(self, tmp_path):
        argv = [
            "trivy",
            "image",
            "--format",
            "sarif",
            "--output",
            "/out/results_sarif.sarif",
            "--input=/x/app.tar",
        ]
        target = tmp_path / "layers.json"
        assert json_argv(argv, target) == [
            "trivy",
            "image",
            "--format",
            "json",
            "--output",
            target.as_posix(),
            "--input=/x/app.tar",
        ]
        assert argv[3] == "sarif"  # the caller's argv is not edited

    def test_equals_spelling_is_replaced(self, tmp_path):
        target = tmp_path / "layers.json"
        assert json_argv(
            ["trivy", "image", "--format=sarif", "--output=/o.sarif", "ref"], target
        ) == [
            "trivy",
            "image",
            "--format=json",
            f"--output={target.as_posix()}",
            "ref",
        ]

    @pytest.mark.parametrize(
        "argv",
        [
            ["trivy", "image", "ref"],
            ["trivy", "image", "--format", "sarif", "ref"],
            ["trivy", "image", "--output", "/o", "ref"],
        ],
    )
    def test_an_argv_without_both_options_is_not_translated(self, argv, tmp_path):
        assert json_argv(argv, tmp_path / "layers.json") is None


class TestTheScannerRunsTheLayerPass:
    """TrivyScanner._attach_image_layers, with the tool's process replaced."""

    def _scanner(self, tmp_path):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
            TrivyScanner,
            TrivyScannerConfig,
        )

        PluginContext.model_rebuild()
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        scanner = TrivyScanner(
            context=PluginContext(
                source_dir=source, output_dir=output, config=AshConfig()
            ),
            config=TrivyScannerConfig(options={"scanners": ["secret"]}),
        )
        scanner.results_dir = output / "scanners" / "trivy"
        scanner.results_dir.mkdir(parents=True)
        return scanner

    def _fake_spawn(self, monkeypatch, document, returncode=0):
        seen = {}

        def spawn(argv, **kwargs):
            seen["argv"] = list(argv)
            if document is not None:
                out = argv[argv.index("--output") + 1]
                Path(out).write_text(json.dumps(document), encoding="utf-8")
            return SimpleNamespace(returncode=returncode, stdout="", stderr="")

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.spawn_run", spawn
        )
        return seen

    def _args(self, scanner, tmp_path):
        scanner._image_layers_json = tmp_path / "layers.json"
        # An engine's own store serves the tag: one store, read twice within
        # one scan, so the join is sound and the pass runs. The bare-tag rows
        # below clear this to pin the guard.
        scanner._image_engine_socket = "/run/docker.sock"
        return ["trivy", "image", "--format", "sarif", "--output", "/o.sarif", "ref"]

    def test_the_second_pass_asks_for_json_and_fills_the_column(
        self, tmp_path, monkeypatch
    ):
        scanner = self._scanner(tmp_path)
        document = json.loads(
            (CAPTURED / "trivy-0.76.2-secret-image.json").read_text(encoding="utf-8")
        )
        seen = self._fake_spawn(monkeypatch, document)
        report = _captured_sarif()
        args = self._args(scanner, tmp_path)
        assert scanner._attach_image_layers(report, args) == 1
        assert seen["argv"][seen["argv"].index("--format") + 1] == "json"
        assert _layer_of(report) == [LAYER]
        assert args[3] == "sarif"

    def test_a_failing_second_pass_leaves_the_column_empty(self, tmp_path, monkeypatch):
        scanner = self._scanner(tmp_path)
        self._fake_spawn(monkeypatch, None, returncode=2)
        report = _captured_sarif()
        assert scanner._attach_image_layers(report, self._args(scanner, tmp_path)) == 0
        assert _layer_of(report) == [None]

    def test_a_second_pass_that_cannot_start_leaves_the_column_empty(
        self, tmp_path, monkeypatch
    ):
        scanner = self._scanner(tmp_path)

        def refuse(argv, **kwargs):
            raise FileNotFoundError("trivy")

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.spawn_run", refuse
        )
        report = _captured_sarif()
        assert scanner._attach_image_layers(report, self._args(scanner, tmp_path)) == 0

    def test_a_bare_tag_with_no_engine_store_skips_the_pass(
        self, tmp_path, monkeypatch
    ):
        # A tag no local store serves can resolve to a DIFFERENT manifest on
        # the second pull, and layers joined across two images attribute the
        # wrong build: the pass is skipped, running nothing.
        scanner = self._scanner(tmp_path)

        def never(argv, **kwargs):  # pragma: no cover - the assertion
            raise AssertionError("the skipped pass must not run the tool")

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.spawn_run", never
        )
        args = self._args(scanner, tmp_path)
        scanner._image_engine_socket = None
        report = _captured_sarif()
        assert scanner._attach_image_layers(report, args) == 0
        assert _layer_of(report) == [None]

    def test_a_digest_pinned_reference_runs_without_an_engine(
        self, tmp_path, monkeypatch
    ):
        # A digest names one manifest wherever it is read, so the join is
        # sound with no local store at all.
        scanner = self._scanner(tmp_path)
        document = json.loads(
            (CAPTURED / "trivy-0.76.2-secret-image.json").read_text(encoding="utf-8")
        )
        seen = self._fake_spawn(monkeypatch, document)
        args = self._args(scanner, tmp_path)
        scanner._image_engine_socket = None
        args[-1] = "registry.example.com/team/app@sha256:" + "a" * 64
        report = _captured_sarif()
        assert scanner._attach_image_layers(report, args) == 1
        assert _layer_of(report) == [LAYER]
        assert seen["argv"][-1] == args[-1]
