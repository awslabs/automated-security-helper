# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The alpha-scanner CI legs are keyed off plugin metadata, not off a name list.

``.github/scripts/alpha-scanner-legs.py`` reads the image's alpha module list
(the Dockerfile's ``ASH_ALPHA_PLUGIN_MODULES``) and each module's own
``ASH_SCANNERS``. The container action loads and checks whatever it names, so a
alpha scanner reaches the leg by being listed in the image, and which registry
serves a plugin plays no part. These tests pin that, and the betterleaks pieces that
ride on it: the container leg, the nix entry and the sandbox-parity leg.
"""

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/alpha-scanner-legs.py"
CONTAINER = ROOT / ".github/actions/validate-container/action.yml"
NIX = ROOT / ".github/actions/validate-nix/action.yml"
FLAKE = ROOT / "flake.nix"
UNIFIED = ROOT / ".github/workflows/ash-unified-ci.yml"
RUN_SCAN_TEST = ROOT / ".github/actions/run-scan-test/action.yml"
BETTERLEAKS_MODULE = "automated_security_helper.plugin_modules.ash_betterleaks_plugins"
KYVERNO_MODULE = "automated_security_helper.plugin_modules.ash_kyverno_plugins"
KYVERNO_FIXTURE = "tests/test_data/scanners/kyverno/positive"
#: kyverno applies only the policies the operator names; every leg names the fixture's.
KYVERNO_POLICIES = (
    '--config-overrides "scanners.kyverno.options.policy_paths=[policies]"'
)


@pytest.fixture(scope="module")
def legs():
    spec = importlib.util.spec_from_file_location("alpha_scanner_legs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dockerfile(tmp_path, *values):
    path = tmp_path / "Dockerfile"
    path.write_text(
        "\n".join(f'ARG ASH_ALPHA_PLUGIN_MODULES="{v}"' for v in values) + "\n"
    )
    return path


def _steps(path):
    return yaml.safe_load(path.read_text())["runs"]["steps"]


def _step(path, name):
    return next(s for s in _steps(path) if s.get("name") == name)


class TestMetadataReader:
    def test_the_image_lists_betterleaks_beside_the_other_alpha_modules(self, legs):
        modules = legs.image_modules()
        assert BETTERLEAKS_MODULE in modules
        assert len(modules) == len(set(modules))

    def test_scanner_names_come_from_the_plugins_declarations(self, legs):
        assert set(legs.module_scanners(BETTERLEAKS_MODULE)) == {"betterleaks"}
        names = {n for m in legs.image_modules() for n in legs.module_scanners(m)}
        assert {"betterleaks", "guarddog", "hadolint"} <= names

    def test_no_registry_identity_enters_the_answer(self, legs, tmp_path):
        # A module is an alpha module because the image lists it and its package
        # declares a scanner; nothing about where it was published is read. The
        # answer for a listed module is the same whatever the list's other entries.
        one = _dockerfile(tmp_path, BETTERLEAKS_MODULE)
        assert legs.image_modules(one) == [BETTERLEAKS_MODULE]
        source = SCRIPT.read_text()
        assert not re.search(r"registry|index_url|pypi", source.split('"""', 2)[2])

    def test_disagreeing_copies_of_the_list_are_refused(self, legs, tmp_path):
        path = _dockerfile(tmp_path, BETTERLEAKS_MODULE, "a.b,c.d")
        with pytest.raises(legs.LegError, match="disagree"):
            legs.image_modules(path)

    def test_no_arg_and_an_empty_list_are_refused(self, legs, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("FROM scratch\n")
        with pytest.raises(legs.LegError, match="no ARG"):
            legs.image_modules(path)
        with pytest.raises(legs.LegError, match="lists no module"):
            legs.image_modules(_dockerfile(tmp_path, ""))

    def test_a_module_that_declares_no_scanner_is_refused(self, legs):
        # automated_security_helper itself has no ASH_SCANNERS: the planted negative.
        with pytest.raises(legs.LegError, match="declares no scanner"):
            legs.module_scanners("automated_security_helper")

    def test_a_module_that_cannot_be_imported_is_a_clean_refusal(self, legs):
        with pytest.raises(legs.LegError, match="cannot import"):
            legs.module_scanners("automated_security_helper.no_such_plugins")

    def test_cli_args_pair_the_flag_with_each_module(self, legs, capsys):
        assert legs.main(["args"]) == 0
        lines = capsys.readouterr().out.split()
        assert lines[0::2] == ["--ash-plugin-modules"] * (len(lines) // 2)
        assert BETTERLEAKS_MODULE in lines[1::2]

    def test_cli_exits_2_on_bad_metadata(self, legs, tmp_path, capsys):
        path = _dockerfile(tmp_path, "")
        assert legs.main(["modules", "--dockerfile", str(path)]) == 2
        assert "lists no module" in capsys.readouterr().err

    def test_scanner_name_spelling(self, legs):
        class CdkNagScanner:
            pass

        assert legs.scanner_name(CdkNagScanner) == "cdk-nag"


class TestContainerLeg:
    def test_the_built_image_scan_names_no_alpha_module(self):
        run = _step(CONTAINER, "Scan with the built image")["run"]
        assert "alpha-scanner-legs.py args" in run
        assert "ash_guarddog_plugins" not in run
        assert "ash_hadolint_plugins" not in run
        assert '"${alpha_args[@]}"' in run

    def test_the_participation_list_is_not_a_hand_kept_alpha_list(self):
        run = _step(CONTAINER, "Assert every image-supplied scanner participated")[
            "run"
        ]
        assert "alpha-scanner-legs.py" in run
        # Neither an alpha scanner's name nor a literal list of them survives in
        # the list the check walks.
        listing = run.split("builtin_supplied = [", 1)[1].split("]", 1)[0]
        for name in ("betterleaks", "guarddog", "hadolint"):
            assert f'"{name}"' not in listing

    def test_a_betterleaks_leg_requires_a_finding_for_a_known_secret(self):
        step = _step(CONTAINER, "Scan with the image's betterleaks (alpha plugin)")
        run = step["run"]
        assert "--scanners betterleaks" in run
        assert 'if [ "$rc" -ne 2 ]' in run
        assert "FAIL: betterleaks reported nothing" in run
        # Derived from the metadata, like the scan above it.
        assert "alpha-scanner-legs.py args" in run
        assert "grep -x -F betterleaks" in run

    def test_the_betterleaks_fixture_secret_is_not_written_in_the_action(self):
        text = CONTAINER.read_text()
        # Assembled at run time so this file never holds the contiguous token
        # shape (the github-pat pattern) that the action must not hold either.
        fixture_secret = (
            "ghp"
            "_"
            "x7Kq9ZmP2vLw4RtYb8NcD3sFh6JgA1eUoW5i"  # pragma: allowlist secret
        )
        assert fixture_secret not in text
        assert not re.search(r"ghp_[0-9a-zA-Z]{36}", text)
        assert not re.search(r"AKIA[A-Z2-7]{16}", text)

    def test_the_leg_does_not_name_a_registry(self):
        run = _step(CONTAINER, "Scan with the image's betterleaks (alpha plugin)")[
            "run"
        ]
        assert not re.search(r"registry|core-plugin", run, re.IGNORECASE)


class TestNixEntry:
    def test_flake_supplies_betterleaks_and_records_the_version_gap(self):
        flake = FLAKE.read_text()
        assert "pkgs.betterleaks" in flake
        note = flake.split("pkgs.betterleaks", 1)[0].rsplit("\n\n", 1)[-1]
        assert "1.8.1" in note and "1.10.1" in note

    def test_nix_leg_loads_the_module_and_requires_the_scanner(self):
        text = NIX.read_text()
        assert f"--ash-plugin-modules {BETTERLEAKS_MODULE}" in text
        listing = text.split("flake_supplied = [", 1)[1].split("]", 1)[0]
        assert '"betterleaks",' in listing

    def test_flake_supplies_kyverno_and_records_the_version_gap(self):
        flake = FLAKE.read_text()
        assert "pkgs.kyverno" in flake
        # The comment between the entry before it and the kyverno entry.
        note = flake.split("pkgs.kyverno", 1)[0].rsplit("pkgs.hadolint", 1)[-1]
        assert "1.19.0" in note and "1.19.2" in note

    def test_nix_leg_loads_kyverno_names_its_policies_and_requires_it(self):
        text = NIX.read_text()
        assert f"--ash-plugin-modules {KYVERNO_MODULE}" in text
        assert KYVERNO_POLICIES in text
        assert f"{KYVERNO_FIXTURE}/policies" in text
        listing = text.split("flake_supplied = [", 1)[1].split("]", 1)[0]
        assert '"kyverno",' in listing


class TestKyvernoLocalLegs:
    """The python-local legs install kyverno with its module loaded, on every OS, and
    require a finding from the committed fixture."""

    @pytest.mark.parametrize("runner", ["Unix", "Windows"])
    def test_the_leg_installs_kyverno_and_requires_the_fixtures_finding(self, runner):
        step = _step(RUN_SCAN_TEST, f"Validate alpha kyverno (Python Local {runner})")
        run = step["run"]
        assert "ash dependencies install --tool kyverno" in run
        assert f"ash_plugin_modules+=[{KYVERNO_MODULE}]" in run
        assert f"--source-dir {KYVERNO_FIXTURE}" in run
        assert f"--ash-plugin-modules {KYVERNO_MODULE}" in run
        assert KYVERNO_POLICIES in run
        assert "--scanners kyverno" in run
        assert "--expect-exit 2 --min-findings 1" in run

    def test_the_fixture_holds_the_policy_and_one_manifest_that_fails_it(self):
        from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_scanner import (
            is_policy_document,
            is_resource_document,
        )

        fixture = ROOT / KYVERNO_FIXTURE
        policy = yaml.safe_load((fixture / "policies/require-team.yaml").read_text())
        assert is_policy_document(policy)
        annotations = policy["metadata"]["annotations"]
        assert annotations["policies.kyverno.io/severity"] == "high"
        (rule,) = policy["spec"]["rules"]
        required = rule["validate"]["pattern"]["metadata"]["labels"]
        pods = {
            path.name: yaml.safe_load(path.read_text())
            for path in sorted((fixture / "k8s").glob("*.yaml"))
        }
        assert set(pods) == {"bad.yaml", "good.yaml"}
        assert all(is_resource_document(pod) for pod in pods.values())
        labels = {name: pod["metadata"].get("labels", {}) for name, pod in pods.items()}
        # One manifest lacks the label the rule requires, so the legs expect one finding.
        assert [name for name, have in labels.items() if set(required) - set(have)] == [
            "bad.yaml"
        ]


class TestSandboxParityLeg:
    def test_parity_installs_loads_and_requires_betterleaks(self):
        text = UNIFIED.read_text()
        assert "ash dependencies install --tool betterleaks" in text
        assert f"betterleaks_module='  - {BETTERLEAKS_MODULE}'" in text
        # The required list names betterleaks only on the legs whose matrix row turns it on.
        assert re.search(r'required="\$required,betterleaks"', text)
        assert re.search(r"--require \"\$required\" \\", text)

    def test_parity_compares_betterleaks_on_bwrap_and_on_sandbox_exec(self):
        """Both parity legs compare betterleaks.

        The macOS sandbox-exec leg once crashed betterleaks before it wrote results and
        its matrix row switched betterleaks off. The scanner now runs under a private
        HOME there (#1132), so the row is back on, as the bwrap row always was. The
        denial filter keeps naming betterleaks so a regression shows up in the log.
        """
        text = UNIFIED.read_text()
        legs = text.split("sandbox-scanner-parity:", 1)[1].split("steps:", 1)[0]
        assert re.search(r"sandbox: bwrap\n\s+betterleaks: \"true\"", legs), (
            "the bwrap leg must keep comparing betterleaks"
        )
        assert re.search(r"sandbox: sandbox-exec\n\s+betterleaks: \"true\"", legs), (
            "the sandbox-exec leg compares betterleaks since #1132"
        )
        assert "|env|betterleaks)" in text, "the denial filter must name betterleaks"
