"""Uninstall, upgrade from N-1, and uninstall again, on the session's kind cluster.

Runs last (conftest.py orders it), because it removes the fresh install the other
modules use. In order:

1. **Uninstall the fresh install** the way README.md says: the CRDs first, which
   deletes every AshScan and AshMcpServer, then ``manifests/``. Between the two, the
   namespace still exists, so "nothing a scan owned is left" is the garbage collector's
   work and not the namespace's deletion. The leftover check is first run before
   anything is deleted and must find the probe's objects, so it cannot pass by looking
   at nothing.
2. **Install N-1**: the operator as it was before the newest change to the code it
   ships (lifecycle.previous_ref), image and CRDs both from that tree.
3. **Under N-1**, finish one scan, and start a second and stop the operator while its
   shards run, so it is mid-flight across the upgrade.
4. **Upgrade** to HEAD's CRDs, manifests and image. Before applying, the CRD that the
   cluster actually holds is compared with HEAD's (crd_compat), and a planted CRD that
   drops the stored version is offered to the API server, which must refuse it.
5. **After the upgrade**: the finished scan's status and Jobs are untouched, the
   mid-flight scan is merged by HEAD's operator, a new scan runs HEAD's argv, every
   merged report passes the shared verdict, and the CRD's stored versions are valid.
6. **Uninstall again**, with the same assertions as 1.
"""

from __future__ import annotations

import copy
import json

import pytest
import yaml

from ash_operator.constants import ASH_CLI, PHASE_FINDINGS
from tests.e2e.crd_compat import upgrade_problems
from tests.e2e.helpers import (
    ASH_IMAGE,
    GROUP,
    NAMESPACE,
    OPERATOR_DIR,
    OPERATOR_IMAGE,
    apply_fixture_configmap,
    apply_scan,
    kubectl,
    kubectl_apply_stdin,
    kubectl_json,
    scan_status,
    wait_for,
    wait_terminal,
)
from tests.e2e.lifecycle import (
    CLUSTER_SCOPED_RBAC,
    PREVIOUS_OPERATOR_IMAGE,
    build_previous_operator,
    exists,
    install_operator,
    operator_pods,
    owned_leftovers,
    remove_image,
    uninstall_crds,
    uninstall_manifests,
    wait_no_leftovers,
)
from tests.e2e.shared_contract import (
    SHARED_FIXTURES,
    case_spec,
    judge,
    load_cases,
    read_merged_output,
)

pytestmark = pytest.mark.e2e

FINDINGS = load_cases()["findings"]
SCAN_CRD = f"ashscans.{GROUP}"


def contract_scan(name: str) -> None:
    apply_scan(
        name,
        source_configmap="shared-findings",
        min_severity=None,
        config=None,
        extra_spec=case_spec(FINDINGS),
    )


def job(name: str) -> dict:
    return kubectl_json("-n", NAMESPACE, "get", "job", name)


def job_argv(name: str) -> list[str]:
    return job(name)["spec"]["template"]["spec"]["containers"][0]["args"]


def uninstall_and_observe(operator_dir) -> dict:
    """Run both uninstall commands and record what each left behind."""
    observed: dict = {"before": owned_leftovers()}
    uninstall_crds(operator_dir)
    observed["crds_after"] = {
        plural: exists("crd", plural) for plural in (SCAN_CRD, f"ashmcpservers.{GROUP}")
    }
    wait_no_leftovers()
    observed["after_crds"] = owned_leftovers()
    observed["namespace_after_crds"] = exists("namespace", NAMESPACE)
    observed["operator_after_crds"] = bool(operator_pods())
    uninstall_manifests(operator_dir)
    observed["namespace_after"] = exists("namespace", NAMESPACE)
    observed["rbac_after"] = {name: exists(name) for name in CLUSTER_SCOPED_RBAC}
    print(f"=== uninstall observations: {json.dumps(observed, sort_keys=True)} ===")
    return observed


def start_uninstall_probe(name: str) -> None:
    """A scan and an MCP server, so uninstall has owned objects of both kinds to remove."""
    apply_fixture_configmap("shared-findings", SHARED_FIXTURES / "findings")
    contract_scan(f"{name}-scan")
    wait_terminal(f"{name}-scan")
    kubectl_apply_stdin(
        yaml.safe_dump(
            {
                "apiVersion": f"{GROUP}/v1alpha1",
                "kind": "AshMcpServer",
                "metadata": {"name": f"{name}-mcp", "namespace": NAMESPACE},
                "spec": {
                    "image": ASH_IMAGE,
                    "imagePullPolicy": "Never",
                    "transport": "streamable-http",
                    "statelessHttp": True,
                    "port": 8000,
                    "mountPath": "/mcp",
                    "serviceAccountName": "ash-scan",
                },
            }
        )
    )
    wait_for(
        lambda: exists("-n", NAMESPACE, "deployment", f"{name}-mcp") or None,
        timeout=180,
        what=f"the operator to create Deployment/{name}-mcp",
    )


def assert_uninstalled(observed: dict) -> None:
    assert observed["before"], (
        "the leftover check found nothing before uninstall, so finding nothing after it "
        "proves nothing"
    )
    assert any(o.startswith("Job/") for o in observed["before"]), observed["before"]
    assert any(o.startswith("Deployment/") for o in observed["before"]), observed["before"]
    assert observed["crds_after"] == {SCAN_CRD: False, f"ashmcpservers.{GROUP}": False}
    assert observed["after_crds"] == [], observed["after_crds"]
    # Still there, so the objects above went because their owners went.
    assert observed["namespace_after_crds"] is True
    assert observed["operator_after_crds"] is True
    assert observed["namespace_after"] is False
    assert observed["rbac_after"] == {name: False for name in CLUSTER_SCOPED_RBAC}


# --------------------------------------------------------------------------- stages


@pytest.fixture(scope="module")
def first_uninstall(installed):
    start_uninstall_probe("uninstall-probe")
    return uninstall_and_observe(OPERATOR_DIR)


@pytest.fixture(scope="module")
def previous(first_uninstall, tmp_path_factory):
    built = build_previous_operator(tmp_path_factory.mktemp("prev"))
    try:
        install_operator(built["dir"], built["image"])
        yield built
    finally:
        remove_image(PREVIOUS_OPERATOR_IMAGE)


@pytest.fixture(scope="module")
def before_upgrade(previous, tmp_path_factory):
    apply_fixture_configmap("shared-findings", SHARED_FIXTURES / "findings")
    pods = operator_pods()
    assert len(pods) == 1, [p["metadata"]["name"] for p in pods]
    observed = {"operator_image": pods[0]["spec"]["containers"][0]["image"]}

    contract_scan("upgrade-old")
    observed["old_status"] = wait_terminal("upgrade-old")
    observed["old_jobs"] = {
        role: job(f"upgrade-old-{role}")["metadata"]["uid"] for role in ("shard", "collect")
    }
    observed["old_shard_argv"] = job_argv("upgrade-old-shard")
    observed["old_output"] = read_merged_output(
        "upgrade-old", observed["old_status"], tmp_path_factory.mktemp("before") / "upgrade-old"
    )

    # Mid-flight: dispatched by N-1, which is then stopped before its shards finish.
    contract_scan("upgrade-inflight")
    wait_for(
        lambda: scan_status("upgrade-inflight").get("phase") == "Scanning" or None,
        timeout=180,
        what="N-1 to dispatch upgrade-inflight",
    )
    kubectl("-n", NAMESPACE, "scale", "deployment/ash-operator", "--replicas=0")
    wait_for(lambda: not operator_pods() or None, timeout=180, what="N-1's pod to stop")
    observed["inflight_collect_before"] = exists("-n", NAMESPACE, "job", "upgrade-inflight-collect")
    observed["inflight_shard_argv"] = job_argv("upgrade-inflight-shard")
    # The shards finish with no operator running, so only HEAD's can merge them.
    kubectl(
        "-n",
        NAMESPACE,
        "wait",
        "--for=condition=complete",
        "job/upgrade-inflight-shard",
        "--timeout=600s",
        timeout=660,
    )
    observed["inflight_phase_before"] = scan_status("upgrade-inflight").get("phase")
    observed["live_crd"] = kubectl_json("get", "crd", SCAN_CRD)
    return observed


@pytest.fixture(scope="module")
def upgraded(before_upgrade):
    live = before_upgrade["live_crd"]
    head_crd = yaml.safe_load((OPERATOR_DIR / "generated" / "crd-ashscans.yaml").read_text())
    observed: dict = {"compat": upgrade_problems(live, head_crd)}

    # Detected: the same comparison against a planted CRD that drops a spec field.
    planted = copy.deepcopy(head_crd)
    spec_schema = planted["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
    del spec_schema["properties"]["extraScanArguments"]
    observed["compat_planted"] = upgrade_problems(live, planted)

    # Refused: a CRD that renames the stored version, offered to the API server.
    renamed = copy.deepcopy(head_crd)
    renamed["spec"]["versions"][0]["name"] = "v1alpha2"
    refusal = kubectl(
        "apply", "--dry-run=server", "-f", "-", stdin=yaml.safe_dump(renamed), check=False
    )
    observed["refusal"] = {"rc": refusal.returncode, "stderr": refusal.stderr}

    install_operator(OPERATOR_DIR, OPERATOR_IMAGE)
    pods = operator_pods()
    assert len(pods) == 1, [p["metadata"]["name"] for p in pods]
    observed["operator_image"] = pods[0]["spec"]["containers"][0]["image"]

    observed["inflight_status"] = wait_terminal("upgrade-inflight")
    observed["inflight_collect_argv"] = job_argv("upgrade-inflight-collect")
    contract_scan("upgrade-new")
    observed["new_status"] = wait_terminal("upgrade-new")
    observed["new_shard_argv"] = job_argv("upgrade-new-shard")
    # Read after HEAD's operator has resumed every object and finished a new run.
    observed["old_status"] = scan_status("upgrade-old")
    observed["old_jobs"] = {
        role: job(f"upgrade-old-{role}")["metadata"]["uid"] for role in ("shard", "collect")
    }
    observed["crd"] = kubectl_json("get", "crd", SCAN_CRD)
    return observed


@pytest.fixture(scope="module")
def merged_outputs(upgraded, tmp_path_factory):
    root = tmp_path_factory.mktemp("upgrade")
    return {
        name: {
            "status": scan_status(name),
            "output": read_merged_output(name, scan_status(name), root / name),
        }
        for name in ("upgrade-old", "upgrade-inflight", "upgrade-new")
    }


def tree_bytes(root) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# What any operator's findings scan has to show, for outputs N-1 produced in part.
# N-1 is free to differ from this tree's case in count (an older operator scanned
# configMap sources at the mount root and reported every finding twice), so the count
# is a floor there. The exact case is required of the scan HEAD's operator ran.
FINDINGS_FLOOR = (
    "--expect-rc",
    str(FINDINGS["expect_rc"]),
    "--min-findings",
    str(FINDINGS["findings"]),
    "--require-scanner",
    FINDINGS["require_scanner"],
    "--selected",
    ",".join(FINDINGS["scanners"]),
)


@pytest.fixture(scope="module")
def final_uninstall(merged_outputs):
    start_uninstall_probe("final-probe")
    return uninstall_and_observe(OPERATOR_DIR)


# --------------------------------------------------------------------------- tests


class TestUninstallTheFreshInstall:
    def test_nothing_the_operator_created_is_left(self, first_uninstall):
        assert_uninstalled(first_uninstall)


class TestPreviousVersion:
    def test_n_minus_one_ran_its_own_image_and_argv(self, previous, before_upgrade):
        assert before_upgrade["operator_image"] == PREVIOUS_OPERATOR_IMAGE
        argv = before_upgrade["old_shard_argv"]
        assert argv[:2] == [previous["cli"], "scan"], argv

    def test_the_n_minus_one_scan_finished(self, before_upgrade):
        assert before_upgrade["old_status"]["phase"] == PHASE_FINDINGS, before_upgrade["old_status"]

    def test_the_inflight_scan_was_left_for_the_upgrade(self, before_upgrade):
        # If N-1 had merged it before it stopped, the test below would prove nothing
        # about HEAD picking up a run it did not start.
        assert before_upgrade["inflight_collect_before"] is False, (
            "N-1 created the collector before it was stopped; the shards finished faster "
            "than the scale-down, so this run did not exercise a mid-flight upgrade"
        )
        assert before_upgrade["inflight_phase_before"] == "Scanning"


class TestCrdUpgrade:
    @pytest.mark.positive_control
    def test_heads_crd_strands_nothing_the_cluster_stored(self, upgraded):
        assert upgraded["compat"] == [], upgraded["compat"]

    @pytest.mark.negative_control
    def test_the_comparison_detects_a_removed_field(self, upgraded):
        assert any("extraScanArguments is removed" in p for p in upgraded["compat_planted"]), (
            upgraded["compat_planted"]
        )

    @pytest.mark.negative_control
    def test_the_api_server_refuses_dropping_the_stored_version(self, upgraded):
        refusal = upgraded["refusal"]
        assert refusal["rc"] != 0, "the API server accepted a CRD without its stored version"
        assert "storedVersions" in refusal["stderr"], refusal["stderr"]

    @pytest.mark.positive_control
    def test_the_stored_versions_are_still_valid(self, upgraded):
        crd = upgraded["crd"]
        served = {v["name"] for v in crd["spec"]["versions"] if v["served"]}
        storage = [v["name"] for v in crd["spec"]["versions"] if v["storage"]]
        assert crd["status"]["storedVersions"] == ["v1alpha1"], crd["status"]
        assert storage == ["v1alpha1"]
        assert set(crd["status"]["storedVersions"]) <= served


class TestAfterUpgrade:
    def test_heads_image_is_running(self, upgraded):
        assert upgraded["operator_image"] == OPERATOR_IMAGE

    def test_the_finished_scan_was_not_touched(self, before_upgrade, upgraded):
        assert upgraded["old_status"] == before_upgrade["old_status"], json.dumps(
            upgraded["old_status"]
        )[:1500]
        assert upgraded["old_jobs"] == before_upgrade["old_jobs"], "the finished run was re-run"

    def test_the_inflight_scan_was_merged_by_heads_operator(self, before_upgrade, upgraded):
        status = upgraded["inflight_status"]
        assert status["phase"] == PHASE_FINDINGS, status
        assert before_upgrade["inflight_shard_argv"][1] == "scan"
        argv = upgraded["inflight_collect_argv"]
        assert "--" in argv and argv[argv.index("--") + 1 : argv.index("--") + 3] == [
            ASH_CLI,
            "merge",
        ], argv

    def test_a_new_scan_runs_heads_argv(self, upgraded):
        assert upgraded["new_status"]["phase"] == PHASE_FINDINGS, upgraded["new_status"]
        assert upgraded["new_shard_argv"][:2] == [ASH_CLI, "scan"], upgraded["new_shard_argv"]

    def test_the_finished_scans_report_is_unchanged(self, before_upgrade, merged_outputs):
        before = tree_bytes(before_upgrade["old_output"])
        after = tree_bytes(merged_outputs["upgrade-old"]["output"])
        assert "reports/ash.sarif" in before and "ash_aggregated_results.json" in before
        assert after == before, sorted(set(before) ^ set(after)) or "file contents differ"

    @pytest.mark.parametrize("name", ["upgrade-old", "upgrade-inflight"])
    def test_the_n_minus_one_outputs_pass_the_shared_verdict(self, merged_outputs, name):
        outcome = merged_outputs[name]
        rc = int(outcome["status"]["merge"]["exitCode"])
        verdict = judge(None, outcome["output"], rc, *FINDINGS_FLOOR)
        assert verdict.returncode == 0, verdict.stdout + verdict.stderr

    def test_the_upgraded_operator_meets_the_case_exactly(self, merged_outputs):
        outcome = merged_outputs["upgrade-new"]
        verdict = judge("findings", outcome["output"], int(outcome["status"]["merge"]["exitCode"]))
        assert verdict.returncode == 0, verdict.stdout + verdict.stderr


class TestUninstallTheUpgradedInstall:
    def test_nothing_the_operator_created_is_left(self, final_uninstall):
        assert_uninstalled(final_uninstall)
