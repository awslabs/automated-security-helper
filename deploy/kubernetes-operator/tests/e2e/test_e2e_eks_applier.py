"""The EKS one-click installer's applier, run against the session's kind cluster.

WHAT IS UNDER TEST
------------------
``deploy/cdk/templates/AshEksOperator.template.json`` installs the operator through a
Lambda whose source is inline in ``Code.ZipFile``. That source is the installer. The
unit suite (tests/unit/deploy/test_eks_operator_applier.py) executes it with every
network edge faked. This module runs the same committed source with only the AWS edges
faked, so every Kubernetes request is real:

- the HTTPS requests ``request()`` sends, verified against the cluster CA that
  ``eks:DescribeCluster`` returns, to the endpoint it returns;
- server-side apply of every manifest, CRDs without force, and the DELETE loop;
- the CloudFormation response, PUT to a local HTTP server that stands in for the
  presigned S3 URL;
- the operator those manifests install, which must reconcile the shared ``findings``
  case to the exit code and the report ``scripts/e2e/assert_outcome.py`` requires.

WHAT IS FAKED, AND WHY THAT IS THE WHOLE LIST
---------------------------------------------
``boto3`` and ``botocore.signers`` are replaced by stand-ins before the source is
loaded, so it cannot reach AWS at all, and the stand-in session refuses every client
but ``eks``. ``eks.describe_cluster`` answers with kind's API server URL and CA, in the
base64 shape EKS uses. ``eks.describe_addon`` answers ResourceNotFound, as on a cluster
without the Pod Identity agent. ``cluster_token`` is replaced by a ServiceAccount token
bound to cluster-admin, which is what the stack's access entry grants the installer
role (AmazonEKSClusterAdminPolicy at cluster scope).

So the STS-presigned token itself, the access entry, IAM and the real EKS endpoints are
still not exercised. Nothing here talks to AWS: OD-13's default is kind only.

ORDER
-----
conftest.py runs this module after the lifecycle module, whose last uninstall leaves no
CRD, namespace or cluster role of the operator's behind. The stack installs all of them
itself, so it has to start from a cluster that has none; the first fixture asserts that.

NEGATIVE CONTROLS
-----------------
An applier with the AshScan CRD left out reports SUCCESS over one object fewer, and the
API server then refuses an AshScan outright. A CA that is not the cluster's makes every
request fail TLS verification, and a token the API server does not know is refused with
a 401 that is not retried. Each must end in the outcome named, or the positive run
proves nothing about which part of it worked.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import http.server
import importlib.util
import json
import re
import ssl
import sys
import tempfile
import threading
import types
from pathlib import Path
from typing import Any

import pytest
import yaml

from ash_operator.constants import PHASE_FINDINGS
from tests.e2e.helpers import (
    CLUSTER_NAME,
    GROUP,
    IMAGE_TAG,
    NAMESPACE,
    REPO_ROOT,
    apply_fixture_configmap,
    apply_scan,
    context,
    kubectl,
    kubectl_json,
    run,
    scan_status,
    wait_for,
    wait_terminal,
)
from tests.e2e.lifecycle import remove_image
from tests.e2e.shared_contract import (
    SHARED_FIXTURES,
    case_spec,
    judge,
    load_cases,
    read_merged_output,
)

pytestmark = pytest.mark.e2e

TEMPLATE = REPO_ROOT / "deploy" / "cdk" / "templates" / "AshEksOperator.template.json"
FINDINGS = load_cases()["findings"]
CRD_NAMES = (f"ashscans.{GROUP}", f"ashmcpservers.{GROUP}")
CLUSTER_ROLE = "ash-operator-crd-reader"
# Every object the applier creates, by scope. The delete path keeps the first list.
CLUSTER_SCOPED = (
    ("namespace", NAMESPACE),
    *(("crd", name) for name in CRD_NAMES),
    ("clusterrole", CLUSTER_ROLE),
    ("clusterrolebinding", CLUSTER_ROLE),
)
NAMESPACED = (
    ("serviceaccount", "ash-operator"),
    ("serviceaccount", "ash-scan"),
    ("role", "ash-operator"),
    ("rolebinding", "ash-operator"),
    ("networkpolicy", "ash-operator-ingress"),
    ("deployment", "ash-operator"),
)
ALL_OBJECTS = len(CLUSTER_SCOPED) + len(NAMESPACED)
# The installer's identity. Bound to cluster-admin, as the stack's access entry binds
# the installer role to AmazonEKSClusterAdminPolicy at cluster scope.
INSTALLER_SA = "ash-cfn-installer-e2e"
INSTALLER_NS = "kube-system"
# A name that matches the template's OperatorImageUri AllowedPattern, which requires a
# registry host. `.invalid` cannot resolve, so the kubelet can only use the copy loaded
# into the node, which is what the Deployment's IfNotPresent default does.
STACK_IMAGE = f"e2e.invalid/ash-operator:{IMAGE_TAG}"


# --------------------------------------------------------------------------- the applier


def template() -> dict[str, Any]:
    return json.loads(TEMPLATE.read_text())


def applier_source() -> str:
    functions = [
        resource
        for resource in template()["Resources"].values()
        if resource["Type"] == "AWS::Lambda::Function"
    ]
    assert len(functions) == 1, f"expected one Lambda in {TEMPLATE.name}, found {len(functions)}"
    source = functions[0]["Properties"]["Code"]["ZipFile"]
    # A plain string. Were it ever an Fn::Join or Fn::Sub, what deploys would be the
    # rendered value and this reassembly would need to render it the same way.
    assert isinstance(source, str) and source.strip(), type(source)
    return source


class _NotFound(Exception):
    """Named like botocore's modeled error, which is all the applier inspects."""


_NotFound.__name__ = "ResourceNotFoundException"


class FakeEks:
    def __init__(self, cluster: dict[str, Any], calls: list[tuple[str, dict]]):
        self._cluster = cluster
        self._calls = calls

    def describe_cluster(self, **kwargs):
        self._calls.append(("describe_cluster", kwargs))
        assert kwargs == {"name": CLUSTER_NAME}, kwargs
        return {"cluster": copy.deepcopy(self._cluster)}

    def describe_addon(self, **kwargs):
        self._calls.append(("describe_addon", kwargs))
        raise _NotFound("ResourceNotFoundException: no eks-pod-identity-agent add-on")


def fake_aws_modules(cluster: dict[str, Any], calls: list) -> dict[str, types.ModuleType]:
    """Stand-ins for the two AWS SDK modules the applier imports at module scope."""

    class Session:
        region_name = "us-east-1"

        def client(self, service):
            assert service == "eks", (
                f"the applier asked for an AWS {service!r} client. This harness fakes only "
                f"EKS; anything else would be a real AWS call it must never make."
            )
            return FakeEks(cluster, calls)

    boto3 = types.ModuleType("boto3")
    session = types.ModuleType("boto3.session")
    session.Session = Session
    boto3.session = session
    botocore = types.ModuleType("botocore")
    signers = types.ModuleType("botocore.signers")

    class RequestSigner:
        def __init__(self, *args, **kwargs):
            raise AssertionError("the STS token signer ran; cluster_token was not replaced")

    signers.RequestSigner = RequestSigner
    botocore.signers = signers
    return {
        "boto3": boto3,
        "boto3.session": session,
        "botocore": botocore,
        "botocore.signers": signers,
    }


@contextlib.contextmanager
def modules_replaced(replacements: dict[str, types.ModuleType]):
    saved = {name: sys.modules.get(name) for name in replacements}
    sys.modules.update(replacements)
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def load_applier(directory: Path, cluster: dict[str, Any], token: str) -> types.ModuleType:
    """The committed applier as a module, loaded the way Lambda loads index.py."""
    path = directory / "ash_eks_applier_e2e.py"
    path.write_text(applier_source(), encoding="utf-8")
    calls: list = []
    fakes = fake_aws_modules(cluster, calls)
    spec = importlib.util.spec_from_file_location("ash_eks_applier_e2e", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with modules_replaced(fakes):
        spec.loader.exec_module(module)
    assert module.boto3 is fakes["boto3"], "the applier bound a real boto3"
    # Replaced by name, so a rename in the applier fails here instead of leaving the
    # real signer to run.
    assert callable(getattr(module, "cluster_token", None)), "the applier has no cluster_token"
    module.cluster_token = lambda session, cluster_name: token
    module.aws_calls = calls
    return module


# --------------------------------------------------------------------------- the edges


class ResponseSink:
    """A local stand-in for CloudFormation's presigned response URL."""

    def __init__(self):
        self.bodies: list[dict[str, Any]] = []
        sink = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):  # noqa: N802 - the stdlib's name
                length = int(self.headers["Content-Length"])
                sink.bodies.append(json.loads(self.rfile.read(length)))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/response"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class LambdaContext:
    @staticmethod
    def get_remaining_time_in_millis():
        return 600_000


def event(request_type: str, sink: ResponseSink, image: str = STACK_IMAGE) -> dict[str, Any]:
    body = {
        "RequestType": request_type,
        "ResponseURL": sink.url,
        "StackId": "arn:aws:cloudformation:us-east-1:e2e:stack/ash-eks-e2e/0",
        "RequestId": f"e2e-{request_type.lower()}",
        "LogicalResourceId": "OperatorInstall",
        "ResourceType": "Custom::AshOperatorInstall",
        "ResourceProperties": {
            "ClusterName": CLUSTER_NAME,
            "Namespace": NAMESPACE,
            "OperatorImage": image,
        },
    }
    if request_type != "Create":
        body["PhysicalResourceId"] = f"{CLUSTER_NAME}/{NAMESPACE}"
    return body


def invoke(applier, request_type: str, sink: ResponseSink) -> dict[str, Any]:
    """One handler call, and the one response it PUT."""
    before = len(sink.bodies)
    applier.handler(event(request_type, sink), LambdaContext())
    sent = sink.bodies[before:]
    assert len(sent) == 1, f"the handler sent {len(sent)} responses for one {request_type}"
    print(f"=== applier {request_type}: {json.dumps(sent[0], sort_keys=True)[:1500]} ===")
    return sent[0]


def kind_cluster_description() -> dict[str, Any]:
    """kind's API server, in the shape eks:DescribeCluster returns."""
    config = json.loads(kubectl("config", "view", "--raw", "--minify", "-o", "json").stdout)
    (cluster,) = config["clusters"]
    assert config["contexts"][0]["name"] == context(), config["contexts"]
    return {
        "name": CLUSTER_NAME,
        "endpoint": cluster["cluster"]["server"],
        "certificateAuthority": {"data": cluster["cluster"]["certificate-authority-data"]},
    }


def installer_token() -> str:
    kubectl("-n", INSTALLER_NS, "create", "serviceaccount", INSTALLER_SA)
    kubectl(
        "create",
        "clusterrolebinding",
        INSTALLER_SA,
        "--clusterrole=cluster-admin",
        f"--serviceaccount={INSTALLER_NS}:{INSTALLER_SA}",
    )
    return kubectl(
        "-n", INSTALLER_NS, "create", "token", INSTALLER_SA, "--duration=2h"
    ).stdout.strip()


CLUSTER_KINDS = frozenset({"namespace", "crd", "clusterrole", "clusterrolebinding"})


def present(kind: str, name: str) -> bool:
    scope = [] if kind in CLUSTER_KINDS else ["-n", NAMESPACE]
    result = kubectl(*scope, "get", kind, name, check=False)
    if result.returncode == 0:
        return True
    assert "NotFound" in result.stderr, result.stderr
    return False


def remove_everything_the_stack_created() -> None:
    """Undo an install by hand, cluster-scoped objects included, for a fresh CREATE."""
    kubectl("delete", "namespace", NAMESPACE, "--ignore-not-found", "--wait=true", timeout=600)
    for crd in CRD_NAMES:
        kubectl("delete", "crd", crd, "--ignore-not-found", "--wait=true", timeout=300)
    for kind in ("clusterrolebinding", "clusterrole"):
        kubectl("delete", kind, CLUSTER_ROLE, "--ignore-not-found")


def operator_available() -> bool:
    deployment = kubectl_json("-n", NAMESPACE, "get", "deployment", "ash-operator")
    conditions = deployment.get("status", {}).get("conditions") or []
    return any(c["type"] == "Available" and c["status"] == "True" for c in conditions)


def system_ca_bundle() -> str:
    """A real PEM bundle that did not sign kind's API server certificate."""
    cafile = ssl.get_default_verify_paths().cafile
    assert cafile and Path(cafile).is_file(), ssl.get_default_verify_paths()
    return base64.b64encode(Path(cafile).read_bytes()).decode("ascii")


ASHSCAN_PROBE = {
    "apiVersion": f"{GROUP}/v1alpha1",
    "kind": "AshScan",
    "metadata": {"name": "eks-probe", "namespace": NAMESPACE},
    "spec": {"image": "x", "shardCount": 1, "source": {"configMap": {"name": "x"}}},
}


# --------------------------------------------------------------------------- stages


@pytest.fixture(scope="module")
def stack_image(operator_image, cluster):
    run(["docker", "tag", operator_image, STACK_IMAGE])
    try:
        run(["kind", "load", "docker-image", STACK_IMAGE, "--name", cluster], timeout=1200)
        yield STACK_IMAGE
    finally:
        remove_image(STACK_IMAGE)


@pytest.fixture(scope="module")
def harness(cluster, ash_image, stack_image, tmp_path_factory):
    leftovers = [f"{kind}/{name}" for kind, name in CLUSTER_SCOPED if present(kind, name)]
    assert not leftovers, (
        f"{leftovers} already exist. This module installs the operator the way the EKS "
        f"stack does, from nothing, and must run after test_e2e_lifecycle.py's last "
        f"uninstall (conftest.py orders it)."
    )
    sink = ResponseSink()
    token = installer_token()
    try:
        yield {
            "cluster": kind_cluster_description(),
            "token": token,
            "sink": sink,
            "dir": tmp_path_factory.mktemp("eks-applier"),
        }
    finally:
        sink.close()
        kubectl("delete", "clusterrolebinding", INSTALLER_SA, "--ignore-not-found")
        kubectl("-n", INSTALLER_NS, "delete", "serviceaccount", INSTALLER_SA, "--ignore-not-found")


@pytest.fixture(scope="module")
def refusals(harness):
    """The two requests that must fail before anything is created."""
    observed = {}
    wrong_ca = dict(harness["cluster"], certificateAuthority={"data": system_ca_bundle()})
    applier = load_applier(harness["dir"], wrong_ca, harness["token"])
    observed["wrong_ca"] = invoke(applier, "Create", harness["sink"])
    applier = load_applier(harness["dir"], harness["cluster"], "not-a-token-this-cluster-issued")
    observed["bad_token"] = invoke(applier, "Create", harness["sink"])
    observed["created"] = [f"{k}/{n}" for k, n in (*CLUSTER_SCOPED, *NAMESPACED) if present(k, n)]
    return observed


@pytest.fixture(scope="module")
def without_the_scan_crd(refusals, harness):
    """The planted defect: the same applier with the AshScan CRD left out of CRDS."""
    applier = load_applier(harness["dir"], harness["cluster"], harness["token"])
    applier.CRDS = [entry for entry in applier.CRDS if entry["kind"] != "AshScan"]
    assert len(applier.CRDS) == 1, applier.CRDS
    observed = {"response": invoke(applier, "Create", harness["sink"])}
    observed["scan_crd_present"] = present("crd", CRD_NAMES[0])
    # A fresh discovery cache, so kubectl asks the API server which kinds it serves.
    # With the cache an earlier module left, it maps AshScan from memory, POSTs, and the
    # refusal reads as a 404 on the URL instead of naming the missing kind.
    with tempfile.TemporaryDirectory(prefix="ash-eks-kubectl-cache-") as cache:
        observed["apply"] = kubectl(
            "--cache-dir",
            cache,
            "apply",
            "-f",
            "-",
            stdin=yaml.safe_dump(ASHSCAN_PROBE),
            check=False,
        )
    remove_everything_the_stack_created()
    return observed


@pytest.fixture(scope="module")
def installed_by_the_stack(without_the_scan_crd, harness):
    applier = load_applier(harness["dir"], harness["cluster"], harness["token"])
    observed: dict[str, Any] = {"create": invoke(applier, "Create", harness["sink"])}
    wait_for(operator_available, timeout=300, what="the stack-installed operator to be Available")
    observed["crds"] = {name: kubectl_json("get", "crd", name) for name in CRD_NAMES}
    observed["pods"] = kubectl_json(
        "-n", NAMESPACE, "get", "pods", "-l", "app.kubernetes.io/name=ash-operator"
    )["items"]
    # An UPDATE with the same properties re-applies every object over the first apply.
    observed["update"] = invoke(applier, "Update", harness["sink"])
    observed["aws_calls"] = list(applier.aws_calls)
    observed["applier"] = applier
    return observed


@pytest.fixture(scope="module")
def stack_scan(installed_by_the_stack, tmp_path_factory):
    apply_fixture_configmap("shared-findings", SHARED_FIXTURES / "findings")
    apply_scan(
        "eks-findings",
        source_configmap="shared-findings",
        min_severity=None,
        config=None,
        extra_spec=case_spec(FINDINGS),
    )
    status = wait_terminal("eks-findings")
    output = read_merged_output(
        "eks-findings", status, tmp_path_factory.mktemp("eks") / "eks-findings"
    )
    return {"status": status, "output": output}


@pytest.fixture(scope="module")
def stack_deleted(stack_scan, installed_by_the_stack, harness):
    observed = {"response": invoke(installed_by_the_stack["applier"], "Delete", harness["sink"])}

    def namespaced_gone():
        return not any(present(kind, name) for kind, name in NAMESPACED) or None

    wait_for(namespaced_gone, timeout=300, what="the stack delete's namespaced objects to go")
    observed["cluster_scoped"] = {f"{k}/{n}": present(k, n) for k, n in CLUSTER_SCOPED}
    observed["scan_kept"] = present("ashscan", "eks-findings")
    # Read only if it survived: a delete that took the CRD took every AshScan with it,
    # and that is the failure the tests below name.
    observed["scan_phase"] = (
        scan_status("eks-findings").get("phase") if observed["scan_kept"] else None
    )
    return observed


# --------------------------------------------------------------------------- tests


@pytest.mark.negative_control
class TestTheApplierCanFail:
    def test_a_ca_that_did_not_sign_the_api_server_is_refused(self, refusals):
        response = refusals["wrong_ca"]
        assert response["Status"] == "FAILED", response
        assert "CERTIFICATE_VERIFY_FAILED" in response["Reason"], response["Reason"]

    def test_a_token_the_cluster_did_not_issue_is_refused(self, refusals):
        response = refusals["bad_token"]
        assert response["Status"] == "FAILED", response
        assert "failed 401" in response["Reason"], response["Reason"]

    def test_neither_refused_install_created_anything(self, refusals):
        assert refusals["created"] == [], refusals["created"]

    def test_an_applier_without_the_scan_crd_installs_one_object_fewer(self, without_the_scan_crd):
        response = without_the_scan_crd["response"]
        # SUCCESS: the applier cannot know a CRD is missing from its own table. The
        # count is what tells the runs apart, which is why the CREATE below is held to
        # the full count.
        assert response["Status"] == "SUCCESS", response
        assert response["Reason"] == f"applied {ALL_OBJECTS - 1} object(s)", response
        assert without_the_scan_crd["scan_crd_present"] is False

    def test_an_applier_without_the_scan_crd_cannot_take_a_scan(self, without_the_scan_crd):
        apply = without_the_scan_crd["apply"]
        assert apply.returncode != 0, "an AshScan was accepted with no AshScan CRD installed"
        assert 'no matches for kind "AshScan"' in apply.stderr, apply.stderr


class TestTheStackInstall:
    def test_the_create_response_reports_every_object(self, installed_by_the_stack):
        response = installed_by_the_stack["create"]
        assert response["Status"] == "SUCCESS", response
        assert response["Reason"] == f"applied {ALL_OBJECTS} object(s)", response
        assert response["PhysicalResourceId"] == f"{CLUSTER_NAME}/{NAMESPACE}"
        assert response["Data"] == {"PodIdentityAgent": "ABSENT"}, response

    def test_the_operator_runs_the_image_the_stack_was_given(self, installed_by_the_stack):
        pods = [
            p for p in installed_by_the_stack["pods"] if not p["metadata"].get("deletionTimestamp")
        ]
        assert len(pods) == 1, [p["metadata"]["name"] for p in pods]
        assert pods[0]["spec"]["containers"][0]["image"] == STACK_IMAGE

    def test_the_image_is_one_the_template_would_accept(self):
        pattern = template()["Parameters"]["OperatorImageUri"]["AllowedPattern"]
        assert re.fullmatch(pattern, STACK_IMAGE), (pattern, STACK_IMAGE)

    def test_the_crds_are_the_stacks_own(self, installed_by_the_stack):
        # Labeled by the applier, so these are the subset CRDs the stack ships and not
        # the operator's generated ones left behind by another module.
        for name, crd in installed_by_the_stack["crds"].items():
            labels = crd["metadata"].get("labels") or {}
            assert labels.get("app.kubernetes.io/managed-by") == "ash-cfn", (name, labels)

    def test_an_update_with_the_same_properties_converges(self, installed_by_the_stack):
        response = installed_by_the_stack["update"]
        assert response["Status"] == "SUCCESS", response
        # The CRDs go in without force. Their field manager is the applier's own, so
        # a re-apply is not a conflict and nothing is reported as kept.
        assert response["Reason"] == f"applied {ALL_OBJECTS} object(s)", response

    def test_the_only_aws_calls_were_the_two_eks_reads(self, installed_by_the_stack):
        names = sorted({name for name, _ in installed_by_the_stack["aws_calls"]})
        assert names == ["describe_addon", "describe_cluster"], names

    def test_the_template_defaults_the_namespace_this_harness_uses(self):
        assert template()["Parameters"]["OperatorNamespace"]["Default"] == NAMESPACE


class TestTheStackInstalledOperatorScans:
    def test_the_findings_case_meets_the_shared_verdict(self, stack_scan):
        verdict = judge(
            "findings", stack_scan["output"], int(stack_scan["status"]["merge"]["exitCode"])
        )
        assert verdict.returncode == 0, verdict.stdout + verdict.stderr

    def test_the_phase_and_exit_code_agree_with_the_case(self, stack_scan):
        status = stack_scan["status"]
        assert status["phase"] == PHASE_FINDINGS, json.dumps(status)[:1500]
        assert status["exitCode"] == FINDINGS["expect_rc"], status


class TestTheStackDelete:
    def test_the_delete_response_is_success(self, stack_deleted):
        response = stack_deleted["response"]
        assert response["Status"] == "SUCCESS", response
        assert response["Reason"] == (
            f"deleted {len(NAMESPACED)} namespaced object(s); kept "
            f"{len(CLUSTER_SCOPED)} cluster-scoped object(s) on purpose"
        ), response

    def test_the_crds_namespace_and_cluster_rbac_are_kept(self, stack_deleted):
        assert stack_deleted["cluster_scoped"] == {f"{k}/{n}": True for k, n in CLUSTER_SCOPED}

    def test_a_scan_outlives_the_stack(self, stack_deleted):
        # Deleting the CRD would have cascade-deleted every AshScan in the cluster.
        assert stack_deleted["scan_kept"] is True
        assert stack_deleted["scan_phase"] == PHASE_FINDINGS
