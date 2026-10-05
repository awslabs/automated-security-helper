"""The EKS operator installer's inline applier, executed rather than grepped.

WHAT IS UNDER TEST
------------------
`deploy/cdk/templates/AshEksOperator.template.json` carries a Lambda whose source is
inline in `Code.ZipFile`. That source is the only thing that actually installs the
operator, and NOTHING ELSE IN THIS REPOSITORY EXECUTES IT. `tsc` sees a TypeScript
template literal, `cdk synth` copies it verbatim, and the CDK jest suite matches
substrings against it. So a wrong call arity, a renamed helper or a name bound to the
wrong kind of object is invisible to every other gate and surfaces as a `TypeError`
during a deploy, after the access entry and the IAM roles already exist.

That is not hypothetical. Two defects reached the committed template and were caught
only by running the code: `documents()` was changed from three parameters to two while
the handler still called it with three, and a later refactor dropped the
`endpoint = cluster["endpoint"]` assignment so both loops referenced an undefined name.

WHY IT READS THE TEMPLATE AND NOT THE TYPESCRIPT
-----------------------------------------------
The template is the artifact an adopter launches. The TypeScript is the source that
produces it, and the two can differ -- the RBAC and CRD tables are interpolated at synth
time, so a constant that never reached the template would still be present in the source.
Reassembling from the committed template tests what would actually deploy.

WHAT IS NOT TESTED HERE
-----------------------
`handler()` runs only with its network edges faked: EKS, the Kubernetes requests made
through `call()`, and the CloudFormation response. That exercises its delete and apply
loops, including the scope guard. The real requests, the token, TLS against the cluster
CA and the response PUT remain unverified until someone deploys the stack. That boundary
is deliberate and is the honest limit of this file.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import re
import tempfile
import types

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
TEMPLATE = REPO_ROOT / "deploy/cdk/templates/AshEksOperator.template.json"
GROUP = "ash.awslabs.github.io"

# Transcribed from the operator's own generated manifests at
# deploy/kubernetes-operator/generated/. Hand-transcribed, not parsed: nothing couples
# this table to those files, so re-check it when either moves.
EXPECTED_CRDS = {
    "ashscans": {
        "kind": "AshScan",
        "listKind": "AshScanList",
        "singular": "ashscan",
        "shortNames": ["ashscan"],
        "required": ["image", "shardCount", "source"],
        "columns": ["Phase", "Shards", "Actionable", "Incomplete", "Age"],
    },
    "ashmcpservers": {
        "kind": "AshMcpServer",
        "listKind": "AshMcpServerList",
        "singular": "ashmcpserver",
        "shortNames": ["ashmcp"],
        "required": ["image"],
        "columns": ["Phase", "Endpoint", "Age"],
    },
}

EXPECTED_NAMESPACED_RULES = [
    ([GROUP], ["ashscans", "ashmcpservers"], ["get", "list", "patch", "watch"]),
    ([GROUP], ["ashscans/status", "ashmcpservers/status"], ["get", "patch"]),
    (["batch"], ["jobs"], ["create", "delete", "get", "list", "watch"]),
    ([""], ["pods"], ["get", "list", "watch"]),
    ([""], ["configmaps"], ["create", "delete", "get", "list", "watch"]),
    ([""], ["persistentvolumeclaims"], ["create", "delete", "get", "list", "watch"]),
    ([""], ["events"], ["create"]),
    (["events.k8s.io"], ["events"], ["create"]),
    (["apps"], ["deployments"], ["create", "get", "list", "patch", "watch"]),
    ([""], ["services"], ["create", "get", "list", "patch", "watch"]),
]


def _flatten(node) -> str:
    """Every literal string in a rendered template fragment, in order."""
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(_flatten(item) for item in node)
    if isinstance(node, dict):
        return "".join(_flatten(value) for value in node.values())
    return ""


@pytest.fixture(scope="module")
def applier_source() -> str:
    """The Lambda source, reassembled out of the committed template."""
    if not TEMPLATE.exists():
        pytest.skip(f"{TEMPLATE} is not present on this ref")
    template = json.loads(TEMPLATE.read_text())
    functions = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::Lambda::Function"
    ]
    assert len(functions) == 1, f"expected one Lambda, found {len(functions)}"
    source = _flatten(functions[0]["Properties"]["Code"]["ZipFile"])
    assert source.strip(), "the ZipFile is empty"
    return source


@pytest.fixture(scope="module")
def applier(applier_source: str, tmp_path_factory: pytest.TempPathFactory) -> dict:
    """The applier executed as a module.

    Executing it is the point: a syntax error, a bad import or a module-scope typo fails
    here, and every check below then runs against real objects rather than text.

    It is written to a file and loaded through the import system, the way Lambda loads
    `index.py` from a ZipFile, rather than passed to `exec()`. The returned mapping is the
    module's own globals, so a test that replaces a name in it changes what `handler()`
    sees.
    """
    pytest.importorskip("boto3", reason="the applier imports boto3 at module scope")
    path = tmp_path_factory.mktemp("eks_applier") / "ash_eks_applier_under_test.py"
    path.write_text(applier_source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("ash_eks_applier_under_test", path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return vars(module)


@pytest.fixture(scope="module")
def docs(applier: dict) -> list:
    """(path, manifest, scope) for a representative install.

    THE ARITY CHECK. This is the exact call `handler()` makes, and calling it with the
    wrong number of arguments is a defect that has reached the committed template before.
    """
    documents = applier["documents"]
    assert callable(documents), f"documents is {type(documents).__name__}, not callable"
    return documents("ash-system", "example.dkr.ecr.us-east-1.amazonaws.com/op:v1")


def test_module_defines_the_names_the_handler_uses(applier: dict) -> None:
    for name in (
        "documents",
        "handler",
        "respond",
        "call",
        "request",
        "CLUSTER",
        "NAMESPACED",
    ):
        assert name in applier, f"the applier defines no {name}"
    assert callable(applier["documents"])
    assert callable(applier["handler"])


def test_scope_constants_are_distinct_and_non_empty(applier: dict) -> None:
    """If these collapsed, the delete rule below would classify everything alike."""
    cluster, namespaced = applier["CLUSTER"], applier["NAMESPACED"]
    assert isinstance(cluster, str) and isinstance(namespaced, str)
    assert cluster and namespaced
    assert cluster != namespaced


def test_ten_documents_with_distinct_paths(docs: list) -> None:
    assert len(docs) == 10
    paths = [path for path, _, _ in docs]
    assert len(set(paths)) == len(paths)
    kinds = [manifest["kind"] for _, manifest, _ in docs]
    assert kinds[0] == "Namespace", "the namespace must be created first"
    assert kinds[-1] == "Deployment", "the deployment must be created last"
    assert kinds.count("CustomResourceDefinition") == 2
    assert kinds.count("ServiceAccount") == 2


def test_every_manifest_is_json_serializable(docs: list) -> None:
    """Each one is sent as a request body, so a non-serializable value is fatal."""
    for _, manifest, _ in docs:
        json.dumps(manifest)


class _FakeEks:
    """The two EKS reads handler() makes, answered locally."""

    def describe_cluster(self, name):  # noqa: ARG002
        return {
            "cluster": {
                "endpoint": "https://cluster.example.invalid",
                "certificateAuthority": {
                    "data": base64.b64encode(b"not a real certificate").decode()
                },
            }
        }

    def describe_addon(self, **_):
        return {"addon": {"status": "ACTIVE"}}


class _FakeSession:
    def client(self, service):
        assert service == "eks", f"unexpected client {service}"
        return _FakeEks()


class _FakeContext:
    @staticmethod
    def get_remaining_time_in_millis() -> int:
        return 600_000


def _run_handler(
    applier: dict, monkeypatch, tmp_path, request_type: str
) -> tuple[list, dict]:
    """Invoke handler() with every network edge replaced, and record what it asked for.

    `call` and `respond` are module globals of the exec'd applier, so replacing them in
    its namespace is what handler() resolves at call time. The real loop, the real
    `documents()` and the real scope guard all run.
    """
    calls: list = []
    responses: list = []

    def fake_call(endpoint, ca_file, token_for, path, method, body, **kwargs):  # noqa: ARG001
        calls.append((method, path, kwargs))
        return 200, b"{}"

    def fake_respond(event, status, reason, physical_id, data=None):  # noqa: ARG001
        responses.append({"status": status, "reason": reason, "id": physical_id})

    def temp_file_here(**kwargs):
        return tempfile.NamedTemporaryFile(**{**kwargs, "dir": str(tmp_path)})

    monkeypatch.setitem(applier, "call", fake_call)
    monkeypatch.setitem(applier, "respond", fake_respond)
    monkeypatch.setitem(
        applier,
        "boto3",
        types.SimpleNamespace(
            session=types.SimpleNamespace(Session=lambda: _FakeSession())
        ),
    )
    monkeypatch.setitem(
        applier, "tempfile", types.SimpleNamespace(NamedTemporaryFile=temp_file_here)
    )
    event = {
        "RequestType": request_type,
        "PhysicalResourceId": "demo/ash-system",
        "ResourceProperties": {
            "ClusterName": "demo",
            "Namespace": "ash-system",
            "OperatorImage": "example.dkr.ecr.us-east-1.amazonaws.com/op:v1",
        },
    }
    applier["handler"](event, _FakeContext())
    assert len(responses) == 1, f"handler responded {len(responses)} times"
    assert responses[0]["status"] == "SUCCESS", responses[0]["reason"]
    return calls, responses[0]


class TestDeleteRule:
    """NOTHING CLUSTER-SCOPED IS EVER DELETED.

    Driven through handler() with a fake `call`, so the guard under test is the one in
    the handler's delete loop. An earlier version re-implemented the scope filter here,
    and removing the guard from the handler left it green. Deleting the namespace
    cascade-deletes everything in it, and deleting a CRD cascade-deletes every AshScan
    in every namespace of the cluster, including an installation this stack knows
    nothing about.
    """

    @pytest.fixture
    def run(self, applier: dict, monkeypatch, tmp_path) -> tuple[list, dict]:
        return _run_handler(applier, monkeypatch, tmp_path, "Delete")

    @pytest.fixture
    def deleted(self, run: tuple[list, dict]) -> list[str]:
        return [path for _, path, _ in run[0]]

    def test_only_deletes_and_reports_what_it_kept(
        self, run: tuple[list, dict]
    ) -> None:
        calls, response = run
        assert {method for method, _, _ in calls} == {"DELETE"}
        assert "kept 5 cluster-scoped" in response["reason"], response["reason"]

    def test_deletes_exactly_the_namespaced_documents(
        self, applier: dict, docs: list, deleted: list[str]
    ) -> None:
        namespaced = [
            path for path, _, scope in reversed(docs) if scope == applier["NAMESPACED"]
        ]
        assert len(namespaced) == 5
        assert deleted == namespaced

    @pytest.mark.parametrize(
        "fragment,what",
        [
            ("customresourcedefinitions", "a CRD (cascade-deletes CRs cluster-wide)"),
            ("/clusterroles/", "the ClusterRole (shared with any second install)"),
            ("/clusterrolebindings/", "the ClusterRoleBinding"),
        ],
    )
    def test_never_deletes(self, deleted: list[str], fragment: str, what: str) -> None:
        offenders = [path for path in deleted if fragment in path]
        assert offenders == [], f"would delete {what}: {offenders}"

    def test_never_deletes_the_namespace(self, deleted: list[str]) -> None:
        assert [p for p in deleted if p.endswith("/namespaces/ash-system")] == []

    def test_does_delete_the_deployment_so_the_operator_stops(
        self, deleted: list[str]
    ) -> None:
        """The converse control: a rule that deleted nothing would pass every test above."""
        assert any("/deployments/" in path for path in deleted)
        assert sum("/serviceaccounts/" in path for path in deleted) == 2
        assert all("/namespaces/ash-system" in path for path in deleted)


class TestApplyForce:
    """CRDs are applied without force; everything the stack owns outright, with it."""

    def test_only_crds_skip_force(self, applier: dict, monkeypatch, tmp_path) -> None:
        calls, _ = _run_handler(applier, monkeypatch, tmp_path, "Create")
        assert len(calls) == 10
        assert {method for method, _, _ in calls} == {"PATCH"}
        for _, path, kwargs in calls:
            is_crd = "/customresourcedefinitions/" in path
            assert kwargs["force"] is (not is_crd), path
            assert kwargs["tolerate_409"] is is_crd, path


class TestCrds:
    @staticmethod
    def _crds(docs: list) -> dict:
        return {
            manifest["spec"]["names"]["plural"]: manifest
            for _, manifest, _ in docs
            if manifest["kind"] == "CustomResourceDefinition"
        }

    def test_both_plurals_are_the_operators(self, docs: list) -> None:
        assert sorted(self._crds(docs)) == ["ashmcpservers", "ashscans"]

    @pytest.mark.parametrize("plural", sorted(EXPECTED_CRDS))
    def test_names_match_the_operator_manifest(self, docs: list, plural: str) -> None:
        spec = self._crds(docs)[plural]["spec"]
        want = EXPECTED_CRDS[plural]
        assert spec["group"] == GROUP
        assert spec["scope"] == "Namespaced"
        assert spec["names"]["kind"] == want["kind"]
        assert spec["names"]["listKind"] == want["listKind"]
        assert spec["names"]["singular"] == want["singular"]
        assert spec["names"]["shortNames"] == want["shortNames"]

    @pytest.mark.parametrize("plural", sorted(EXPECTED_CRDS))
    def test_metadata_name_is_plural_dot_group(self, docs: list, plural: str) -> None:
        """Anything else is rejected with a name mismatch that reads as a schema error."""
        manifest = self._crds(docs)[plural]
        assert manifest["metadata"]["name"] == f"{plural}.{GROUP}"

    @pytest.mark.parametrize("plural", sorted(EXPECTED_CRDS))
    def test_printer_columns_include_phase(self, docs: list, plural: str) -> None:
        """`Phase` is the field a missing `--namespace` is diagnosed from.

        Without it `kubectl get ashscans` hides the symptom of the operator's own most
        recent regression, so these columns are not decoration.
        """
        version = self._crds(docs)[plural]["spec"]["versions"][0]
        names = [column["name"] for column in version["additionalPrinterColumns"]]
        assert names == EXPECTED_CRDS[plural]["columns"]
        assert "Phase" in names
        for column in version["additionalPrinterColumns"]:
            assert set(column) == {"name", "type", "jsonPath"}

    @pytest.mark.parametrize("plural", sorted(EXPECTED_CRDS))
    def test_spec_validates_what_the_operator_needs(
        self, docs: list, plural: str
    ) -> None:
        version = self._crds(docs)[plural]["spec"]["versions"][0]
        spec_schema = version["schema"]["openAPIV3Schema"]["properties"]["spec"]
        assert spec_schema["required"] == EXPECTED_CRDS[plural]["required"]
        # Without minLength an empty image validates and the operator dispatches a Job
        # with no image.
        assert spec_schema["properties"]["image"]["minLength"] == 1
        # And unknown fields survive, so a richer spec still validates against the subset
        # schema this stack installs.
        assert spec_schema["x-kubernetes-preserve-unknown-fields"] is True


class TestRbac:
    @staticmethod
    def _by_kind(docs: list, kind: str) -> list:
        return [manifest for _, manifest, _ in docs if manifest["kind"] == kind]

    def test_one_cluster_role_granting_only_crd_reads(self, docs: list) -> None:
        roles = self._by_kind(docs, "ClusterRole")
        assert len(roles) == 1
        assert roles[0]["rules"] == [
            {
                "apiGroups": ["apiextensions.k8s.io"],
                "resources": ["customresourcedefinitions"],
                "verbs": ["get", "list", "watch"],
            }
        ]

    def test_namespaced_rules_are_set_equal_to_the_operator_table(
        self, docs: list
    ) -> None:
        """Set equality, so an OVER-grant fails as loudly as a missing grant.

        A "contains everything required" assertion passes with an extra verb sitting
        beside the required ones, which is how a `leases` rule granted on an invented
        rationale survived until someone measured it.
        """
        roles = self._by_kind(docs, "Role")
        assert len(roles) == 1
        # An exact count first: an empty rules list satisfies every "does not contain"
        # assertion below and would report clean RBAC having installed nothing.
        rules = roles[0]["rules"]
        assert len(rules) == len(EXPECTED_NAMESPACED_RULES)
        got = sorted(
            (tuple(r["apiGroups"]), tuple(r["resources"]), tuple(sorted(r["verbs"])))
            for r in rules
        )
        want = sorted(
            (tuple(groups), tuple(resources), tuple(sorted(verbs)))
            for groups, resources, verbs in EXPECTED_NAMESPACED_RULES
        )
        assert got == want

    def test_no_rule_is_empty_in_any_field(self, docs: list) -> None:
        for manifest in self._by_kind(docs, "Role") + self._by_kind(
            docs, "ClusterRole"
        ):
            for rule in manifest["rules"]:
                assert rule["apiGroups"] and rule["resources"] and rule["verbs"]

    def test_no_wildcards_anywhere(self, docs: list) -> None:
        for manifest in self._by_kind(docs, "Role") + self._by_kind(
            docs, "ClusterRole"
        ):
            for rule in manifest["rules"]:
                assert "*" not in rule["apiGroups"] + rule["resources"] + rule["verbs"]

    def test_never_asks_for_secrets(self, docs: list) -> None:
        """A scanner able to read every Secret is a far larger target than one that cannot."""
        for manifest in self._by_kind(docs, "Role") + self._by_kind(
            docs, "ClusterRole"
        ):
            for rule in manifest["rules"]:
                assert "secrets" not in rule["resources"]

    def test_pods_is_read_only_and_jobs_has_no_patch(self, docs: list) -> None:
        rules = self._by_kind(docs, "Role")[0]["rules"]
        pods = next(r for r in rules if r["resources"] == ["pods"])
        assert sorted(pods["verbs"]) == ["get", "list", "watch"]
        jobs = next(r for r in rules if r["resources"] == ["jobs"])
        assert "patch" not in jobs["verbs"]

    def test_no_leases_rule(self, docs: list) -> None:
        """Measured unused against the running operator; it was the only over-grant.

        Re-adding it is correct only together with dropping `--standalone`, never alone.
        """
        rules = self._by_kind(docs, "Role")[0]["rules"]
        assert not any(rule["resources"] == ["leases"] for rule in rules)

    def test_bindings_name_the_operator_account(self, docs: list) -> None:
        for kind in ("RoleBinding", "ClusterRoleBinding"):
            for manifest in self._by_kind(docs, kind):
                assert len(manifest["subjects"]) == 1
                assert manifest["subjects"][0]["name"] == "ash-operator"

    def test_both_service_accounts_exist(self, docs: list) -> None:
        """The scan Jobs need their own account, and it gets no RBAC by design."""
        names = sorted(
            manifest["metadata"]["name"]
            for _, manifest, _ in docs
            if manifest["kind"] == "ServiceAccount"
        )
        assert names == ["ash-operator", "ash-scan"]


class TestDeployment:
    @staticmethod
    def _deployment(docs: list) -> dict:
        return next(m for _, m, _ in docs if m["kind"] == "Deployment")

    def test_replicas_is_an_int(self, docs: list) -> None:
        """A string "1" is rejected by the API server.

        This is why the manifests are built in Python rather than routed through the
        custom resource's properties, which CloudFormation renders as strings.
        """
        replicas = self._deployment(docs)["spec"]["replicas"]
        assert replicas == 1
        assert isinstance(replicas, int)
        assert not isinstance(replicas, bool)

    def test_namespace_arrives_by_fieldref_not_a_literal(self, docs: list) -> None:
        """The pair, not either half.

        An args entry referencing `$(WATCH_NAMESPACE)` with no such env var does not
        error: the kubelet leaves it unexpanded and kopf watches a namespace literally
        named `$(WATCH_NAMESPACE)`, which fails the same silent way a missing
        `--namespace` does.
        """
        container = self._deployment(docs)["spec"]["template"]["spec"]["containers"][0]
        assert container["args"] == ["--namespace", "$(WATCH_NAMESPACE)"]
        assert container["env"] == [
            {
                "name": "WATCH_NAMESPACE",
                "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}},
            }
        ]
        referenced = re.fullmatch(r"\$\((\w+)\)", container["args"][1])
        assert referenced is not None
        assert referenced.group(1) == container["env"][0]["name"]

    def test_command_is_unset(self, docs: list) -> None:
        """Setting it replaces the ENTRYPOINT and discards `kopf run` entirely."""
        container = self._deployment(docs)["spec"]["template"]["spec"]["containers"][0]
        assert "command" not in container

    def test_runs_as_the_uid_the_image_has(self, docs: list) -> None:
        """The uid is the one the operator Dockerfile creates and selects with USER.

        A uid the image does not create runs the process with no passwd entry and no
        home, so `pwd.getpwuid(os.getuid())` raises `KeyError`. Read from the
        Dockerfile rather than written here, so changing the image's uid without this
        stack fails here instead of in a cluster.
        """
        dockerfile = (
            REPO_ROOT / "deploy" / "kubernetes-operator" / "Dockerfile"
        ).read_text()
        user = re.search(r"^USER\s+(\d+)\s*$", dockerfile, re.MULTILINE)
        created = re.search(r"useradd\s+--uid\s+(\d+)\b", dockerfile)
        assert user and created, (
            "the operator Dockerfile no longer creates a numeric uid"
        )
        assert user.group(1) == created.group(1)
        pod = self._deployment(docs)["spec"]["template"]["spec"]
        assert pod["securityContext"]["runAsUser"] == int(user.group(1))
        assert pod["securityContext"]["runAsNonRoot"] is True
        assert pod["serviceAccountName"] == "ash-operator"

    def test_container_is_hardened(self, docs: list) -> None:
        container = self._deployment(docs)["spec"]["template"]["spec"]["containers"][0]
        security = container["securityContext"]
        assert security["allowPrivilegeEscalation"] is False
        assert security["readOnlyRootFilesystem"] is True
        assert security["capabilities"]["drop"] == ["ALL"]

    def test_selector_matches_the_pod_labels(self, docs: list) -> None:
        """A selector that matches nothing produces a Deployment that never becomes ready."""
        spec = self._deployment(docs)["spec"]
        selector = spec["selector"]["matchLabels"]
        assert selector.items() <= spec["template"]["metadata"]["labels"].items()


class TestResponseBound:
    """The response must fit CloudFormation's 4,096-byte custom resource quota.

    The quota row does not say whether it counts the whole body or only `Data`, so the
    applier bounds the whole body and this checks it the same way.
    """

    def test_the_cap_is_declared(self, applier: dict) -> None:
        assert applier["RESPONSE_MAX_BYTES"] == 4096

    def test_a_pathological_reason_is_truncated_to_fit(self, applier: dict) -> None:
        """Non-ASCII is the case that matters.

        A character slice plus `ensure_ascii=True` turned 1,000 characters into 6,000
        bytes of escapes -- on an error message, which is when the response matters most.
        """
        captured: dict = {}

        def fake_urlopen(request, timeout=None):  # noqa: ARG001
            captured["body"] = request.data

            class _Response:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *_):
                    return False

            return _Response()

        applier["urllib"].request.urlopen = fake_urlopen
        event = {
            "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/s/"
            + "u" * 36,
            "RequestId": "r" * 36,
            "LogicalResourceId": "L" * 255,
            "ResponseURL": "https://example.invalid/presigned",
        }
        applier["respond"](event, "FAILED", "�" * 4000, "c" * 100 + "/" + "n" * 63, {})
        assert captured["body"], "respond() sent no body"
        assert len(captured["body"]) <= 4096, f"body was {len(captured['body'])} bytes"
        # And it is still valid JSON carrying the verdict, not merely short.
        parsed = json.loads(captured["body"].decode("utf-8"))
        assert parsed["Status"] == "FAILED"
        assert parsed["LogicalResourceId"] == "L" * 255
