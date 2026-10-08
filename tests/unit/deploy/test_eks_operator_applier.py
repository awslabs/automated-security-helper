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
import copy
import importlib.util
import json
import pathlib
import re
import tempfile
import types

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
TEMPLATE = REPO_ROOT / "deploy/cdk/templates/AshEksOperator.template.json"
OPERATOR_YAML = REPO_ROOT / "deploy/kubernetes-operator/manifests/operator.yaml"
GROUP = "ash.awslabs.github.io"

OPERATOR_DIR = REPO_ROOT / "deploy/kubernetes-operator"
RBAC_YAML = OPERATOR_DIR / "manifests/rbac.yaml"
MANIFESTS_DIR = OPERATOR_DIR / "manifests"


def _manifest_files(directory: pathlib.Path) -> list:
    """Every file `kubectl apply -f manifests/` reads: .json, .yaml and .yml.

    RBAC is read from all of them, not rbac.yaml alone, so a Role added to
    operator.yaml, to a new file, or to a JSON file is compared too.
    """
    return sorted(
        path
        for path in directory.iterdir()
        if path.suffix in (".json", ".yaml", ".yml")
    )


MANIFEST_YAMLS = _manifest_files(MANIFESTS_DIR)
CRD_YAMLS = sorted((OPERATOR_DIR / "generated").glob("crd-*.yaml"))


def _yaml_docs(path: pathlib.Path) -> list:
    return [doc for doc in yaml.safe_load_all(path.read_text()) if doc]


def _operator_crds() -> dict:
    """The operator's generated CRDs, by plural.

    Parsed, not transcribed. This table used to be a hand copy of those files, and it
    agreed with the template while both lacked the `Coverage` column the operator's
    AshScan CRD had gained.
    """
    crds = {}
    for path in CRD_YAMLS:
        for doc in _yaml_docs(path):
            if doc["kind"] == "CustomResourceDefinition":
                crds[doc["spec"]["names"]["plural"]] = doc
    return crds


RBAC_KINDS = ("ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding")

# Every kind the operator's manifests may carry, with the top-level fields each may
# have besides apiVersion, kind and metadata. A document of any other kind is reported,
# and so is any other field, so a new kind, a wrapper or a field this file does not read
# cannot be applied by `kubectl apply -f manifests/` while every comparison skips it.
# The RBAC kinds' fields are checked in _rbac_drift, against RBAC_DOC_FIELDS.
MANIFEST_KINDS = {
    "ClusterRole": None,
    "ClusterRoleBinding": None,
    "Deployment": {"spec", "status"},
    "List": {"items"},
    "Namespace": {"spec", "status"},
    "NetworkPolicy": {"spec", "status"},
    "Role": None,
    "RoleBinding": None,
    "ServiceAccount": {"automountServiceAccountToken", "imagePullSecrets", "secrets"},
}


def _walk_manifests(raw: list) -> tuple[list, list[str]]:
    """The documents kubectl would apply, and every problem found on the way.

    kubectl treats ANY object with an `items` key as a list and applies its items,
    whatever its kind; keying on a `*List` kind let a Namespace carrying a Role and a
    RoleBinding in `items` grant Secrets reads with every comparison green. So the kind
    allowlist is checked on every document first, including wrappers, then any document
    with `items` is replaced by its items, recursively. A `*List` without `items` is
    reported rather than expanded to nothing.
    """
    docs: list = []
    problems: list[str] = []
    for doc in raw:
        if not isinstance(doc, dict):
            problems.append(f"manifests: not an object: {doc!r}")
            continue
        key, kind = _rbac_key(doc), doc.get("kind")
        allowed = MANIFEST_KINDS.get(kind, False) if isinstance(kind, str) else False
        if allowed is False:
            problems.append(f"manifests: kind not in the allowlist: {key}")
        elif allowed is not None:
            extra = set(doc) - allowed - {"apiVersion", "kind", "metadata", "items"}
            problems += [
                f"manifests: unknown field on {key}: {f}" for f in sorted(extra)
            ]
        if "items" in doc:
            if not (isinstance(kind, str) and kind.endswith("List")):
                problems.append(f"manifests: items on a non-List kind: {key}")
            items, more = _walk_manifests(doc.get("items") or [])
            docs += items
            problems += more
        elif isinstance(kind, str) and kind.endswith("List"):
            problems.append(f"manifests: List without items: {key}")
        else:
            docs.append(doc)
    return docs, problems


def _manifest_docs(paths: list) -> list:
    """The documents of every manifest file, as kubectl would apply them."""
    return _walk_manifests([doc for path in paths for doc in _yaml_docs(path)])[0]


def _manifest_problems(paths: list) -> list[str]:
    """What _walk_manifests reports for these files; empty when every document is read."""
    return _walk_manifests([doc for path in paths for doc in _yaml_docs(path)])[1]


def _set_json(value) -> str:
    """A value as canonical JSON: keys sorted and every array sorted, recursively.

    Structural, not delimiter-joined. Joining members with a comma made `["a", "b"]`
    and `["a,b"]` render alike, and RBAC matches those strings literally, so a rule
    granting nothing compared equal to one granting two resources. Every array in an
    RBAC object is a set to the API server, so sorting makes a reordering compare
    equal and nothing else.
    """

    def norm(v):
        if isinstance(v, list):
            return sorted(
                (norm(x) for x in v), key=lambda x: json.dumps(x, sort_keys=True)
            )
        if isinstance(v, dict):
            return {k: norm(v[k]) for k in sorted(v)}
        return v

    return json.dumps(norm(value), sort_keys=True, separators=(",", ":"))


def _canonical_rules(rules: list) -> list[str]:
    """Rules as sorted canonical JSON, every key kept, so order never matters."""
    return sorted(_set_json(r) for r in rules)


def _rbac_key(doc: dict) -> str:
    """`Kind namespace/name`; a cluster-scoped object has no namespace."""
    meta = doc.get("metadata") or {}
    return f"{doc.get('kind')} {meta.get('namespace', '(cluster)')}/{meta.get('name')}"


# The top-level and metadata keys an RBAC document may carry here; others are reported.
RBAC_DOC_FIELDS = {
    "apiVersion",
    "kind",
    "metadata",
    "rules",
    "aggregationRule",
    "roleRef",
    "subjects",
}
METADATA_FIELDS = {"name", "namespace", "labels", "annotations"}


def _invalidities(doc: dict) -> list[str]:
    """Inputs the API server would reject, so they fail in CI and not at apply time.

    Nothing is defaulted: a roleRef without apiGroup is invalid rather than rbac's
    group, and `apiGroups: []` is not `[""]`.
    """
    out = []
    for rule in doc.get("rules") or []:
        if not rule.get("verbs"):
            out.append(f"rule without verbs: {_set_json(rule)}")
        if not rule.get("resources") and not rule.get("nonResourceURLs"):
            out.append(f"rule without resources: {_set_json(rule)}")
        if rule.get("resources") and not rule.get("apiGroups"):
            out.append(f"rule with empty apiGroups: {_set_json(rule)}")
    if str(doc.get("kind", "")).endswith("Binding"):
        ref = doc.get("roleRef") or {}
        out += [
            f"roleRef without {k}"
            for k in ("apiGroup", "kind", "name")
            if not ref.get(k)
        ]
    return out


def _rbac_drift(installed: list, operator: list, stack_labels: dict) -> list[str]:
    """Every way two lists of manifests disagree on RBAC, as readable lines.

    ALL documents of the four RBAC kinds are compared: the set of (kind, namespace,
    name) in both directions, then for each object on both sides its apiVersion,
    labels, annotations and rules or aggregationRule, or its roleRef and subjects.
    Every value is compared as structure (`_set_json`), nothing is projected or
    defaulted, and a field this function does not know is reported rather than
    skipped. Unknown kinds and wrappers are reported by _walk_manifests. One function serves the real files and the planted copies below, so the
    controls exercise the comparison the real assertion makes.
    """
    drift: list[str] = []

    def diff(what: str, ours: list, theirs: list) -> None:
        drift.extend(f"{what}: only in the stack: {x}" for x in ours if x not in theirs)
        drift.extend(
            f"{what}: only in the operator: {x}" for x in theirs if x not in ours
        )
        # Membership alone would let a duplicated entry on one side pass as equal.
        for side, items in (("stack", ours), ("operator", theirs)):
            drift.extend(
                f"{what}: repeated in the {side}: {x}"
                for x in sorted({x for x in items if items.count(x) > 1})
            )

    keyed = {}
    for side, docs in (("stack", installed), ("operator", operator)):
        rbac = [d for d in docs if isinstance(d, dict) and d.get("kind") in RBAC_KINDS]
        keyed[side] = {_rbac_key(d): d for d in rbac}
        # Two documents with one key would collapse here and hide each other.
        if len(keyed[side]) != len(rbac):
            drift.append(f"RBAC objects: the {side} repeats a kind/namespace/name")
        for doc in rbac:
            key = _rbac_key(doc)
            drift += [
                f"{key}: unknown field in the {side}: {f}"
                for f in sorted(set(doc) - RBAC_DOC_FIELDS)
            ]
            drift += [
                f"{key}: unknown metadata field in the {side}: {f}"
                for f in sorted(set(doc.get("metadata") or {}) - METADATA_FIELDS)
            ]
            drift += [f"{key}: invalid in the {side}: {x}" for x in _invalidities(doc)]
    ours, theirs = keyed["stack"], keyed["operator"]
    diff("RBAC objects", sorted(ours), sorted(theirs))
    stack_own = {_set_json([k, v]) for k, v in stack_labels.items()}
    for key in sorted(set(ours) & set(theirs)):
        mine, other = ours[key], theirs[key]
        diff(
            f"{key} apiVersion",
            [_set_json(mine.get("apiVersion"))],
            [_set_json(other.get("apiVersion"))],
        )
        # Every operator label must be on the stack's object with the same value, and
        # every stack label other than its own bookkeeping LABELS on the operator's. An
        # aggregate-to-admin label merges the role into a built-in one.
        their_labels = [
            _set_json([k, v])
            for k, v in (other["metadata"].get("labels") or {}).items()
        ]
        my_labels = [
            label
            for label in (
                _set_json([k, v])
                for k, v in (mine["metadata"].get("labels") or {}).items()
            )
            if label not in stack_own or label in their_labels
        ]
        diff(f"{key} labels", my_labels, their_labels)
        diff(
            f"{key} annotations",
            [_set_json(mine["metadata"].get("annotations") or {})],
            [_set_json(other["metadata"].get("annotations") or {})],
        )
        if mine["kind"].endswith("Binding"):
            diff(
                f"{key} roleRef",
                [_set_json(mine.get("roleRef"))],
                [_set_json(other.get("roleRef"))],
            )
            diff(
                f"{key} subjects",
                sorted(_set_json(x) for x in mine.get("subjects") or []),
                sorted(_set_json(x) for x in other.get("subjects") or []),
            )
        else:
            diff(
                f"{key} rules",
                _canonical_rules(mine.get("rules") or []),
                _canonical_rules(other.get("rules") or []),
            )
            diff(
                f"{key} aggregationRule",
                [_set_json(mine.get("aggregationRule"))],
                [_set_json(other.get("aggregationRule"))],
            )
    return drift


def _operator_role_rules(kind: str, name: str) -> list:
    roles = [
        doc
        for doc in _manifest_docs([RBAC_YAML])
        if doc["kind"] == kind and doc["metadata"]["name"] == name
    ]
    assert len(roles) == 1, f"expected one {kind}/{name} in {RBAC_YAML}"
    return _canonical_rules(roles[0]["rules"])


def _spec_schema(crd: dict) -> dict:
    """The `spec` schema of a CRD's one served version."""
    return crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]


OPERATOR_CRDS = _operator_crds()
EXPECTED_CRDS = {
    plural: {
        "kind": crd["spec"]["names"]["kind"],
        "listKind": crd["spec"]["names"]["listKind"],
        "singular": crd["spec"]["names"]["singular"],
        "shortNames": crd["spec"]["names"].get("shortNames", []),
        "required": _spec_schema(crd).get("required", []),
        "columns": crd["spec"]["versions"][0].get("additionalPrinterColumns", []),
    }
    for plural, crd in OPERATOR_CRDS.items()
}
EXPECTED_NAMESPACED_RULES = _operator_role_rules("Role", "ash-operator")
EXPECTED_CLUSTER_RULES = _operator_role_rules("ClusterRole", "ash-operator-crd-reader")


def test_the_parsed_operator_contract_is_populated() -> None:
    """Non-vacuity: a parser that found nothing would make every comparison below pass."""
    assert sorted(EXPECTED_CRDS) == ["ashmcpservers", "ashscans"]
    for want in EXPECTED_CRDS.values():
        assert "image" in want["required"]
        assert any(column["name"] == "Phase" for column in want["columns"])
    assert len(EXPECTED_NAMESPACED_RULES) == 10
    assert len(EXPECTED_CLUSTER_RULES) == 1


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


def test_eleven_documents_with_distinct_paths(docs: list) -> None:
    assert len(docs) == 11
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
        assert len(namespaced) == 6
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
        # The NetworkPolicy goes too, and only after the Deployment it guards.
        policies = [i for i, path in enumerate(deleted) if "/networkpolicies/" in path]
        deployments = [i for i, path in enumerate(deleted) if "/deployments/" in path]
        assert len(policies) == 1 and deployments[0] < policies[0], deleted
        assert all("/namespaces/ash-system" in path for path in deleted)


class TestApplyForce:
    """CRDs are applied without force; everything the stack owns outright, with it."""

    def test_only_crds_skip_force(self, applier: dict, monkeypatch, tmp_path) -> None:
        calls, _ = _run_handler(applier, monkeypatch, tmp_path, "Create")
        assert len(calls) == 11
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
        # Whole columns, in order: a column with the right name and the wrong jsonPath
        # prints a blank cell in `kubectl get`.
        assert version["additionalPrinterColumns"] == EXPECTED_CRDS[plural]["columns"]
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

    @pytest.mark.parametrize("plural", sorted(EXPECTED_CRDS))
    def test_subset_constraints_equal_the_operator_crd(
        self, docs: list, plural: str
    ) -> None:
        """Every constraint the subset schema states is the operator CRD's own.

        The subset is deliberate (the full CRDs do not fit the inline template budget),
        but what it DOES validate has to agree with the real schema. A `shardCount`
        maximum of 50 here and 100 there would reject, at install time on EKS, a scan the
        operator accepts everywhere else. Unknown-field preservation is the subset's own
        mechanism and is the one key not compared.
        """
        subset = _spec_schema(self._crds(docs)[plural])["properties"]
        real = _spec_schema(OPERATOR_CRDS[plural])["properties"]
        assert subset, "the subset schema declares no spec properties"
        for name, constraints in subset.items():
            assert name in real, f"{plural}: spec.{name} is not in the operator CRD"
            for key, value in constraints.items():
                if key == "x-kubernetes-preserve-unknown-fields":
                    continue
                assert real[name].get(key) == value, (
                    f"{plural}: spec.{name}.{key} is {value!r} in the stack and "
                    f"{real[name].get(key)!r} in the operator CRD"
                )


# Names the planted-drift controls below report, kept short so each line reads whole.
# Keys and values the planted-drift controls below report.
EXTRA_CR = "ClusterRole (cluster)/ash-operator-extra"
EXTRA_SA = "ServiceAccount ash-system/ash-extra"
CR = "ClusterRole (cluster)/ash-operator-crd-reader"
CRB = "ClusterRoleBinding (cluster)/ash-operator-crd-reader"
ROLE = "Role ash-system/ash-operator"
RB = "RoleBinding ash-system/ash-operator"
SUBJECT = {"kind": "ServiceAccount", "name": "ash-operator", "namespace": "ash-system"}
CRB_REF = {
    "apiGroup": "rbac.authorization.k8s.io",
    "kind": "ClusterRole",
    "name": "ash-operator-crd-reader",
}
SECRETS_ROLE = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "Role",
    "metadata": {"name": "ash-secrets", "namespace": "ash-system"},
    "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
}
SECRETS_BINDING = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "RoleBinding",
    "metadata": {"name": "ash-secrets", "namespace": "ash-system"},
    "roleRef": {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": "ash-secrets",
    },
    "subjects": [SUBJECT],
}


def _find(docs: list, kind: str, name: str) -> dict:
    found = [d for d in docs if d.get("kind") == kind and d["metadata"]["name"] == name]
    assert len(found) == 1, f"expected one {kind}/{name}"
    return found[0]


def _rule(doc: dict, resource: str) -> dict:
    return next(r for r in doc["rules"] if resource in (r.get("resources") or []))


def _add_verb(docs: list) -> None:
    _rule(_find(docs, "Role", "ash-operator"), "jobs")["verbs"].append("patch")


def _comma_resources(docs: list) -> None:
    rule = _rule(_find(docs, "Role", "ash-operator"), "ashscans")
    rule["resources"] = ["ashscans,ashmcpservers"]


def _comma_verbs(docs: list) -> None:
    rule = _rule(_find(docs, "Role", "ash-operator"), "configmaps")
    rule["verbs"] = ["create,delete,get,list,watch"]


def _resource_names(docs: list) -> None:
    _rule(_find(docs, "Role", "ash-operator"), "configmaps")["resourceNames"] = ["one"]


def _non_resource_urls(docs: list) -> None:
    _find(docs, "ClusterRole", "ash-operator-crd-reader")["rules"].append(
        {"nonResourceURLs": ["/metrics"], "verbs": ["get"]}
    )


AGGREGATION = {"clusterRoleSelectors": [{"matchLabels": {"ash-aggregate": "true"}}]}


def _aggregation_rule(docs: list) -> None:
    _find(docs, "ClusterRole", "ash-operator-crd-reader")["aggregationRule"] = (
        AGGREGATION
    )


ADMIN_LABEL = "rbac.authorization.k8s.io/aggregate-to-admin"


def _admin_label(docs: list) -> None:
    _find(docs, "ClusterRole", "ash-operator-crd-reader")["metadata"]["labels"] = {
        ADMIN_LABEL: "true"
    }


def _annotation(docs: list) -> None:
    _find(docs, "Role", "ash-operator")["metadata"]["annotations"] = {"note": "x"}


def _rule_unknown_key(docs: list) -> None:
    _rule(_find(docs, "Role", "ash-operator"), "pods")["futureField"] = ["x"]


def _doc_unknown_field(docs: list) -> None:
    _find(docs, "Role", "ash-operator")["futureField"] = 1


def _metadata_unknown_field(docs: list) -> None:
    _find(docs, "Role", "ash-operator")["metadata"]["finalizers"] = ["x"]


def _subject_changed(docs: list) -> None:
    _find(docs, "RoleBinding", "ash-operator")["subjects"][0]["name"] = "ash-scan"


def _subject_api_group(docs: list) -> None:
    _find(docs, "RoleBinding", "ash-operator")["subjects"][0]["apiGroup"] = "example.io"


def _subject_duplicated(docs: list) -> None:
    _find(docs, "RoleBinding", "ash-operator")["subjects"].append(dict(SUBJECT))


def _role_ref_changed(docs: list) -> None:
    _find(docs, "ClusterRoleBinding", "ash-operator-crd-reader")["roleRef"]["name"] = (
        "view"
    )


def _role_ref_without_group(docs: list) -> None:
    del _find(docs, "RoleBinding", "ash-operator")["roleRef"]["apiGroup"]


def _empty_api_groups(docs: list) -> None:
    _rule(_find(docs, "Role", "ash-operator"), "pods")["apiGroups"] = []


def _rule_line(side: str, rule: dict) -> str:
    return f"{ROLE} rules: only in the {side}: {_set_json(rule)}"


JOBS = {
    "apiGroups": ["batch"],
    "resources": ["jobs"],
    "verbs": ["get", "list", "watch", "create", "delete"],
}
SCANS = {
    "apiGroups": ["ash.awslabs.github.io"],
    "resources": ["ashscans", "ashmcpservers"],
    "verbs": ["get", "list", "watch", "patch"],
}
CONFIGMAPS = {
    "apiGroups": [""],
    "resources": ["configmaps"],
    "verbs": ["get", "list", "watch", "create", "delete"],
}
PODS = {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}


class TestRbac:
    @staticmethod
    def _by_kind(docs: list, kind: str) -> list:
        return [manifest for _, manifest, _ in docs if manifest["kind"] == kind]

    def test_one_cluster_role_granting_only_crd_reads(self, docs: list) -> None:
        roles = self._by_kind(docs, "ClusterRole")
        assert len(roles) == 1
        # Parsed from rbac.yaml, not written here, so the operator widening or
        # narrowing its ClusterRole without this stack fails.
        assert _canonical_rules(roles[0]["rules"]) == EXPECTED_CLUSTER_RULES
        assert EXPECTED_CLUSTER_RULES == [
            _set_json(
                {
                    "apiGroups": ["apiextensions.k8s.io"],
                    "resources": ["customresourcedefinitions"],
                    "verbs": ["get", "list", "watch"],
                }
            )
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
        assert _canonical_rules(rules) == EXPECTED_NAMESPACED_RULES

    def test_every_rbac_object_equals_the_operator_rbac_yaml(
        self, docs: list, applier: dict
    ) -> None:
        """The full set of Roles, ClusterRoles and bindings, both ways, refs included."""
        installed = [manifest for _, manifest, _ in docs]
        operator = _manifest_docs(MANIFEST_YAMLS)
        assert RBAC_YAML in MANIFEST_YAMLS
        assert _manifest_problems(MANIFEST_YAMLS) == []
        # Non-vacuity: two empty sides would agree.
        want = [CR, CRB, ROLE, RB]
        assert (
            sorted(_rbac_key(d) for d in installed if d["kind"] in RBAC_KINDS) == want
        )
        assert sorted(_rbac_key(d) for d in operator if d["kind"] in RBAC_KINDS) == want
        assert _rbac_drift(installed, operator, applier["LABELS"]) == []

    @pytest.mark.parametrize(
        ("edit", "expected"),
        [
            pytest.param(
                _add_verb,
                [
                    _rule_line("stack", JOBS),
                    _rule_line(
                        "operator", {**JOBS, "verbs": [*JOBS["verbs"], "patch"]}
                    ),
                ],
                id="rule-extra-verb",
            ),
            pytest.param(
                _comma_resources,
                [
                    _rule_line("stack", SCANS),
                    _rule_line(
                        "operator", {**SCANS, "resources": ["ashscans,ashmcpservers"]}
                    ),
                ],
                id="comma-joined-resources",
            ),
            pytest.param(
                _comma_verbs,
                [
                    _rule_line("stack", CONFIGMAPS),
                    _rule_line(
                        "operator",
                        {**CONFIGMAPS, "verbs": ["create,delete,get,list,watch"]},
                    ),
                ],
                id="comma-joined-verbs",
            ),
            pytest.param(
                _resource_names,
                [
                    _rule_line("stack", CONFIGMAPS),
                    _rule_line("operator", {**CONFIGMAPS, "resourceNames": ["one"]}),
                ],
                id="rule-resource-names",
            ),
            pytest.param(
                _non_resource_urls,
                [
                    f"{CR} rules: only in the operator: "
                    + _set_json({"nonResourceURLs": ["/metrics"], "verbs": ["get"]})
                ],
                id="rule-non-resource-urls",
            ),
            pytest.param(
                _aggregation_rule,
                [
                    f"{CR} aggregationRule: only in the stack: null",
                    f"{CR} aggregationRule: only in the operator: "
                    + _set_json(AGGREGATION),
                ],
                id="aggregation-rule",
            ),
            pytest.param(
                _admin_label,
                [
                    f"{CR} labels: only in the operator: "
                    + _set_json([ADMIN_LABEL, "true"])
                ],
                id="aggregate-to-admin-label",
            ),
            pytest.param(
                _annotation,
                [
                    f"{ROLE} annotations: only in the stack: {{}}",
                    f'{ROLE} annotations: only in the operator: {{"note":"x"}}',
                ],
                id="annotation",
            ),
            pytest.param(
                _rule_unknown_key,
                [
                    _rule_line("stack", PODS),
                    _rule_line("operator", {**PODS, "futureField": ["x"]}),
                ],
                id="rule-unknown-key",
            ),
            pytest.param(
                _doc_unknown_field,
                [f"{ROLE}: unknown field in the operator: futureField"],
                id="document-unknown-field",
            ),
            pytest.param(
                _metadata_unknown_field,
                [f"{ROLE}: unknown metadata field in the operator: finalizers"],
                id="metadata-unknown-field",
            ),
            pytest.param(
                _subject_changed,
                [
                    f"{RB} subjects: only in the stack: {_set_json(SUBJECT)}",
                    f"{RB} subjects: only in the operator: "
                    + _set_json({**SUBJECT, "name": "ash-scan"}),
                ],
                id="role-binding-subject",
            ),
            pytest.param(
                _subject_api_group,
                [
                    f"{RB} subjects: only in the stack: {_set_json(SUBJECT)}",
                    f"{RB} subjects: only in the operator: "
                    + _set_json({**SUBJECT, "apiGroup": "example.io"}),
                ],
                id="subject-api-group",
            ),
            pytest.param(
                _subject_duplicated,
                [f"{RB} subjects: repeated in the operator: {_set_json(SUBJECT)}"],
                id="subject-duplicated",
            ),
            pytest.param(
                _role_ref_changed,
                [
                    f"{CRB} roleRef: only in the stack: {_set_json(CRB_REF)}",
                    f"{CRB} roleRef: only in the operator: "
                    + _set_json({**CRB_REF, "name": "view"}),
                ],
                id="cluster-role-binding-roleref",
            ),
        ],
    )
    def test_controls_planted_rbac_edits(
        self, docs: list, applier: dict, edit, expected: list
    ) -> None:
        """A planted edit to the parsed manifests, read the way the real assertion is.

        Structural rather than textual, so a control does not depend on one line of
        rbac.yaml staying as it is: a text anchor that stops matching would fail as
        "plant did not land", which reads as drift being caught when nothing was
        compared.
        """
        operator = copy.deepcopy(_manifest_docs(MANIFEST_YAMLS))
        before = json.dumps(operator, sort_keys=True)
        edit(operator)
        assert json.dumps(operator, sort_keys=True) != before, "the plant did not land"
        installed = [manifest for _, manifest, _ in docs]
        assert _rbac_drift(installed, operator, applier["LABELS"]) == expected

    @pytest.mark.parametrize(
        ("edit", "first"),
        [
            pytest.param(
                _role_ref_without_group,
                f"{RB}: invalid in the operator: roleRef without apiGroup",
                id="role-ref-without-api-group",
            ),
            pytest.param(
                _empty_api_groups,
                f"{ROLE}: invalid in the operator: rule with empty apiGroups: "
                + _set_json({**PODS, "apiGroups": []}),
                id="empty-api-groups",
            ),
        ],
    )
    def test_controls_invalid_input_is_reported_not_defaulted(
        self, docs: list, applier: dict, edit, first: str
    ) -> None:
        operator = copy.deepcopy(_manifest_docs(MANIFEST_YAMLS))
        edit(operator)
        installed = [manifest for _, manifest, _ in docs]
        drift = _rbac_drift(installed, operator, applier["LABELS"])
        assert drift[0] == first
        # And the value itself differs from the stack's, so it is drift as well.
        assert len(drift) == 3

    @pytest.mark.parametrize(
        ("files", "expected"),
        [
            pytest.param(
                {"extra-rbac.json": json.dumps(SECRETS_ROLE)},
                ["RBAC objects: only in the operator: Role ash-system/ash-secrets"],
                id="json-manifest",
            ),
            pytest.param(
                {
                    "zz-list.yaml": json.dumps(
                        {
                            "apiVersion": "v1",
                            "kind": "List",
                            "items": [SECRETS_ROLE, SECRETS_BINDING],
                        }
                    )
                },
                [
                    "RBAC objects: only in the operator: Role ash-system/ash-secrets",
                    "RBAC objects: only in the operator: RoleBinding ash-system/ash-secrets",
                ],
                id="kind-list",
            ),
            pytest.param(
                {
                    "rbac.yaml": RBAC_YAML.read_text()
                    + "\n---\n"
                    + json.dumps(
                        {
                            "apiVersion": "v1",
                            "kind": "Namespace",
                            "metadata": {"name": "ash-system"},
                            "items": [SECRETS_ROLE, SECRETS_BINDING],
                        }
                    )
                },
                [
                    "manifests: items on a non-List kind: Namespace (cluster)/ash-system",
                    "RBAC objects: only in the operator: Role ash-system/ash-secrets",
                    "RBAC objects: only in the operator: RoleBinding ash-system/ash-secrets",
                ],
                id="H3-items-on-a-namespace",
            ),
            pytest.param(
                {
                    "operator.yaml": OPERATOR_YAML.read_text().replace(
                        "kind: Namespace\nmetadata:\n  name: ash-system\n",
                        "kind: Namespace\nmetadata:\n  name: ash-system\nitems:\n"
                        f"  - {json.dumps(SECRETS_ROLE)}\n",
                        1,
                    )
                },
                [
                    "manifests: items on a non-List kind: Namespace (cluster)/ash-system",
                    "RBAC objects: only in the operator: Role ash-system/ash-secrets",
                ],
                id="H2-items-on-the-existing-namespace",
            ),
            pytest.param(
                {
                    "zz-sa.yaml": json.dumps(
                        {
                            "apiVersion": "v1",
                            "kind": "ServiceAccount",
                            "metadata": {
                                "name": "ash-extra",
                                "namespace": "ash-system",
                            },
                            "items": [SECRETS_ROLE],
                        }
                    )
                },
                [
                    f"manifests: items on a non-List kind: {EXTRA_SA}",
                    "RBAC objects: only in the operator: Role ash-system/ash-secrets",
                ],
                id="H-items-on-a-service-account",
            ),
            pytest.param(
                {
                    "zz-k.yaml": "apiVersion: v1\nkind: AccessList\nmetadata: {name: k}\n"
                },
                [
                    "manifests: kind not in the allowlist: AccessList (cluster)/k",
                    "manifests: List without items: AccessList (cluster)/k",
                ],
                id="K-list-without-items",
            ),
            pytest.param(
                {
                    "zz-ns.yaml": "apiVersion: v1\nkind: Namespace\n"
                    "metadata: {name: other}\nfutureField: 1\n"
                },
                ["manifests: unknown field on Namespace (cluster)/other: futureField"],
                id="unknown-field-on-a-non-rbac-kind",
            ),
            pytest.param(
                {
                    "zz-other.yml": "apiVersion: v1\nkind: ConfigMap\n"
                    "metadata: {name: surprise, namespace: ash-system}\n"
                },
                ["manifests: kind not in the allowlist: ConfigMap ash-system/surprise"],
                id="kind-outside-allowlist",
            ),
            pytest.param(
                {
                    "rbac.yaml": RBAC_YAML.read_text()
                    + "\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
                    "metadata: {name: ash-scan, namespace: ash-system}\n"
                    'rules: [{apiGroups: [""], resources: [secrets], verbs: [get]}]\n'
                },
                ["RBAC objects: only in the operator: Role ash-system/ash-scan"],
                id="extra-role-in-rbac-yaml",
            ),
            pytest.param(
                {
                    "zz-extra.yaml": "apiVersion: rbac.authorization.k8s.io/v1\n"
                    "kind: ClusterRole\nmetadata: {name: ash-operator-extra}\n"
                    'rules: [{apiGroups: [""], resources: [nodes], verbs: [get]}]\n'
                },
                [f"RBAC objects: only in the operator: {EXTRA_CR}"],
                id="extra-cluster-role",
            ),
        ],
    )
    def test_controls_planted_manifest_files(
        self, docs: list, applier: dict, tmp_path: pathlib.Path, files: dict, expected
    ) -> None:
        """Files planted in a copy of manifests/, with file discovery run again on it."""
        for path in MANIFEST_YAMLS:
            (tmp_path / path.name).write_text(path.read_text())
        for name, text in files.items():
            (tmp_path / name).write_text(text)
        files_read = _manifest_files(tmp_path)
        operator = _manifest_docs(files_read)
        installed = [manifest for _, manifest, _ in docs]
        drift = _manifest_problems(files_read)
        drift += _rbac_drift(installed, operator, applier["LABELS"])
        assert drift == expected

    def test_control_order_anywhere_in_rbac_yaml_is_not_drift(
        self, docs: list, applier: dict
    ) -> None:
        """A reordering is a no-op to the API server, so it must not go red here.

        Every array in every document is reversed, recursively, and the documents too.
        """

        def reversed_all(value):
            if isinstance(value, list):
                return [reversed_all(x) for x in reversed(value)]
            if isinstance(value, dict):
                return {k: reversed_all(v) for k, v in value.items()}
            return value

        operator = _manifest_docs(MANIFEST_YAMLS)
        shuffled = reversed_all(operator)
        assert shuffled != operator
        installed = [manifest for _, manifest, _ in docs]
        assert _rbac_drift(installed, shuffled, applier["LABELS"]) == []

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
        assert container["args"][:2] == ["--namespace", "$(WATCH_NAMESPACE)"]
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


# The only container fields the two install paths may disagree on.
IMAGE_FIELDS = ("image", "imagePullPolicy")


def _without(mapping: dict, *keys: str) -> dict:
    return {k: v for k, v in mapping.items() if k not in keys}


class TestParityWithOperatorYaml:
    """The CloudFormation install and `kubectl apply` of operator.yaml must agree.

    There are two install paths for one operator, and they drifted once: operator.yaml
    gained kopf's --liveness endpoint, its probes, a CPU limit and a deny-all-ingress
    NetworkPolicy while the applier's Deployment changed only its uid. checkov scans
    the YAML and cannot see Python inside a template's ZipFile, so nothing flagged it.

    These compare the Deployment spec, the pod spec and the container whole, so a field
    added to either side fails until the other has it. The image, the namespace and the
    labels legitimately differ (the stack takes the first two as parameters and adds a
    managed-by label), so object metadata and the container's image fields are left out.
    """

    @staticmethod
    def _yaml_docs() -> list:
        """Every manifest kubectl applies, not operator.yaml alone.

        A second Deployment or NetworkPolicy in another file is applied too, so `_one`
        must see it and fail, rather than compare the first one it happens to read.
        """
        assert _manifest_problems(MANIFEST_YAMLS) == []
        return _manifest_docs(MANIFEST_YAMLS)

    @staticmethod
    def _one(docs: list, kind: str) -> dict:
        found = [d for d in docs if d["kind"] == kind]
        assert len(found) == 1, f"expected one {kind}, found {len(found)}"
        return found[0]

    def test_control_a_second_deployment_in_manifests_is_refused(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Planted in a copy of manifests/: two Deployments must not pass as one."""
        for path in MANIFEST_YAMLS:
            (tmp_path / path.name).write_text(path.read_text())
        shipped = self._one(self._yaml_docs(), "Deployment")
        second = copy.deepcopy(shipped)
        second["metadata"]["name"] = "ash-operator-two"
        (tmp_path / "zz-second.json").write_text(json.dumps(second))
        planted = _manifest_docs(_manifest_files(tmp_path))
        with pytest.raises(AssertionError, match="expected one Deployment, found 2"):
            self._one(planted, "Deployment")

    @pytest.fixture
    def pods(self, docs: list) -> tuple[dict, dict]:
        cdk = self._one([m for _, m, _ in docs], "Deployment")
        shipped = self._one(self._yaml_docs(), "Deployment")
        return cdk["spec"]["template"]["spec"], shipped["spec"]["template"]["spec"]

    def test_deployment_spec_matches_outside_the_pod_template(self, docs: list) -> None:
        cdk = self._one([m for _, m, _ in docs], "Deployment")["spec"]
        shipped = self._one(self._yaml_docs(), "Deployment")["spec"]
        assert _without(cdk, "template") == _without(shipped, "template")

    def test_pod_spec_matches_outside_the_containers(
        self, pods: tuple[dict, dict]
    ) -> None:
        cdk, shipped = pods
        assert _without(cdk, "containers") == _without(shipped, "containers")

    def test_container_matches_except_the_image(self, pods: tuple[dict, dict]) -> None:
        """Whole, so a field added to operator.yaml fails here until the applier has it.

        Only the image reference and its pull policy may differ: the stack takes the
        image as a parameter, and operator.yaml carries a local development tag.
        """
        (cdk,) = pods[0]["containers"]
        (shipped,) = pods[1]["containers"]
        assert cdk["image"] == "example.dkr.ecr.us-east-1.amazonaws.com/op:v1"
        assert _without(cdk, *IMAGE_FIELDS) == _without(shipped, *IMAGE_FIELDS)

    def test_network_policy_matches(self, applier: dict, docs: list) -> None:
        shipped = self._one(self._yaml_docs(), "NetworkPolicy")
        found = [(m, s) for _, m, s in docs if m["kind"] == "NetworkPolicy"]
        assert len(found) == 1, f"the applier installs {len(found)} NetworkPolicies"
        cdk, scope = found[0]
        assert cdk["metadata"]["name"] == shipped["metadata"]["name"]
        assert cdk["spec"] == shipped["spec"]
        # Namespaced, so a stack delete removes it with the Deployment it guards.
        assert scope == applier["NAMESPACED"]

    def test_network_policy_selects_the_installed_pod(self, docs: list) -> None:
        manifests = [m for _, m, _ in docs]
        policy = self._one(manifests, "NetworkPolicy")
        deployment = self._one(manifests, "Deployment")
        assert policy["metadata"]["namespace"] == deployment["metadata"]["namespace"]
        selector = policy["spec"]["podSelector"]["matchLabels"]
        labels = deployment["spec"]["template"]["metadata"]["labels"]
        assert selector and selector.items() <= labels.items()

    def test_network_policy_is_applied_before_the_deployment(self, docs: list) -> None:
        """So the pod never runs, even briefly, without the policy in place."""
        kinds = [m["kind"] for _, m, _ in docs]
        assert kinds.index("NetworkPolicy") < kinds.index("Deployment")


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
