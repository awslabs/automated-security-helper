"""Pins the operator's grants and the scanned-source schema at their current width.

Both are reviewed once and then only re-read by accident. Adding `secrets` to the
pods rule in rbac.yaml, or `hostPath` to the source schema, left every other unit
test green: crd-drift would notice the schema change, but regenerating the CRDs
clears that, and nothing read rbac.yaml for its verbs at all. A widening has to
change this file as well, which makes it a decision in the diff rather than a side
effect.

Two layers, because they fail for different reasons. EXPECTED_RULES and
EXPECTED_BINDINGS are an exact pin: every (apiGroups, resources, verbs) rule, every
role's top-level keys and labels (so aggregation cannot refill a role's rules), and
every binding, as reviewed, read from every object `kubectl apply -f manifests/`
would send (.yaml, .yml and .json files, List items expanded) rather than rbac.yaml
alone, and manifests/ may hold only the reviewed files. Any change at all, `create`
on pods included, goes red there and has to be re-pinned by hand. The denylist
tests below it name the grants that must never be re-pinned, so the reviewer
updating the pin is told which kind of widening they are looking at.

Every pin is keyed by (kind, namespace, name), because that is what identifies an
object to the API server: a Role keyed by kind and name alone let a same-named copy
in another namespace stand in for the real one while the real one was widened. And
a binding pin only means something if the operator runs as the account it binds, so
EXPECTED_OBJECTS pins every object manifests/ holds, the Deployment's namespace and
serviceAccountName are pinned, and a Secret or any other workload is refused: each
of those could run code as, or hand out the token of, an account no pin here reads.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

import pytest
import yaml

from ash_operator.generate_manifests import _source_volume_schema

OPERATOR_DIR = Path(__file__).resolve().parents[1]
MANIFESTS_DIR = OPERATOR_DIR / "manifests"
RBAC_YAML = MANIFESTS_DIR / "rbac.yaml"
SCAN_CRD = OPERATOR_DIR / "generated" / "crd-ashscans.yaml"

# Resources whose read or write turns the operator's account into something wider
# than a scan dispatcher: credential reads, a shell or a log stream into pods that
# hold scanned source, token minting, and anything that edits RBAC itself.
FORBIDDEN_RESOURCES = frozenset(
    {
        "secrets",
        "pods/exec",
        "pods/log",
        "pods/attach",
        "pods/portforward",
        "serviceaccounts/token",
        "roles",
        "rolebindings",
        "clusterroles",
        "clusterrolebindings",
    }
)
# Verbs that let an account grant or assume permissions it does not hold.
FORBIDDEN_VERBS = frozenset({"escalate", "bind", "impersonate"})

SOURCE_VOLUME_KEYS = {"persistentVolumeClaim", "configMap", "secret", "csi"}


# The reviewed grants, rule for rule. Each rule is (apiGroups, resources, verbs) with
# every list sorted, so reordering a list in the YAML is not a change but adding or
# removing any member is. Keep this in step with the comments in rbac.yaml, which
# give the reason for each grant.
Rule = tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]
# (kind, namespace, name). The namespace is None for a cluster-scoped object.
ObjectKey = tuple[str, str | None, str]

OPERATOR_NAMESPACE = "ash-system"
OPERATOR_ACCOUNT = "ash-operator"
SCAN_ACCOUNT = "ash-scan"
OPERATOR_DEPLOYMENT: ObjectKey = ("Deployment", OPERATOR_NAMESPACE, "ash-operator")

EXPECTED_RULES: dict[ObjectKey, list[Rule]] = {
    ("ClusterRole", None, "ash-operator-crd-reader"): [
        (("apiextensions.k8s.io",), ("customresourcedefinitions",), ("get", "list", "watch")),
    ],
    ("Role", OPERATOR_NAMESPACE, "ash-operator"): [
        (
            ("ash.awslabs.github.io",),
            ("ashmcpservers", "ashscans"),
            ("get", "list", "patch", "watch"),
        ),
        (("ash.awslabs.github.io",), ("ashmcpservers/status", "ashscans/status"), ("get", "patch")),
        (("batch",), ("jobs",), ("create", "delete", "get", "list", "watch")),
        (("",), ("pods",), ("get", "list", "watch")),
        (("",), ("configmaps",), ("create", "delete", "get", "list", "watch")),
        (("",), ("persistentvolumeclaims",), ("create", "delete", "get", "list", "watch")),
        (("",), ("events",), ("create",)),
        (("events.k8s.io",), ("events",), ("create",)),
        (("apps",), ("deployments",), ("create", "get", "list", "patch", "watch")),
        (("",), ("services",), ("create", "get", "list", "patch", "watch")),
    ],
}

# A binding widens an account without touching any rule above: binding the
# operator's account to a built-in ClusterRole such as `edit` would leave every rule
# pinned and every denylist test green. So the bindings are pinned too, as
# (kind/name, namespace, roleRef kind/name, sorted subjects).
EXPECTED_BINDINGS = {
    (
        "ClusterRoleBinding/ash-operator-crd-reader",
        None,
        "ClusterRole/ash-operator-crd-reader",
        (("ServiceAccount", "ash-operator", "ash-system"),),
    ),
    (
        "RoleBinding/ash-operator",
        "ash-system",
        "Role/ash-operator",
        (("ServiceAccount", "ash-operator", "ash-system"),),
    ),
}

RULE_KEYS = {"apiGroups", "resources", "verbs"}
ROLE_KINDS = ("Role", "ClusterRole")
# Every top-level key a reviewed role may carry. The rule pin compares `rules` alone,
# and a key beside it can change what the role grants without touching them:
# aggregationRule makes the API server overwrite `rules` with the union of every
# ClusterRole its selectors match, which with the built-in roles' label is
# cluster-admin.
ROLE_KEYS = frozenset({"apiVersion", "kind", "metadata", "rules"})
# The labels each reviewed role carries, exactly. A label is how aggregation finds a
# role: rbac.authorization.k8s.io/aggregate-to-admin folds its rules into the
# built-in admin role, and any label can match some other aggregated ClusterRole's
# selector, so none is added without re-pinning here.
EXPECTED_ROLE_LABELS: dict[ObjectKey, dict[str, str]] = {owner: {} for owner in EXPECTED_RULES}
RBAC_KINDS = frozenset({"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"})

# `kubectl apply -f manifests/` reads every file in the directory (not its
# subdirectories) whose name ends in one of these, so all of them are manifests.
KUBECTL_SUFFIXES = (".json", ".yaml", ".yml")
# Everything manifests/ may hold, as reviewed. A new file is a new set of objects
# the adopter applies, so adding one changes this set in the same diff.
EXPECTED_MANIFEST_FILES = frozenset({"operator.yaml", "rbac.yaml"})

# Every object `kubectl apply -f manifests/` creates, as reviewed. The binding pin
# above names the account it grants to; this names everything that could run as an
# account or carry its credential, so a Pod in kube-system running as a controller's
# account, or a token Secret for the operator's, is a change to this set.
EXPECTED_OBJECTS: frozenset[ObjectKey] = frozenset(
    {
        ("Namespace", None, OPERATOR_NAMESPACE),
        OPERATOR_DEPLOYMENT,
        ("ServiceAccount", OPERATOR_NAMESPACE, OPERATOR_ACCOUNT),
        ("ServiceAccount", OPERATOR_NAMESPACE, SCAN_ACCOUNT),
        # Denies ingress to the operator pod; grants nothing to anyone.
        ("NetworkPolicy", OPERATOR_NAMESPACE, "ash-operator-ingress"),
        *EXPECTED_RULES,
        ("ClusterRoleBinding", None, "ash-operator-crd-reader"),
        ("RoleBinding", OPERATOR_NAMESPACE, "ash-operator"),
    }
)
# Kinds that run a container, and so run as some ServiceAccount. Only the operator
# Deployment may appear; the scan pods are created by the operator, not shipped.
WORKLOAD_KINDS = frozenset(
    {
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
        "CronJob",
    }
)
REVIEWED_WORKLOADS = frozenset({OPERATOR_DEPLOYMENT})


def _json_documents(text: str) -> list:
    # kubectl decodes a .json file as a stream, so it may hold several objects back
    # to back. json.loads would reject that and hide every object after the first.
    decoder = json.JSONDecoder()
    docs = []
    rest = text.lstrip()
    while rest:
        doc, end = decoder.raw_decode(rest)
        docs.append(doc)
        rest = rest[end:].lstrip()
    return docs


def _flatten(doc: dict, path: Path) -> list[dict]:
    # kubectl expands a List (kind List, or any <Kind>List) client-side and applies
    # each item, so a ClusterRoleBinding inside one grants as much as a top-level one.
    assert isinstance(doc, dict), f"{path.name}: a document is not a mapping: {doc!r}"
    if str(doc.get("kind", "")).endswith("List") or "items" in doc:
        return [item for child in doc.get("items") or [] for item in _flatten(child, path)]
    return [doc]


def manifest_documents(manifests_dir: Path = MANIFESTS_DIR) -> list[tuple[Path, dict]]:
    # Every object `kubectl apply -f manifests/` would send, not only rbac.yaml's.
    # Adopters and the e2e apply the whole directory, so a ClusterRoleBinding in
    # operator.yaml, in a .yml or .json file, or wrapped in a List grants exactly as
    # much as one in rbac.yaml and has to be caught by the same pin.
    paths = sorted(
        path
        for path in manifests_dir.iterdir()
        if path.is_file() and path.suffix in KUBECTL_SUFFIXES
    )
    assert manifests_dir / "rbac.yaml" in paths, f"{manifests_dir / 'rbac.yaml'} is missing"
    docs = []
    for path in paths:
        text = path.read_text()
        raw = _json_documents(text) if path.suffix == ".json" else list(yaml.safe_load_all(text))
        docs.extend((path, obj) for doc in raw if doc for obj in _flatten(doc, path))
    assert docs, "manifests/ yielded no documents"
    return docs


def rbac_documents(manifests_dir: Path = MANIFESTS_DIR) -> list[dict]:
    return [doc for _, doc in manifest_documents(manifests_dir)]


def object_key(doc: dict) -> ObjectKey:
    metadata = doc.get("metadata") or {}
    return (doc.get("kind"), metadata.get("namespace"), metadata.get("name"))


def describe(key: ObjectKey) -> str:
    kind, namespace, name = key
    return f"{kind}/{namespace}/{name}" if namespace else f"{kind}/{name}"


def _as_rule(rule: dict) -> Rule:
    return tuple(tuple(sorted(rule.get(key) or [])) for key in ("apiGroups", "resources", "verbs"))


def rbac_rules() -> list[tuple[str, dict]]:
    rules = [
        (describe(object_key(doc)), rule)
        for doc in rbac_documents()
        if doc["kind"] in ("Role", "ClusterRole")
        for rule in doc.get("rules") or []
    ]
    assert rules, "manifests/ yielded no rules, so the checks below would pass vacuously"
    return rules


def test_rbac_objects_live_only_in_rbac_yaml():
    # The pin below reads every manifest, so this is not what catches a widening. It
    # keeps the grants in the one file whose comments give the reason for each, so a
    # reviewer reading rbac.yaml is reading all of them.
    stray = [
        f"{path.name}: {doc['kind']}/{doc['metadata'].get('name')}"
        for path, doc in manifest_documents()
        if doc.get("kind") in RBAC_KINDS and path != RBAC_YAML
    ]
    assert not stray, f"RBAC objects outside rbac.yaml: {stray}"


def role_problems(docs: list[dict]) -> list[str]:
    problems = []
    actual: dict[ObjectKey, list[Rule]] = {}
    for doc in docs:
        if doc["kind"] not in ROLE_KINDS:
            continue
        key = object_key(doc)
        owner = describe(key)
        if key in actual:
            # kubectl applies both and the later one wins, so which grant reaches the
            # cluster depends on file order. Refused rather than resolved either way.
            problems.append(f"{owner} is defined more than once in manifests/")
        extra = set(doc) - ROLE_KEYS
        if extra:
            problems.append(f"{owner} carries {sorted(extra)} beside its rules: {doc}")
        labels = doc["metadata"].get("labels") or {}
        if labels != EXPECTED_ROLE_LABELS.get(key, {}):
            problems.append(f"{owner} has labels {labels}, not the reviewed ones")
        for rule in doc.get("rules") or []:
            # Only the three pinned keys. resourceNames or nonResourceURLs would change
            # what the rule means without changing the tuple compared below.
            if set(rule) != RULE_KEYS:
                problems.append(f"{owner} has a rule with keys {sorted(rule)}: {rule}")
        actual[key] = sorted(_as_rule(rule) for rule in doc.get("rules") or [])
    expected = {key: sorted(rules) for key, rules in EXPECTED_RULES.items()}
    for key in sorted(actual.keys() | expected.keys(), key=repr):
        if actual.get(key) != expected.get(key):
            problems.append(
                f"{describe(key)}: the grants differ from the reviewed pin. If the change is "
                "intended, update EXPECTED_RULES in the same commit and say why in rbac.yaml: "
                f"reviewed {expected.get(key)}, found {actual.get(key)}"
            )
    return problems


def test_every_rule_is_exactly_the_reviewed_rule():
    problems = role_problems(rbac_documents())
    assert not problems, "\n".join(problems)


def actual_bindings(docs: list[dict]) -> set:
    actual = set()
    for doc in docs:
        if doc["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        ref = doc["roleRef"]
        subjects = tuple(
            sorted(
                (subject["kind"], subject["name"], subject.get("namespace"))
                for subject in doc.get("subjects") or []
            )
        )
        actual.add(
            (
                f"{doc['kind']}/{doc['metadata']['name']}",
                doc["metadata"].get("namespace"),
                f"{ref['kind']}/{ref['name']}",
                subjects,
            )
        )
    return actual


def test_every_binding_is_exactly_the_reviewed_binding():
    assert actual_bindings(rbac_documents()) == EXPECTED_BINDINGS


def object_problems(docs: list[dict]) -> list[str]:
    problems = []
    keys = [object_key(doc) for doc in docs]
    for key, count in sorted(Counter(keys).items(), key=repr):
        if count > 1:
            problems.append(f"{describe(key)} is defined more than once in manifests/")
    for doc, key in zip(docs, keys, strict=True):
        # Named outright rather than left to the set pin below: a Secret here is a
        # credential committed to the repository, or a service-account-token Secret
        # that mints a token for whatever account its annotation names. Neither is
        # re-pinned.
        if key[0] == "Secret":
            problems.append(f"{describe(key)}: manifests/ must not ship a Secret: {doc}")
        elif key[0] in WORKLOAD_KINDS and key not in REVIEWED_WORKLOADS:
            # A workload runs as the account in its pod spec, in whatever namespace it
            # names, so any account in the cluster is reachable from here.
            problems.append(f"{describe(key)}: a workload other than the operator's: {doc}")
    unexpected = set(keys) ^ EXPECTED_OBJECTS
    if unexpected:
        problems.append(
            "manifests/ objects differ from EXPECTED_OBJECTS: "
            + ", ".join(
                f"{'unreviewed' if key in keys else 'missing'} {describe(key)}"
                for key in sorted(unexpected, key=repr)
            )
        )
    operators = [doc for doc, key in zip(docs, keys, strict=True) if key == OPERATOR_DEPLOYMENT]
    if not operators:
        problems.append(
            f"no Deployment ash-operator in namespace {OPERATOR_NAMESPACE}: the bindings are "
            f"pinned to {OPERATOR_NAMESPACE}/{OPERATOR_ACCOUNT}, so the operator must run there"
        )
    for doc in operators:
        pod = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
        # serviceAccount is the deprecated alias; the API server honors it when
        # serviceAccountName is empty, so it is held to the same value.
        for field in ("serviceAccountName", "serviceAccount"):
            if field in pod and pod[field] != OPERATOR_ACCOUNT:
                problems.append(
                    f"{describe(OPERATOR_DEPLOYMENT)} runs as {field}={pod[field]!r}, not "
                    f"{OPERATOR_ACCOUNT!r}, the account every binding is pinned to"
                )
        if pod.get("serviceAccountName") != OPERATOR_ACCOUNT:
            problems.append(
                f"{describe(OPERATOR_DEPLOYMENT)} does not set serviceAccountName: "
                f"{OPERATOR_ACCOUNT}"
            )
    scan_accounts = [
        doc
        for doc, key in zip(docs, keys, strict=True)
        if key == ("ServiceAccount", OPERATOR_NAMESPACE, SCAN_ACCOUNT)
    ]
    for doc in scan_accounts:
        # The pods the operator creates set this false themselves. Pinned on the
        # account too, so a pod that names ash-scan without the field gets no token.
        if doc.get("automountServiceAccountToken") is not False:
            problems.append(
                f"{describe(object_key(doc))} has automountServiceAccountToken="
                f"{doc.get('automountServiceAccountToken')!r}, not false"
            )
    return problems


def test_every_object_is_exactly_the_reviewed_object():
    problems = object_problems(rbac_documents())
    assert not problems, "\n".join(problems)


def pin_problems(manifests_dir: Path) -> list[str]:
    # Everything the exact pins above refuse, for a manifests directory other than
    # the committed one, so the tests below can break a copy and watch it fail.
    docs = rbac_documents(manifests_dir)
    problems = role_problems(docs) + object_problems(docs)
    unexpected = actual_bindings(docs) ^ EXPECTED_BINDINGS
    if unexpected:
        problems.append(f"bindings differ from the reviewed pin: {sorted(map(repr, unexpected))}")
    return problems


def test_manifests_dir_holds_only_the_reviewed_files():
    # Hidden files and subdirectories too: neither is applied today, but a file a
    # reviewer did not expect is the place a grant would hide.
    present = {path.name for path in MANIFESTS_DIR.iterdir()}
    assert present == EXPECTED_MANIFEST_FILES, (
        f"manifests/ holds {sorted(present - EXPECTED_MANIFEST_FILES)} unreviewed and "
        f"lacks {sorted(EXPECTED_MANIFEST_FILES - present)}"
    )


ADMIN_BINDING = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRoleBinding",
    "metadata": {"name": "ash-operator-admin"},
    "roleRef": {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "ClusterRole",
        "name": "cluster-admin",
    },
    "subjects": [{"kind": "ServiceAccount", "name": "ash-operator", "namespace": "ash-system"}],
}
ADMIN_ENTRY = (
    "ClusterRoleBinding/ash-operator-admin",
    None,
    "ClusterRole/cluster-admin",
    (("ServiceAccount", "ash-operator", "ash-system"),),
)


def _write_admin_yml(d: Path) -> None:
    (d / "extra.yml").write_text(yaml.safe_dump(ADMIN_BINDING))


def _write_admin_json(d: Path) -> None:
    # Two objects back to back, the binding second, as kubectl's stream decoder allows.
    namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "x"}}
    (d / "extra.json").write_text(json.dumps(namespace) + "\n" + json.dumps(ADMIN_BINDING))


def _append_admin_list(d: Path) -> None:
    wrapped = {"apiVersion": "v1", "kind": "List", "items": [ADMIN_BINDING]}
    with (d / "operator.yaml").open("a") as handle:
        handle.write("---\n" + yaml.safe_dump(wrapped))


def _append_admin_typed_list(d: Path) -> None:
    wrapped = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBindingList",
        "items": [{"apiVersion": "v1", "kind": "List", "items": [ADMIN_BINDING]}],
    }
    with (d / "operator.yaml").open("a") as handle:
        handle.write("---\n" + yaml.safe_dump(wrapped))


def _edit_crd_reader(d: Path, edit) -> None:
    # Rewrites rbac.yaml with one change to the ClusterRole bound to the operator.
    # The rewrite drops the file's comments, which nothing here reads.
    path = d / "rbac.yaml"
    docs = [doc for doc in yaml.safe_load_all(path.read_text()) if doc]
    (role,) = [
        doc
        for doc in docs
        if doc["kind"] == "ClusterRole" and doc["metadata"]["name"] == "ash-operator-crd-reader"
    ]
    edit(role)
    path.write_text(yaml.safe_dump_all(docs))


def _add_aggregation_rule(d: Path) -> None:
    # The API server's aggregation controller overwrites `rules` with the union of
    # every ClusterRole the selectors match. This selector matches the built-in
    # roles, cluster-admin among them, and `rules` in the file stays as reviewed.
    selector = {"matchLabels": {"kubernetes.io/bootstrapping": "rbac-defaults"}}
    _edit_crd_reader(
        d, lambda role: role.update(aggregationRule={"clusterRoleSelectors": [selector]})
    )


def _add_aggregate_to_label(d: Path) -> None:
    # The other direction: this label folds the role's rules into the built-in
    # `admin` role, widening every account bound to admin rather than the operator's.
    _edit_crd_reader(
        d,
        lambda role: (
            role["metadata"]
            .setdefault("labels", {})
            .update({"rbac.authorization.k8s.io/aggregate-to-admin": "true"})
        ),
    )


def _replace(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert text.count(old) == 1, (path, old)
    path.write_text(text.replace(old, new))


def _append(path: Path, doc: dict) -> None:
    with path.open("a") as handle:
        handle.write("---\n" + yaml.safe_dump(doc))


def _widen_role_behind_a_same_name_decoy(d: Path) -> None:
    # The real Role gains pods/create, which lets the operator run a pod as any
    # account in ash-system. A copy of the reviewed Role in another namespace,
    # placed after it, is what a pin keyed by kind and name alone compared instead.
    path = d / "rbac.yaml"
    docs = [doc for doc in yaml.safe_load_all(path.read_text()) if doc]
    (role,) = [doc for doc in docs if object_key(doc) == ("Role", "ash-system", "ash-operator")]
    decoy = json.loads(json.dumps(role))
    decoy["metadata"]["namespace"] = "default"
    (pods,) = [rule for rule in role["rules"] if rule["resources"] == ["pods"]]
    pods["verbs"].append("create")
    path.write_text(yaml.safe_dump_all([*docs, decoy]))


def _duplicate_the_role(d: Path) -> None:
    path = d / "rbac.yaml"
    docs = [doc for doc in yaml.safe_load_all(path.read_text()) if doc]
    (role,) = [doc for doc in docs if object_key(doc) == ("Role", "ash-system", "ash-operator")]
    path.write_text(yaml.safe_dump_all([*docs, role]))


def _run_operator_as_default(d: Path) -> None:
    _replace(d / "operator.yaml", "serviceAccountName: ash-operator", "serviceAccountName: default")


def _move_operator_to_kube_system(d: Path) -> None:
    # kube-system holds controller accounts with wide built-in grants, so the
    # Deployment there can run as one of them while every binding stays as pinned.
    _replace(
        d / "operator.yaml",
        "  name: ash-operator\n  namespace: ash-system\n",
        "  name: ash-operator\n  namespace: kube-system\n",
    )
    _replace(
        d / "operator.yaml",
        "serviceAccountName: ash-operator",
        "serviceAccountName: clusterrole-aggregation-controller",
    )


def _add_pod_in_kube_system(d: Path) -> None:
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "ash-helper", "namespace": "kube-system"},
        "spec": {
            "serviceAccountName": "generic-garbage-collector",
            "containers": [{"name": "c", "image": "ash-operator:local"}],
        },
    }
    _append(d / "operator.yaml", pod)


def _add_operator_token_secret(d: Path) -> None:
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "kubernetes.io/service-account-token",
        "metadata": {
            "name": "ash-operator-token",
            "namespace": "ash-system",
            "annotations": {"kubernetes.io/service-account.name": "ash-operator"},
        },
    }
    _append(d / "rbac.yaml", secret)


def _automount_the_scan_token(d: Path) -> None:
    _replace(
        d / "rbac.yaml",
        "automountServiceAccountToken: false",
        "automountServiceAccountToken: true",
    )


def test_the_pin_is_clean_on_an_untouched_copy(tmp_path):
    # The control for the test below: copying the directory alone changes nothing.
    shutil.copytree(MANIFESTS_DIR, tmp_path / "manifests")
    assert pin_problems(tmp_path / "manifests") == []


@pytest.mark.parametrize(
    ("inject", "marker"),
    [
        (_write_admin_yml, "ClusterRoleBinding/ash-operator-admin"),
        (_write_admin_json, "ClusterRoleBinding/ash-operator-admin"),
        (_append_admin_list, "ClusterRoleBinding/ash-operator-admin"),
        (_append_admin_typed_list, "ClusterRoleBinding/ash-operator-admin"),
        (_add_aggregation_rule, "aggregationRule"),
        (_add_aggregate_to_label, "rbac.authorization.k8s.io/aggregate-to-admin"),
        (_widen_role_behind_a_same_name_decoy, "Role/ash-system/ash-operator: the grants differ"),
        (_duplicate_the_role, "Role/ash-system/ash-operator is defined more than once"),
        (_run_operator_as_default, "serviceAccountName='default'"),
        (_move_operator_to_kube_system, "no Deployment ash-operator in namespace ash-system"),
        (_add_pod_in_kube_system, "Pod/kube-system/ash-helper: a workload other than"),
        (_add_operator_token_secret, "must not ship a Secret"),
        (_automount_the_scan_token, "automountServiceAccountToken=True"),
    ],
    ids=[
        "yml-file",
        "json-stream",
        "list-in-operator-yaml",
        "nested-typed-list",
        "aggregation-rule",
        "aggregate-to-label",
        "same-name-other-namespace",
        "duplicate-role",
        "operator-as-default",
        "operator-in-kube-system",
        "pod-in-kube-system",
        "token-secret",
        "scan-account-automount",
    ],
)
def test_the_pin_refuses_a_widening_however_kubectl_would_read_it(tmp_path, inject, marker):
    # Each of these widens a grant through `kubectl apply -f manifests/`, and each
    # once left every test in this file green.
    shutil.copytree(MANIFESTS_DIR, tmp_path / "manifests")
    inject(tmp_path / "manifests")
    problems = pin_problems(tmp_path / "manifests")
    assert any(marker in problem for problem in problems), problems


def test_the_scan_account_has_no_binding():
    # ash-scan runs third-party scanners over foreign source. It exists so those pods
    # do not run as `default`, and holds no grant at all.
    for doc in rbac_documents():
        for subject in doc.get("subjects") or []:
            assert subject.get("name") != "ash-scan", f"{doc['kind']} binds ash-scan: {doc}"


@pytest.mark.parametrize("field", ["apiGroups", "resources", "verbs", "resourceNames"])
def test_no_wildcard_anywhere(field):
    for owner, rule in rbac_rules():
        assert "*" not in (rule.get(field) or []), f"{owner} has '*' in {field}: {rule}"


def test_no_non_resource_urls():
    for owner, rule in rbac_rules():
        assert "nonResourceURLs" not in rule, f"{owner} grants nonResourceURLs: {rule}"


def test_no_forbidden_resource_is_granted():
    for owner, rule in rbac_rules():
        hit = FORBIDDEN_RESOURCES & set(rule.get("resources") or [])
        assert not hit, f"{owner} grants {sorted(hit)}: {rule}"


def test_no_rbac_api_group_at_all():
    for owner, rule in rbac_rules():
        assert "rbac.authorization.k8s.io" not in (rule.get("apiGroups") or []), (
            f"{owner} has a rule on the RBAC API group: {rule}"
        )


def test_no_privilege_granting_verb():
    for owner, rule in rbac_rules():
        hit = FORBIDDEN_VERBS & set(rule.get("verbs") or [])
        assert not hit, f"{owner} grants {sorted(hit)}: {rule}"


def test_the_source_schema_offers_exactly_the_reviewed_volume_types():
    # hostPath would hand the node's filesystem to a pod running third-party
    # scanners over foreign code; emptyDir describes a tree nothing populated,
    # which scans clean. Neither is offered, and nothing new is either.
    schema = _source_volume_schema()
    assert set(schema["properties"]) == SOURCE_VOLUME_KEYS
    # A structural schema prunes unknown members only when this is absent.
    assert not schema.get("x-kubernetes-preserve-unknown-fields")


def test_the_committed_crd_carries_the_same_source_schema():
    crd = yaml.safe_load(SCAN_CRD.read_text())
    (version,) = crd["spec"]["versions"]
    source = version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["source"]
    assert set(source["properties"]) == SOURCE_VOLUME_KEYS
    assert not source.get("x-kubernetes-preserve-unknown-fields")
