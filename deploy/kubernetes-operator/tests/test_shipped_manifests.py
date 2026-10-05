"""The hand-written manifests under ``manifests/``, and the image they assume.

Everything else in this suite tests the *builders*. These two files are hand-written, so
nothing checked them at all until a sibling lane building the same Deployment in CDK
added a runtime check that the name inside ``$(...)`` matches the env var's name -- and
asking the same question here showed no test read ``manifests/operator.yaml``.

The failure it guards against does not error. Kubernetes expands ``$(VAR)`` in ``args``
only against variables defined in that container's own ``env``; an unresolvable
reference is passed through **verbatim**. So renaming the env var and not the reference
makes kopf watch a namespace literally called ``$(WATCH_NAMESPACE)``, which 403s or
matches nothing, and the operator starts, reports healthy and reconciles nothing.

The argument has to be there at all for a separate measured reason. ``--standalone`` is
in the image's ENTRYPOINT but ``--namespace`` is not, and kopf given neither ``-n`` nor
``-A`` does not default to the pod's namespace -- it warns and switches to cluster-wide,
where every watcher 403s against the namespaced Role. Measured in kind with ``args`` and
``env`` stripped: the AshScan still reached ``phase: Scanning`` with its shard Job
``Complete 3/3``, then hung with no collector and no verdict. A scan that appears to be
working is the worst available failure, so both halves are pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

OPERATOR_DIR = Path(__file__).resolve().parents[1]
OPERATOR_YAML = OPERATOR_DIR / "manifests" / "operator.yaml"
DOCKERFILE = OPERATOR_DIR / "Dockerfile"

# Kubernetes' own substitution syntax for env vars in command/args.
VAR_REFERENCE = re.compile(r"^\$\((?P<name>[A-Za-z_][A-Za-z0-9_]*)\)$")


def namespace_argument(container: dict) -> str:
    """Return the value following ``--namespace``, or fail saying what is missing.

    Shared so no caller reaches it via ``args.index("--namespace")``, which raises a
    bare ``ValueError`` when the flag is absent. That is the correct verdict arrived at
    by accident: the test fails, and the reader gets `'--namespace' is not in list`
    instead of the reason a missing namespace matters.
    """
    args = container.get("args") or []
    assert "--namespace" in args, (
        f"no --namespace in args ({args!r}). kopf given neither -n nor -A warns and "
        f"switches to cluster-wide, where every watcher 403s against the namespaced "
        f"Role -- measured: the scan reaches phase Scanning with its shards Complete "
        f"3/3 and then hangs with no collector and no verdict."
    )
    index = args.index("--namespace")
    assert index + 1 < len(args), (
        f"--namespace is the last element of args ({args!r}), so it has no value. kopf "
        f"would reject the flag at startup and the pod would crash-loop."
    )
    return args[index + 1]


@pytest.fixture(scope="module")
def operator_container() -> dict:
    docs = [d for d in yaml.safe_load_all(OPERATOR_YAML.read_text()) if d]
    deployments = [d for d in docs if d["kind"] == "Deployment"]
    assert len(deployments) == 1, f"expected one Deployment, found {len(deployments)}"
    containers = deployments[0]["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1, f"expected one container, found {len(containers)}"
    return containers[0]


@pytest.fixture(scope="module")
def entrypoint() -> list[str]:
    match = re.search(r"^ENTRYPOINT\s+(\[[^\]]*\])", DOCKERFILE.read_text(), re.M)
    assert match, f"no ENTRYPOINT found in {DOCKERFILE}"
    import json

    return json.loads(match.group(1))


class TestImageEntrypoint:
    def test_it_runs_kopf_against_the_operator_module(self, entrypoint):
        assert entrypoint[:2] == ["kopf", "run"]
        assert "-m" in entrypoint
        assert entrypoint[entrypoint.index("-m") + 1] == "ash_operator.main"

    def test_it_is_standalone(self, entrypoint):
        # Peering disabled, which is why no leases grant is in rbac.yaml. If this ever
        # changes, that grant has to come back in the same commit.
        assert "--standalone" in entrypoint

    def test_it_carries_no_namespace_of_its_own(self, entrypoint):
        # The reason the Deployment must supply one. If a --namespace ever appears here
        # it would be baked into the image and could not follow the pod.
        assert "--namespace" not in entrypoint
        assert "-n" not in entrypoint
        assert "--all-namespaces" not in entrypoint
        assert "-A" not in entrypoint


class TestOperatorDeployment:
    def test_command_is_not_set(self, operator_container):
        # `command` replaces the ENTRYPOINT. Setting it would discard
        # `kopf run --standalone -m ash_operator.main` entirely and exec whatever was
        # given instead.
        assert "command" not in operator_container, (
            "setting command: discards the image's ENTRYPOINT, so kopf never runs"
        )

    def test_args_pin_a_namespace(self, operator_container):
        # The message lives in namespace_argument, so every caller gets it rather than
        # only this one.
        assert namespace_argument(operator_container)

    def test_the_variable_reference_names_a_variable_that_exists(self, operator_container):
        """The check a sibling lane added in CDK, asked of this file.

        An unresolvable ``$(VAR)`` is not an error -- the kubelet passes it through, and
        kopf watches a namespace literally named ``$(WATCH_NAMESPACE)``.
        """
        value = namespace_argument(operator_container)
        match = VAR_REFERENCE.match(value)
        assert match, (
            f"--namespace is {value!r}. Expected a $(VAR) reference so the namespace "
            f"follows the pod rather than being hard-coded."
        )
        declared = {e["name"] for e in operator_container.get("env", [])}
        assert match.group("name") in declared, (
            f"args reference $({match.group('name')}) but the container declares "
            f"{sorted(declared)}. Kubernetes expands $(VAR) only against this "
            f"container's own env and passes an unresolvable reference through "
            f"verbatim, so kopf would watch a namespace literally called {value!r} and "
            f"reconcile nothing while reporting healthy."
        )

    def test_the_namespace_comes_from_the_downward_api(self, operator_container):
        value = namespace_argument(operator_container)
        match = VAR_REFERENCE.match(value)
        # Asserted rather than extracted-and-hoped. `VAR_REFERENCE.match(...).group(...)`
        # raises AttributeError on a literal value, which fails the test with a bare
        # `'NoneType' object has no attribute 'group'` -- the right verdict reached with
        # none of the reasoning. Every other assertion in this file explains its
        # consequence; a traceback from an incidental exception does not, and the reader
        # who hits it is the one who most needs the explanation.
        assert match, (
            f"--namespace is {value!r}, not a $(VAR) reference, so there is no env var "
            f"for this test to trace. A literal namespace pins the manifest to one "
            f"install; see test_the_variable_reference_names_a_variable_that_exists."
        )
        name = match.group("name")
        entries = [e for e in operator_container.get("env", []) if e["name"] == name]
        assert entries, (
            f"args reference $({name}) but no env var of that name is declared. "
            f"Kubernetes passes an unresolvable reference through verbatim, so kopf "
            f"would watch a namespace literally called {value!r}."
        )
        entry = entries[0]
        assert entry.get("valueFrom", {}).get("fieldRef", {}).get("fieldPath") == (
            "metadata.namespace"
        ), (
            f"{name} should come from a fieldRef on metadata.namespace, so one manifest "
            f"works in any namespace. Got {entry!r}."
        )
        assert "value" not in entry, "a literal namespace pins this manifest to one install"

    def test_every_env_var_referenced_in_args_is_declared(self, operator_container):
        # Generalised: any future $(VAR) in args is held to the same rule, not just the
        # namespace one.
        declared = {e["name"] for e in operator_container.get("env", [])}
        referenced = {
            m.group(1)
            for arg in operator_container.get("args", [])
            for m in re.finditer(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)", str(arg))
        }
        assert referenced <= declared, (
            f"args reference undeclared env var(s) {sorted(referenced - declared)}; "
            f"Kubernetes passes those through literally rather than failing."
        )


class TestRbacAndEntrypointAgree:
    def test_no_leases_grant_while_the_entrypoint_is_standalone(self, entrypoint):
        """The two files have to agree, and nothing else checks that they do.

        A leases grant with `--standalone` is a permission with no consumer; dropping
        `--standalone` without the grant makes kopf fail to create its own lease. Either
        state is defensible, shipping the mismatch is not -- and the mismatch is what
        shipped, which is how this test came to exist.
        """
        rules = [
            rule
            for doc in yaml.safe_load_all((OPERATOR_DIR / "manifests" / "rbac.yaml").read_text())
            if doc and doc["kind"] in ("Role", "ClusterRole")
            for rule in doc["rules"]
        ]
        grants_leases = any(
            "coordination.k8s.io" in rule["apiGroups"] and "leases" in rule["resources"]
            for rule in rules
        )
        standalone = "--standalone" in entrypoint
        assert not (standalone and grants_leases), (
            "rbac.yaml grants coordination.k8s.io/leases while the ENTRYPOINT is "
            "--standalone, which disables peering -- so nothing can ever create one."
        )
        assert standalone or grants_leases, (
            "the ENTRYPOINT is not --standalone, so kopf will try to create a peering "
            "Lease, but rbac.yaml does not grant coordination.k8s.io/leases."
        )

    def test_the_deployment_does_not_claim_leader_election_while_standalone(self, entrypoint):
        # operator.yaml once said "One replica plus leader election" beside an
        # ENTRYPOINT that disables peering and an RBAC file with no leases grant. A
        # reader sizing replicas from that comment would get two dispatchers.
        if "--standalone" in entrypoint:
            text = OPERATOR_YAML.read_text().lower()
            assert "leader election" not in text
            assert "peering keeps" not in text
