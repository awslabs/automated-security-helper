"""The shapes the controller applies, and the properties that make them safe."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

from ash_operator import manifests
from ash_operator.constants import (
    CONFIG_PATH,
    JOB_COMPLETION_INDEX_LABEL,
    OUTPUT_MOUNT,
    SOURCE_MOUNT,
)
from ash_operator.contract import build_scan_argv

SCAN = {
    "metadata": {
        "name": "demo",
        "namespace": "ash-system",
        "uid": "11111111-2222-3333-4444-555555555555",
    }
}
SPEC = {
    "image": "ash:local",
    "shardCount": 3,
    "source": {"persistentVolumeClaim": {"claimName": "src", "readOnly": True}},
    "minSeverity": "MEDIUM",
}
PREFIX = "/workspace/results/run-11111111-2222-3333-4444-555555555555"
RBAC_YAML = Path(__file__).resolve().parents[1] / "manifests" / "rbac.yaml"


def shard_job(spec=None, **kwargs):
    return manifests.build_shard_job(
        scan=SCAN,
        spec={**SPEC, **(spec or {})},
        configmap_name="demo-run-abc",
        has_config=kwargs.pop("has_config", True),
        results_prefix=PREFIX,
        results_claim_name="demo-results",
        **kwargs,
    )


def collect_job(spec=None, **kwargs):
    return manifests.build_collect_job(
        scan=SCAN,
        spec={**SPEC, **(spec or {})},
        configmap_name="demo-run-abc",
        has_config=kwargs.pop("has_config", True),
        results_prefix=PREFIX,
        results_claim_name="demo-results",
        merge_output=f"{PREFIX}/merged",
        **kwargs,
    )


class TestRunConfigMap:
    def test_it_is_immutable(self):
        # The structural fix for the split-brain roster case: the kubelet re-syncs a
        # mounted ConfigMap into running pods, so a mutable one lets shard 0
        # partition a different roster from its siblings.
        cm = manifests.build_run_configmap(scan=SCAN, ash_config={"project_name": "p"})
        assert cm["immutable"] is True

    def test_the_name_is_content_addressed(self):
        a = manifests.build_run_configmap(scan=SCAN, ash_config={"project_name": "a"})
        b = manifests.build_run_configmap(scan=SCAN, ash_config={"project_name": "b"})
        assert a["metadata"]["name"] != b["metadata"]["name"]
        again = manifests.build_run_configmap(scan=SCAN, ash_config={"project_name": "a"})
        assert a["metadata"]["name"] == again["metadata"]["name"]

    def test_no_config_means_no_config_file(self):
        # Pointing ASH_CONFIG at a missing path makes ASH log a missing-config
        # notice on every scan, which reads like a failure in a log someone is
        # searching for a real one.
        cm = manifests.build_run_configmap(scan=SCAN, ash_config=None)
        assert ".ash.yaml" not in cm["data"]

    def test_the_config_round_trips_as_yaml(self):
        config = {"global_settings": {"severity_threshold": "HIGH"}, "project_name": "p"}
        cm = manifests.build_run_configmap(scan=SCAN, ash_config=config)
        assert yaml.safe_load(cm["data"][".ash.yaml"]) == config

    def test_it_carries_the_collector_modules_not_a_second_copy(self):
        # The collector imports ash_operator.attempts -- the same file the unit
        # tests above exercise. A re-implementation in shell would have put the one
        # piece of genuinely new logic where nothing tests it.
        cm = manifests.build_run_configmap(scan=SCAN, ash_config=None)
        assert "_attempts.py" in cm["data"]
        assert "_constants.py" in cm["data"]
        assert "collect.py" in cm["data"]
        assert "def resolve_shard_set" in cm["data"]["_attempts.py"]

    def test_the_shipped_attempts_module_is_byte_identical_to_the_repo_copy(self):
        from pathlib import Path

        import ash_operator.attempts as attempts_module

        cm = manifests.build_run_configmap(scan=SCAN, ash_config=None)
        on_disk = Path(attempts_module.__file__).read_text(encoding="utf-8")
        assert cm["data"]["_attempts.py"] == on_disk


class TestShardJob:
    def test_indexed_with_matching_completions(self):
        job = shard_job()
        assert job["spec"]["completionMode"] == "Indexed"
        assert job["spec"]["completions"] == 3
        assert job["spec"]["parallelism"] == 3

    def test_backoff_limit_defaults_to_zero(self):
        assert shard_job()["spec"]["backoffLimit"] == 0

    def test_a_retry_may_be_enabled_because_publication_is_attempt_qualified(self):
        assert shard_job({"backoffLimit": 2})["spec"]["backoffLimit"] == 2

    def test_the_container_never_holds_an_api_token(self):
        # A pod running third-party scanners over foreign source has no business
        # holding an API credential, and nothing in the shard path calls the API.
        pod = shard_job()["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False

    def test_the_source_is_mounted_read_only(self):
        mounts = shard_job()["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        source = next(m for m in mounts if m["mountPath"] == SOURCE_MOUNT)
        assert source["readOnly"] is True

    def test_output_is_not_inside_or_above_the_source(self):
        mounts = {
            m["mountPath"]
            for m in shard_job()["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        }
        assert SOURCE_MOUNT in mounts and OUTPUT_MOUNT in mounts
        assert not OUTPUT_MOUNT.startswith(SOURCE_MOUNT + "/")
        assert not SOURCE_MOUNT.startswith(OUTPUT_MOUNT + "/")

    def test_the_shard_integers_are_not_in_the_args(self):
        # They are appended by the entrypoint from the environment. A manifest-level
        # "$(JOB_COMPLETION_INDEX)" reference would resolve only against variables
        # defined earlier in the same container's env list, and the Job controller
        # appends that one.
        args = shard_job()["spec"]["template"]["spec"]["containers"][0]["args"]
        assert "--shard-index" not in args
        assert "--shard-count" not in args

    def test_the_composed_argv_equals_the_contract(self):
        """The Job args plus the entrypoint's append must equal build_scan_argv.

        Asserting only one half would let the two drift: the args could lose the
        source dir, or the entrypoint could stop appending the integers, and either
        test alone would still pass.
        """
        job = shard_job()
        args = job["spec"]["template"]["spec"]["containers"][0]["args"]
        entrypoint = manifests.build_run_configmap(scan=SCAN, ash_config=None)["data"][
            "shard-entrypoint.sh"
        ]
        appended = re.search(
            r'"\$@" --shard-index "\$\{ASH_SHARD_INDEX\}" --shard-count "\$\{ASH_SHARD_COUNT\}"',
            entrypoint,
        )
        assert appended, "the entrypoint no longer appends the two shard integers"
        composed = args + ["--shard-index", "2", "--shard-count", "3"]
        expected = build_scan_argv(
            source_dir=SOURCE_MOUNT,
            output_dir=OUTPUT_MOUNT,
            shard_index=2,
            shard_count=3,
        )
        # build_scan_argv puts the integers before the three trailing flags; the
        # entrypoint appends them at the end. Compare as multisets plus a check
        # that every flag/value pair survived.
        assert sorted(composed) == sorted(expected)
        for flag, value in (
            ("--source-dir", SOURCE_MOUNT),
            ("--output-dir", OUTPUT_MOUNT),
            ("--shard-index", "2"),
            ("--shard-count", "3"),
        ):
            assert composed[composed.index(flag) + 1] == value

    def test_ash_config_is_only_set_when_the_file_exists(self):
        with_config = shard_job(has_config=True)
        names = {
            e["name"]: e.get("value")
            for e in with_config["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert names["ASH_CONFIG"] == CONFIG_PATH
        without = shard_job(has_config=False)
        names = {e["name"] for e in without["spec"]["template"]["spec"]["containers"][0]["env"]}
        assert "ASH_CONFIG" not in names

    def test_the_attempt_identity_comes_from_the_pod_name(self):
        env = {
            e["name"]: e for e in shard_job()["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert env["ASH_POD_NAME"]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
        assert env["ASH_POD_UID"]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.uid"

    def test_the_security_context_drops_everything_it_can(self):
        ctx = shard_job()["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        assert ctx["allowPrivilegeEscalation"] is False
        assert ctx["capabilities"]["drop"] == ["ALL"]
        assert ctx["runAsNonRoot"] is True

    def test_read_only_root_filesystem_is_deliberately_absent(self):
        # Measured elsewhere in this stack: a read-only root makes a scanner whose
        # tool cannot write come back MISSING rather than failing, and with
        # fail_on_incomplete_scanners defaulting to False a MISSING scanner merges
        # into a report that reads as a complete scan. If this assertion is ever
        # flipped, the flip needs that measurement redone, not just a green suite.
        ctx = shard_job()["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        assert "readOnlyRootFilesystem" not in ctx

    def test_an_over_large_shard_count_is_refused(self):
        with pytest.raises(Exception, match="at most"):
            shard_job({"shardCount": 999})

    def test_children_are_owned_so_deletion_collects_them(self):
        job = shard_job()
        owner = job["metadata"]["ownerReferences"][0]
        assert owner["uid"] == SCAN["metadata"]["uid"]
        assert owner["controller"] is True
        # blockOwnerDeletion needs delete on the owner's finalizers, which a
        # security tool should not hold.
        assert "blockOwnerDeletion" not in owner


class TestCollectJob:
    def test_it_is_not_indexed(self):
        spec = collect_job()["spec"]
        assert "completionMode" not in spec
        assert "completions" not in spec

    def test_no_results_flags_are_baked_in(self):
        # The controller must not decide which shards exist: it would have to glob
        # or trust its own bookkeeping, and the collector's index walk is what turns
        # a short set into a named refusal.
        args = collect_job()["spec"]["template"]["spec"]["containers"][0]["args"]
        assert "--results" not in args

    def test_the_verdict_flags_are_passed_through_to_merge(self):
        args = collect_job({"failOnIncompleteScanners": True})["spec"]["template"]["spec"][
            "containers"
        ][0]["args"]
        assert "--min-severity" in args and "MEDIUM" in args
        assert "--fail-on-incomplete-scanners" in args

    def test_it_reports_through_the_termination_message(self):
        container = collect_job()["spec"]["template"]["spec"]["containers"][0]
        assert container["terminationMessagePath"] == "/dev/termination-log"
        assert container["terminationMessagePolicy"] == "File"

    def test_the_shard_count_reaches_the_collector(self):
        args = collect_job()["spec"]["template"]["spec"]["containers"][0]["args"]
        assert args[args.index("--shard-count") + 1] == "3"


class TestResultsPvc:
    def test_a_supplied_claim_means_no_pvc_is_created(self):
        assert (
            manifests.build_results_pvc(scan=SCAN, spec={**SPEC, "results": {"claimName": "mine"}})
            is None
        )

    def test_the_default_pvc_is_owned_by_the_scan(self):
        pvc = manifests.build_results_pvc(scan=SCAN, spec=SPEC)
        assert pvc["metadata"]["ownerReferences"][0]["uid"] == SCAN["metadata"]["uid"]


MCP = {"metadata": {"name": "mcp", "namespace": "ash-system", "uid": "abc-123"}}


AUTH_SPEC = {
    "image": "ash:local",
    "auth": {
        "headerName": "X-Ash-Token",
        "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}},
    },
}

# The exact string an earlier version of this operator handed to `ashx mcp` as the
# expected credential. Named once, so every test below refers to the same bytes.
BYPASS_LITERAL = "${ASH_MCP_AUTH_HEADER_VALUE}"


def mcp_deployment(spec=None):
    return manifests.build_mcp_deployment(
        server=MCP,
        spec=spec if spec is not None else {"image": "ash:local"},
        configmap_name="cm",
        has_config=False,
    )


class TestMcpAuthIsNotBypassable:
    """Regression tests for an auth bypass this operator shipped and a test pinned.

    The bug: ``build_mcp_argv`` emitted the literal ``${ASH_MCP_AUTH_HEADER_VALUE}``
    as an argv element and the container ran ``sh -c 'exec "$0" "$@"' <argv>``. A
    positional parameter's *value* is never re-expanded, so ``ashx`` received the
    placeholder verbatim and ``hmac.compare_digest``'d request headers against those
    28 characters -- a constant in a public repository, also readable with
    ``kubectl get deploy -o yaml``. Anyone sending the literal authenticated; the
    holder of the real secret got 401. ``ashx mcp``'s ``--auth-header-value`` declares
    no ``envvar=``, so nothing upstream supplied the real value either.

    The test that used to live here asserted the literal was *present* in the
    rendered manifest, so the suite passed only while the bypass existed. These
    assert the opposite, and the last one would have caught it.
    """

    def test_the_bypass_literal_is_absent_from_the_whole_manifest(self):
        rendered = yaml.safe_dump(mcp_deployment(AUTH_SPEC))
        assert BYPASS_LITERAL not in rendered, (
            "the unexpanded placeholder is back in the manifest. Whatever consumes it "
            "will treat those characters as the expected credential."
        )

    def test_no_auth_value_flag_appears_in_argv_at_all(self):
        # Not merely "not the placeholder": the flag itself must not be in argv,
        # because argv is what `kubectl describe pod` and the runtime process list
        # show. The entrypoint appends it from the environment.
        command = mcp_deployment(AUTH_SPEC)["spec"]["template"]["spec"]["containers"][0]["command"]
        argv = command[4:]  # /bin/sh, -c, script, $0 label, then argv
        assert "--auth-header-value" not in argv
        assert "--auth-header-name" in argv and "X-Ash-Token" in argv

    def test_the_value_is_expanded_inside_the_script_not_passed_as_a_positional(self):
        """The fix, asserted structurally.

        A variable referenced in the script *text* is expanded by the shell; the same
        text sitting in a positional is not. This distinguishes the two.
        """
        command = mcp_deployment(AUTH_SPEC)["spec"]["template"]["spec"]["containers"][0]["command"]
        script = command[2]
        assert '--auth-header-value "$ASH_MCP_AUTH_HEADER_VALUE"' in script
        assert script.count('exec "$@"') >= 1
        # And the old shape is gone.
        assert 'exec "$0" "$@"' not in script

    def test_the_real_value_reaches_argv_when_the_script_runs(self):
        """Run the emitted command for real and check what `ashx` would receive.

        The structural assertions above would both pass for a script that referenced
        the wrong variable name, so this executes the actual emitted script with a
        known value in the environment and inspects the resulting argv. `true` stands
        in for `ashx`; `printf` records what it was called with.
        """
        command = mcp_deployment(AUTH_SPEC)["spec"]["template"]["spec"]["containers"][0]["command"]
        script, label, argv = command[2], command[3], command[4:]
        # Swap `ashx` for something that prints its argv, keeping every other element.
        probe_argv = ["/bin/echo", *argv[1:]]
        result = subprocess.run(
            ["/bin/sh", "-c", script, label, *probe_argv],
            capture_output=True,
            text=True,
            check=True,
            env={
                "ASH_MCP_AUTH_REQUIRED": "1",
                "ASH_MCP_AUTH_HEADER_VALUE": "the-real-secret",
                "PATH": "/usr/bin:/bin",
            },
        )
        assert "--auth-header-value the-real-secret" in result.stdout, result.stdout
        assert BYPASS_LITERAL not in result.stdout, (
            "the literal placeholder reached argv, which is the bypass itself"
        )

    def test_an_empty_secret_refuses_to_start_rather_than_serving_without_auth(self):
        # The alternative -- take the no-auth branch -- would publish an
        # unauthenticated MCP control surface for a CR that asked for auth.
        command = mcp_deployment(AUTH_SPEC)["spec"]["template"]["spec"]["containers"][0]["command"]
        script, label, argv = command[2], command[3], command[4:]
        result = subprocess.run(
            ["/bin/sh", "-c", script, label, "/bin/echo", *argv[1:]],
            capture_output=True,
            text=True,
            check=False,
            env={
                "ASH_MCP_AUTH_REQUIRED": "1",
                "ASH_MCP_AUTH_HEADER_VALUE": "",
                "PATH": "/usr/bin:/bin",
            },
        )
        assert result.returncode == 78, (result.returncode, result.stdout, result.stderr)
        assert result.stdout == "", "the server was started despite an empty credential"
        assert "Refusing to start" in result.stderr

    def test_without_auth_the_server_still_starts(self):
        # Positive control. Without it, every assertion above would also hold for an
        # entrypoint that refused to start under all conditions.
        command = mcp_deployment()["spec"]["template"]["spec"]["containers"][0]["command"]
        script, label, argv = command[2], command[3], command[4:]
        result = subprocess.run(
            ["/bin/sh", "-c", script, label, "/bin/echo", *argv[1:]],
            capture_output=True,
            text=True,
            check=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert "mcp" in result.stdout
        assert "--auth-header-value" not in result.stdout

    def test_auth_required_is_only_set_when_auth_is_configured(self):
        with_auth = {
            e["name"]: e
            for e in mcp_deployment(AUTH_SPEC)["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert with_auth["ASH_MCP_AUTH_REQUIRED"]["value"] == "1"
        assert with_auth["ASH_MCP_AUTH_HEADER_VALUE"]["valueFrom"]["secretKeyRef"] == {
            "name": "s",
            "key": "k",
        }
        without = {
            e["name"] for e in mcp_deployment()["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        assert "ASH_MCP_AUTH_REQUIRED" not in without
        assert "ASH_MCP_AUTH_HEADER_VALUE" not in without


class TestMcpShapes:
    def test_the_secret_reaches_the_pod_only_as_a_reference(self):
        container = mcp_deployment(AUTH_SPEC)["spec"]["template"]["spec"]["containers"][0]
        assert any(e.get("valueFrom", {}).get("secretKeyRef") for e in container["env"])
        # No env entry carries a literal value for the credential.
        assert all(
            e.get("name") != "ASH_MCP_AUTH_HEADER_VALUE" or "value" not in e
            for e in container["env"]
        )

    def test_a_header_name_without_a_secret_ref_is_refused(self):
        with pytest.raises(Exception, match="secretKeyRef"):
            manifests.build_mcp_deployment(
                server=MCP,
                spec={"image": "ash:local", "auth": {"headerName": "X"}},
                configmap_name="cm",
                has_config=False,
            )

    def test_the_service_is_cluster_ip_only(self):
        service = manifests.build_mcp_service(server=MCP, spec={"image": "ash:local"})
        assert service["spec"]["type"] == "ClusterIP"

    def test_the_server_binds_all_interfaces_so_the_service_can_route(self):
        deployment = manifests.build_mcp_deployment(
            server=MCP, spec={"image": "ash:local"}, configmap_name="cm", has_config=False
        )
        command = deployment["spec"]["template"]["spec"]["containers"][0]["command"]
        assert "0.0.0.0" in command  # noqa: S104 - asserting the bind address

    def test_the_probes_are_tcp_not_http(self):
        # Measured: `ashx mcp` answers 401 to a bare GET on its mount path, and a
        # kubelet httpGet probe accepts only 200-399. An httpGet probe there can
        # never pass -- the pod stays unready and the rollout times out while the
        # server is working. If this assertion is ever flipped back, re-measure what
        # the endpoint returns first.
        deployment = manifests.build_mcp_deployment(
            server=MCP, spec={"image": "ash:local"}, configmap_name="cm", has_config=False
        )
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        for probe_name in ("livenessProbe", "readinessProbe"):
            probe = container[probe_name]
            assert "tcpSocket" in probe, probe
            assert "httpGet" not in probe, probe


def test_the_completion_index_label_is_the_one_kubernetes_sets():
    # Pinned because the operator attributes a pod to a shard with it, and reading
    # the wrong label yields shardIndex -1 on every pod with no error anywhere.
    assert JOB_COMPLETION_INDEX_LABEL == "batch.kubernetes.io/job-completion-index"


class TestPodServiceAccount:
    """Every pod the operator creates runs as the rule-less ``ash-scan`` account.

    rbac.yaml creates ``ash-scan`` with no Role and no RoleBinding so that these pods
    do not run as ``default``, whose token an adopter may have bound to something.
    That only holds if the builders default to it rather than to ``default``.
    """

    def service_accounts(self, spec=None, mcp_spec=None):
        return {
            "shard": shard_job(spec)["spec"]["template"]["spec"]["serviceAccountName"],
            "collect": collect_job(spec)["spec"]["template"]["spec"]["serviceAccountName"],
            "mcp": mcp_deployment(mcp_spec)["spec"]["template"]["spec"]["serviceAccountName"],
        }

    def test_the_default_is_the_rule_less_account_not_default(self):
        assert self.service_accounts() == {
            "shard": "ash-scan",
            "collect": "ash-scan",
            "mcp": "ash-scan",
        }

    def test_an_empty_name_falls_back_to_the_rule_less_account(self):
        accounts = self.service_accounts(
            spec={"scanServiceAccountName": ""},
            mcp_spec={"image": "ash:local", "serviceAccountName": ""},
        )
        assert set(accounts.values()) == {"ash-scan"}

    def test_a_named_account_is_honored(self):
        accounts = self.service_accounts(
            spec={"scanServiceAccountName": "mine"},
            mcp_spec={"image": "ash:local", "serviceAccountName": "mine"},
        )
        assert set(accounts.values()) == {"mine"}

    def test_the_default_account_is_shipped_and_bound_to_nothing(self):
        docs = [d for d in yaml.safe_load_all(RBAC_YAML.read_text()) if d]
        names = {d["metadata"]["name"] for d in docs if d["kind"] == "ServiceAccount"}
        assert manifests.SCAN_SERVICE_ACCOUNT in names
        bound = {
            s["name"]
            for d in docs
            if d["kind"] in ("RoleBinding", "ClusterRoleBinding")
            for s in d.get("subjects", [])
            if s.get("kind") == "ServiceAccount"
        }
        assert manifests.SCAN_SERVICE_ACCOUNT not in bound


class TestDefaultResources:
    """A CR that sets no resources must not schedule unbounded pods.

    Without a default, a shard or collector pod gets no requests (so the scheduler
    packs it anywhere) and no limits (so one runaway scanner can take the node's
    memory). An adopter's namespace quota that requires limits also refuses such a
    pod outright.
    """

    @staticmethod
    def resources(job):
        return job["spec"]["template"]["spec"]["containers"][0]["resources"]

    @pytest.mark.parametrize("build", [shard_job, collect_job], ids=["shard", "collect"])
    def test_requests_and_limits_are_set_when_the_cr_sets_none(self, build):
        res = self.resources(build())
        for section in ("requests", "limits"):
            assert set(res.get(section, {})) == {"cpu", "memory"}, res

    def test_the_defaults_are_not_shared_mutable_state(self):
        first = self.resources(shard_job())
        first["limits"]["memory"] = "1Ki"
        assert self.resources(shard_job())["limits"]["memory"] != "1Ki"

    def test_cr_resources_replace_the_default(self):
        mine = {"requests": {"cpu": "1", "memory": "2Gi"}}
        assert self.resources(shard_job({"resources": mine})) == mine
        assert self.resources(collect_job({"resources": mine})) == mine

    def test_collect_resources_win_over_resources_for_the_collector(self):
        mine = {"limits": {"memory": "3Gi"}}
        job = collect_job({"resources": {"limits": {"memory": "9Gi"}}, "collectResources": mine})
        assert self.resources(job) == mine

    def test_the_crd_descriptions_quote_the_real_defaults(self):
        from ash_operator.constants import DEFAULT_COLLECT_RESOURCES, DEFAULT_SHARD_RESOURCES
        from ash_operator.generate_manifests import render_all

        crd = yaml.safe_load(render_all()["crd-ashscans.yaml"])
        props = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"][
            "properties"
        ]
        for key, default in (
            ("resources", DEFAULT_SHARD_RESOURCES),
            ("collectResources", DEFAULT_COLLECT_RESOURCES),
        ):
            for section in default.values():
                for quantity in section.values():
                    assert quantity in props[key]["description"], (key, quantity)
