"""End to end against a real kind cluster.

The six things this file has to demonstrate, and the order they matter in:

1. **A planted finding comes back.** A scan of a tree with a known bandit finding
   and a known planted credential must report them. Zero findings on this fixture
   fails the test, because given that `ashx scan` checks source/output collision by
   equality only, a green scan of a dirty tree is reachable and looks like success.
2. **A negative control.** A clean tree must report zero findings *and* succeed.
   Without it, (1) shows only that the pipeline reports something.
3. **The fan-out happened.** N pods, each with a distinct shard index, and the merge
   consumed every one of them -- asserted from the provenance the shards stamped,
   not from the operator's own bookkeeping.
4. **A partial scan reads as Incomplete, with its partial results.** A scanner
   that cannot run makes `ashx merge` exit 1 under ASH's default
   `fail_on_incomplete_scanners: true`; the run must end `Incomplete` with
   `coverageComplete: false` and the findings that did come back, never `Clean`.
5. **A missing shard is refused, never silently clean.** Asserted twice: once
   deterministically by removing a published shard and re-running the collector, and
   once by deleting a running pod, where the acceptable outcomes are "the retry
   republished and the run succeeded" and "the run was refused" but never "succeeded
   over a subset".
6. **Nothing is keyed on shard index.** A second run with a different scanner roster
   must reassign scanners without the operator reusing anything from the first.
"""

from __future__ import annotations

import json
import textwrap
import time

import pytest
import yaml

from ash_operator.constants import (
    ASH_CLI,
    PHASE_CLEAN,
    PHASE_FINDINGS,
    PHASE_INCOMPLETE,
    PHASE_REFUSED,
)
from tests.e2e.helpers import (
    ASH_IMAGE,
    ASH_IMAGE_NOSTAMP,
    GROUP,
    NAMESPACE,
    TERMINAL,
    apply_fixture_configmap,
    apply_scan,
    kubectl,
    kubectl_apply_stdin,
    kubectl_json,
    scan_status,
    scan_uid,
    shard_pods,
    wait_for,
    wait_terminal,
)

pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module", autouse=True)
def fixtures(installed):
    apply_fixture_configmap("fixture-dirty", "dirty")
    apply_fixture_configmap("fixture-clean", "clean")
    yield


@pytest.fixture(scope="module")
def result(fixtures):
    apply_scan("dirty-scan", source_configmap="fixture-dirty")
    return wait_terminal("dirty-scan")


class TestDirtyFixtureReportsItsFinding:
    """The positive case. A zero-finding result here is a test failure."""

    def test_the_run_reached_a_verdict_rather_than_hanging(self, result):
        assert result["phase"] in TERMINAL

    def test_it_is_not_refused(self, result):
        assert result["phase"] != PHASE_REFUSED, (
            f"the run was refused: {result.get('merge', {}).get('refusalReason')}"
        )

    def test_the_planted_findings_came_back(self, result):
        # The assertion the whole e2e exists for. Given that --output-dir being an
        # ancestor of the source passes `ashx scan`'s equality-only collision check,
        # "0 findings on a fixture that has some" is a reachable false green.
        actionable = result["findings"]["actionable"]
        assert actionable is not None, "the merged report carried no finding count"
        assert int(actionable) >= 1, (
            f"the dirty fixture reported {actionable} actionable findings. It contains "
            f"a bandit B602/B307 pair and a planted AWS credential, so zero means the "
            f"scan did not see the tree -- check that the output directory is not an "
            f"ancestor of the source mount."
        )

    def test_the_verdict_is_findings_with_ash_exit_code_two(self, result):
        assert result["phase"] == PHASE_FINDINGS, result.get("merge")
        assert result["exitCode"] == 2
        assert result["merge"]["exitCode"] == 2

    def test_the_coverage_was_complete(self, result):
        # Findings with a gap would be exit 1 / Incomplete. Both selected scanners
        # ran, so the report must say so, assessed by ASH's own rule.
        assert result["coverageComplete"] is True, result.get("coverageGaps")
        assert result["coverageSource"] == "ash-coverage-rule"

    def test_two_different_scanners_each_contributed(self, result):
        # Direct evidence that the fan-out contributed rather than merely ran: bandit
        # and detect-secrets land on different shards at shardCount 3, and both are
        # present with findings in the merged report.
        by_name = {s["name"]: s for s in result["scannerCompleteness"]}
        assert by_name["bandit"]["findingCount"] >= 1, by_name["bandit"]
        assert by_name["detect-secrets"]["findingCount"] >= 1, by_name["detect-secrets"]
        assert (
            by_name["bandit"]["owningShardIndex"] != by_name["detect-secrets"]["owningShardIndex"]
        ), (
            "bandit and detect-secrets were owned by the same shard, so this run does "
            "not demonstrate that findings crossed the shard boundary"
        )

    def test_every_scanner_is_attributed_to_an_owning_shard(self, result):
        # The merge keeps only the owning shard's entry for each scanner, keyed on
        # assigned_scanners. Unioning the two dictionaries instead makes every
        # sharded scanner read SKIPPED with its findings attributed to a scanner the
        # report says never ran.
        for entry in result["scannerCompleteness"]:
            assert entry["owningShardIndex"] >= 0, entry

    def test_the_completeness_of_every_scanner_is_reported(self, result):
        # Surfaced whether or not failOnIncompleteScanners is on, because an adopter
        # who turns the gate on and sees an opaque failure is a support burden either
        # way.
        assert result["scannerCompleteness"], "no per-scanner completeness was reported"
        assert "incompleteScanners" in result
        for entry in result["scannerCompleteness"]:
            assert entry["completeness"] in {"Complete", "Incomplete", "Unknown"}

    def test_a_scanner_that_did_not_run_is_not_reported_as_having_passed(self, result):
        by_name = {s["name"]: s for s in result["scannerCompleteness"]}
        # Only bandit and detect-secrets were selected, so the other eight must read
        # SKIPPED -- "not selected" -- and not PASSED.
        for name in ("grype", "syft", "semgrep", "cfn-nag"):
            assert by_name[name]["status"] == "SKIPPED", by_name[name]


@pytest.fixture(scope="module")
def uid(fixtures):
    apply_scan("dirty-scan", source_configmap="fixture-dirty")
    wait_terminal("dirty-scan")
    return scan_uid("dirty-scan")


class TestShardFanOut:
    def test_three_pods_ran_with_three_distinct_indices(self, uid):
        pods = shard_pods(uid)
        indices = sorted(
            int(p["metadata"]["labels"]["batch.kubernetes.io/job-completion-index"]) for p in pods
        )
        assert indices == [0, 1, 2], (
            f"expected shard indices [0, 1, 2], saw {indices} across "
            f"{[p['metadata']['name'] for p in pods]}"
        )

    def test_every_shard_pod_succeeded_even_the_one_that_found_things(self, uid):
        # A shard never owns the verdict. A shard that exited non-zero for findings
        # would be retried, and there would be nothing wrong with it to fix.
        phases = {p["metadata"]["name"]: p["status"]["phase"] for p in shard_pods(uid)}
        assert set(phases.values()) == {"Succeeded"}, phases

    def test_the_merge_consumed_every_index(self, uid):
        merge = scan_status("dirty-scan")["merge"]
        assert merge["consumedShardIndices"] == [0, 1, 2]
        assert merge["expectedShardCount"] == 3

    def test_ash_merge_agrees_about_what_it_consumed(self, uid):
        # Two independent accountings: the collector's index walk, and the shard
        # count `ashx merge` derived from the provenance inside the result files. A
        # disagreement between them is reported rather than averaged away.
        merge = scan_status("dirty-scan")["merge"]
        assert merge["mergeReportedShardCount"] == 3
        assert merge["mergeReportedShardIndices"] == [0, 1, 2]

    def test_the_candidate_roster_was_recorded_and_agreed(self, uid):
        # candidate_scanners is the only check that can see a split-brain roster:
        # with it a coverage hole is refused, without it the same hole merges clean.
        # So this asserts the field was actually present, not that nothing went wrong.
        assert scan_status("dirty-scan")["merge"]["candidateRosterAgreed"] is True

    def test_the_shard_job_is_indexed(self, uid):
        job = kubectl_json("-n", NAMESPACE, "get", "job", "dirty-scan-shard")
        assert job["spec"]["completionMode"] == "Indexed"
        assert job["spec"]["completions"] == 3

    def test_each_pod_was_handed_a_different_shard_index_on_its_command_line(self, uid):
        """Read the index out of each shard's own results, not out of the pod spec.

        The pod spec does not carry the integers -- the entrypoint appends them from
        the environment -- so asserting on the spec would prove nothing. The results
        file records what `ScanPhase` was actually asked to do.
        """
        indices = []
        for pod in shard_pods(uid):
            logs = kubectl("-n", NAMESPACE, "logs", pod["metadata"]["name"], check=False).stdout
            marker = "--shard-index "
            assert marker in logs, (
                f"pod {pod['metadata']['name']} never logged its argv; the entrypoint "
                f"logs it before running the scan, so its absence means the scan "
                f"never started"
            )
            fragment = logs.split(marker, 1)[1].split()[0]
            indices.append(int(fragment))
        assert sorted(indices) == [0, 1, 2], indices


@pytest.fixture(scope="module")
def clean_result(fixtures):
    apply_scan("clean-scan", source_configmap="fixture-clean")
    return wait_terminal("clean-scan")


@pytest.mark.negative_control
class TestCleanFixtureNegativeControl:
    def test_it_is_clean(self, clean_result):
        assert clean_result["phase"] == PHASE_CLEAN, (
            f"the clean fixture did not come back Clean: "
            f"{clean_result.get('merge', {}).get('refusalReason') or clean_result}"
        )
        assert clean_result["exitCode"] == 0
        assert clean_result["coverageComplete"] is True

    def test_it_reports_zero_actionable_findings(self, clean_result):
        # Without this, the dirty test shows only that the pipeline reports
        # something. A pipeline that always reported two findings would pass there
        # and fail here.
        assert int(clean_result["findings"]["actionable"] or 0) == 0, clean_result["findings"]

    def test_the_merge_exit_code_is_zero(self, clean_result):
        assert clean_result["merge"]["exitCode"] == 0

    def test_the_scanners_still_ran(self, clean_result):
        # A clean result because nothing ran is not a clean result. Both selected
        # scanners must be Complete and must have had their dependencies satisfied.
        by_name = {s["name"]: s for s in clean_result["scannerCompleteness"]}
        for name in ("bandit", "detect-secrets"):
            assert by_name[name]["status"] == "PASSED", by_name[name]
            assert by_name[name]["completeness"] == "Complete"
            assert by_name[name]["dependenciesSatisfied"] is True

    def test_the_merge_still_consumed_every_index(self, clean_result):
        assert clean_result["merge"]["consumedShardIndices"] == [0, 1, 2]


@pytest.fixture(scope="module")
def incomplete_result(fixtures):
    # cfn-nag needs ruby, which the e2e image does not carry, so it is recorded
    # MISSING while bandit runs and finds the planted B602/B307. One shard owns
    # both, so `ashx merge` cannot refuse the shard as having completed nothing; it
    # writes the merged report and exits 1 for the gap, which is the #640 case.
    apply_scan(
        "partial-scan",
        source_configmap="fixture-dirty",
        shard_count=1,
        scanners=["bandit", "cfn-nag"],
    )
    return wait_terminal("partial-scan")


@pytest.mark.negative_control
class TestAPartialScanIsIncomplete:
    def test_the_phase_is_incomplete_not_clean_or_findings(self, incomplete_result):
        assert incomplete_result["phase"] == PHASE_INCOMPLETE, (
            f"phase {incomplete_result['phase']!r}, exit {incomplete_result.get('exitCode')}, "
            f"gaps {incomplete_result.get('coverageGaps')}, "
            f"refusal {incomplete_result.get('merge', {}).get('refusalReason')}"
        )

    def test_ash_merge_exited_one(self, incomplete_result):
        assert incomplete_result["exitCode"] == 1

    def test_the_gap_is_named(self, incomplete_result):
        assert incomplete_result["coverageComplete"] is False
        assert any("cfn-nag" in gap for gap in incomplete_result["coverageGaps"]), (
            incomplete_result["coverageGaps"]
        )
        assert "cfn-nag" in incomplete_result["incompleteScanners"]

    def test_the_partial_results_are_kept(self, incomplete_result):
        # Incomplete is not a refusal: what did run is reported. Zero here would mean
        # the partial results were dropped and the phase is the only signal left.
        assert int(incomplete_result["findings"]["actionable"] or 0) >= 1, incomplete_result[
            "findings"
        ]
        by_name = {s["name"]: s for s in incomplete_result["scannerCompleteness"]}
        assert by_name["bandit"]["findingCount"] >= 1, by_name["bandit"]
        assert by_name["cfn-nag"]["status"] == "MISSING", by_name["cfn-nag"]


HOLE_JOB = textwrap.dedent(
    """
    apiVersion: batch/v1
    kind: Job
    metadata:
      name: hole-probe
      namespace: {namespace}
    spec:
      backoffLimit: 0
      template:
        spec:
          restartPolicy: Never
          automountServiceAccountToken: false
          serviceAccountName: ash-scan
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            fsGroup: 1000
          volumes:
            - name: ash-results
              persistentVolumeClaim:
                claimName: {claim}
            - name: ash-config
              configMap:
                name: {configmap}
                defaultMode: 0444
            - name: ash-tmp
              emptyDir: {{}}
            - name: ash-out
              emptyDir: {{}}
          containers:
            - name: hole
              image: {image}
              imagePullPolicy: Never
              command: ["/bin/sh", "-c"]
              args:
                - |
                  set -u
                  # Remove a published shard, then re-run the collector against the
                  # same prefix. Deterministic, unlike racing a running pod, and it
                  # exercises the exact path a lost shard takes.
                  rm -rf "{prefix}/attempts/shard-1"
                  rm -rf "{prefix}/selected"
                  export ASH_CONFIG_MOUNT=/workspace/config
                  export ASH_PYLIB_DIR=/tmp/pylib
                  /bin/sh /workspace/config/collect-entrypoint.sh \
                    --prefix {prefix} --shard-count 3 \
                    --merge-output /workspace/out/merged \
                    --termination-message-path /dev/termination-log \
                    -- {ash_cli} merge --min-severity MEDIUM
              volumeMounts:
                - name: ash-results
                  mountPath: /workspace/results
                - name: ash-config
                  mountPath: /workspace/config
                  readOnly: true
                - name: ash-tmp
                  mountPath: /tmp
                - name: ash-out
                  mountPath: /workspace/out
              terminationMessagePath: /dev/termination-log
              terminationMessagePolicy: File
    """
)


@pytest.mark.negative_control
class TestAMissingShardIsRefused:
    """The failure mode the whole design is built against.

    A merge over a subset exits 0 and reports a clean scan. This removes a published
    shard from a run that already succeeded and re-runs the collector against it, so
    the refusal is measured rather than reasoned about.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def probe(fixtures):
        apply_scan("hole-scan", source_configmap="fixture-dirty")
        status = wait_terminal("hole-scan")
        assert status["merge"]["consumedShardIndices"] == [0, 1, 2], (
            "the control run did not consume every shard, so removing one proves nothing"
        )
        body = HOLE_JOB.format(
            namespace=NAMESPACE,
            claim=status["resultsClaimName"],
            configmap=status["configMapName"],
            image=ASH_IMAGE,
            prefix=status["resultsPrefix"],
            ash_cli=ASH_CLI,
        )
        kubectl("-n", NAMESPACE, "delete", "job", "hole-probe", "--ignore-not-found")
        kubectl_apply_stdin(body)

        def finished():
            job = kubectl_json("-n", NAMESPACE, "get", "job", "hole-probe")
            conditions = {
                c["type"]: c["status"] for c in (job.get("status") or {}).get("conditions", [])
            }
            if conditions.get("Complete") == "True" or conditions.get("Failed") == "True":
                return job
            return None

        wait_for(finished, timeout=600, what="the hole probe Job to finish")
        pods = kubectl_json("-n", NAMESPACE, "get", "pods", "-l", "job-name=hole-probe")
        pod = pods["items"][0]
        terminated = pod["status"]["containerStatuses"][0]["state"]["terminated"]
        yield terminated
        # The probe is this test's own Job, not the scan's, so nothing collects it. Its
        # finished pod still names hole-scan's results claim, and pvc-protection keeps
        # a claim that any pod object names, finished or not: measured on kind, the
        # claim sat in Terminating until the Job was deleted, which held up uninstall.
        kubectl("-n", NAMESPACE, "delete", "job", "hole-probe", "--wait=true", "--timeout=120s")

    def test_the_collector_exits_non_zero(self, probe):
        assert probe["exitCode"] != 0, (
            "the collector exited 0 with shard 1 missing. That is the silent false "
            "green this design exists to prevent."
        )

    def test_the_refusal_names_the_missing_index(self, probe):
        summary = json.loads(probe["message"])
        assert summary["phase"] == PHASE_REFUSED
        assert "[1]" in summary["refusal"], summary["refusal"]

    def test_the_refusal_explains_the_consequence_not_just_the_rule(self, probe):
        summary = json.loads(probe["message"])
        assert "clean scan" in summary["refusal"]

    def test_no_merged_report_was_produced(self, probe):
        summary = json.loads(probe["message"])
        assert summary["mergeExitCode"] is None, (
            "the merge ran despite the coverage check failing; verify_shard_coverage "
            "runs before anything is merged so a bad set leaves no half-written report"
        )


class TestPodDeletionMidRun:
    """Delete a running shard pod and assert the outcome is never silently clean.

    Racier than the hole probe on purpose: this is the Kubernetes-specific failure
    the CDK backends never face, and it is worth exercising through the real path
    even though the timing is not guaranteed. Two outcomes are acceptable -- the
    retry republished under a new attempt id and the run succeeded, or the Job gave
    up and the collector refused. The one unacceptable outcome is a terminal
    answer -- Clean, Findings or Incomplete -- over a subset of the indices.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def outcome(fixtures):
        apply_scan(
            "evict-scan",
            source_configmap="fixture-dirty",
            backoff_limit=2,
            shard_count=3,
        )
        uid = wait_for(
            lambda: scan_uid("evict-scan") if scan_status("evict-scan") else None,
            timeout=120,
            what="AshScan/evict-scan to be admitted",
        )

        deleted = None
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline and deleted is None:
            for pod in shard_pods(uid):
                index = pod["metadata"]["labels"].get("batch.kubernetes.io/job-completion-index")
                if pod["status"]["phase"] == "Running" and index == "0":
                    kubectl(
                        "-n",
                        NAMESPACE,
                        "delete",
                        "pod",
                        pod["metadata"]["name"],
                        "--grace-period=0",
                        "--force",
                        check=False,
                    )
                    deleted = pod["metadata"]["name"]
                    break
            if scan_status("evict-scan").get("phase") in TERMINAL:
                break
            time.sleep(1)

        status = wait_terminal("evict-scan")
        return {"deleted": deleted, "status": status, "uid": uid}

    def test_a_pod_was_actually_deleted_or_the_test_says_so(self, outcome):
        # Reported rather than skipped. If the scan finished before a pod could be
        # deleted, this test has not exercised the retry path and saying so is more
        # useful than a green tick.
        if outcome["deleted"] is None:
            pytest.fail(
                "no shard pod was observed Running long enough to delete, so the "
                "retry path was not exercised by this run. The deterministic "
                "TestAMissingShardIsRefused probe still covers the refusal; this "
                "failure means the eviction timing needs widening, not that the "
                "operator is wrong."
            )

    def test_the_outcome_is_never_silently_clean(self, outcome):
        status = outcome["status"]
        phase = status["phase"]
        consumed = status["merge"]["consumedShardIndices"]
        assert phase in TERMINAL
        if phase != PHASE_REFUSED:
            assert consumed == [0, 1, 2], (
                f"the run reported {phase} having consumed {consumed} of 3 shards. "
                f"A merge over a subset exits 0 and reports a clean scan, which is "
                f"exactly the outcome that must never happen."
            )
        # The dirty fixture has findings, so an answer other than a refusal is Findings.
        assert phase in {PHASE_REFUSED, PHASE_FINDINGS}, phase

    def test_the_retry_republished_under_a_new_attempt_id(self, outcome):
        """The one assertion that shows attempt qualification working in-cluster.

        Keyed on whether the *walk completed*, not on whether the run was clean. A
        ``Findings`` phase already implies a complete walk -- an incomplete one yields
        ``Refused`` -- and a dirty fixture always ends Findings because the merge
        finds the planted findings. Gating on a clean phase made this skip on every
        run, so the assertion existed and never executed.
        """
        status = outcome["status"]
        if status["phase"] == PHASE_REFUSED:
            pytest.skip(
                "the run was Refused, which is an acceptable outcome for a deleted "
                "pod: the Job gave up and the collector named the missing index. "
                "There is no republished attempt to inspect."
            )
        consumed = status["merge"]["consumedShardIndices"]
        assert consumed == [0, 1, 2], (
            f"phase is {status['phase']} but only {consumed} were consumed; a "
            f"non-Refused phase is supposed to imply a complete walk"
        )
        selected = {entry["i"]: entry["a"] for entry in status["merge"]["selectedAttempts"]}
        assert selected[0] != outcome["deleted"], (
            f"shard 0 was merged from attempt {selected[0]!r}, which is the pod that "
            f"was deleted. A deleted pod's attempt must not be what the merge used -- "
            f"that would mean the retry published over it rather than beside it."
        )


@pytest.mark.negative_control
class TestProvenanceAbsentIsRefused:
    """The negative control for the provenance check.

    ``TestShardFanOut`` asserts ``candidateRosterAgreed is True``, which shows the
    provenance was present and says nothing about its absence. This runs a scan with
    an ASH that does not stamp ``candidate_scanners`` -- a supported ``spec.image``,
    since the operator does not require any particular ASH version -- and asserts the
    operator refuses.

    Why it has to refuse rather than warn: with the field absent from every shard,
    ``ashx merge`` skips the union check entirely. A mid-rollout state where two
    executors partition different scanner sets without overlapping then merges into a
    report that reads as a complete scan of the whole tree, with a scanner having run
    nowhere. Nothing downstream can see it. For a while this operator detected exactly
    that condition, wrote ``candidateRosterAgreed: false`` into ``.status``, and
    reported success anyway.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def result(fixtures):
        apply_scan(
            "nostamp-scan",
            source_configmap="fixture-dirty",
            extra_spec={"image": ASH_IMAGE_NOSTAMP},
        )
        status = wait_terminal("nostamp-scan")
        # Printed on success, not only on failure. The refusal is the result of this
        # arm, and a reader who wants to see what the operator actually wrote should
        # not have to re-run the suite with a watcher attached to get it -- sampling
        # the cluster from outside misses the terminal state, because the fixture
        # tears the cluster down as soon as the class finishes.
        print(f"=== nostamp-scan terminal status ===\n{json.dumps(status, indent=2)}")
        return status

    def test_the_run_is_refused(self, result):
        assert result["phase"] == PHASE_REFUSED, (
            f"a scan whose shards recorded no candidate_scanners reported "
            f"{result['phase']!r}. `ashx merge` does not refuse that case, so the "
            f"operator is the only thing that can -- and a detected coverage hole "
            f"reported as success is worse than one never detected. "
            f"merge={json.dumps(result.get('merge', {}))[:600]}"
        )

    def test_the_roster_field_records_the_absence(self, result):
        assert result["merge"]["candidateRosterAgreed"] is False

    def test_the_refusal_explains_what_cannot_be_checked(self, result):
        reason = result["merge"]["refusalReason"]
        assert "candidate_scanners" in reason
        assert "coverage hole" in reason
        assert "predates" in reason, (
            "the refusal does not name the likely cause, so an adopter has to guess "
            "which of their images is at fault"
        )

    def test_the_shards_really_did_run_and_merge(self, result):
        """The refusal must be about provenance, not about a failed scan.

        Without this, the test would pass for an image that simply could not run --
        which would make the negative control vacuous, since any broken image produces
        a refusal.
        """
        assert result["merge"]["consumedShardIndices"] == [0, 1, 2]
        assert result["merge"]["exitCode"] is not None, (
            "the merge never ran, so this refusal is not the provenance one"
        )
        by_name = {s["name"]: s for s in result["scannerCompleteness"]}
        assert by_name["bandit"]["findingCount"] >= 1, (
            "the patched image found nothing, so it is broken in some other way and "
            "this test is not measuring what it claims"
        )

    def test_the_patched_image_differs_only_in_that_field(self, result):
        # Same fixture, same scanners, same shard count as the dirty-scan arm, so the
        # only difference between Findings there and Refused here is the stamping.
        dirty = scan_status("dirty-scan")
        if not dirty:
            pytest.skip("the dirty-scan arm has not run in this session")
        assert dirty["merge"]["candidateRosterAgreed"] is True
        assert dirty["phase"] == PHASE_FINDINGS
        assert result["phase"] == PHASE_REFUSED
        assert dirty["merge"]["consumedShardIndices"] == result["merge"]["consumedShardIndices"]


class TestNothingIsKeyedOnShardIndex:
    """A roster change must reassign scanners without anything stale surviving.

    The partition reshuffles by sort *position*, not by count: adding an
    early-sorting name moves every shard, a late-sorting one moves none. So any
    per-index cache the operator kept would be wrong for every scanner after a
    config change.
    """

    def test_a_second_run_with_a_different_roster_reassigns(self, fixtures):
        apply_scan(
            "roster-a", source_configmap="fixture-dirty", scanners=["bandit", "detect-secrets"]
        )
        first = wait_terminal("roster-a")
        apply_scan(
            "roster-b",
            source_configmap="fixture-dirty",
            scanners=["bandit"],
            shard_count=2,
        )
        second = wait_terminal("roster-b")

        assert first["phase"] in TERMINAL and second["phase"] in TERMINAL
        a_owners = {s["name"]: s["owningShardIndex"] for s in first["scannerCompleteness"]}
        b_owners = {s["name"]: s["owningShardIndex"] for s in second["scannerCompleteness"]}
        # Different shard counts, so the assignment must differ for at least one
        # scanner. Identical assignments would mean something was reused.
        assert a_owners != b_owners, (
            f"a 3-shard run and a 2-shard run produced identical scanner ownership "
            f"({a_owners}); the partition should be a function of the count"
        )
        assert second["merge"]["consumedShardIndices"] == [0, 1]

    def test_the_two_runs_used_different_configmaps_and_result_prefixes(self, fixtures):
        a = scan_status("roster-a")
        b = scan_status("roster-b")
        assert a["configMapName"] != b["configMapName"]
        assert a["resultsPrefix"] != b["resultsPrefix"], (
            "two runs shared a results prefix; one run's attempts would satisfy the "
            "other's index walk"
        )

    def test_the_run_configmap_is_immutable(self, fixtures):
        name = scan_status("roster-a")["configMapName"]
        cm = kubectl_json("-n", NAMESPACE, "get", "configmap", name)
        assert cm["immutable"] is True, (
            "the run ConfigMap is mutable, so the kubelet can re-sync a changed "
            "config into a running pod and leave one shard partitioning a different "
            "roster from its siblings"
        )


class TestMcpServer:
    def test_an_mcp_server_becomes_ready_and_is_reachable(self, installed):
        body = yaml.safe_dump(
            {
                "apiVersion": f"{GROUP}/v1alpha1",
                "kind": "AshMcpServer",
                "metadata": {"name": "mcp-e2e", "namespace": NAMESPACE},
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
        kubectl_apply_stdin(body)

        # Wait for the Deployment to *exist* before waiting for it to be Available.
        # `kubectl wait` on an object that does not exist yet fails immediately with
        # NotFound rather than waiting for it, so a single `kubectl wait` here raced
        # the reconciler and the assertion below then fired on an empty pod list --
        # reporting "no MCP pod became Ready" for a Deployment the operator had not
        # been given time to create. Polling for existence first is what closes that
        # race; measured, it was the cause of a failure that read like a broken probe.
        wait_for(
            lambda: (
                kubectl("-n", NAMESPACE, "get", "deployment", "mcp-e2e", check=False).returncode
                == 0
            ),
            timeout=180,
            what="the operator to create Deployment/mcp-e2e",
        )

        def a_pod_is_ready():
            pods = kubectl_json("-n", NAMESPACE, "get", "pods", "-l", f"{GROUP}/mcp-name=mcp-e2e")
            return [
                p["metadata"]["name"]
                for p in pods["items"]
                if any(
                    c.get("type") == "Ready" and c.get("status") == "True"
                    for c in (p["status"].get("conditions") or [])
                )
            ]

        try:
            wait_for(a_pod_is_ready, timeout=300, what="an MCP pod to become Ready")
        except AssertionError as err:
            describe = kubectl(
                "-n", NAMESPACE, "describe", "deployment/mcp-e2e", check=False
            ).stdout
            pod_describe = kubectl(
                "-n", NAMESPACE, "describe", "pods", "-l", f"{GROUP}/mcp-name=mcp-e2e", check=False
            ).stdout
            raise AssertionError(
                "no MCP pod became Ready. The probe is a TCP connect, so an unready "
                "pod means the server did not bind its port -- check the capability "
                f"probe's exit code and the container's log.\n{err}\n"
                f"{describe[-1500:]}\n{pod_describe[-2500:]}"
            ) from err

        status = wait_for(
            lambda: kubectl_json("-n", NAMESPACE, "get", "ashmcpserver", "mcp-e2e").get("status"),
            timeout=120,
            what="AshMcpServer/mcp-e2e status",
        )
        assert status["phase"] == "Deployed"
        assert status["endpoint"].endswith(":8000/mcp")

    def test_the_capability_probe_ran_and_passed(self, installed):
        pods = kubectl_json("-n", NAMESPACE, "get", "pods", "-l", f"{GROUP}/mcp-name=mcp-e2e")
        pod = pods["items"][0]
        init = pod["status"]["initContainerStatuses"][0]
        assert init["state"]["terminated"]["exitCode"] == 0
        logs = kubectl(
            "-n",
            NAMESPACE,
            "logs",
            pod["metadata"]["name"],
            "-c",
            "ash-mcp-capability-probe",
            check=False,
        ).stdout
        assert "--stateless-http" in logs, (
            "the probe did not report on --stateless-http, so it did not check the "
            "thing it exists to check"
        )

    def test_the_service_routes_to_the_pod(self, installed):
        """Reach the Service by its cluster DNS name and read the HTTP status back.

        Run from inside the MCP pod with the Python already in the ASH image, rather
        than from a throwaway pod pulling ``curlimages/curl``. A cluster with no
        egress cannot pull that image, and the test would then skip -- which would
        have left the one assertion that actually exercises Service DNS and routing
        not running at all on exactly the clusters where it matters most.

        Any HTTP status counts. Measured directly against ``ashx mcp``: a bare GET on
        the mount path returns **401**, because the MCP SDK will not serve a request
        that is not a protocol handshake. A status code of any kind proves DNS
        resolved, the Service routed and the server answered; a connection refusal or
        a DNS failure does not, and that is the distinction being drawn.
        """
        pods = kubectl_json("-n", NAMESPACE, "get", "pods", "-l", f"{GROUP}/mcp-name=mcp-e2e")
        pod = pods["items"][0]["metadata"]["name"]
        script = (
            "import urllib.error,urllib.request;"
            "u='http://mcp-e2e.ash-system.svc.cluster.local:8000/mcp';"
            "\ntry:\n"
            "    print('STATUS', urllib.request.urlopen(u, timeout=20).status)\n"
            "except urllib.error.HTTPError as e:\n"
            "    print('STATUS', e.code)\n"
        )
        result = kubectl(
            "-n",
            NAMESPACE,
            "exec",
            pod,
            "-c",
            "ash-mcp",
            "--",
            "python3",
            "-c",
            script,
            check=False,
            timeout=180,
        )
        assert "STATUS " in result.stdout, (
            f"no HTTP status came back from the Service's cluster DNS name. stdout="
            f"{result.stdout!r} stderr={result.stderr[-1500:]!r}"
        )
        code = int(result.stdout.split("STATUS ", 1)[1].split()[0])
        assert 100 <= code <= 599, code
