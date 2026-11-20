"""Retry-safe result addressing: the failure modes it exists to catch.

Every test here corresponds to something that, without the attempt-qualified
layout, merges to a clean report. The positive control comes first: without it,
every refusal below could be a function that refuses everything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ash_operator.attempts import (
    AttemptMarker,
    ShardSetError,
    attempts_dir,
    resolve_shard_set,
    run_prefix,
    sha256_file,
    verify_attempt,
)
from ash_operator.constants import ATTEMPT_MARKER_FILENAME, RESULTS_FILENAME


def publish(
    prefix: str,
    shard_index: int,
    attempt_id: str,
    *,
    shard_count: int,
    body: dict | None = None,
    partial: bool = False,
    corrupt_digest: bool = False,
    omit_marker: bool = False,
    omit_results: bool = False,
    claimed_index: int | None = None,
    claimed_count: int | None = None,
) -> Path:
    """Write one attempt directory the way shard-entrypoint.sh does."""
    suffix = ".partial" if partial else ""
    directory = Path(attempts_dir(prefix, shard_index)) / f"{attempt_id}{suffix}"
    directory.mkdir(parents=True, exist_ok=True)
    digest = "0" * 64
    if not omit_results:
        results = directory / RESULTS_FILENAME
        results.write_text(
            json.dumps(
                body
                or {
                    "metadata": {
                        "shard": {
                            "shard_index": shard_index,
                            "shard_count": shard_count,
                            "assigned_scanners": ["bandit"],
                            "candidate_scanners": ["bandit", "detect-secrets"],
                            "selected_scanners": ["bandit"],
                        }
                    },
                    "scanner_results": {},
                }
            )
        )
        digest = sha256_file(results)
    if corrupt_digest:
        digest = "f" * 64
    if not omit_marker:
        marker = AttemptMarker(
            attempt_id=attempt_id,
            pod_uid=f"uid-{attempt_id}",
            shard_index=shard_index if claimed_index is None else claimed_index,
            shard_count=shard_count if claimed_count is None else claimed_count,
            scan_exit_code=0,
            results_sha256=digest,
        )
        (directory / ATTEMPT_MARKER_FILENAME).write_text(marker.to_json())
    return directory


class TestPositiveControl:
    def test_a_healthy_two_shard_set_resolves(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-1")
        publish(prefix, 0, "job-0-aaaa", shard_count=2)
        publish(prefix, 1, "job-1-bbbb", shard_count=2)
        selected = resolve_shard_set(prefix=prefix, shard_count=2)
        assert [s.shard_index for s in selected] == [0, 1]
        assert all(s.discarded_attempt_ids == () for s in selected)


class TestMissingShards:
    def test_a_missing_index_is_refused_and_named(self, tmp_path):
        # Without this, the merge runs over 2 of 3 shards, exits 0 and reports a
        # clean scan of a tree a third of which never ran.
        prefix = run_prefix(str(tmp_path), "scan-uid-2")
        publish(prefix, 0, "job-0-a", shard_count=3)
        publish(prefix, 2, "job-2-c", shard_count=3)
        with pytest.raises(ShardSetError, match=r"shard index\(es\) \[1\] of 3"):
            resolve_shard_set(prefix=prefix, shard_count=3)

    def test_no_shards_at_all_is_refused(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-3")
        with pytest.raises(ShardSetError, match=r"\[0, 1\] of 2"):
            resolve_shard_set(prefix=prefix, shard_count=2)

    def test_the_refusal_says_why_rather_than_only_what(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-3b")
        publish(prefix, 0, "job-0-a", shard_count=2)
        with pytest.raises(ShardSetError) as err:
            resolve_shard_set(prefix=prefix, shard_count=2)
        assert "exit 0" in str(err.value)
        assert "clean scan" in str(err.value)


class TestRetryOverwrite:
    def test_a_partial_publication_is_invisible(self, tmp_path):
        # The whole scheme in one test: attempt 2 died mid-copy, so its directory
        # still carries the .partial suffix. Attempt 1's published result is
        # untouched and is what resolves.
        prefix = run_prefix(str(tmp_path), "scan-uid-4")
        publish(prefix, 0, "job-0-first", shard_count=1)
        publish(prefix, 0, "job-0-second", shard_count=1, partial=True)
        selected = resolve_shard_set(prefix=prefix, shard_count=1)
        assert selected[0].attempt_id == "job-0-first"

    def test_two_completed_attempts_pick_one_deterministically(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-5")
        publish(prefix, 0, "job-0-aaa", shard_count=1)
        publish(prefix, 0, "job-0-zzz", shard_count=1)
        first = resolve_shard_set(prefix=prefix, shard_count=1)
        second = resolve_shard_set(prefix=prefix, shard_count=1)
        assert first[0].attempt_id == second[0].attempt_id == "job-0-zzz"
        # The loser is recorded rather than deleted: two attempts of one index both
        # finishing means a retry raced a success, and a human may want to know.
        assert first[0].discarded_attempt_ids == ("job-0-aaa",)

    def test_a_file_changed_after_publication_is_refused(self, tmp_path):
        # This is the overwrite the scheme exists to detect. `ashx merge` cannot see
        # it: one file at one path, present and parseable.
        prefix = run_prefix(str(tmp_path), "scan-uid-6")
        directory = publish(prefix, 0, "job-0-a", shard_count=1)
        (directory / RESULTS_FILENAME).write_text('{"scanner_results": {}}')
        with pytest.raises(ShardSetError, match="changed after it was published"):
            resolve_shard_set(prefix=prefix, shard_count=1)

    def test_a_marker_whose_digest_disagrees_is_refused(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-7")
        publish(prefix, 0, "job-0-a", shard_count=1, corrupt_digest=True)
        with pytest.raises(ShardSetError, match="changed after it was published"):
            resolve_shard_set(prefix=prefix, shard_count=1)


class TestAttemptVerification:
    def test_an_unmarked_directory_is_skipped_not_refused(self, tmp_path):
        # A directory with no marker is a normal intermediate state, so it is
        # skipped. Only a directory that *claims* completeness and fails
        # verification is an error.
        prefix = run_prefix(str(tmp_path), "scan-uid-8")
        publish(prefix, 0, "job-0-unmarked", shard_count=1, omit_marker=True)
        publish(prefix, 0, "job-0-zgood", shard_count=1)
        selected = resolve_shard_set(prefix=prefix, shard_count=1)
        assert selected[0].attempt_id == "job-0-zgood"

    def test_a_marker_with_no_results_file_is_refused(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-9")
        publish(prefix, 0, "job-0-a", shard_count=1, omit_results=True)
        with pytest.raises(ShardSetError, match="no ash_aggregated_results.json"):
            resolve_shard_set(prefix=prefix, shard_count=1)

    def test_a_marker_filed_under_the_wrong_index_is_refused(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-10")
        publish(prefix, 0, "job-0-a", shard_count=2, claimed_index=1)
        publish(prefix, 1, "job-1-b", shard_count=2)
        with pytest.raises(ShardSetError, match="published under shard-0"):
            resolve_shard_set(prefix=prefix, shard_count=2)

    def test_an_unreadable_marker_is_refused(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-11")
        directory = publish(prefix, 0, "job-0-a", shard_count=1)
        (directory / ATTEMPT_MARKER_FILENAME).write_text("not json at all")
        with pytest.raises(ShardSetError, match="could not be read"):
            verify_attempt(str(directory), expected_shard_index=0)


class TestShardCountDisagreement:
    def test_shards_from_different_runs_are_refused(self, tmp_path):
        prefix = run_prefix(str(tmp_path), "scan-uid-12")
        publish(prefix, 0, "job-0-a", shard_count=2)
        publish(prefix, 1, "job-1-b", shard_count=2, claimed_count=3)
        with pytest.raises(ShardSetError, match="disagree about shard_count"):
            resolve_shard_set(prefix=prefix, shard_count=2)


class TestRunPrefix:
    def test_the_prefix_is_keyed_on_uid_not_name(self, tmp_path):
        # A name can be reused. Two runs sharing a prefix would put two runs'
        # attempts under one index, and one of them would satisfy the walk.
        assert run_prefix("/r", "uid-a") != run_prefix("/r", "uid-b")
        assert "uid-a" in run_prefix("/r", "uid-a")

    def test_an_empty_uid_is_refused(self):
        with pytest.raises(ValueError, match="keyed on nothing collides"):
            run_prefix("/r", "")

    def test_two_concurrent_runs_do_not_see_each_other(self, tmp_path):
        a = run_prefix(str(tmp_path), "uid-a")
        b = run_prefix(str(tmp_path), "uid-b")
        publish(a, 0, "job-0-a", shard_count=1)
        with pytest.raises(ShardSetError, match=r"\[0\] of 1"):
            resolve_shard_set(prefix=b, shard_count=1)


class TestSurplusShards:
    def test_a_shard_with_an_empty_assignment_still_counts(self, tmp_path):
        # A count above the scanner count gives surplus shards an empty
        # assignment. That is wasteful, not wrong -- measured elsewhere at 50
        # shards over 5 scanners, where 45 came back empty and the merged findings
        # matched one unsharded scan. The walk must not treat an empty assignment
        # as a missing shard.
        prefix = run_prefix(str(tmp_path), "scan-uid-13")
        body = {
            "metadata": {
                "shard": {
                    "shard_index": 1,
                    "shard_count": 2,
                    "assigned_scanners": [],
                    "candidate_scanners": ["bandit"],
                    "selected_scanners": [],
                }
            },
            "scanner_results": {},
        }
        publish(prefix, 0, "job-0-a", shard_count=2)
        publish(prefix, 1, "job-1-b", shard_count=2, body=body)
        selected = resolve_shard_set(prefix=prefix, shard_count=2)
        assert len(selected) == 2
