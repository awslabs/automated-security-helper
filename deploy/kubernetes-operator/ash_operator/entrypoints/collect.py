#!/usr/bin/env python3
"""The collector: index walk, then ``ash merge``, then a summary the operator reads.

Runs in the *same image as the shards*, on purpose. ``ash merge`` consumes results
written by whatever ASH produced each shard and copes with version skew; a
collector running a different ASH than the shards would introduce that skew rather
than tolerate it.

It is a Python script rather than shell because it reuses
:mod:`ash_operator.attempts` verbatim -- the same module the operator's unit tests
exercise. The alternative, reimplementing the index walk in shell inside the
ConfigMap, would have put the one piece of genuinely new logic in this design in
the one place nothing tests it.

How the operator learns what happened: this script writes a compact JSON summary
to the container's termination message path. The operator reads it from
``pod.status.containerStatuses[].state.terminated.message``. That needs no
ServiceAccount token on this pod and no shared volume mounted into the operator.
The kubelet caps the message at 4 KiB, so the summary has a budget and *says so*
when it has to drop detail -- a silently truncated summary would be invalid JSON
and the operator would report "unknown" for a run that succeeded.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ash_operator.attempts import ShardSetError, resolve_shard_set, selected_dir
from ash_operator.constants import RESULTS_FILENAME

# The kubelet truncates the termination message at 4096 bytes. Stay well inside it
# so a message that reaches the operator is always parseable.
TERMINATION_MESSAGE_BUDGET = 3600


def log(message: str) -> None:
    print(f"[ash-collect] {message}", file=sys.stderr, flush=True)


def write_termination_message(path: str, payload: dict) -> None:
    """Write *payload* as JSON, shedding detail rather than being truncated.

    ``candidateRosterAgreed``, ``phase``, ``refusal``, ``consumedShardIndices`` and
    ``mergeExitCode`` are **not** in the shed list and must never be added to it.
    The operator's ``derive_phase`` refuses when ``candidateRosterAgreed`` is not
    ``True``, so shedding it would turn a coverage hole the collector had already
    detected into a ``Refused`` with no stated reason -- or, if the refusal were
    relaxed to treat a missing key as fine, back into a silent success.
    """
    shed_order = ["scanners", "discardedAttempts", "selectedAttempts"]
    body = dict(payload)
    text = json.dumps(body, separators=(",", ":"), sort_keys=True)
    dropped: list[str] = []
    while len(text.encode()) > TERMINATION_MESSAGE_BUDGET and shed_order:
        key = shed_order.pop(0)
        if key in body:
            body.pop(key)
            dropped.append(key)
        body["omittedFromStatus"] = dropped
        text = json.dumps(body, separators=(",", ":"), sort_keys=True)
    if len(text.encode()) > TERMINATION_MESSAGE_BUDGET:
        body = {
            "phase": payload.get("phase", "Unknown"),
            "mergeExitCode": payload.get("mergeExitCode"),
            "omittedFromStatus": ["everything except the verdict"],
        }
        text = json.dumps(body, separators=(",", ":"), sort_keys=True)
    try:
        Path(path).write_text(text)
    except OSError as err:  # pragma: no cover - only when /dev/termination-log is absent
        log(f"could not write termination message to {path}: {err}")
    log(f"summary: {text}")


def summarize_scanners(merged_results: dict, shard_owners: dict[str, int]) -> list[dict]:
    """Per-scanner completeness, from the merged report.

    Completeness survives the shard boundary: ``_adopt_owning_shard_results`` keeps
    only the owning shard's entry for each scanner, keyed on ``assigned_scanners``,
    so the merged report distinguishes "not in my shard" from "failed". This turns
    that into three fields per scanner and nothing more, because the budget above
    is 3.6 KiB and the full report stays on the results volume.
    """
    out = []
    for name, entry in sorted((merged_results.get("scanner_results") or {}).items()):
        entry = entry or {}
        out.append(
            {
                "n": name,
                "s": entry.get("status"),
                "o": shard_owners.get(name, -1),
                "d": bool(entry.get("dependencies_satisfied", True)),
                "f": int(entry.get("finding_count") or 0),
                "a": int(entry.get("actionable_finding_count") or 0),
            }
        )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", required=True, help="results prefix for this run")
    parser.add_argument("--shard-count", type=int, required=True)
    parser.add_argument("--merge-output", required=True)
    parser.add_argument("--termination-message-path", default="/dev/termination-log")
    parser.add_argument(
        "merge_argv",
        nargs=argparse.REMAINDER,
        help="the ash merge argv, after --; --results flags are appended by this script",
    )
    args = parser.parse_args(argv)

    summary: dict = {
        "phase": "Unknown",
        "shardCount": args.shard_count,
        "consumedShardIndices": [],
        "selectedAttempts": [],
        "discardedAttempts": [],
        "mergeExitCode": None,
        "refusal": None,
    }

    # ── 1. index walk, before anything is merged ─────────────────────────────
    try:
        selected = resolve_shard_set(prefix=args.prefix, shard_count=args.shard_count)
    except ShardSetError as err:
        summary["phase"] = "Refused"
        summary["refusal"] = str(err)[:1200]
        log(f"REFUSED: {err}")
        write_termination_message(args.termination_message_path, summary)
        return 1

    summary["consumedShardIndices"] = [item.shard_index for item in selected]
    summary["selectedAttempts"] = [
        {"i": item.shard_index, "a": item.attempt_id} for item in selected
    ]
    summary["discardedAttempts"] = [
        {"i": item.shard_index, "a": attempt}
        for item in selected
        for attempt in item.discarded_attempt_ids
    ]
    if summary["discardedAttempts"]:
        log(
            f"{len(summary['discardedAttempts'])} attempt(s) were complete but not "
            f"selected. Two attempts of one index both finishing means a retry "
            f"raced a success; either is a whole-shard result, so the greatest "
            f"attempt id wins and the rest are recorded rather than deleted."
        )

    # ── 2. stage exactly one directory per index ─────────────────────────────
    # One --results per shard, never the shared parent: resolve_results_file
    # searches a directory recursively and requires exactly one candidate, so a
    # parent holding every shard is refused -- correctly, because picking one of
    # several would silently drop shards.
    results_dirs = []
    for item in selected:
        staged = selected_dir(args.prefix, item.shard_index)
        if os.path.exists(staged):
            shutil.rmtree(staged)
        os.makedirs(os.path.dirname(staged), exist_ok=True)
        shutil.copytree(item.directory, staged)
        if not Path(staged, RESULTS_FILENAME).is_file():
            summary["phase"] = "Refused"
            summary["refusal"] = (
                f"staging shard {item.shard_index} left no {RESULTS_FILENAME} in {staged}"
            )
            write_termination_message(args.termination_message_path, summary)
            return 1
        results_dirs.append(staged)

    shard_owners: dict[str, int] = {}
    shard_candidates: dict[int, list[str]] = {}
    for item in selected:
        try:
            with open(Path(item.directory, RESULTS_FILENAME)) as handle:
                shard_doc = json.load(handle)
        except (OSError, ValueError):
            continue
        shard_meta = ((shard_doc.get("metadata") or {}).get("shard")) or {}
        for name in shard_meta.get("assigned_scanners") or []:
            shard_owners[name] = item.shard_index
        candidates = shard_meta.get("candidate_scanners")
        if candidates is not None:
            shard_candidates[item.shard_index] = sorted(candidates)

    # Measured rather than assumed: every shard should have resolved the same
    # candidate set. `ash merge` refuses a disagreement, but only when the field is
    # present on every shard -- a set where some shards omit it is refused too,
    # while a set where *none* carries it is accepted with the hole intact. So
    # report what was actually recorded instead of asserting it was fine.
    if shard_candidates:
        distinct = {tuple(v) for v in shard_candidates.values()}
        summary["candidateRosterAgreed"] = len(distinct) == 1
        if len(shard_candidates) != len(selected):
            summary["candidateRosterAgreed"] = False
            log(
                f"only {len(shard_candidates)} of {len(selected)} shards recorded "
                f"candidate_scanners; the union check cannot see a coverage hole "
                f"across a mixed set."
            )
    else:
        summary["candidateRosterAgreed"] = False
        log(
            "no shard recorded candidate_scanners. A mid-rollout roster change "
            "could have left a scanner unassigned on every shard and the merge "
            "would not refuse it."
        )

    # ── 3. merge. This exit code is the verdict. ─────────────────────────────
    merge_argv = [arg for arg in args.merge_argv if arg != "--"]
    if not merge_argv:
        raise SystemExit("no ash merge argv was supplied after --")
    full_argv = list(merge_argv)
    for directory in results_dirs:
        full_argv += ["--results", directory]
    full_argv += ["--output-dir", args.merge_output]
    log(f"argv: {full_argv}")
    completed = subprocess.run(full_argv, check=False)  # noqa: S603 - argv, no shell
    summary["mergeExitCode"] = completed.returncode

    merged_path = Path(args.merge_output, RESULTS_FILENAME)
    if not merged_path.is_file():
        summary["phase"] = "Refused"
        summary["refusal"] = (
            f"ash merge exited {completed.returncode} and wrote no {RESULTS_FILENAME}. "
            f"Its exit code alone cannot distinguish a refused coverage check from "
            f"findings, so the missing file is what this reports."
        )
        write_termination_message(args.termination_message_path, summary)
        return 1

    with open(merged_path) as handle:
        merged = json.load(handle)
    meta = merged.get("metadata") or {}
    stats = meta.get("summary_stats") or {}
    summary["scanners"] = summarize_scanners(merged, shard_owners)
    summary["findings"] = {
        "total": stats.get("total"),
        "actionable": stats.get("actionable"),
        "suppressed": stats.get("suppressed"),
    }
    summary["mergedShardCount"] = meta.get("merged_shard_count")
    summary["mergedShardIndices"] = meta.get("merged_shard_indices")
    summary["phase"] = "Succeeded" if completed.returncode == 0 else "Failed"
    write_termination_message(args.termination_message_path, summary)
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
