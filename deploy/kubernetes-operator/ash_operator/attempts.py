"""Retry-safe result addressing.

This is the one part of the design that has no precedent in the repository, so it
is spelled out here rather than left to the reader.

**The gap.** ``ash merge`` refuses a duplicate shard index when it arrives as two
``--results`` entries -- its message is explicit, "merging does not deduplicate".
It has no defence against **one** file that a retry overwrote. Neither CodeBuild
backend faces this, because CodeBuild actions inside a CodePipeline run do not
re-execute into the same artifact location. Kubernetes does: a pod can be
OOMKilled, evicted, preempted or drained, and a ``backoffLimit`` retry gets the
same ``JOB_COMPLETION_INDEX``, therefore the same natural output path. If attempt
1 finished and uploaded, and a spurious attempt 2 died halfway through
overwriting it, the collector sees one present-looking file and merges it. The
merged report reads as a complete scan of the whole tree.

**The scheme.** Results are addressed by *(shard index, attempt id)*, attempts are
immutable once published, and publication is a directory rename:

    <results>/attempts/shard-<K>/<attempt-id>.partial/   <- being written
    <results>/attempts/shard-<K>/<attempt-id>/           <- published, immutable
        ash_aggregated_results.json
        .shard-exit-code
        .attempt-complete                                <- marker, written LAST
        reports/...
    <results>/selected/shard-<K>/                        <- collector's copy

The attempt id is the pod's own name. For an ``Indexed`` Job that is
``<job>-<index>-<random>``: the index is stable across retries and the suffix is
not, which is exactly the identity needed. The pod's UID is recorded inside the
marker as a second witness, because a name is a label and a UID is a fact.

Order of operations in the worker, and why each step is where it is:

1. ``ash scan`` writes to a node-local ``emptyDir``, not to the shared volume.
   Writing the scan's own scratch directly to a shared volume would make a
   half-written file visible under the published name.
2. Copy the output tree into ``<attempt-id>.partial/``. A reader that sees this
   name knows nothing about it is trustworthy.
3. Write ``.attempt-complete`` inside the ``.partial`` directory, containing the
   attempt id, the pod UID, the scan's exit code and the SHA-256 of
   ``ash_aggregated_results.json``.
4. ``mv`` the directory to its published name. Rename within one filesystem is
   atomic, so the published name never exists in a partial state -- the marker is
   already inside it at the instant it appears.
5. ``exit 0``. A worker never owns the verdict; exiting non-zero for findings
   would make the Job controller retry a shard that succeeded.

The collector walks ``0..N-1`` by index -- not a glob over whatever landed -- and
for each index considers only published directories whose marker verifies. Then:

* zero verifying attempts for an index  -> **refuse**, naming the index.
* one                                    -> use it.
* more than one                          -> use the lexicographically greatest
  attempt id, record the discarded ones. Both are whole-shard results by
  construction, so either is correct; determinism matters so that a re-reconcile
  of the same volume selects the same one and the status does not flap.

**What this guarantees.**

* A retry cannot replace a completed attempt. Attempt ids differ, and a published
  directory is never written to again.
* A partial copy is never visible as complete. The marker is inside the directory
  before the directory exists under its published name, and the collector
  re-reads and re-hashes the results file rather than trusting the marker's
  presence.
* A missing shard is distinguishable from a clean one. Zero verifying attempts is
  a refusal naming the index; it is never a merge over a subset.
* Two attempts both finishing is visible in ``.status`` rather than silent.

**What this does not guarantee.**

* It assumes ``rename(2)`` within the results volume is atomic -- true for one
  POSIX filesystem, and true server-side on NFS, but an NFS client's cached
  directory listing can lag a rename made by another client. The collector calls
  ``os.scandir`` fresh on every reconcile rather than caching a listing, which
  narrows but does not close that window. On a volume that is not a single
  filesystem (two PVs behind one path) the rename degrades to copy-and-unlink and
  is not atomic; the scheme is not safe there and the operator does not detect it.
* The SHA-256 is computed by the same pod that wrote the file, so it detects
  truncation in transit and *not* a pod that lies. Nothing here is a defence
  against a compromised scanner image; that is what the worker's empty
  ServiceAccount and dropped capabilities are for.
* Discarded attempts are not garbage-collected beyond the lifetime of the results
  volume. A long-lived shared PVC accumulates them; ``ttlSecondsAfterFinished``
  removes the Jobs but not the files.
* It says nothing about *two concurrent AshScans*. Each run gets its own results
  prefix keyed on the scan's UID, so they cannot collide -- but that is the
  prefix's job, not this scheme's.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from ash_operator.constants import (
    ATTEMPT_MARKER_FILENAME,
    ATTEMPTS_DIRNAME,
    PARTIAL_SUFFIX,
    RESULTS_FILENAME,
    SELECTED_DIRNAME,
)

_ATTEMPT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,252}$")


class ShardSetError(RuntimeError):
    """The published attempts do not reconstruct exactly one whole scan."""


@dataclass(frozen=True)
class AttemptMarker:
    """The contents of ``.attempt-complete``."""

    attempt_id: str
    pod_uid: str
    shard_index: int
    shard_count: int
    scan_exit_code: int
    results_sha256: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "attemptId": self.attempt_id,
                "podUid": self.pod_uid,
                "shardIndex": self.shard_index,
                "shardCount": self.shard_count,
                "scanExitCode": self.scan_exit_code,
                "resultsSha256": self.results_sha256,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> AttemptMarker:
        raw = json.loads(text)
        return cls(
            attempt_id=str(raw["attemptId"]),
            pod_uid=str(raw.get("podUid", "")),
            shard_index=int(raw["shardIndex"]),
            shard_count=int(raw["shardCount"]),
            scan_exit_code=int(raw.get("scanExitCode", -1)),
            results_sha256=str(raw["resultsSha256"]),
        )


@dataclass(frozen=True)
class SelectedAttempt:
    """One shard index resolved to one published, verified attempt."""

    shard_index: int
    attempt_id: str
    directory: str
    marker: AttemptMarker
    discarded_attempt_ids: tuple[str, ...]


def run_prefix(results_root: str, scan_uid: str) -> str:
    """Return the results prefix for one AshScan run.

    Keyed on the CR's UID and not its name. A name can be reused -- delete an
    AshScan and create another with the same name and it would land on the
    previous run's attempts, where a stale published directory for shard 2 would
    satisfy the index walk and merge someone else's scan.
    """
    if not scan_uid:
        raise ValueError("scan_uid is required; a run prefix keyed on nothing collides")
    return str(Path(results_root) / f"run-{scan_uid}")


def attempts_dir(prefix: str, shard_index: int) -> str:
    return str(Path(prefix) / ATTEMPTS_DIRNAME / f"shard-{int(shard_index)}")


def selected_dir(prefix: str, shard_index: int) -> str:
    return str(Path(prefix) / SELECTED_DIRNAME / f"shard-{int(shard_index)}")


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _published_attempts(directory: str) -> list[str]:
    """List published attempt directory names, freshest listing, partials excluded.

    ``os.scandir`` every call rather than caching: on a shared volume the whole
    point is that another writer published between two reconciles.
    """
    try:
        entries = list(os.scandir(directory))
    except FileNotFoundError:
        return []
    names = []
    for entry in entries:
        if not entry.is_dir():
            continue
        if entry.name.endswith(PARTIAL_SUFFIX):
            continue
        if not _ATTEMPT_ID_RE.match(entry.name):
            continue
        names.append(entry.name)
    return sorted(names)


def verify_attempt(directory: str, *, expected_shard_index: int) -> AttemptMarker | None:
    """Return the marker if *directory* is a trustworthy published attempt.

    Returns ``None`` -- rather than raising -- when the directory is not usable,
    because a half-published attempt sitting next to a good one is a normal state
    after a retry, not an error. A directory that *claims* completeness and fails
    verification is different, and that does raise: it means something wrote a
    marker it could not back up, and treating that as "just skip it" is how a
    coverage hole becomes a clean report.
    """
    marker_path = Path(directory) / ATTEMPT_MARKER_FILENAME
    results_path = Path(directory) / RESULTS_FILENAME
    if not marker_path.is_file():
        return None
    try:
        marker = AttemptMarker.from_json(marker_path.read_text())
    except (OSError, ValueError, KeyError) as err:
        raise ShardSetError(
            f"{marker_path} exists but could not be read as an attempt marker "
            f"({type(err).__name__}: {err}). A shard that published an unreadable "
            f"marker did not demonstrably contribute its scanners, and skipping it "
            f"would merge a hole as clean."
        ) from err
    if marker.shard_index != expected_shard_index:
        raise ShardSetError(
            f"{marker_path} claims shardIndex {marker.shard_index} but is published "
            f"under shard-{expected_shard_index}. The results volume has been "
            f"written by something that does not agree with the partition."
        )
    if not results_path.is_file():
        raise ShardSetError(
            f"{directory} carries a completion marker but no {RESULTS_FILENAME}. "
            f"Exit 2 for findings and exit 2 for an unrecognized option are "
            f"indistinguishable, which is why the results file is the liveness "
            f"test -- and here it is absent."
        )
    actual = sha256_file(results_path)
    if actual != marker.results_sha256:
        raise ShardSetError(
            f"{results_path} hashes to {actual[:16]}… but its marker recorded "
            f"{marker.results_sha256[:16]}…. The file changed after it was "
            f"published, which is the overwrite this addressing scheme exists to "
            f"detect."
        )
    return marker


def resolve_shard_set(*, prefix: str, shard_count: int) -> list[SelectedAttempt]:
    """Walk ``0..shard_count-1`` and resolve each index to one verified attempt.

    Walking indices rather than globbing is deliberate. ``ash merge`` learns
    ``shard_count`` from the provenance *inside* the result files, so a collector
    that merges whatever it finds produces a short merge that is caught one layer
    later with a worse message -- and only if the provenance is intact. The index
    walk names the missing index here, before anything is merged.
    """
    if shard_count < 1:
        raise ShardSetError(f"shard_count must be at least 1, got {shard_count}")

    selected: list[SelectedAttempt] = []
    missing: list[int] = []
    for index in range(shard_count):
        directory = attempts_dir(prefix, index)
        verified: list[tuple[str, AttemptMarker]] = []
        for name in _published_attempts(directory):
            marker = verify_attempt(str(Path(directory) / name), expected_shard_index=index)
            if marker is not None:
                verified.append((name, marker))
        if not verified:
            missing.append(index)
            continue
        verified.sort(key=lambda pair: pair[0])
        winner_name, winner_marker = verified[-1]
        selected.append(
            SelectedAttempt(
                shard_index=index,
                attempt_id=winner_name,
                directory=str(Path(directory) / winner_name),
                marker=winner_marker,
                discarded_attempt_ids=tuple(name for name, _ in verified[:-1]),
            )
        )

    if missing:
        raise ShardSetError(
            f"no verified attempt for shard index(es) {missing} of {shard_count}. "
            f"Merging the remaining {len(selected)} would exit 0 and report a clean "
            f"scan of a tree that was only partly scanned, so the merge is refused. "
            f"Each listed index either never ran, or ran and never published."
        )

    counts = sorted({item.marker.shard_count for item in selected})
    if counts != [shard_count]:
        raise ShardSetError(
            f"shards disagree about shard_count: saw {counts}, expected "
            f"[{shard_count}]. Results carrying different counts come from "
            f"different runs, and merging them would double-count some scanners "
            f"while missing others."
        )
    return selected
