# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The base-image pre-pull must survive one registry refusing, and must refuse a wrong image.

Why this file exists
--------------------
``.github/actions/prepull-base-image`` pulls the Dockerfile's base image once per job so the
container legs do not each hit ECR Public's anonymous quotas at ``FROM ${BASE_IMAGE}``. It
originally had one registry, so a refusal ended the job and the remedy was a human noticing
and pressing re-run. It now tries ``public.ecr.aws`` and then ``docker.io``, whose quotas are
metered on different axes and counted separately, which gives one runner two independent
chances in one job.

That fallback is only safe if the second registry serves the same bytes as the first. So the
action reads ``ARG BASE_IMAGE_DIGEST`` from the Dockerfile and refuses to leave any image in
the local store that is not that digest. A fallback that accepts a different image is a silent
supply-chain substitution, which is strictly worse than the pull failing -- and it would be
invisible, precisely because the whole point of the pre-pull is to make the local store
authoritative for the build that follows.

What this asserts
-----------------
Six behaviours, one class each, by running the action's own shell with the container runtime
replaced by a stub that records its argv:

1. the primary answering means one registry is touched and nothing is retagged;
2. the primary refusing with the ``Data limit exceeded`` signature falls through to Docker Hub
   and tags the result under the exact reference the Dockerfile's ``FROM`` resolves;
3. the primary refusing with the bare rate-limit signature retries the primary first;
4. both registries refusing fails, naming both;
5. a registry whose tag does not resolve to the pinned digest is refused, with nothing tagged;
6. a non-quota error fails on the first attempt without trying the fallback.

Cases 5 and 6 are the ones that matter most. 5 is the substitution the digest pin exists to
stop. 6 is the failure mode a fallback introduces: trying the next registry on a real error
turns a clear failure into a slow one and reports a typo in the tag as a quota problem.

The script is not copied into this file. It is extracted from the YAML, so the action and the
test cannot drift apart while the test stays green.

What it deliberately does not check
-----------------------------------
It does not check that ``public.ecr.aws/docker/library/python`` and ``docker.io/library/python``
really are the same image -- that was measured out of band (both answer
``3.12-slim-bookworm`` with index digest ``sha256:392307d2...``, mediaType
``application/vnd.oci.image.index.v1+json``) and the action enforces it at run time. A test
that reached the network would be measuring the registries, not the action, and would spend
from the very quotas under discussion.

It does not exercise podman, finch or nerdctl. The action only ever asks a runtime for
``pull``, ``tag`` and ``image inspect --format '{{.Id}}'``, and it compares two ids that both
came from the same runtime in the same call -- so no runtime's notion of "the digest" is relied
on. What is not covered is whether all four accept a ``repo@sha256:...`` reference as an
inspect target and a tag source; that was verified on docker 25.0.16 only. The action's
response to a runtime that does not is a loud failure with the runtime named, never a silently
accepted image, which is the property this file's ``test_empty_image_id_is_refused`` pins.

Failure mode of this harness itself
-----------------------------------
The trap here is an assertion satisfied by a harness that never ran: "did not retag" and "did
not try the fallback" are both true of a script that died at line one. Every such assertion in
this file is therefore paired with positive evidence that control reached the relevant point --
a pull the stub actually recorded, or the action's own annotation. ``TestTheHarnessCanFail``
holds the controls: a frozen copy of the pre-fallback script must FAIL the fallback
assertions, and a deliberately broken runtime must not pass the digest check.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION = REPO_ROOT / ".github" / "actions" / "prepull-base-image" / "action.yml"
DOCKERFILE = REPO_ROOT / "Dockerfile"

PRIMARY_REPO = "public.ecr.aws/docker/library/python"
FALLBACK_REPO = "docker.io/library/python"

# Any two distinct ids; the harness only needs them to compare unequal.
ID_PINNED = "sha256:" + "1" * 64
ID_OTHER = "sha256:" + "2" * 64

# Same mechanism and both conditions as tests/unit/test_floating_major_tag_workflow.py, so
# there is one skip idiom for this reason rather than two that can drift. On a GitHub Windows
# runner `bash` resolves to C:\Windows\System32\bash.exe, the WSL launcher stub, which is on
# PATH whether or not a distribution is installed; a which() guard alone therefore passes and
# then every assertion fails on empty output. The step under test runs on ubuntu-latest under
# `bash`, so skipping is the honest answer rather than pointing the harness at Git Bash and
# reporting a pass about a configuration that does not exist.
_REQUIRES_BASH = [
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; the action under test runs on ubuntu-latest",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None, reason="the step under test is a bash script"
    ),
]


def _requires_bash(func):
    """Apply _REQUIRES_BASH to one test, for classes that are not wholly skipped."""
    for mark in reversed(_REQUIRES_BASH):
        func = mark(func)
    return func


# The stub runtime. It models exactly the three verbs the action uses, and a local image store
# as two flat files, so a test can say "this ref refuses with that wire error" and "that ref
# resolves to this id" without a daemon or a network.
#
# It exits 64 on any invocation it was not taught, rather than 0 or 1. A stub that silently
# tolerated an unexpected subcommand would let the action grow a dependency on runtime
# behaviour nobody checked.
RUNTIME_STUB = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"

lookup() {  # lookup <tsv-file> <key>; prints the first value or nothing
  [ -f "$1" ] || return 0
  awk -F'\t' -v k="$2" '$1 == k { print $2; exit }' "$1"
}

present() { [ -f "$STUB_PRESENT" ] && grep -Fxq "$1" "$STUB_PRESENT"; }

id_for() {
  local id
  id="$(lookup "$STUB_IDS" "$1")"
  printf '%s' "${id:-$STUB_DEFAULT_ID}"
}

cmd="${1:-}"
shift || true

case "$cmd" in
  pull)
    ref="$1"
    case "$(lookup "$STUB_RULES" "$ref")" in
      datalimit)
        echo "Error response from daemon: toomanyrequests: Data limit exceeded" >&2
        exit 1
        ;;
      ratelimit)
        echo "Error response from daemon: toomanyrequests: Rate exceeded" >&2
        exit 1
        ;;
      hub429)
        echo "Error response from daemon: toomanyrequests: You have reached your unauthenticated pull rate limit." >&2
        exit 1
        ;;
      unknown)
        echo "Error response from daemon: manifest for $ref not found: manifest unknown: Requested image not found" >&2
        exit 1
        ;;
      *)
        printf '%s\n' "$ref" >> "$STUB_PRESENT"
        echo "Status: Downloaded newer image for $ref"
        exit 0
        ;;
    esac
    ;;
  image)
    [ "${1:-}" = "inspect" ] || { echo "stub: unsupported: image ${1:-}" >&2; exit 64; }
    shift
    if [ "${1:-}" = "--format" ]; then
      [ "$2" = '{{.Id}}' ] || { echo "stub: unsupported format: $2" >&2; exit 64; }
      shift 2
    fi
    ref="$1"
    present "$ref" || { echo "stub: no such image: $ref" >&2; exit 1; }
    if [ "${STUB_BLANK_IDS:-0}" = "1" ]; then
      echo ""
      exit 0
    fi
    id_for "$ref"
    echo ""
    ;;
  tag)
    src="$1"
    dst="$2"
    present "$src" || { echo "stub: no such image: $src" >&2; exit 1; }
    printf '%s\n' "$dst" >> "$STUB_PRESENT"
    printf '%s\t%s\n' "$dst" "$(id_for "$src")" >> "$STUB_IDS"
    echo "$dst"
    ;;
  *)
    echo "stub: unexpected invocation: $cmd $*" >&2
    exit 64
    ;;
esac
"""

# The backoff is real seconds in CI and pointless here, so `sleep` records and returns. Kept
# as a stub rather than shortening the action's schedule: the test asserts on the attempt
# counts and on the fact that a wait happened, not on how long it was.
SLEEP_STUB = r"""#!/usr/bin/env bash
printf '%s\n' "$1" >> "$STUB_SLEEP_LOG"
"""

# The pre-fallback script, verbatim from action.yml at 80371ea1 (PR #660). Frozen on purpose:
# see "failure mode of this harness itself". The fallback assertions must fail against it.
FROZEN_SINGLE_REGISTRY_SCRIPT = r"""set -uo pipefail

runtime="${RUNTIME:-docker}"
# shellcheck disable=SC2206
wrapper=( ${WRAPPER} )

base="$(sed -n 's/^ARG BASE_IMAGE=\(.*\)$/\1/p' "${DOCKERFILE}" | head -n 1)"
if [ -z "${base}" ]; then
  echo "::error::no 'ARG BASE_IMAGE=' line in ${DOCKERFILE}; nothing to pre-pull."
  exit 1
fi
echo "base image: ${base}"

if "${wrapper[@]}" "${runtime}" image inspect "${base}" >/dev/null 2>&1; then
  echo "already present locally; not pulling"
  exit 0
fi

log="$(mktemp)"
for n in $(seq 1 "${ATTEMPTS}"); do
  echo "=== pull attempt ${n} of ${ATTEMPTS} ==="
  if "${wrapper[@]}" "${runtime}" pull "${base}" 2>&1 | tee "${log}"; then
    exit 0
  fi
  if grep -q 'Data limit exceeded' "${log}"; then
    echo "::error::RE-RUN THIS JOB. ECR Public refused to serve ${base}."
    exit 1
  fi
  if ! grep -qE 'toomanyrequests|429 Too Many Requests' "${log}"; then
    echo "::error::pulling ${base} failed for another reason."
    exit 1
  fi
  if [ "${n}" -eq "${ATTEMPTS}" ]; then
    echo "::error::ECR Public rate-limited every one of ${ATTEMPTS} pull attempts."
    exit 1
  fi
  sleep $(( n * 15 ))
done
"""


def _dockerfile_arg(name: str, text: str | None = None) -> str:
    """Read an `ARG <name>=` default out of the repository's Dockerfile."""
    body = text if text is not None else DOCKERFILE.read_text(encoding="utf-8")
    match = re.search(rf"^ARG {re.escape(name)}=(.*)$", body, flags=re.MULTILINE)
    assert match is not None, f"no 'ARG {name}=' line in the Dockerfile"
    return match.group(1).strip()


BASE_IMAGE = _dockerfile_arg("BASE_IMAGE")
BASE_IMAGE_DIGEST = _dockerfile_arg("BASE_IMAGE_DIGEST")
TAG = BASE_IMAGE.rsplit(":", 1)[1]

PRIMARY_TAG_REF = f"{PRIMARY_REPO}:{TAG}"
PRIMARY_PIN_REF = f"{PRIMARY_REPO}@{BASE_IMAGE_DIGEST}"
FALLBACK_TAG_REF = f"{FALLBACK_REPO}:{TAG}"
FALLBACK_PIN_REF = f"{FALLBACK_REPO}@{BASE_IMAGE_DIGEST}"


def _prepull_script() -> str:
    """The action's one shell step, located by content rather than by name."""
    doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    steps = [s for s in doc["runs"]["steps"] if isinstance(s, dict) and s.get("run")]
    assert len(steps) == 1, (
        f"expected exactly one shell step in {ACTION.name}, found {len(steps)}. "
        "The harness runs that step; more than one means it is running part of the action."
    )
    return steps[0]["run"]


class Result:
    """What the step did: its status, its output, and every runtime call it made."""

    def __init__(
        self,
        proc: subprocess.CompletedProcess,
        calls: list[str],
        sleeps: list[str],
        present: list[str],
    ):
        self.proc = proc
        self.calls = calls
        self.sleeps = sleeps
        self.present = present

    @property
    def ok(self) -> bool:
        return self.proc.returncode == 0

    @property
    def output(self) -> str:
        return self.proc.stdout + self.proc.stderr

    def pulls(self, ref: str | None = None) -> list[str]:
        out = [c for c in self.calls if c.startswith("pull ")]
        if ref is not None:
            out = [c for c in out if c == f"pull {ref}"]
        return out

    @property
    def tags(self) -> list[tuple[str, str]]:
        out = []
        for call in self.calls:
            parts = call.split()
            if parts and parts[0] == "tag":
                out.append((parts[1], parts[2]))
        return out

    @property
    def registries_pulled(self) -> set[str]:
        hosts = set()
        for call in self.pulls():
            ref = call.split(" ", 1)[1]
            hosts.add(ref.split("/", 1)[0])
        return hosts

    def describe(self) -> str:
        return (
            f"exit={self.proc.returncode}\n"
            "runtime calls:\n  " + ("\n  ".join(self.calls) or "(none)") + "\n"
            f"sleeps: {self.sleeps or '(none)'}\n"
            f"output:\n{self.output}"
        )


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _run(
    tmp_path: Path,
    rules: dict[str, str] | None = None,
    ids: dict[str, str] | None = None,
    present: list[str] | None = None,
    attempts: int = 3,
    script: str | None = None,
    blank_ids: bool = False,
    dockerfile_text: str | None = None,
) -> Result:
    """Run the action's shell against the stub runtime.

    ``rules`` maps a reference to how the registry answers a pull of it: ``datalimit``,
    ``ratelimit``, ``hub429`` or ``unknown``. Anything absent succeeds. ``ids`` maps a
    reference to the image id the runtime reports for it; anything absent reports the pinned
    id, so a test only has to name the reference it wants to diverge.
    """
    script = _prepull_script() if script is None else script
    assert "${{" not in script, (
        "the step's run block contains an Actions expression, which this harness does not "
        "expand -- it would be running a template rather than the real script"
    )

    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    bin_dir = work / "bin"
    bin_dir.mkdir(exist_ok=True)

    _write_exec(bin_dir / "docker", RUNTIME_STUB)
    _write_exec(bin_dir / "sleep", SLEEP_STUB)

    log = work / "calls.log"
    sleep_log = work / "sleeps.log"
    present_file = work / "present"
    rules_file = work / "rules.tsv"
    ids_file = work / "ids.tsv"

    log.write_text("", encoding="utf-8")
    sleep_log.write_text("", encoding="utf-8")
    present_file.write_text(
        "".join(f"{ref}\n" for ref in (present or [])), encoding="utf-8"
    )
    rules_file.write_text(
        "".join(f"{k}\t{v}\n" for k, v in (rules or {}).items()), encoding="utf-8"
    )
    ids_file.write_text(
        "".join(f"{k}\t{v}\n" for k, v in (ids or {}).items()), encoding="utf-8"
    )

    dockerfile = work / "Dockerfile"
    if dockerfile_text is None:
        dockerfile_text = (
            f"ARG BASE_IMAGE={BASE_IMAGE}\nARG BASE_IMAGE_DIGEST={BASE_IMAGE_DIGEST}\n"
            "FROM ${BASE_IMAGE} AS only\n"
        )
    dockerfile.write_text(dockerfile_text, encoding="utf-8")

    script_path = work / "step.sh"
    script_path.write_text(script, encoding="utf-8")

    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(work),
        "ATTEMPTS": str(attempts),
        "RUNTIME": "docker",
        "WRAPPER": "",
        "DOCKERFILE": str(dockerfile),
        "STUB_LOG": str(log),
        "STUB_SLEEP_LOG": str(sleep_log),
        "STUB_PRESENT": str(present_file),
        "STUB_RULES": str(rules_file),
        "STUB_IDS": str(ids_file),
        "STUB_DEFAULT_ID": ID_PINNED,
        "STUB_BLANK_IDS": "1" if blank_ids else "0",
    }
    # The shell Actions gives a composite `shell: bash` step. `-e` in particular is not
    # optional: the script relies on it, so a harness without it would be running a more
    # forgiving shell than production.
    proc = subprocess.run(  # nosec B603 — fixed interpreter, list args, no shell
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(script_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return Result(
        proc,
        [line for line in log.read_text(encoding="utf-8").splitlines() if line],
        [line for line in sleep_log.read_text(encoding="utf-8").splitlines() if line],
        [
            line
            for line in present_file.read_text(encoding="utf-8").splitlines()
            if line
        ],
    )


class TestThePrimaryRegistryIsUnchanged:
    """Case 1. ECR Public first, and a success there touches nothing else."""

    pytestmark = _REQUIRES_BASH

    def test_only_the_primary_registry_is_contacted(self, tmp_path: Path):
        result = _run(tmp_path)

        assert result.ok, (
            f"the primary answered; the step should succeed\n{result.describe()}"
        )
        assert result.pulls(PRIMARY_TAG_REF), (
            f"the step must pull the Dockerfile's own reference\n{result.describe()}"
        )
        assert result.registries_pulled == {"public.ecr.aws"}, (
            "a successful primary pull must not contact the fallback registry, but the step "
            f"pulled from {sorted(result.registries_pulled)}\n{result.describe()}"
        )

    def test_nothing_is_retagged_when_the_primary_answers(self, tmp_path: Path):
        result = _run(tmp_path)

        assert result.pulls(PRIMARY_TAG_REF), (
            f"positive evidence first: the step must have pulled\n{result.describe()}"
        )
        assert result.tags == [], (
            "the Dockerfile's reference already names the primary, so a successful primary "
            f"pull needs no local tag\n{result.describe()}"
        )

    def test_the_pinned_digest_is_fetched_by_digest(self, tmp_path: Path):
        """The content-addressed fetch is what makes a substitution impossible."""
        result = _run(tmp_path)

        assert result.pulls(PRIMARY_PIN_REF), (
            "the step must pull the pinned digest reference, not just the tag -- pulling by "
            "digest is what makes the registry unable to answer with different content\n"
            f"{result.describe()}"
        )

    def test_a_verified_local_image_short_circuits_every_pull(self, tmp_path: Path):
        """A warm runner that already holds the pinned content needs no registry at all."""
        result = _run(tmp_path, present=[PRIMARY_TAG_REF, PRIMARY_PIN_REF])

        assert result.ok, f"{result.describe()}"
        assert "already present locally at the pinned digest" in result.output, (
            f"positive evidence the short-circuit is the path taken\n{result.describe()}"
        )
        assert result.pulls() == [], (
            f"nothing should be pulled when the pinned image is already local\n{result.describe()}"
        )

    def test_a_local_image_at_the_wrong_digest_does_not_short_circuit(
        self, tmp_path: Path
    ):
        """A warm image that is not the pinned one must not be accepted on its name alone."""
        result = _run(
            tmp_path,
            present=[PRIMARY_TAG_REF],
            ids={PRIMARY_TAG_REF: ID_OTHER},
        )

        assert result.pulls(), (
            "a local image whose id is not the pinned one must send the step to the registry "
            f"rather than being accepted because its name matched\n{result.describe()}"
        )


class TestTheDataLimitFallsThroughToDockerHub:
    """Case 2. The refusal that cannot be waited out is the one the fallback is for."""

    pytestmark = _REQUIRES_BASH

    @pytest.fixture
    def result(self, tmp_path: Path) -> Result:
        return _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
        )

    def test_the_step_succeeds_via_the_fallback(self, result: Result):
        assert result.ok, (
            "a data-limit refusal on the primary must be survivable in-job\n"
            f"{result.describe()}"
        )
        assert result.pulls(FALLBACK_TAG_REF), (
            f"the fallback registry must actually be pulled from\n{result.describe()}"
        )

    def test_the_data_limit_is_not_retried(self, result: Result):
        """Measured: when a runner hits the data cap it hits it on every attempt."""
        assert len(result.pulls(PRIMARY_TAG_REF)) == 1, (
            "the monthly volume cap is not cleared by waiting, so it must cost exactly one "
            f"attempt before moving on\n{result.describe()}"
        )
        assert result.sleeps == [], (
            f"there is nothing to wait out, so nothing should sleep\n{result.describe()}"
        )

    def test_the_fallback_image_is_tagged_as_the_dockerfile_reference(
        self, result: Result
    ):
        """The build resolves `FROM ${BASE_IMAGE}`; the bytes have to be under that name."""
        assert (FALLBACK_PIN_REF, BASE_IMAGE) in result.tags, (
            f"expected the pinned Docker Hub reference to be tagged as {BASE_IMAGE}, but the "
            f"step tagged {result.tags}\n{result.describe()}"
        )
        assert BASE_IMAGE in result.present, (
            f"{BASE_IMAGE} must exist in the local store when the step exits 0, or the build "
            f"goes back to the refusing registry\n{result.describe()}"
        )

    def test_the_tag_source_is_the_digest_not_the_fallback_tag(self, result: Result):
        """Tagging from the digest keeps the local image pinned end to end."""
        sources = [src for src, _dst in result.tags]
        assert FALLBACK_TAG_REF not in sources, (
            "tagging from the fallback's tag reference would place whatever that tag happens "
            f"to resolve to; the digest reference is the pinned one\n{result.describe()}"
        )


class TestTheRateLimitRetriesBeforeFallingThrough:
    """Case 3. One quota is worth waiting on, and it is not the other one."""

    pytestmark = _REQUIRES_BASH

    @pytest.fixture
    def result(self, tmp_path: Path) -> Result:
        return _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "ratelimit", PRIMARY_PIN_REF: "ratelimit"},
            attempts=3,
        )

    def test_the_primary_is_retried_to_the_attempt_limit(self, result: Result):
        assert len(result.pulls(PRIMARY_TAG_REF)) == 3, (
            "the 1/second rate limit clears on its own, so it is worth retrying; expected 3 "
            f"attempts at attempts=3\n{result.describe()}"
        )
        assert len(result.sleeps) == 2, (
            f"three attempts means two waits between them\n{result.describe()}"
        )

    def test_the_fallback_runs_after_the_retries(self, result: Result):
        assert result.ok, f"{result.describe()}"
        assert result.pulls(FALLBACK_TAG_REF), (
            "exhausting the retries on the primary must fall through rather than fail -- the "
            f"whole point is that a second quota is probably not also spent\n{result.describe()}"
        )
        first_fallback = next(
            i for i, c in enumerate(result.calls) if c == f"pull {FALLBACK_TAG_REF}"
        )
        primary_attempts = [
            i for i, c in enumerate(result.calls) if c == f"pull {PRIMARY_TAG_REF}"
        ]
        assert max(primary_attempts) < first_fallback, (
            "the fallback must come after the primary's retries, not interleaved with them\n"
            f"{result.describe()}"
        )

    def test_docker_hub_is_not_retried_on_its_own_rate_limit(self, tmp_path: Path):
        """Docker Hub counts per window per address, so there is nothing to wait out."""
        result = _run(
            tmp_path,
            rules={
                PRIMARY_TAG_REF: "ratelimit",
                PRIMARY_PIN_REF: "ratelimit",
                FALLBACK_TAG_REF: "hub429",
                FALLBACK_PIN_REF: "hub429",
            },
            attempts=3,
        )

        assert len(result.pulls(FALLBACK_TAG_REF)) == 1, (
            "retrying Docker Hub inside one job cannot clear a per-window allowance, so it "
            f"must cost one attempt\n{result.describe()}"
        )


class TestBothRegistriesRefusing:
    """Case 4. When there is nothing left to try, say so and say what to do."""

    pytestmark = _REQUIRES_BASH

    @pytest.fixture
    def result(self, tmp_path: Path) -> Result:
        return _run(
            tmp_path,
            rules={
                PRIMARY_TAG_REF: "datalimit",
                PRIMARY_PIN_REF: "datalimit",
                FALLBACK_TAG_REF: "hub429",
                FALLBACK_PIN_REF: "hub429",
            },
        )

    def test_the_step_fails(self, result: Result):
        assert result.pulls(FALLBACK_TAG_REF), (
            f"positive evidence both registries were tried\n{result.describe()}"
        )
        assert not result.ok, (
            f"no registry served the base image, so the step must fail\n{result.describe()}"
        )

    def test_the_error_names_both_registries(self, result: Result):
        errors = [line for line in result.output.splitlines() if "::error::" in line]
        assert errors, (
            f"a failure must carry an ::error:: annotation\n{result.describe()}"
        )
        joined = "\n".join(errors)
        assert "public.ecr.aws" in joined and "docker.io" in joined, (
            "the operator reading this has to know both registries were tried, or they will "
            f"look for a fix in the one they happen to think of\n{result.describe()}"
        )

    def test_the_error_says_to_re_run(self, result: Result):
        """The remedy is a re-run landing on another address, not waiting for the month."""
        assert "RE-RUN" in result.output, (
            "both quotas are per egress address, so the actionable instruction is to re-run; "
            "an operator told to wait for the quota to reset waits days for something a "
            f"re-run fixes in minutes\n{result.describe()}"
        )


class TestAWrongDigestIsRefused:
    """Case 5. The one this whole design exists to make impossible."""

    pytestmark = _REQUIRES_BASH

    @pytest.fixture
    def primary_mismatch(self, tmp_path: Path) -> Result:
        return _run(tmp_path, ids={PRIMARY_TAG_REF: ID_OTHER})

    def test_a_primary_mismatch_fails(self, primary_mismatch: Result):
        assert primary_mismatch.pulls(PRIMARY_PIN_REF), (
            f"positive evidence the step reached the digest check\n{primary_mismatch.describe()}"
        )
        assert not primary_mismatch.ok, (
            "the tag does not resolve to the pinned digest, so the step must fail rather than "
            f"hand the build an image nobody reviewed\n{primary_mismatch.describe()}"
        )
        assert "DIGEST MISMATCH" in primary_mismatch.output, (
            f"the failure must be reported as what it is\n{primary_mismatch.describe()}"
        )

    def test_a_primary_mismatch_tags_nothing(self, primary_mismatch: Result):
        assert primary_mismatch.tags == [], (
            "a mismatched image must not be placed under the reference the build resolves; "
            f"that is the silent substitution\n{primary_mismatch.describe()}"
        )

    def test_a_primary_mismatch_does_not_try_the_fallback(
        self, primary_mismatch: Result
    ):
        """The fallback mirrors the same upstream tag, so it would report the same digest."""
        assert primary_mismatch.registries_pulled == {"public.ecr.aws"}, (
            "a digest mismatch is not a quota problem and asking Docker Hub would turn a "
            f"clear failure into a confusing one\n{primary_mismatch.describe()}"
        )

    def test_the_mismatch_message_says_what_to_do_about_a_tag_bump(
        self, primary_mismatch: Result
    ):
        """The next person to see this will be whoever bumped the tag."""
        output = primary_mismatch.output
        assert "ARG BASE_IMAGE_DIGEST" in output, (
            f"the message must name the line to edit\n{primary_mismatch.describe()}"
        )
        assert "RepoDigests" in output, (
            "the message must carry the command that produces the new value, not just say "
            f"that a new value is needed\n{primary_mismatch.describe()}"
        )
        assert "DID NOT CHANGE" in output.upper(), (
            "the message must also cover the other reading -- an unchanged tag that moved is "
            f"not a pin to update, it is something to investigate\n{primary_mismatch.describe()}"
        )

    def test_a_fallback_mismatch_is_refused_too(self, tmp_path: Path):
        """The check is per registry, not only on the primary."""
        result = _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
            ids={FALLBACK_TAG_REF: ID_OTHER},
        )

        assert result.pulls(FALLBACK_PIN_REF), (
            f"positive evidence the fallback's digest check ran\n{result.describe()}"
        )
        assert not result.ok, f"{result.describe()}"
        assert result.tags == [], (
            "a mismatched fallback image must never be tagged as the Dockerfile's reference\n"
            f"{result.describe()}"
        )

    def test_empty_image_id_is_refused(self, tmp_path: Path):
        """A runtime that answers the inspect but reports nothing must not pass the check.

        Two empty strings compare equal. This is the shape of the harness-that-never-ran
        failure, one layer down: a comparison that passes because neither side said anything.
        It is also the plausible real outcome on a runtime this action has not been tried on.
        """
        result = _run(tmp_path, blank_ids=True)

        assert result.pulls(PRIMARY_PIN_REF), (
            f"positive evidence the step got as far as comparing ids\n{result.describe()}"
        )
        assert not result.ok, (
            "an unverifiable base image must be refused, not accepted because the check could "
            f"not run\n{result.describe()}"
        )
        assert "no image id" in result.output, (
            f"the failure must name the cause as a runtime-support gap\n{result.describe()}"
        )
        assert result.tags == [], f"{result.describe()}"


class TestANonQuotaErrorFailsImmediately:
    """Case 6. The failure mode a fallback introduces, closed on purpose."""

    pytestmark = _REQUIRES_BASH

    @pytest.fixture
    def result(self, tmp_path: Path) -> Result:
        return _run(tmp_path, rules={PRIMARY_TAG_REF: "unknown"}, attempts=5)

    def test_it_fails(self, result: Result):
        assert result.pulls(PRIMARY_TAG_REF), (
            f"positive evidence a pull was attempted\n{result.describe()}"
        )
        assert not result.ok, (
            f"an unknown manifest is not fixed by trying again\n{result.describe()}"
        )

    def test_it_costs_exactly_one_attempt(self, result: Result):
        assert len(result.pulls(PRIMARY_TAG_REF)) == 1, (
            "a real error must not be retried; retrying it turns a clear failure into a slow "
            f"one\n{result.describe()}"
        )
        assert result.sleeps == [], f"{result.describe()}"

    def test_it_does_not_try_the_fallback(self, result: Result):
        assert result.registries_pulled == {"public.ecr.aws"}, (
            "trying the next registry on a real error reports a typo in the tag as a quota "
            f"problem\n{result.describe()}"
        )

    def test_the_error_says_it_was_not_a_quota(self, result: Result):
        assert "other than a registry quota" in result.output, (
            "the log has to distinguish this from the quota case, or whoever reads it goes "
            f"looking for a concurrency problem in the matrix\n{result.describe()}"
        )


class TestThePinsAreReadFromTheDockerfile:
    """Neither value may be duplicated into the action, and both must be present."""

    def test_the_action_reads_both_args_from_the_dockerfile(self):
        script = _prepull_script()
        assert "ARG BASE_IMAGE=" in script and "ARG BASE_IMAGE_DIGEST=" in script, (
            "the action must derive the tag and the digest from the Dockerfile; a copy here "
            "could leave the pre-pull pulling a different image than the build"
        )
        assert BASE_IMAGE not in script, (
            f"the action must not hardcode {BASE_IMAGE}; that is the drift the Dockerfile "
            "read exists to prevent"
        )
        assert BASE_IMAGE_DIGEST not in script, (
            "the action must not hardcode the digest either"
        )

    def test_the_dockerfile_pins_a_well_formed_index_digest(self):
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", BASE_IMAGE_DIGEST), (
            f"ARG BASE_IMAGE_DIGEST is {BASE_IMAGE_DIGEST!r}, which is not a sha256 digest"
        )

    def test_the_digest_sits_next_to_the_tag(self):
        """The visible-omission argument is a diff-context argument, so measure the distance.

        Git shows three lines of context by default. A one-line tag bump therefore only puts
        the digest in front of a reviewer if the digest is within three lines of the tag --
        which matters because Dependabot raises exactly that one-line bump here.
        """
        lines = DOCKERFILE.read_text(encoding="utf-8").splitlines()
        tag_line = next(
            i for i, line in enumerate(lines) if line.startswith("ARG BASE_IMAGE=")
        )
        digest_line = next(
            i
            for i, line in enumerate(lines)
            if line.startswith("ARG BASE_IMAGE_DIGEST=")
        )
        assert 0 < digest_line - tag_line <= 3, (
            f"ARG BASE_IMAGE is at line {tag_line + 1} and ARG BASE_IMAGE_DIGEST at line "
            f"{digest_line + 1}. More than three lines apart and a one-line tag bump's diff "
            "hunk no longer shows the digest, which is the only thing making a forgotten "
            "digest visible to a reviewer."
        )

    @_requires_bash
    def test_a_dockerfile_without_a_digest_is_refused(self, tmp_path: Path):
        """No pin means no way to establish the two registries agree, so no pre-pull."""
        result = _run(
            tmp_path,
            dockerfile_text=f"ARG BASE_IMAGE={BASE_IMAGE}\nFROM ${{BASE_IMAGE}}\n",
        )
        assert not result.ok, f"{result.describe()}"
        assert result.pulls() == [], (
            f"nothing may be pulled before the pin is known\n{result.describe()}"
        )
        assert "ARG BASE_IMAGE_DIGEST" in result.output, f"{result.describe()}"


class TestTheHarnessCanFail:
    """Controls. Without these the file could be asserting over a script that never ran."""

    pytestmark = _REQUIRES_BASH

    def test_the_frozen_single_registry_script_fails_the_fallback_assertions(
        self, tmp_path: Path
    ):
        """The pre-fallback action must not satisfy this file's central claim."""
        result = _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
            script=FROZEN_SINGLE_REGISTRY_SCRIPT,
        )

        assert not result.ok, (
            "the frozen pre-fallback script must fail on a data-limit refusal; if it passes, "
            "this harness cannot tell the fix from its absence"
        )
        assert result.pulls(FALLBACK_TAG_REF) == [], (
            "the frozen script has no fallback, so seeing one means the harness is running "
            f"something other than what it was handed\n{result.describe()}"
        )

    def test_the_frozen_script_also_fails_the_digest_assertions(self, tmp_path: Path):
        """Nothing in the pre-fallback script looks at a digest."""
        result = _run(
            tmp_path,
            ids={PRIMARY_TAG_REF: ID_OTHER},
            script=FROZEN_SINGLE_REGISTRY_SCRIPT,
        )

        assert result.ok, (
            "the frozen script accepts whatever the tag resolves to -- that is the gap the "
            f"pin closes. If this fails, the control no longer isolates the change\n{result.describe()}"
        )
        assert "DIGEST MISMATCH" not in result.output, f"{result.describe()}"

    def test_the_stub_refuses_an_invocation_it_was_not_taught(self, tmp_path: Path):
        """A stub that tolerated unknown verbs would hide the action growing a dependency."""
        result = _run(tmp_path, script="docker frobnicate 2>&1 || echo rc=$?\n")
        assert "rc=64" in result.output, (
            f"expected the stub to reject an unknown subcommand\n{result.describe()}"
        )

    def test_the_action_has_exactly_one_shell_step(self):
        """The locator resolves the step by having a `run`; more than one and it is ambiguous."""
        doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        runs = [s for s in doc["runs"]["steps"] if isinstance(s, dict) and s.get("run")]
        assert len(runs) == 1, f"found {len(runs)} shell steps in {ACTION.name}"


class TestNoPublishSurfacesAreAdded:
    """The image must never leave the job that pulled it. This repository is public."""

    def test_the_action_adds_no_cache_artifact_or_push(self):
        """Read the parsed steps, not the file text.

        The comment block names actions/cache and actions/upload-artifact in the course of
        explaining why neither is used, so a text search over the whole file reports the
        explanation as the violation. What matters is what the action *runs*.
        """
        doc = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        steps = doc["runs"]["steps"]

        used = [s.get("uses", "") for s in steps if isinstance(s, dict)]
        for forbidden in ("actions/cache", "upload-artifact", "download-artifact"):
            offenders = [u for u in used if forbidden in u]
            assert offenders == [], (
                f"{forbidden} would put the base image somewhere any read token can fetch it; "
                f"on a public repository that publishes it. Found: {offenders}"
            )

        script = _prepull_script()
        assert not re.search(r"(?m)^\s*(\S+\s+)*\S*\bpush\b", script), (
            "the step must not push the image to a registry"
        )
