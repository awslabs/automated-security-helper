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
Eight behaviours, one class each, by running the action's own shell with the container runtime
replaced by a stub that records its argv:

1. the primary answering means one registry is touched, nothing is retagged, and no base-image
   override is exported -- the common path's build argv is byte for byte what it was;
2. the primary refusing with the ``Data limit exceeded`` signature falls through to Docker Hub
   and tags the result under the exact reference the Dockerfile's ``FROM`` resolves;
3. the fallback actually REACHES the build, by exporting a digest-pinned
   ``ASH_BASE_IMAGE_OVERRIDE``, because the local tag in 2 does not reach three of the four
   runtimes. See ``TestTheFallbackReachesTheBuild`` for the measurement;
4. the primary refusing with the bare rate-limit signature retries the primary first;
5. both registries refusing fails, naming both;
6. a registry whose tag does not resolve to the pinned digest is refused, with nothing tagged
   and nothing exported;
7. a non-quota error fails on the first attempt without trying the fallback;
8. a runtime that cannot inspect a ``repo@sha256:...`` reference is still able to verify the
   pin, and a runtime that cannot answer any form of the question is still refused.

Plus one that is static rather than behavioural, because it has to be:

9. every array expansion in the step is guarded against bash's pre-4.4 ``set -u`` treatment
   of an element-less array. See ``TestTheStepRunsUnderTheBashMacOSShips`` for why no test
   that merely runs the script can establish this on a modern bash.

Cases 3, 6 and 7 are the ones that matter most. 6 is the substitution the digest pin exists to
stop. 7 is the failure mode a fallback introduces: trying the next registry on a real error
turns a clear failure into a slow one and reports a typo in the tag as a quota problem. 3 is
the one this file learned the hard way -- 2 held for months while the build it was meant to
unblock failed anyway, because a step that exits 0 having placed an image somewhere nobody
reads is indistinguishable in a log from a step that worked.

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

It runs no real runtime. The action only ever asks one for ``pull``, ``tag`` and
``image inspect --format '{{.Id}}'``, and it compares two ids that both came from the same
runtime in the same format -- so no runtime's notion of "the digest" is relied on.

The gap this file used to name here has since been measured and is now covered by stub, not by
hope. nerdctl -- which is what finch runs -- cannot inspect a ``repo@sha256:...`` reference at
all, for the reason set out on ``TestARuntimeThatRefusesADigestReference``, and the finch leg
of #672 failed on exactly that. The stub therefore models three runtimes by
``STUB_DIGEST_INSPECT``: ``docker`` (measured on docker 25.0.16: both the repository-qualified
and bare-digest forms of the argument resolve), ``nerdctl`` (read from nerdctl's source at
v2.2.2, v2.3.5 and v2.4.0: the repository-qualified form does not resolve and the bare digest
does) and ``neither`` (a runtime that answers no form, which must end in a refusal).

Still not covered: whether podman's and finch's real binaries behave as their sources say, and
whether every runtime accepts a digest reference as a ``tag`` source. The action's response to
a runtime that cannot answer is a loud failure naming the runtime and quoting what it said,
never a silently accepted image, which is the property ``test_empty_image_id_is_refused`` and
``test_a_runtime_that_answers_no_form_is_still_refused`` pin.

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
    # How this runtime answers an inspect whose argument carries a digest. `docker` is what
    # docker 25.0.16 was measured doing; `nerdctl` is what nerdctl 2.2.2/2.3.5/2.4.0 do, which
    # is to refuse `repo@sha256:...` and accept a bare `sha256:...`; `neither` is a runtime
    # that answers no form of the question, which must end in a refusal.
    case "${STUB_DIGEST_INSPECT:-docker}" in
      docker) : ;;
      nerdctl | neither)
        case "$ref" in
          *@sha256:*)
            # Verbatim shape of nerdctl's own answer: pkg/cmd/image/inspect.go keeps only
            # candidates whose tag equals the requested tag, having rewritten the empty tag a
            # digest-suffixed reference carries to `latest`, so nothing matches.
            echo "FATA[0000] 1 errors:" >&2
            echo "no such image: $ref" >&2
            exit 1
            ;;
          sha256:*)
            if [ "${STUB_DIGEST_INSPECT}" != "nerdctl" ]; then
              echo "stub: no such image: $ref" >&2
              exit 1
            fi
            # Resolve by target digest, which is what the bare form asks containerd for: the
            # first present reference pinned at this digest.
            ref="$(awk -v d="@$ref" 'index($0, d) { print; exit }' "$STUB_PRESENT")"
            [ -n "$ref" ] || { echo "stub: no such image: $1" >&2; exit 1; }
            ;;
        esac
        ;;
      *) echo "stub: unknown STUB_DIGEST_INSPECT: ${STUB_DIGEST_INSPECT}" >&2; exit 64 ;;
    esac
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

# The pre-fallback script from action.yml at 80371ea1 (PR #660). Frozen on purpose: see
# "failure mode of this harness itself". The fallback assertions must fail against it.
#
# Not quite verbatim, and the one edit is deliberate: the two `"${wrapper[@]}"` expansions
# carry the same `+` guard the shipped action now carries. ``WRAPPER`` is empty here, and on
# bash before 4.4 -- macOS ships 3.2.57 -- expanding an element-less array under `set -u` is
# an unbound variable error. Unguarded, this control dies at its first runtime call on every
# macOS leg, which makes `test_the_frozen_single_registry_script_fails_the_fallback_assertions`
# pass for the wrong reason and `test_the_frozen_script_also_fails_the_digest_assertions`
# fail outright. What this copy is frozen *for* is the absence of a fallback and of a digest
# check; the wrapper spelling is not one of the properties under control, so guarding it
# keeps the control meaningful instead of preserving a byte that only decides whether the
# control runs at all.
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

if "${wrapper[@]+"${wrapper[@]}"}" "${runtime}" image inspect "${base}" >/dev/null 2>&1; then
  echo "already present locally; not pulling"
  exit 0
fi

log="$(mktemp)"
for n in $(seq 1 "${ATTEMPTS}"); do
  echo "=== pull attempt ${n} of ${ATTEMPTS} ==="
  if "${wrapper[@]+"${wrapper[@]}"}" "${runtime}" pull "${base}" 2>&1 | tee "${log}"; then
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
        exported: dict[str, str],
    ):
        self.proc = proc
        self.calls = calls
        self.sleeps = sleeps
        self.present = present
        # What the step wrote to $GITHUB_ENV, which is how it hands the build the reference to
        # resolve. Parsed as `NAME=value` per line, the only form the step emits.
        self.exported = exported

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

    def inspects(self, ref: str | None = None) -> list[str]:
        """Every `image inspect` the step issued, as the reference it asked about."""
        prefix = "image inspect --format {{.Id}} "
        out = [c[len(prefix) :] for c in self.calls if c.startswith(prefix)]
        if ref is not None:
            out = [c for c in out if c == ref]
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
            f"exported to GITHUB_ENV: {self.exported or '(nothing)'}\n"
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
    digest_inspect: str = "docker",
    github_env: bool = True,
) -> Result:
    """Run the action's shell against the stub runtime.

    ``rules`` maps a reference to how the registry answers a pull of it: ``datalimit``,
    ``ratelimit``, ``hub429`` or ``unknown``. Anything absent succeeds. ``ids`` maps a
    reference to the image id the runtime reports for it; anything absent reports the pinned
    id, so a test only has to name the reference it wants to diverge. ``digest_inspect``
    selects which runtime's answer to a digest-bearing inspect argument the stub gives:
    ``docker``, ``nerdctl`` or ``neither``. ``github_env=False`` runs with ``GITHUB_ENV``
    unset, which is a hand-run of the script outside Actions and the one configuration in
    which the step cannot tell the build which registry answered.
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
        "STUB_DIGEST_INSPECT": digest_inspect,
    }
    # Actions always sets GITHUB_ENV for a composite `run:` step and the file already exists,
    # so the harness supplies both rather than letting the step create the file -- a test that
    # passed only because `>>` created a missing path would not be measuring production.
    github_env_file = work / "github_env"
    github_env_file.write_text("", encoding="utf-8")
    if github_env:
        env["GITHUB_ENV"] = str(github_env_file)
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
    exported: dict[str, str] = {}
    for line in github_env_file.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        name, _, value = line.partition("=")
        exported[name] = value

    return Result(
        proc,
        [line for line in log.read_text(encoding="utf-8").splitlines() if line],
        [line for line in sleep_log.read_text(encoding="utf-8").splitlines() if line],
        [
            line
            for line in present_file.read_text(encoding="utf-8").splitlines()
            if line
        ],
        exported,
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

    def test_no_base_image_override_is_exported_when_the_primary_answers(
        self, tmp_path: Path
    ):
        """The common path must leave the build's argv byte for byte what it already was.

        The fallback hands the build a rewritten reference through
        ``ASH_BASE_IMAGE_OVERRIDE``. Exporting it when nothing was rewritten would add a
        ``--build-arg BASE_IMAGE=`` to every container build in the repository, on the path
        that is supposed to be unchanged, and would make the Dockerfile's own default
        unreachable in CI.
        """
        result = _run(tmp_path)

        assert result.pulls(PRIMARY_TAG_REF), (
            f"positive evidence first: the step must have pulled\n{result.describe()}"
        )
        assert "ASH_BASE_IMAGE_OVERRIDE" not in result.exported, (
            "the primary answered, so the Dockerfile's own ARG BASE_IMAGE default is correct "
            f"and nothing should redirect it\n{result.describe()}"
        )

    def test_the_warm_short_circuit_exports_no_override_either(self, tmp_path: Path):
        """The other path that never reaches a fallback."""
        result = _run(tmp_path, present=[PRIMARY_TAG_REF, PRIMARY_PIN_REF])

        assert "already present locally at the pinned digest" in result.output, (
            f"positive evidence the short-circuit is the path taken\n{result.describe()}"
        )
        assert result.exported == {}, (
            "an image already local at the pinned digest is under the primary reference, so "
            f"there is nothing to redirect\n{result.describe()}"
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


class TestTheFallbackReachesTheBuild:
    """The local tag is not how the build finds the fallback image. Measured, not assumed.

    Why this class exists
    ---------------------
    The first fallback pulled from Docker Hub, tagged the result under the ECR reference, and
    announced that "the build resolves it from the local store without touching
    public.ecr.aws". That was true of plain ``docker build`` and podman and false of the two
    runtimes driving BuildKit. From the finch leg's own log -- the retag succeeded, the build
    started 2.07s later and died at the Dockerfile's first instruction still asking ECR
    Public::

        >>> FROM ${BASE_IMAGE} AS uv-reqs
        error: failed to solve: public.ecr.aws/docker/library/python:3.12-slim-bookworm:
        failed to resolve source metadata for ...: 429 Too Many Requests

    BuildKit's OCI worker builds its resolver with ``ImageStore: nil, // explicitly``, so
    there is no local store for ``FROM`` to consult and nothing to push an image into. That
    covers nerdctl, finch, and ``docker buildx build`` on a ``docker-container`` driver --
    which is what every docker cell in this repository runs, because run-scan-test sets up
    ``docker/setup-buildx-action`` (driver defaults to ``docker-container``) and exports
    ``ACTIONS_RUNTIME_TOKEN``, which switches ASH's build to ``docker buildx build --load``.

    So the step exports ``ASH_BASE_IMAGE_OVERRIDE`` and the three build entrypoints pass it
    through as ``--build-arg BASE_IMAGE=``. Changing what ``FROM`` asks for is uniform across
    every runtime, because no runtime has a say in what a build-arg names.

    What is measured here and what is measured elsewhere
    ---------------------------------------------------
    This class pins the part that is this repository's: the variable is exported, digest-
    pinned, only on the fallback path, and the message no longer claims an outcome the step
    cannot guarantee. Whether BuildKit ignores a local tag is a property of BuildKit, so
    asserting it here would be measuring BuildKit rather than the action. That was measured out
    of band, and the measurement is recorded in
    ``tests/unit/test_base_image_override_reaches_every_build_entrypoint.py`` -- four runs of
    one instrument, including the control that proves the instrument can see a local tag at
    all.

    Not covered here or there: nerdctl, finch and podman have no binary on the machine this
    was developed on, so their rows in the table above rest on the CI log and on their sources.
    Only CI can close that.
    """

    pytestmark = _REQUIRES_BASH

    @pytest.fixture
    def result(self, tmp_path: Path) -> Result:
        return _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
        )

    def test_the_build_is_told_which_registry_answered(self, result: Result):
        assert result.ok, f"{result.describe()}"
        assert result.exported.get("ASH_BASE_IMAGE_OVERRIDE") == FALLBACK_PIN_REF, (
            "the fallback has to reach the build by changing what FROM asks for, because the "
            "BuildKit runtimes never consult the local store; expected "
            f"ASH_BASE_IMAGE_OVERRIDE={FALLBACK_PIN_REF}\n{result.describe()}"
        )

    def test_the_exported_reference_is_digest_pinned(self, result: Result):
        """More pinned than the primary path, not less.

        ``FROM ${BASE_IMAGE}`` accepts a digest-suffixed value; only ``docker tag`` refuses
        one, which is why ARG BASE_IMAGE_DIGEST is a separate Dockerfile line. So the fallback
        can hand the build content rather than a name, and exporting the fallback's *tag*
        would throw that away for nothing.
        """
        override = result.exported.get("ASH_BASE_IMAGE_OVERRIDE", "")
        assert override.endswith(f"@{BASE_IMAGE_DIGEST}"), (
            "the exported reference must carry the pinned digest, so that a Docker Hub tag "
            f"moving between the check and the build cannot change the base image\n"
            f"{result.describe()}"
        )
        assert override != FALLBACK_TAG_REF, (
            f"exporting the fallback's tag would be less pinned than the digest that was "
            f"just verified\n{result.describe()}"
        )

    def test_the_notice_no_longer_claims_the_local_store_resolves_it(
        self, result: Result
    ):
        """The exact sentence that made a broken path look healthy for hours.

        Asserted as an absence rather than left to review, because it exited 0 and read as a
        success: nothing about the log said the build was about to go back to the registry
        that had just refused.
        """
        assert "resolves it from the local store" not in result.output, (
            "this step cannot guarantee that any builder resolves FROM from the local store, "
            "and claiming it is what hid the finch failure. State the mechanism actually "
            f"relied on instead\n{result.describe()}"
        )

    def test_the_notice_names_the_mechanism_it_does_rely_on(self, result: Result):
        assert "ASH_BASE_IMAGE_OVERRIDE" in result.output, (
            "an operator reading this log has to be able to see how the fallback reaches the "
            f"build, so the notice has to name the variable\n{result.describe()}"
        )

    def test_the_local_tag_is_kept_as_a_second_layer(self, result: Result):
        """Demoted, not removed.

        Plain ``docker build`` and podman do resolve FROM from the local store, so the tag is
        what keeps any consumer that never reads ASH_BASE_IMAGE_OVERRIDE working on those two.
        Dropping it would trade a working path for tidiness.
        """
        assert (FALLBACK_PIN_REF, BASE_IMAGE) in result.tags, (
            f"the local tag under {BASE_IMAGE} is still worth its one metadata write\n"
            f"{result.describe()}"
        )

    def test_a_refused_fallback_exports_nothing(self, tmp_path: Path):
        """Nothing may be handed to the build on a path that ended in a refusal."""
        result = _run(
            tmp_path,
            rules={
                PRIMARY_TAG_REF: "datalimit",
                PRIMARY_PIN_REF: "datalimit",
                FALLBACK_TAG_REF: "hub429",
                FALLBACK_PIN_REF: "hub429",
            },
        )

        assert not result.ok, (
            f"both registries refused; the step must fail\n{result.describe()}"
        )
        assert result.exported == {}, (
            "no registry served the image, so redirecting the build at one of them would "
            f"point it at a reference that is not in the local store\n{result.describe()}"
        )

    def test_a_fallback_at_the_wrong_digest_exports_nothing(self, tmp_path: Path):
        """The substitution the pin exists to stop must not be handed to the build either."""
        result = _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
            ids={FALLBACK_TAG_REF: ID_OTHER},
        )

        assert not result.ok, (
            f"a fallback whose tag is not the pinned content must be refused\n"
            f"{result.describe()}"
        )
        assert result.exported == {}, (
            "the digest check failed, so the build must not be redirected at the registry "
            f"that offered the wrong content\n{result.describe()}"
        )

    def test_without_github_env_the_degradation_is_announced(self, tmp_path: Path):
        """A hand-run outside Actions cannot export, and must say what that costs.

        Not an error: running this script directly is a legitimate way to use it. But it is
        exactly the state the retag alone used to be mistaken for, so the warning names the
        runtimes that will still fail rather than merely reporting an unset variable.
        """
        result = _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
            github_env=False,
        )

        assert result.ok, (
            f"the image was sourced and tagged; that is still a success\n{result.describe()}"
        )
        assert "::warning::" in result.output and "GITHUB_ENV" in result.output, (
            "the step could not tell the build which registry answered, which is the failure "
            f"mode this whole change exists to remove; it has to say so\n{result.describe()}"
        )
        for runtime in ("nerdctl", "finch", "buildx"):
            assert runtime in result.output, (
                f"the warning has to name {runtime} as still affected, or whoever reads it "
                f"cannot tell whether their own leg is broken\n{result.describe()}"
            )

    def test_the_exported_line_cannot_carry_a_second_variable(self, tmp_path: Path):
        """GITHUB_ENV is line-oriented, so one value per line is a property worth pinning."""
        result = _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
        )

        assert list(result.exported) == ["ASH_BASE_IMAGE_OVERRIDE"], (
            "the step must write exactly one variable; anything else means a value carried a "
            f"newline into an environment every later step in the job reads\n"
            f"{result.describe()}"
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


class TestARuntimeThatRefusesADigestReference:
    """The finch failure. A runtime can pull `repo@sha256:...` and still not inspect it.

    Measured cause, from nerdctl's own resolver rather than from finch: for a digest-suffixed
    reference ``pkg/cmd/image/inspect.go`` ends up comparing the candidate's tag against
    ``latest`` -- the empty tag such a reference carries is rewritten to ``latest`` on the
    requested side instead of being accepted on the candidate side -- so nothing matches unless
    a ``repo:latest`` record happens to sit at that digest. Present identically at v2.2.2
    (finch 1.19.0's bundled nerdctl), v2.3.5 (``scripts/setup-nerdctl-linux.sh``'s) and
    v2.4.0. A bare ``sha256:...`` argument takes a different branch and does resolve, so that
    is the second form this step is willing to ask.
    """

    pytestmark = _REQUIRES_BASH

    def test_the_step_succeeds_where_only_the_bare_digest_resolves(
        self, tmp_path: Path
    ):
        result = _run(tmp_path, digest_inspect="nerdctl")

        assert result.pulls(PRIMARY_PIN_REF), (
            f"positive evidence the step reached the digest fetch\n{result.describe()}"
        )
        assert result.ok, (
            "the pinned content is in the local store and the runtime can be asked for its id; "
            f"refusing here would be the bug this closes\n{result.describe()}"
        )

    def test_the_repository_form_is_asked_first_and_the_bare_digest_only_after(
        self, tmp_path: Path
    ):
        """Order matters: the first form is the one docker answers."""
        result = _run(tmp_path, digest_inspect="nerdctl")
        asked = result.inspects()

        assert PRIMARY_PIN_REF in asked, (
            f"the repository-qualified form must still be asked first\n{result.describe()}"
        )
        assert BASE_IMAGE_DIGEST in asked, (
            "the step must fall back to the bare digest when the repository-qualified form "
            f"answers nothing\n{result.describe()}"
        )
        assert asked.index(PRIMARY_PIN_REF) < asked.index(BASE_IMAGE_DIGEST), (
            f"the bare digest must be a fallback, not the first choice\n{result.describe()}"
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            pytest.param({}, id="cold-runner"),
            pytest.param(
                {"present": [PRIMARY_TAG_REF, PRIMARY_PIN_REF]}, id="warm-at-the-pin"
            ),
        ],
    )
    def test_the_docker_path_never_asks_the_bare_digest(
        self, tmp_path: Path, kwargs: dict
    ):
        """The measured-working runtime is asked nothing new whenever its answer matters."""
        result = _run(tmp_path, **kwargs)

        assert result.ok and result.inspects(PRIMARY_PIN_REF), (
            f"positive evidence the docker path ran and compared ids\n{result.describe()}"
        )
        assert result.inspects(BASE_IMAGE_DIGEST) == [], (
            "the repository-qualified form answered, so there is no second question to ask, "
            f"and asking it anyway would be a new dependency\n{result.describe()}"
        )

    def test_the_bare_digest_is_reached_only_after_the_first_form_answers_nothing(
        self, tmp_path: Path
    ):
        """The one docker case that does reach the second form, pinned rather than a surprise.

        A runner holding the tag at some other digest: the repository-qualified form answers
        nothing because that content is not local, so the bare form is tried and also answers
        nothing. Both are local, networkless lookups, and the run ends exactly where it ended
        before -- on the mismatch, after pulling.
        """
        result = _run(
            tmp_path, present=[PRIMARY_TAG_REF], ids={PRIMARY_TAG_REF: ID_OTHER}
        )

        assert result.inspects(BASE_IMAGE_DIGEST) == [BASE_IMAGE_DIGEST], (
            "the bare form must be asked exactly once here -- never before the "
            f"repository-qualified form, and never twice\n{result.describe()}"
        )
        assert not result.ok and "DIGEST MISMATCH" in result.output, (
            f"and the outcome is the one the pin exists to produce\n{result.describe()}"
        )

    def test_a_moved_tag_is_still_refused_on_that_runtime(self, tmp_path: Path):
        """The fallback form must not become a way to pass the digest check."""
        result = _run(
            tmp_path, ids={PRIMARY_TAG_REF: ID_OTHER}, digest_inspect="nerdctl"
        )

        assert result.pulls(PRIMARY_PIN_REF), (
            f"positive evidence ids were compared\n{result.describe()}"
        )
        assert not result.ok, (
            f"a tag that does not resolve to the pin must be refused\n{result.describe()}"
        )
        assert "DIGEST MISMATCH" in result.output, f"{result.describe()}"
        assert result.tags == [], f"{result.describe()}"

    def test_the_fallback_registry_still_works_on_that_runtime(self, tmp_path: Path):
        """The whole point of the action has to keep working, not just the happy path."""
        result = _run(
            tmp_path,
            rules={PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"},
            digest_inspect="nerdctl",
        )

        assert result.ok, f"{result.describe()}"
        assert result.tags == [(FALLBACK_PIN_REF, BASE_IMAGE)], (
            "the fallback's bytes still have to land under the reference the Dockerfile's "
            f"FROM resolves\n{result.describe()}"
        )

    def test_a_runtime_that_answers_no_form_is_still_refused(self, tmp_path: Path):
        """Adding a second spelling must not turn the unsupported case into a pass."""
        result = _run(tmp_path, digest_inspect="neither")

        assert result.pulls(PRIMARY_PIN_REF), (
            f"positive evidence both pulls happened before the check\n{result.describe()}"
        )
        assert not result.ok, (
            "no form of the question answered, so the pin is unchecked and the image must "
            f"not be handed to the build\n{result.describe()}"
        )
        assert "no image id" in result.output, f"{result.describe()}"
        assert result.tags == [], f"{result.describe()}"

    def test_the_refusal_names_the_reference_that_went_unanswered(self, tmp_path: Path):
        """Both references in one message left the finch failure ambiguous.

        The tag resolved there and the pinned reference did not, which is the whole shape of
        the problem, and the message as written could not say so.
        """
        result = _run(tmp_path, digest_inspect="neither")

        assert not result.ok, f"{result.describe()}"
        assert f"no image id for {PRIMARY_PIN_REF}" in result.output, (
            "the tag answered and the pinned reference did not, so the message must say that "
            f"rather than naming both\n{result.describe()}"
        )
        assert f"no image id for {PRIMARY_TAG_REF}" not in result.output, (
            f"and it must not accuse the reference that answered\n{result.describe()}"
        )

    def test_the_refusal_carries_the_runtimes_own_explanation(self, tmp_path: Path):
        """The original failure said the id was empty and nothing about why.

        That stream was going to /dev/null. A refusal that does not carry it costs whoever
        reads the log a round trip through a runtime they may not have.
        """
        result = _run(tmp_path, digest_inspect="neither")

        assert not result.ok, f"{result.describe()}"
        assert "no such image" in result.output, (
            "the runtime's own reason for answering nothing has to reach the log, or the next "
            f"unsupported runtime is diagnosed the same slow way\n{result.describe()}"
        )
        assert f"--format '{{{{.Id}}}}' {PRIMARY_PIN_REF}" in result.output, (
            "and the log has to say which invocation produced it, since the step asks about "
            f"more than one reference\n{result.describe()}"
        )


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

    def test_a_mutant_that_proceeds_on_an_unverifiable_image_is_caught(
        self, tmp_path: Path
    ):
        """The tempting weakening, applied on purpose, must not survive the refusal test.

        "If we cannot compare the ids, carry on" is the one-line change that would have turned
        the finch leg green, and it is the change this file exists to make impossible. So the
        mutation is that change and not an arbitrary break: skip the comparison when either id
        is missing, rather than refusing.
        """
        script = _prepull_script()
        mutant, refusal_subs = re.subn(
            r'if \[ -z "\$\{tag_id\}" \] \|\| \[ -z "\$\{pin_id\}" \]; then',
            'if [ -z "${tag_id}" ] && [ -z "${pin_id}" ] && false; then',
            script,
        )
        mutant, compare_subs = re.subn(
            r'if \[ "\$\{tag_id\}" != "\$\{pin_id\}" \]; then',
            'if [ -n "${tag_id}" ] && [ -n "${pin_id}" ] '
            '&& [ "${tag_id}" != "${pin_id}" ]; then',
            mutant,
        )
        assert (refusal_subs, compare_subs) == (1, 1), (
            "the mutation matched nothing, so this control is checking a script it did not "
            f"change. Re-derive the patterns from the action. Substitutions: {refusal_subs} "
            f"refusal, {compare_subs} comparison"
        )

        weakened = _run(tmp_path, script=mutant, digest_inspect="neither")
        real = _run(tmp_path, digest_inspect="neither")

        assert weakened.ok, (
            "the mutant is supposed to accept the unverified image; if it does not, the "
            "mutation is not the one described and the control proves nothing\n"
            f"{weakened.describe()}"
        )
        assert not real.ok, (
            "and the shipped script must refuse the same input -- that gap is the whole "
            f"assertion\n{real.describe()}"
        )

    def test_a_mutant_that_only_retags_is_caught(self, tmp_path: Path):
        """The state the action was actually in, applied on purpose.

        The shipped action before this change pulled from Docker Hub, tagged the result under
        the ECR reference, and told nobody. That exited 0 and the build then died at
        ``FROM ${BASE_IMAGE}`` still asking the registry that had refused. So the mutation is
        that exact regression -- drop the export, keep the retag -- and the control is that
        ``TestTheFallbackReachesTheBuild`` must be able to tell the two apart.
        """
        script = _prepull_script()
        mutant, subs = re.subn(
            r'printf \'%s\\n\' "ASH_BASE_IMAGE_OVERRIDE=\$\{override\}" '
            r'>> "\$\{GITHUB_ENV\}"',
            ":",
            script,
        )
        assert subs == 1, (
            "the mutation matched nothing, so this control is checking a script it did not "
            f"change. Re-derive the pattern from the action. Substitutions: {subs}"
        )

        fallback = {PRIMARY_TAG_REF: "datalimit", PRIMARY_PIN_REF: "datalimit"}
        weakened = _run(tmp_path, rules=fallback, script=mutant)
        real = _run(tmp_path, rules=fallback)

        assert weakened.ok and weakened.tags, (
            "the mutant still pulls and still retags, which is precisely why the regression "
            f"was invisible; if it fails outright the control proves nothing\n"
            f"{weakened.describe()}"
        )
        assert "ASH_BASE_IMAGE_OVERRIDE" not in weakened.exported, (
            f"the mutation is supposed to remove the export\n{weakened.describe()}"
        )
        assert real.exported.get("ASH_BASE_IMAGE_OVERRIDE") == FALLBACK_PIN_REF, (
            "and the shipped script must export it -- that gap is the whole assertion, and it "
            f"is the difference between a green step and a build that works\n"
            f"{real.describe()}"
        )

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


# ${name[@]} or ${name[*]} with a bare name subscript -- an array expansion. A numeric
# subscript such as ${PIPESTATUS[0]} is not one of these and is not matched, and neither is
# "$@", which nounset has always exempted.
_ARRAY_EXPANSION = re.compile(r"\$\{([A-Za-z_]\w*)\[([@*])\]\}")

# The same expansion wrapped in its own `+` guard: ${name[@]+"${name[@]}"}. The inner
# quotes are optional here only so the check does not dictate a spelling it does not need
# to; the shipped action quotes them.
_GUARDED_ARRAY_EXPANSION = re.compile(
    r"\$\{(?P<name>[A-Za-z_]\w*)\[(?P<sub>[@*])\]\+"
    r'"?\$\{(?P=name)\[(?P=sub)\]\}"?\}'
)


def _shell_code_only(script: str) -> str:
    """``script`` with whole-line ``#`` comments removed.

    Needed for the same reason ``test_the_action_adds_no_cache_artifact_or_push`` reads the
    parsed steps rather than the file text: the action explains this very rule in prose, and
    quotes bash's CHANGES entry verbatim, so a scan over the raw text reports the
    explanation as the violation.

    Whole-line only, which is the honest limit: an unguarded expansion written in a trailing
    comment would still be reported. That false positive costs one reworded comment to clear,
    and it is worth having rather than parsing shell quoting to work out where a ``#`` really
    does start a comment. An unguarded expansion in *code* on a line that also carries a
    trailing comment is still caught, and ``${base##*:}`` is untouched because its ``#`` is
    not the first character of the line.
    """
    return "\n".join(
        line for line in script.split("\n") if not line.lstrip().startswith("#")
    )


def _unguarded_array_expansions(script: str) -> list[str]:
    """Every array expansion in ``script``'s code that is not wrapped in a ``+`` guard."""
    stripped = _GUARDED_ARRAY_EXPANSION.sub("", _shell_code_only(script))
    return [f"${{{name}[{sub}]}}" for name, sub in _ARRAY_EXPANSION.findall(stripped)]


class TestTheStepRunsUnderTheBashMacOSShips:
    """No array expansion may be unguarded, because macOS bash is 3.2 and `set -u` is on.

    WHY. ``runner-wrapper`` is empty for docker and podman, so ``wrapper`` is an array with
    no elements on most legs. bash before 4.4 treats expanding an element-less array under
    ``set -u`` as an unbound variable and exits; from bash's CHANGES for 4.4-rc2, under
    "3. New Features in Bash":

        Using ${a[@]} or ${a[*]} with an array without any assigned elements when the
        nounset option is enabled no longer throws an unbound variable error.

    macOS ships 3.2.57 -- Apple stopped at the last GPLv2 release -- so the unguarded form
    is fatal there and fine everywhere else. Measured on #672: all ten ``PyTest - macos-*``
    legs died with ``step.sh: line 93: wrapper[*]: unbound variable`` before issuing a single
    runtime call, and every assertion about pulls and retags failed downstream.

    WHAT THIS PROVES, AND WHAT IT DOES NOT. It is a static check, and it has to be, because
    the machines this suite runs on outside macOS have bash 4.4 or newer: on those the
    unguarded code is correct, so no test that merely *runs* the script can catch this.
    ``BASH_COMPAT`` does not help -- measured on 5.2.15, every level from 31 to 44 still
    accepts the unguarded empty expansion, so the 4.4 change is not gated on the compat
    level and cannot be replayed.

    So this proves only that no unguarded expansion survives in the script, which is enough
    to make the 3.2 rule unreachable. It does not prove the guarded form behaves correctly
    on 3.2 -- that rests on ``${p+word}`` being exempt from nounset, which is what the 4.4
    entry above scopes its change *away* from. It does not check whether each array can
    actually be empty; it is deliberately blunt and would flag one that never is. And it
    says nothing about any other bash 4.x-only construct: nothing here would catch a
    ``declare -A`` or a ``mapfile``. It is scoped to this action's shell, not to the other
    composite actions in the repository.
    """

    def test_no_array_expansion_in_the_step_is_unguarded(self):
        script = _prepull_script()
        assert _unguarded_array_expansions(script) == [], (
            "these array expansions are unguarded, and each is an `unbound variable` exit "
            "on macOS's bash 3.2 whenever the array is empty -- which `wrapper` is on every "
            'docker and podman leg. Spell them ${name[@]+"${name[@]}"}: '
            f"{_unguarded_array_expansions(script)}"
        )

    def test_the_step_really_does_expand_some_arrays(self):
        """Guard against the check passing because it matched nothing at all."""
        guarded = _GUARDED_ARRAY_EXPANSION.findall(_shell_code_only(_prepull_script()))
        assert len(guarded) >= 4, (
            "the step is expected to expand `wrapper` four times -- once as argv and three "
            "times into a message -- so finding fewer guarded expansions than that means "
            f"this check is looking at something other than the action. Found: {guarded}"
        )

    def test_the_frozen_control_script_is_guarded_too(self):
        """The pre-fallback control has to be able to run on macOS or it controls nothing.

        Unguarded it dies at its first runtime call, which satisfies
        ``test_the_frozen_single_registry_script_fails_the_fallback_assertions`` for the
        wrong reason and breaks its sibling outright.
        """
        assert _unguarded_array_expansions(FROZEN_SINGLE_REGISTRY_SCRIPT) == [], (
            "the frozen control expands an array unguarded, so on macOS it exits before it "
            "reaches the behaviour it is frozen to demonstrate: "
            f"{_unguarded_array_expansions(FROZEN_SINGLE_REGISTRY_SCRIPT)}"
        )

    def test_the_check_detects_an_unguarded_expansion(self):
        """The control. A detector that matches nothing passes every input.

        The input is the shipped script with the guards removed, rather than a hand-written
        sample, so what this proves is that the check discriminates the defect as it was
        actually written from the fix as it was actually applied.
        """
        code = _shell_code_only(_prepull_script())
        unguarded, subs = _GUARDED_ARRAY_EXPANSION.subn(
            lambda m: f"${{{m.group('name')}[{m.group('sub')}]}}", code
        )
        assert subs >= 4, (
            "un-guarding matched fewer sites than the action has, so this control is built "
            f"from a script it did not change. Substitutions: {subs}"
        )
        found = _unguarded_array_expansions(unguarded)
        assert len(found) == subs, (
            "the check must report every site whose guard was removed, and reported "
            f"{len(found)} of {subs}: {found}"
        )
