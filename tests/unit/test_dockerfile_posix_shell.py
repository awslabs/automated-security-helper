# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every RUN in every Dockerfile must be POSIX sh, and this is what enforces it.

Why this exists
---------------
The Dockerfile used to declare ``SHELL ["/bin/bash", "-c"]``. buildah honours that
only in ``docker`` image format; in OCI format it discards it and says so once per
instruction. So ``RUN`` executed under bash on docker and under ``/bin/sh`` -- dash
in this base image -- on podman and finch.

That produced the worst possible distribution for a defect: correct on the runtime
most people develop against, silently wrong on the two used in CI and by anyone who
picked a different runtime. Measured on run 35177045049, job 105060929678:

    [2/3] STEP 44/58: RUN set -uex; if [[ "${OFFLINE}" == "YES" ]]; then ...
    + [[ NO == YES ]]
    /bin/sh: 1: [[: not found
    [2/3] STEP 45/58: ARG TRIVY_VERSION="v0.69.3"

The build continued and the image was published. Two things made it silent. The
``set -x`` trace printed an evaluated-looking comparison, because dash expands
before it execs, so the log reads as a test that ran and was false. And the failing
command was the *condition of an* ``if``, which under ``set -e`` is a false branch
rather than an error -- so ``set -uex`` did not abort.

The consequence was not cosmetic: with ``OFFLINE=YES`` the same thing happens, since
``[[`` is absent whatever the variable holds. Offline images built with podman or
finch got no grype database and no semgrep or opengrep rules cache. No CI leg caught
it because the only offline cell in the scan matrix is ``oci-runner: docker``.

What this test does and does not buy
------------------------------------
It is a text check, not a shell. It cannot prove a RUN is POSIX; it can only reject
the constructs that are known to differ, which is why the fix also removed the
``SHELL`` directive so all three runtimes agree. Two properties make it worth having
anyway: it runs in every unit-test leg with no container, and it names the specific
construct and the reason, so the next person does not have to rediscover buildah's
behaviour from a 57-line warning stream.

What was rejected
-----------------
1. Forcing ``--format docker`` in ``run_ash_container`` so SHELL is honoured. It
   fixes CI and not a hand-run ``podman build``, it changes the published image
   format for unrelated reasons, and it leaves the Dockerfile depending on a
   directive that one supported runtime ignores.
2. ``hadolint``. It has no rule for this: DL4006 is about pipefail and assumes you
   *have* set SHELL, which is the opposite of the contract here. Adding a linter and
   a container image to check one property this file already knows how to check is a
   worse trade.
3. Asserting the shell from inside the build (a RUN that fails if ``$BASH_VERSION``
   is unset). That tests the runtime rather than the source, so it can only fail
   after someone has already built an image, and it cannot say which line is wrong.

Known limitations
-----------------
* Regex probes, so a bashism spelled unusually can slip through -- ``eval`` of a
  constructed ``[[`` for instance. The probes cover the forms that appear in
  practice, and :class:`TestTheProbesActuallyFire` is the control that they fire at
  all.
* Comments inside a RUN's line continuations are scanned along with the command,
  because a ``\``-continued RUN has no comment syntax of its own. A commented-out
  bashism inside a RUN is therefore a false positive; write it outside the RUN.
* Only ``RUN`` is checked. ``CMD``/``ENTRYPOINT`` in exec form name their
  interpreter explicitly, and in shell form they run at container start under
  ``/bin/sh`` on every runtime, so they never had the divergence this guards.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every Dockerfile whose RUN lines this contract covers. The generated
# automated_security_helper/assets/Dockerfile is deliberately absent: hatch_build.py
# derives it from the root one by rewriting COPY paths only, so it cannot introduce a
# bashism the root file does not have, and it does not exist in a fresh checkout.
DOCKERFILES = [
    REPO_ROOT / "Dockerfile",
    REPO_ROOT / "deploy/terraform/modules/ash-image-pipeline/files/wrapper.Dockerfile",
    REPO_ROOT / "deploy/terraform/modules/codecommit-gate/files/gate.Dockerfile",
]

# (name, regex, why /bin/sh cannot run it)
BASHISMS = [
    (
        "[[ ]]",
        re.compile(r"(^|[;&|(}\s])\[\[(\s|$)"),
        (
            "bash keyword. dash says '[[: not found', and as an if-condition that is a "
            "false branch under set -e rather than an error"
        ),
    ),
    (
        "== inside [ ]",
        re.compile(r"(^|[;&|(}\s])\[\s[^]]*\s==\s"),
        "POSIX test(1) compares with '='; dash's [ rejects '==' as an unexpected operator",
    ),
    (
        "source",
        re.compile(r"(^|[;&|(}\s])source\s+\S"),
        "dash has no 'source' builtin; use '.'",
    ),
    (
        "array assignment",
        re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*=\("),
        "dash has no arrays",
    ),
    (
        "${var,,} / ${var^^}",
        re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(,,|\^\^)"),
        "bash case modification; dash reports 'Bad substitution'",
    ),
    (
        "${var/x/y}",
        re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*/"),
        "bash pattern replacement; dash reports 'Bad substitution'",
    ),
    (
        "${!var}",
        re.compile(r"\$\{!"),
        "bash indirect expansion; dash reports 'Bad substitution'",
    ),
    (
        "process substitution",
        re.compile(r"(^|[\s;&|(])[<>]\("),
        "bash only",
    ),
    (
        "&> redirect",
        re.compile(r"&>"),
        "bash only; dash parses it as background-then-redirect and the exit status differs",
    ),
    (
        "function keyword",
        re.compile(r"(^|[;&|(}\s])function\s+\w+\s*(\(\)|\{)"),
        "bash only; POSIX form is 'name() { ... }'",
    ),
    (
        "set -o pipefail",
        # -o may be its own word or bundled into a cluster, as in `set -euo pipefail`.
        re.compile(
            r"(^|[;&|(}\s])set\s+(-[a-zA-Z]*o[a-zA-Z]*\s+pipefail|(-[a-zA-Z]+\s+)*-o\s+pipefail)"
        ),
        (
            "not a dash option; dash exits with 'Illegal option -o pipefail'. Use "
            "assets/with-retry.sh, which runs its argument under 'bash -o pipefail -c'"
        ),
    ),
    (
        "here-string <<<",
        re.compile(r"<<<"),
        "bash only",
    ),
    (
        "(( )) as a command",
        # $(( )) is POSIX arithmetic expansion and must not match; (( )) alone is bash.
        re.compile(r"(^|[^$\w])\(\([^)]*\)\)"),
        "bash only. '$(( ))' arithmetic expansion is POSIX and is fine",
    ),
    (
        "brace expansion",
        # Shell-word alternation only. Excludes JSON, which carries quotes and colons.
        re.compile(r"\{[A-Za-z0-9._*/@=-]+(,[A-Za-z0-9._*/@=-]+)+\}"),
        (
            "bash only; dash passes the braces through literally, so 'mkdir -p a/{b,c}' "
            "creates a directory named '{b,c}'"
        ),
    ),
    (
        "echo -e",
        re.compile(r"(^|[;&|(}\s])echo\s+(-[a-zA-Z]+\s+)*-e\b"),
        (
            "dash's echo interprets escapes by default and prints '-e' as a literal argument; "
            "use printf"
        ),
    ),
    (
        "local",
        re.compile(r"(^|[;&|(}\s])local\s+\S"),
        "not POSIX. dash happens to support it, but it is unspecified and other /bin/sh do not",
    ),
    (
        "pushd / popd",
        re.compile(r"(^|[;&|(}\s])(pushd|popd)(\s|$)"),
        "bash only; use 'cd' in a subshell",
    ),
    (
        "trap ... ERR",
        re.compile(r"trap\s+.*\sERR(\s|$)"),
        "bash only; ERR is not a POSIX trap condition",
    ),
]


def run_instructions(path: Path):
    """Yield ``(line_number, joined_command)`` for each RUN, continuations folded in.

    A ``\\``-continued RUN is one command to the shell, so the probes have to see it
    as one string -- a bashism split across two physical lines would otherwise match
    neither.
    """
    lines = path.read_text().splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if re.match(r"^RUN\s", stripped):
            start = index + 1
            parts = [stripped]
            while parts[-1].rstrip().endswith("\\") and index + 1 < len(lines):
                index += 1
                parts.append(lines[index].strip())
            joined = " ".join(p.rstrip().rstrip("\\").strip() for p in parts)
            yield start, joined
        index += 1


def _findings(text_by_line):
    return [
        (line_no, name, why, command)
        for line_no, command in text_by_line
        for name, probe, why in BASHISMS
        if probe.search(command)
    ]


class TestEveryRunIsPosixSh:
    @pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.name)
    def test_no_run_instruction_uses_a_bashism(self, dockerfile: Path):
        assert dockerfile.is_file(), f"{dockerfile} is missing; update DOCKERFILES"

        findings = _findings(run_instructions(dockerfile))

        assert not findings, "\n".join(
            [
                (
                    f"{dockerfile.relative_to(REPO_ROOT)} has {len(findings)} RUN "
                    f"instruction(s) that /bin/sh cannot run. buildah discards SHELL in "
                    f"OCI format, so these are silently skipped under podman and finch "
                    f"while working under docker:"
                )
            ]
            + [
                f"  line {line_no}: {name} -- {why}\n    {command[:160]}"
                for line_no, name, why, command in findings
            ]
        )

    def test_the_root_dockerfile_declares_no_bash_shell(self):
        """A `SHELL ["/bin/bash", ...]` here would restore the divergence.

        Not a style preference. With it, docker runs RUN under bash and buildah runs
        it under sh, so the test above stops describing what actually executes on two
        of the three supported runtimes.
        """
        offenders = [
            (i, line)
            for i, line in enumerate(
                (REPO_ROOT / "Dockerfile").read_text().splitlines(), 1
            )
            if re.match(r"^\s*SHELL\s", line)
        ]
        assert not offenders, (
            "Dockerfile sets SHELL: "
            + "; ".join(f"line {i}: {line.strip()}" for i, line in offenders)
            + ". buildah ignores it in OCI image format, so it makes RUN mean two "
            "different things depending on the runtime. Keep every RUN POSIX instead."
        )


class TestTheProbesActuallyFire:
    """The control. A detector that matches nothing passes every file, including a
    broken one, so the probes are exercised against text that must trip them."""

    POSITIVE = {
        "[[ ]]": 'RUN if [[ -n "$X" ]]; then echo y; fi',
        "== inside [ ]": 'RUN [ "$A" == "$B" ]',
        "source": "RUN source /etc/profile",
        "array assignment": "RUN arr=(1 2 3)",
        "${var,,} / ${var^^}": "RUN echo ${VAR,,}",
        "${var/x/y}": "RUN echo ${PATH/usr/opt}",
        "${!var}": 'RUN echo "${!indirect}"',
        "process substitution": "RUN cat <(echo hi)",
        "&> redirect": "RUN cmd &> /dev/null",
        "function keyword": "RUN function f() { echo x; }",
        "set -o pipefail": "RUN set -euo pipefail; echo hi",
        "here-string <<<": 'RUN read x <<< "hello"',
        "(( )) as a command": "RUN (( x++ )) || true",
        "brace expansion": "RUN mkdir -p /deps/{a,b,c}",
        "echo -e": 'RUN echo -e "x\\ty"',
        "local": "RUN local x=1",
        "pushd / popd": "RUN pushd /tmp && popd",
        "trap ... ERR": "RUN trap 'echo x' ERR",
    }

    def test_every_probe_has_a_positive_case(self):
        assert set(self.POSITIVE) == {name for name, _, _ in BASHISMS}, (
            "a probe was added or renamed without a positive case, so nothing "
            "proves it can match"
        )

    @pytest.mark.parametrize("name", sorted(POSITIVE))
    def test_the_probe_fires_on_its_own_positive_case(self, name, tmp_path):
        target = tmp_path / "Dockerfile"
        target.write_text(self.POSITIVE[name] + "\n")

        hits = {found for _, found, _, _ in _findings(run_instructions(target))}
        assert name in hits, (
            f"the {name!r} probe did not match {self.POSITIVE[name]!r}, so it would "
            f"not have caught this construct in the real Dockerfile"
        )

    @pytest.mark.parametrize(
        "command",
        [
            'RUN echo "$(( 1 + 2 ))"',  # POSIX arithmetic expansion, not (( ))
            'RUN [ "$A" = "$B" ] && echo eq',  # single = is correct
            'RUN set -uex; if [ "${OFFLINE}" = "YES" ]; then echo y; fi',  # the fix itself
            'RUN echo \'{"a":1,"b":2}\' > /tmp/x.json',  # JSON, not brace expansion
            "RUN . /etc/profile",  # POSIX dot, not source
            "RUN mkdir -p ${A} ${B}",
            "RUN printf '%s\\n' one two",
            "RUN with-retry 'curl -sSf https://x/y | sh'",  # pipefail lives in with-retry
        ],
    )
    def test_posix_constructs_are_not_flagged(self, command, tmp_path):
        """The other half of the control. Probes that flag correct POSIX get
        disabled by whoever hits the false positive, so they have to be tight."""
        target = tmp_path / "Dockerfile"
        target.write_text(command + "\n")

        findings = _findings(run_instructions(target))
        assert not findings, (
            f"{command!r} is POSIX sh and was flagged as "
            f"{[name for _, name, _, _ in findings]}"
        )


class TestContinuationFolding:
    def test_a_bashism_split_across_a_continuation_is_still_found(self, tmp_path):
        """The real instance spanned ten physical lines.

        Folding is what makes the probes see one command. Without it a construct
        broken across a ``\\`` would match no single line and the check would pass
        on a file containing exactly the defect it exists to find.
        """
        target = tmp_path / "Dockerfile"
        target.write_text(
            'RUN set -uex; if [[ "$A" \\\n    == "$B" ]]; then \\\n    echo y; \\\n    fi\n'
        )

        findings = _findings(run_instructions(target))
        assert findings, "a continued RUN was not folded before matching"
        assert findings[0][0] == 1, "the finding must report the RUN's first line"
