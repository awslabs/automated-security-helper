# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Nothing under .github/, in the Dockerfile or in scripts/ fetches a remote file unverified.

Why this file exists
--------------------
The reusable scan workflow installed OpenGrep with a bare
``gh release download --repo opengrep/opengrep --pattern 'opengrep_manylinux_x86'``:
no tag, so whatever release was newest that day, and no digest, so whatever bytes the
URL served. The repository's own cache-seeding job did the same and wrote the result
into the Actions cache that every caller's scan then restored and put on PATH. The
image built uv twice from ``curl -LsSf https://astral.sh/uv/install.sh | sh`` and ran
an unpinned ``get-pip.py``. Each was found by reading, and nothing would have caught
the next one.

The rule
--------
For every ``run:`` script in a workflow or composite action, and for the Dockerfile
and every shell script under scripts/ and .github/:

* Piping a fetch into an interpreter (``curl ... | sh``, ``| bash``, ``| python``) is
  refused outright. The bytes run before anything could check them.
* ``gh release download``, ``curl`` and ``wget`` must be followed, later in the same
  script, by a SHA256 check: ``sha256sum -c`` / ``--check``, ``shasum -a 256 -c``, or a
  ``sha256sum`` whose output is compared with ``=`` or ``!=``. A check *before* the
  fetch does not count, and neither does one in a different step -- a later step is
  not guaranteed to run, and the binary is on disk in between.
* Going through ASH's verified installers (``ashx dependencies install``,
  ``install-pinned-tool``) is compliant by construction, because neither is a raw
  fetch: they resolve the URL and digest from utils/tool_downloads.py and refuse a
  mismatch.

Fetches that are deliberately unverified -- data rather than code, or a signing key
that is itself the trust anchor -- are listed in ``_ALLOWED`` with the reason, one
entry per site. A new fetch fails here until someone writes that reason down or adds
the check.

What it does not cover
----------------------
* ``uses:`` steps. A third-party action that downloads something is governed by
  .github/scripts/assert-actions-pinned.mjs, which pins the action's own code.
* Index-resolved installs (``pip install``, ``npm install``, ``gem install``). Those
  are dependency resolution with its own lockfile story, not release-asset fetches.
* Whether the digest a check compares against is the RIGHT one. This proves a check
  exists in the right place; the pin's provenance is recorded where the pin lives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_DIR = REPO_ROOT / ".github"

# A fetcher in command position: at the start of a command, after a shell operator or
# an opening quote/paren, or after a wrapper that runs its argument as a command.
# Command position is what separates `curl -o x URL` from `apt-get install curl`.
_FETCH = re.compile(
    r"(?:^|[;&|(`'\"]|\b(?:then|do|retry|with-retry|sudo|exec)\b)\s*"
    r"(?P<cmd>curl|wget|gh\s+release\s+download)\b"
)
_PIPE_TO_INTERPRETER = re.compile(
    r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:sh|bash|zsh|dash|python3?|perl|ruby|node)\b"
)
_VERIFY = re.compile(
    r"sha256sum\s+(?:[^|;&]*\s)?(?:-c|--check)\b"
    r"|shasum\s+-a\s*256\s+(?:[^|;&]*\s)?(?:-c|--check)\b"
    r"|sha256sum[^\n]*(?:!=|\s=\s|==)"
    r"|(?:!=|\s=\s|==)[^\n]*sha256sum"
)


@dataclass(frozen=True)
class Finding:
    where: str
    line: str
    problem: str

    def __str__(self) -> str:
        return f"  {self.where}: {self.problem}\n      {self.line.strip()[:160]}"


def _logical_lines(script: str) -> list[str]:
    """Join backslash continuations and drop comment-only lines."""
    joined: list[str] = []
    buffer = ""
    for raw in script.splitlines():
        if not buffer and raw.lstrip().startswith("#"):
            continue
        if raw.rstrip().endswith("\\"):
            buffer += raw.rstrip()[:-1] + " "
            continue
        joined.append(buffer + raw)
        buffer = ""
    if buffer:
        joined.append(buffer)
    return joined


def unverified_fetches(script: str, where: str) -> list[Finding]:
    """Every fetch in ``script`` that is piped into an interpreter or never verified."""
    lines = _logical_lines(script)
    findings: list[Finding] = []
    for index, line in enumerate(lines):
        match = _FETCH.search(line)
        if match is None:
            continue
        rest = line[match.start("cmd") :]
        if _PIPE_TO_INTERPRETER.search(rest):
            findings.append(
                Finding(
                    where,
                    line,
                    "fetch piped into an interpreter; nothing can verify it",
                )
            )
            continue
        after = [rest] + lines[index + 1 :]
        if not any(_VERIFY.search(candidate) for candidate in after):
            findings.append(
                Finding(
                    where, line, f"{match.group('cmd')} with no SHA256 check after it"
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Every deliberately unverified fetch, by file and a substring of the fetch line.
# ---------------------------------------------------------------------------

_ALLOWED: dict[tuple[str, str], str] = {
    (
        ".github/workflows/run-ash-security-scan.yml",
        '"${ASH_ASSETS_URL}/Gemfile"',
    ): (
        "cfn-nag's Gemfile, fetched from the same repository and ref the scan installs "
        "ASH itself from (ash-repo at ash-version). It is read by bundler with the same "
        "trust as the ASH code that runs next; pinning it would mean pinning ASH."
    ),
    (
        ".github/workflows/run-ash-security-scan.yml",
        '"${ASH_ASSETS_URL}/Gemfile.lock"',
    ): "The lockfile beside that Gemfile; same source, same trust, same reason.",
    (
        ".github/actions/run-scan-test/action.yml",
        "gitlab-sast-schema.json",
    ): (
        "GitLab's SAST report JSON schema at the tag the reporter emits. Data handed "
        "to ajv to validate test output; never executed, and a wrong file fails the "
        "validation rather than passing it."
    ),
    (
        "Dockerfile",
        "deb.nodesource.com/gpgkey/nodesource-repo.gpg.key",
    ): (
        "The apt signing key for the NodeSource repository. It is the trust anchor apt "
        "then verifies every nodejs package against, not a binary. Pinning its "
        "fingerprint is a reasonable follow-up and is not this change."
    ),
    (
        "Dockerfile",
        "https://semgrep.dev/c/${i}",
    ): (
        "semgrep's published rulesets, cached for offline scans. Rule data that is "
        "meant to change between builds, parsed rather than executed; there is no "
        "stable digest to pin."
    ),
    (
        "scripts/setup-finch-linux.sh",
        "artifact.runfinch.com/deb/GPG_KEY.pub",
    ): (
        "The apt signing key for the Finch repository; the same trust-anchor shape as "
        "the NodeSource key in the Dockerfile. CI-only runner setup."
    ),
}


def _allowed(finding: Finding) -> bool:
    rel = finding.where.split(":", 1)[0]
    return any(rel == path and needle in finding.line for path, needle in _ALLOWED)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def _steps(data: dict) -> Iterator[tuple[str, dict]]:
    for job_id, job in (data.get("jobs") or {}).items():
        for index, step in enumerate((job or {}).get("steps") or []):
            yield f"jobs.{job_id}.steps[{index}]", step
    for index, step in enumerate((data.get("runs") or {}).get("steps") or []):
        yield f"runs.steps[{index}]", step


def _scripts() -> Iterator[tuple[str, str]]:
    files = sorted(GITHUB_DIR.rglob("*.yml")) + sorted(GITHUB_DIR.rglob("*.yaml"))
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        for location, step in _steps(data):
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                name = step.get("name") or location
                yield f"{rel}: {name}", step["run"]
    yield "Dockerfile", (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    shell_scripts = sorted((REPO_ROOT / "scripts").glob("*.sh")) + sorted(
        GITHUB_DIR.rglob("*.sh")
    )
    for path in shell_scripts:
        yield path.relative_to(REPO_ROOT).as_posix(), path.read_text(encoding="utf-8")


def _all_findings() -> list[Finding]:
    return [
        f for where, script in _scripts() for f in unverified_fetches(script, where)
    ]


# ---------------------------------------------------------------------------
# The repository
# ---------------------------------------------------------------------------


def test_no_remote_download_goes_unverified():
    bad = [f for f in _all_findings() if not _allowed(f)]
    assert not bad, (
        "these steps fetch a remote file without verifying it. Pin a version and a "
        "SHA256 and check it before the file is used (see "
        "automated_security_helper/utils/tool_downloads.py, `ashx dependencies "
        "install --tool`, assets/install-pinned-tool.py), or, if the file is data "
        "rather than code, add it to _ALLOWED with the reason:\n"
        + "\n".join(str(f) for f in bad)
    )


def test_every_allowlist_entry_still_matches_a_fetch():
    """A stale entry is a silent hole waiting for a new fetch on the same line."""
    findings = _all_findings()
    stale = [
        (path, needle)
        for path, needle in _ALLOWED
        if not any(
            f.where.split(":", 1)[0] == path and needle in f.line for f in findings
        )
    ]
    assert not stale, f"_ALLOWED entries that no longer match any fetch: {stale}"


def test_the_collector_sees_the_sites_it_must_see():
    """Positive control on the real tree: a collector that read nothing passes above.

    The verified nerdctl download in scripts/ and the allowlisted fetches are known to
    exist, so they must be found -- the first as compliant, the rest as allowlisted.
    """
    scripts = dict(_scripts())
    assert any(
        w.startswith(".github/workflows/run-ash-security-scan.yml") for w in scripts
    )
    assert any(w.startswith(".github/actions/") for w in scripts), (
        "no composite action step was collected"
    )
    nerdctl = scripts["scripts/setup-nerdctl-linux.sh"]
    assert _FETCH.search(nerdctl) and unverified_fetches(nerdctl, "nerdctl") == []
    assert len(_all_findings()) >= len(_ALLOWED)


def test_the_opengrep_install_sites_use_the_verified_paths():
    """The two sites that started this, checked by what they do now."""

    def code(name: str) -> str:
        # Comment lines describe the removed command, so they are left out.
        text = (GITHUB_DIR / "workflows" / name).read_text(encoding="utf-8")
        return "\n".join(_logical_lines(text))

    scan = code("run-ash-security-scan.yml")
    seed = code("ash-repo-scan.yml")
    assert "gh release download" not in scan
    assert "gh release download" not in seed
    assert "--tool opengrep" in scan
    assert "install-pinned-tool.py opengrep" in seed


# ---------------------------------------------------------------------------
# Positive and negative controls on synthetic scripts
# ---------------------------------------------------------------------------

_RED = {
    "bare gh release download": (
        "gh release download --repo opengrep/opengrep --pattern 'opengrep_manylinux_x86' "
        '--dir "$D"\nchmod +x "$D/opengrep_manylinux_x86"\n'
    ),
    "curl piped to sh": "curl -LsSf https://astral.sh/uv/install.sh | sh\n",
    "curl piped to sudo bash": "curl -fsSL https://example.invalid/i.sh | sudo -E bash -s\n",
    "wget a binary": "wget -q -O /usr/local/bin/tool https://example.invalid/tool\n",
    "curl to file then run": (
        "curl -sSfL -o tool https://example.invalid/tool\nchmod +x tool\n./tool --version\n"
    ),
    "check before the fetch": (
        'echo "$PIN  tool" | sha256sum -c -\ncurl -sSfL -o tool https://example.invalid/t\n'
    ),
    "with-retry wrapper": "with-retry 'curl -sSf https://example.invalid/get-pip.py -o g.py && python3 g.py'\n",
    "continued line": "curl -sSfL \\\n  -o tool \\\n  https://example.invalid/tool\n",
    "sha256sum used only to print": (
        "curl -sSfL -o tool https://example.invalid/tool\nsha256sum tool\n"
    ),
}

_GREEN = {
    "curl then sha256sum -c": (
        "curl -fsSL -o t.tgz https://example.invalid/t.tgz\n"
        'echo "${EXPECTED}  t.tgz" | sha256sum -c -\ntar xzf t.tgz\n'
    ),
    "gh release download then --check": (
        "gh release download v1.15.1 --repo opengrep/opengrep --pattern x --dir d\n"
        "sha256sum --check pins.txt\n"
    ),
    "compared digest": (
        "curl -sSfL -o tool https://example.invalid/tool\n"
        '[ "$(sha256sum tool | cut -d" " -f1)" = "${PIN}" ] || exit 1\n'
    ),
    "verified installer": 'uvx --from "$SRC" ash dependencies install --tool opengrep\n',
    "pinned-tool script": "install-pinned-tool uv -b /root/.local/bin\n",
    "curl as a package name": "apt-get install -y --no-install-recommends git curl && rm -rf /x\n",
    "commented out": "# curl -LsSf https://astral.sh/uv/install.sh | sh\necho ok\n",
}


@pytest.mark.parametrize("name", sorted(_RED))
def test_synthetic_unverified_fetch_is_red(name):
    assert unverified_fetches(_RED[name], name), f"{name!r} was not flagged"


@pytest.mark.parametrize("name", sorted(_GREEN))
def test_synthetic_compliant_script_is_green(name):
    assert unverified_fetches(_GREEN[name], name) == []


def test_a_synthetic_workflow_and_composite_action_are_both_collected(tmp_path):
    """The step walker reads jobs.*.steps and runs.steps alike."""
    workflow = {
        "jobs": {
            "j": {
                "steps": [
                    {"name": "bad", "run": _RED["bare gh release download"]},
                    {"name": "good", "run": _GREEN["curl then sha256sum -c"]},
                ]
            }
        }
    }
    action = {
        "runs": {"using": "composite", "steps": [{"run": _RED["curl piped to sh"]}]}
    }
    found = []
    for label, data in (("wf", workflow), ("action", action)):
        for location, step in _steps(data):
            found += unverified_fetches(step["run"], f"{label}:{location}")
    assert [f.where for f in found] == ["wf:jobs.j.steps[0]", "action:runs.steps[0]"]
