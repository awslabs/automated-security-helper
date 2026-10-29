# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The offline scan-validation leg must leave npm-audit out of its scan.

Why this file exists
--------------------
npm-audit cannot run offline: npm, yarn and pnpm audit a lockfile by asking the
registry, so an offline scan reports npm-audit MISSING
for a project with a lockfile beside a `package.json`, and exits 1 for it. This
repository has such projects (deploy/cdk and deploy/cdk-constructs), and the
python-container leg with `offline: true` scans the repository, so without the
exclusion it runs into that MISSING on every run. docs/content/faq.md tells users to
pass `--exclude-scanners npm-audit` for an offline scan of a JavaScript project; the
leg does the same.

What is asserted
----------------
The "Validate ASH using Python + Container" step of .github/actions/run-scan-test is
run against a stand-in `ash` that records its arguments, for both config files, with
`offline` on and off. Offline, the scan gets `--offline --exclude-scanners npm-audit`;
online, it gets neither, so npm-audit runs on every online leg. ASH also takes
scanner selection and its config from the environment, so no ASH_* variable may reach
the scan besides the ASH_TEST_* inputs and the step's four cache and base-image
variables. The runs show the script exports none. The layers the runs do not see are
read instead:
* the step's own env block;
* the calling workflow's env, the job's env, the job container's env and any env its
  `options` set (`-e`, `--env`, `--env-file`), and the env of each step on the way to
  the action, which a composite passes on to its steps;
* any step of the calling job, the action or a local composite they reach that
  writes GITHUB_ENV or GITHUB_PATH at all: named as `$GITHUB_ENV` or
  `${{ github.env }}` on any line of its script (comment-led lines and heredoc
  bodies too), held in an env value, or a redirection or tee to a target named only
  at run time (`${!X}`, `${{ inputs.file }}`, `${${{ env.X }}}`, `$(printenv X)`).
  Each such write is
  a finding unless ENV_WRITE_ALLOWLIST names its step and line, and the allowlist
  is empty because no step writes either file today. Names can be built in ways no
  reader follows, so the write is what is counted; the name readers (an ASH_* name
  in the script or an env, PATH, BASH_ENV, PYTHONPATH or LD_PRELOAD) say in the
  finding what they saw, and an ASH_* name is a finding even on a listed step;
* core.exportVariable, core.addPath or a direct write of either file in an
  actions/github-script step.
A caller is found however its `uses:` path is spelled, and through a wrapper
composite. A local action that is not a composite, and a `docker://` step, fail the
walk rather than being passed over, since what they write cannot be read. Planted
trees check that each shape is found.

What it does not read: remote actions (owner/repo@ref), whose code is elsewhere; the
job container's image; and a program a step runs (a repository script, or a
github-script `require()` of a repository file) that writes either file without the
step naming it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"
STEP_NAME = "Validate ASH using Python + Container"


def _step() -> dict:
    steps = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]
    matches = [step for step in steps if step.get("name") == STEP_NAME]
    assert len(matches) == 1, f"expected one {STEP_NAME!r} step, found {len(matches)}"
    return matches[0]


#: Separates a record's argv from the ASH_* variables the call saw.
_ENV_MARK = "<environment>"

#: The step's own ASH_* variables besides its ASH_TEST_* inputs: cache and base-image
#: plumbing for the container build, none of which selects scanners or a config.
_STEP_ASH_ENV = {
    "ASH_TOOL_DOWNLOAD_CACHE",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
    "ASH_GHA_BUILD_CACHE_EXPORT",
}


def _install_stand_in(tmp_path: Path) -> tuple[Path, str]:
    """An `ash` that records its argv and every ASH_* variable it was given.

    Each call appends one record: its arguments, _ENV_MARK, then `NAME=value` for
    each exported ASH_* variable except the ASH_TEST_* inputs, sorted. ASH reads
    scanner selection and its config from the environment as well as from
    arguments (ASH_SCANNERS, ASH_EXCLUDED_SCANNERS, ASH_CONFIG, ASH_PLUGIN_MODULES,
    ASH_CHANGED_FILES_ONLY and others), so naming a few would let another one pass.
    Returns the record file and a PATH of the stand-in and the system directories.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    stand_in = bin_dir / "ash"
    stand_in.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\0" "$@" "{_ENV_MARK}" >> "{calls}"\n'
        "for name in $(compgen -e | LC_ALL=C sort); do\n"
        '  case "$name" in\n'
        "    ASH_TEST_*) ;;\n"
        f'    ASH_*) printf "%s\\0" "$name=${{!name}}" >> "{calls}" ;;\n'
        "  esac\n"
        "done\n"
        f'printf "\\n" >> "{calls}"\n',
        encoding="utf-8",
    )
    stand_in.chmod(0o755)
    path = os.pathsep.join([str(bin_dir), "/usr/bin", "/bin"])
    assert shutil.which("ash", path=path) == str(stand_in), (
        "the stand-in is not the ash this PATH resolves"
    )
    return calls, path


def _records(calls: Path) -> list[list[str]]:
    lines = calls.read_text(encoding="utf-8").split("\n")
    return [line.strip("\0").split("\0") for line in lines if line]


def _scan_argv(tmp_path: Path, offline: str, config_file: str) -> list[list[str]]:
    """Run the step's script with a stand-in ash; return each ash call's record.

    PATH holds the stand-in and the system directories only, and the script runs in
    tmp_path, so a stand-in that failed to install cannot hand the call to the real
    ash, which would start a container build of the repository.
    """
    calls, path = _install_stand_in(tmp_path)
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    result = subprocess.run(
        [shutil.which("bash") or "bash", "-e", "-o", "pipefail", "-c", _step()["run"]],
        cwd=tmp_path,
        env={
            "PATH": path,
            "RUNNER_TEMP": str(runner_temp),
            "ASH_TEST_OS": "ubuntu-latest",
            "ASH_TEST_PLATFORM": "linux/amd64",
            "ASH_TEST_CONFIG_FILE": config_file,
            "ASH_TEST_OFFLINE": offline,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return _records(calls)


def _scans(records: list[list[str]]) -> list[list[str]]:
    scans = [record for record in records if "--mode" in record]
    assert len(scans) == 1, f"expected one scan, the step ran ash as {records}"
    return scans


_SCAN = [
    "--mode",
    "container",
    "--build-target",
    "ci",
    "--verbose",
    "--no-progress",
    "--ash-revision-to-install",
    "LOCAL",
]
_OFFLINE = ["--offline", "--exclude-scanners", "npm-audit"]
#: The community legs read .ash/.ash_community_plugins.yaml, a config inside the
#: scanned tree, which cannot load ash_snyk_plugins itself, so the step names the
#: module on the command line.
_COMMUNITY = [
    "--config",
    ".ash/.ash_community_plugins.yaml",
    "--ash-plugin-modules",
    "automated_security_helper.plugin_modules.ash_snyk_plugins",
]
#: Every leg names the repository's own bandit and grype configs: a config file
#: inside the scanned tree no longer chooses a scanner's config file, so the
#: operator does. These select no scanner and leave none out.
_OVERRIDES = [
    "--config-overrides",
    "scanners.bandit.options.config_file=.ash/bandit.yaml",
    "--config-overrides",
    "scanners.grype.options.config_file=.ash/.grype.yaml",
]
#: The community config's own `use_default_config: false` is ignored for the same
#: reason, so the community legs set it the same way.
_COMMUNITY_OVERRIDES = [
    "--config-overrides",
    "scanners.ferret-scan.options.use_default_config=false",
]
#: No ASH_* variable besides the ASH_TEST_* inputs reaches the scan.
_NO_ASH_ENV = [_ENV_MARK]


def _expected_scan(offline: bool, config_file: str) -> list[str]:
    """The one `ash` record the step's scan writes, in the step's argument order."""
    argv = list(_SCAN)
    if offline:
        argv += _OFFLINE
    if config_file == "community":
        argv += _COMMUNITY
    argv += _OVERRIDES
    if config_file == "community":
        argv += _COMMUNITY_OVERRIDES
    return argv + _NO_ASH_ENV


@pytest.mark.unit
def test_the_step_takes_the_offline_and_config_inputs():
    """The values the script branches on come from the action's inputs."""
    env = _step()["env"]
    assert env["ASH_TEST_OFFLINE"] == "${{ inputs.offline }}"
    assert env["ASH_TEST_CONFIG_FILE"] == "${{ inputs.config-file }}"


@pytest.mark.unit
def test_the_step_sets_no_other_ash_variable():
    """The runs below see only what the script exports; this covers the step's env.

    A scanner selection or config set here would reach the real scan on every leg
    while the stand-in, which is not given this block, saw nothing.
    """
    names = {
        name
        for name in _step()["env"]
        if name.startswith("ASH_") and not name.startswith("ASH_TEST_")
    }
    assert names == _STEP_ASH_ENV, (
        f"the step's ASH_* variables changed to {sorted(names)}; check that none "
        "selects scanners or a config, then update _STEP_ASH_ENV"
    )


ACTION_USES = "./.github/actions/run-scan-test"


def _ash_names(env: dict | None) -> set[str]:
    return {name for name in (env or {}) if name.startswith("ASH_")}


#: The job's environment file, as the script names it: $GITHUB_ENV, or the
#: `${{ github.env }}` expression, which the runner renders to the same path.
_ENV_FILE = re.compile(r"\bGITHUB_ENV\b|\bgithub\.env\b")

#: An ASH_* name written out, not expanded: `ASH_X=value`, `ASH_X<<DELIMITER`, a
#: name handed to printf apart from its value, or the bare `ASH_` prefix a script
#: builds names from (`env | grep '^ASH_'`, `printf 'ASH_%s=%s\\n' CONFIG x`).
#: `$ASH_X` and `${ASH_X}` read a variable and are not counted.
_ASH_NAME = re.compile(r"(?<![\w${])ASH_\w*")

#: The job's PATH file, which prepends a directory to PATH for every later step, so a
#: shim `ash` there would be the one the offline step runs.
_PATH_FILE = re.compile(r"\bGITHUB_PATH\b|\bgithub\.path\b")

#: Either file, as a script or an env value names it.
_ENV_OR_PATH_FILE = re.compile(r"\bGITHUB_(?:ENV|PATH)\b|\bgithub\.(?:env|path)\b")

#: Variables that change what every later step runs: PATH (a shim `ash`), BASH_ENV (a
#: file every later bash step sources, which can export anything), PYTHONPATH (code
#: ASH imports) and LD_PRELOAD (a library every process loads).
_RUNTIME_NAME = re.compile(r"(?<![\w${])(?:BASH_ENV|PATH|PYTHONPATH|LD_PRELOAD)\b")


#: docker run's flags that set the container's env, in a job container's `options`:
#: `-e` (with its value apart or joined, `-eNAME=x`, or ending a cluster of short
#: flags, `-ie`), and `--env` or `--env-file` followed by any separator. Any of them
#: is counted, since the name, or the file's lines, are not read here.
_CONTAINER_ENV_OPTION = re.compile(r"(?:^|\s)(?:-[A-Za-z]*e|--env\b)")


def _uncommented(script: str, marker: str = "#") -> str:
    return "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith(marker)
    )


def _exports_ash_to_github_env(run: str) -> bool:
    """Whether a step's script writes an ASH_* variable into the job's environment file.

    Read as a whole, comment lines aside, because a write can span lines (a `{ ...; }`
    group redirected once, or a heredoc), and a name can be printed apart from its
    value (`printf '%s=%s\\n' ASH_CONFIG x`). That also counts a script that names an
    ASH_* variable for any other reason and writes something else to the file, which
    is the safe side to err on: no step here does today.
    """
    text = _uncommented(run)
    return bool(_ENV_FILE.search(text)) and bool(_ASH_NAME.search(text))


def _runtime_writes(run: str) -> list[str]:
    """What a step's script writes that changes what later steps run.

    A GITHUB_PATH write puts a directory ahead of the rest of PATH, and PATH or
    BASH_ENV written to the environment file does the same or runs a file of the
    writer's choosing before every later bash step. Either can hand the offline step
    an `ash`, or an environment, that no other reader here sees.
    """
    text = _uncommented(run)
    found = []
    if _PATH_FILE.search(text):
        found.append("writes GITHUB_PATH")
    if _ENV_FILE.search(text) and _RUNTIME_NAME.search(text):
        found.append("writes PATH, BASH_ENV, PYTHONPATH or LD_PRELOAD to GITHUB_ENV")
    return found


def _env_names_ash(env: dict | None) -> bool:
    """Whether a step's own env holds an ASH_* name, as a key or inside a value."""
    return any(
        str(name).startswith("ASH_") or _ASH_NAME.search(str(value))
        for name, value in (env or {}).items()
    )


#: Each direct call of exportVariable (core.exportVariable or a destructured one),
#: with its first argument.
_EXPORT_VARIABLE_CALL = re.compile(r"\bexportVariable\s*\(\s*([^,)]*)")


def _exports_ash_from_github_script(step: dict) -> bool:
    """Whether an actions/github-script step writes the job's environment unreadably.

    core.exportVariable writes the job's environment as GITHUB_ENV does, and
    core.addPath writes GITHUB_PATH. Counted:
    * a call whose name is a string literal starting with ASH_, or is not a plain
      literal at all, since that name cannot be read here;
    * exportVariable named any way but a direct call (an alias, `core['...']`);
    * core.addPath, and any mention of GITHUB_ENV, GITHUB_PATH or BASH_ENV, which a
      script reaches through process.env to write the files itself.
    The action name is compared without regard to case, as GitHub resolves it. `//`
    comment lines aside.
    """
    uses = str(step.get("uses") or "").lower()
    if not uses.startswith("actions/github-script@"):
        return False
    text = _uncommented(str((step.get("with") or {}).get("script") or ""), "//")
    if (
        _ENV_FILE.search(text)
        or _PATH_FILE.search(text)
        or "BASH_ENV" in text
        or re.search(r"\baddPath\b", text)
    ):
        return True
    calls = _EXPORT_VARIABLE_CALL.findall(text)
    if len(calls) != len(re.findall(r"exportVariable", text)):
        return True
    for argument in calls:
        literal = re.fullmatch(r"""(['"`])([^'"`$]*)\1""", argument.strip())
        if literal is None or literal.group(2).startswith("ASH_"):
            return True
    return False


def _uses_local(step: dict) -> str | None:
    uses = str(step.get("uses") or "").strip()
    return uses.rstrip("/") if uses.startswith("./") else None


def _is_the_action(uses: str | None, root: Path) -> bool:
    """Whether a local `uses:` names run-scan-test, however its path is spelled."""
    if uses is None:
        return False
    action = root / ACTION_USES[2:]
    return (root / uses[2:]).resolve() == action.resolve()


def _action_file_runs(uses: str, root: Path) -> tuple[Path, dict]:
    """(resolved action file, its `runs`) for a local action of any kind."""
    directory = root / uses[2:]
    files = [directory / name for name in ("action.yml", "action.yaml")]
    action = next((path for path in files if path.is_file()), None)
    assert action, f"{uses} has no action.yml"
    runs = yaml.safe_load(action.read_text(encoding="utf-8")).get("runs") or {}
    return action.resolve(), runs


def _is_composite(runs: dict) -> bool:
    """`runs.using` names a composite, compared without regard to case or space."""
    return str(runs.get("using") or "").strip().lower() == "composite"


def _action_runs(uses: str, root: Path) -> tuple[Path, dict]:
    """(resolved action file, its `runs`) for a local composite action.

    A JavaScript or Docker action has no steps here; what it exports is in code this
    walk cannot read, so in a calling job it fails rather than pass the action over.
    """
    action, runs = _action_file_runs(uses, root)
    assert _is_composite(runs), (
        f"{uses} is a {runs.get('using')!r} action, so the steps it runs cannot be "
        "read for ASH_* exports; read it another way before using it in this job"
    )
    return action, runs


def _reaches(uses: str | None, root: Path, seen: frozenset[Path] = frozenset()) -> bool:
    """Whether a local `uses:` is run-scan-test, or a composite that runs it.

    Only a composite runs other actions, so a JavaScript or Docker action never
    reaches it, and a job elsewhere that uses one does not fail the search for
    callers. In a calling job the walk still refuses such an action.
    """
    if uses is None:
        return False
    if _is_the_action(uses, root):
        return True
    action, runs = _action_file_runs(uses, root)
    if not _is_composite(runs) or action in seen:
        return False
    return any(
        _reaches(_uses_local(step), root, seen | {action})
        for step in runs.get("steps") or []
    )


def _carry(carried: dict, calling_step: dict) -> dict:
    """What a composite's steps see from the step that runs it: its env and inputs.

    The env of a `uses:` step reaches the composite's steps, and its `with:` values
    reach them as `${{ inputs.<name> }}`; both are kept under their own keys, on top
    of what that step itself was handed.
    """
    return {
        **carried,
        **(calling_step.get("env") or {}),
        **{f"inputs.{k}": v for k, v in (calling_step.get("with") or {}).items()},
    }


def _composite_steps(
    uses: str, seen: set[Path], root: Path = REPO_ROOT, carried: dict | None = None
) -> list[tuple[str, dict]]:
    """(where, step) for every step of a local composite, and of those it uses.

    Each step is a copy with `_carried`: the env and inputs the calling steps
    handed it (_carry).
    """
    action, runs = _action_runs(uses, root)
    if action in seen:
        return []
    seen.add(action)
    carried = carried or {}
    found = []
    # Named by the resolved path, so `./a/../a/x` and `./a/./x` read as `a/x`.
    where = action.relative_to(root.resolve())
    for step in runs.get("steps") or []:
        found.append(
            (f"{where.as_posix()}: {step.get('name')}", {**step, "_carried": carried})
        )
        nested = _uses_local(step)
        if nested:
            found.extend(_composite_steps(nested, seen, root, _carry(carried, step)))
    return found


def _callers(root: Path = REPO_ROOT) -> list[tuple[str, dict, dict]]:
    """(workflow file, workflow, job) for every job that runs the action.

    A job runs it from one of its own steps, or through a local composite that does,
    however deep.
    """
    workflows = root / ".github" / "workflows"
    found = []
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (workflow.get("jobs") or {}).values():
            if any(
                _reaches(_uses_local(step), root) for step in job.get("steps") or []
            ):
                found.append((path.name, workflow, job))
    return found


@dataclass(frozen=True)
class EnvWrite:
    """A write of GITHUB_ENV or GITHUB_PATH that a walked step may make."""

    #: The walk's name for the step: `<workflow>: <step name>` for a step of the
    #: calling job, `<action file>: <step name>` for a composite's.
    step: str
    #: The one variable it writes; PATH for a GITHUB_PATH write.
    variable: str
    #: The script line that writes it, exactly as it stands, stripped.
    line: str
    #: Why the variable is safe to hand every later step, the offline one included.
    reason: str


#: Every GITHUB_ENV or GITHUB_PATH write the walk may meet. Empty: no step it reaches
#: writes either file today. A step that starts to needs an entry here, so the
#: export is reviewed for what it hands the offline step.
ENV_WRITE_ALLOWLIST: tuple[EnvWrite, ...] = ()


#: `NAME=` written out on a line, not inside an expansion.
_ASSIGNMENT = re.compile(r"(?<![\w$])([A-Za-z_][A-Za-z0-9_]*)=")


def _check_entry(entry: EnvWrite) -> None:
    """An entry pins one simple write of one named variable, with a reason.

    The variable is an identifier and nothing on the line says ASH. The line is a
    single command that writes that one name to GITHUB_ENV, or (for PATH) a
    directory to GITHUB_PATH: no `;`, no `{` (a group, or a brace expansion that
    writes more names), no `<<` (a heredoc, whose body is what is written), and no
    trailing `\\` (a command continued onto a line the entry does not pin).
    """
    where = entry.step
    assert entry.reason.strip(), f"{where}: an allowlist entry needs a reason"
    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", entry.variable), (
        f"{where}: {entry.variable!r} is not a variable name"
    )
    line = entry.line.strip()
    assert "ASH" not in line and "ASH" not in entry.variable, (
        f"{where}: an ASH_* variable cannot be allowlisted"
    )
    assert not re.search(r"[;{]|<<", line) and not line.endswith("\\"), (
        f"{where}: an entry pins one simple write: no ';', '{{', '<<' or continuation"
    )
    names = _ASSIGNMENT.findall(line)
    if (
        entry.variable == "PATH"
        and _PATH_FILE.search(line)
        and not _ENV_FILE.search(line)
    ):
        assert not names, f"{where}: a GITHUB_PATH write names no variable"
        return
    assert _ENV_FILE.search(line), f"{where}: the line does not write GITHUB_ENV"
    assert names == [entry.variable], (
        f"{where}: the line does not write {entry.variable}, and only it: {names}"
    )


def _ash_writers(
    root: Path = REPO_ROOT, allowlist: tuple[EnvWrite, ...] = ENV_WRITE_ALLOWLIST
) -> tuple[list[str], list[str]]:
    """(the workflows that run the action, every layer that can set its environment).

    Read for each calling job:
    * the workflow's env, the job's env and the job container's env, and any env
      the container's `options` set with -e, --env or --env-file;
    * the env of each step, in the job or in a composite, that leads to the action,
      which composites pass on to their steps;
    * every step of the job and of each local composite it reaches, however deep,
      that writes GITHUB_ENV or GITHUB_PATH, unless `allowlist` names its step and
      every line that writes (see _env_write_finding);
    * core.exportVariable, core.addPath or a direct write of either file in an
      actions/github-script step.
    A `docker://` step, or a local action that is not a composite, fails the walk:
    what it writes cannot be read here. Remote actions (owner/repo@ref) are not read.
    """
    for entry in allowlist:
        _check_entry(entry)
    callers = _callers(root)
    findings = []
    for name, workflow, job in callers:
        container = job.get("container")
        inherited = {
            **(workflow.get("env") or {}),
            **(job.get("env") or {}),
            **((container.get("env") or {}) if isinstance(container, dict) else {}),
        }
        layers = {
            "workflow env": workflow.get("env"),
            "job env": job.get("env"),
            "job container env": container.get("env")
            if isinstance(container, dict)
            else None,
        }
        for layer, env in layers.items():
            if _ash_names(env):
                findings.append(f"{name}: {layer} sets {sorted(_ash_names(env))}")
        options = container.get("options") if isinstance(container, dict) else None
        if options and _CONTAINER_ENV_OPTION.search(str(options)):
            findings.append(
                f"{name}: job container options set its env (-e, --env or --env-file)"
            )
        seen: set[Path] = set()
        steps = []
        for other in job.get("steps") or []:
            steps.append((f"{name}: {other.get('name') or other.get('uses')}", other))
            nested = _uses_local(other)
            if nested:
                steps.extend(_composite_steps(nested, seen, root, _carry({}, other)))
        if not any(
            where.startswith(".github/actions/run-scan-test/") for where, _ in steps
        ):
            findings.append(f"{name}: the action's own steps were not reached")
        for where, other in steps:
            assert not str(other.get("uses") or "").startswith("docker://"), (
                f"{where} runs a docker:// image, whose writes to the job's "
                "environment cannot be read here"
            )
            if _reaches(_uses_local(other), root) and _ash_names(other.get("env")):
                findings.append(
                    f"{where} passes {sorted(_ash_names(other.get('env')))} on to "
                    "the action's steps"
                )
            finding = _env_write_finding(where, other, inherited, allowlist)
            if finding:
                findings.append(finding)
            if _exports_ash_from_github_script(other):
                findings.append(f"{where} exports an ASH_* variable from github-script")
    return [name for name, *_ in callers], findings


#: A redirection (`>`, `>>`, `>|`, or tee with any options) whose target is named
#: only at run time, so the file it writes cannot be read here: an indirect
#: expansion (`${!X}`), an expression (`${{ inputs.file }}`, or one inside an
#: expansion, `${${{ env.X }}}`) or a command substitution (`$(printenv X)`).
_UNREADABLE_TARGET = re.compile(
    r"""(?:>[>|]?|\btee\b(?:\s+-\S+)*)\s*["']?(?:\$\{!|\$\{\{|\$\{\$\{\{|\$\()"""
)

#: Any redirection or tee, for a step whose env names the environment file.
_REDIRECTION = re.compile(r">[>|]?|\btee\b")


def _env_write_finding(
    where: str, step: dict, inherited: dict, allowlist: tuple[EnvWrite, ...]
) -> str | None:
    """The finding for a step that writes GITHUB_ENV or GITHUB_PATH, if any.

    Any such write is a finding unless every line that makes it is on the allowlist
    for this step: the file can be named in ways no reader here follows, and a name
    can be built, so the write itself is what is counted, not the names in it. A
    write that the name readers tie to an ASH_* variable is a finding even when its
    lines are listed. The readers' results go in the message, so a finding says
    what it saw.
    """
    # Every line, comment-led ones too: a heredoc body is not a comment, and a
    # script can uncomment its own lines and run them (`sed 's/^#//' <<EOF | bash`).
    # A command continued with a trailing `\` is read as the one line it is, so a
    # listed line cannot be the tail of a write that began a line earlier.
    raw = re.sub(r"\\\n", " ", step.get("run") or "")
    inherited = {**inherited, **(step.get("_carried") or {})}
    env = {**inherited, **(step.get("env") or {})}
    env_names_file = any(_ENV_OR_PATH_FILE.search(str(v)) for v in env.values())
    lines = [
        line.strip()
        for line in raw.splitlines()
        if _ENV_OR_PATH_FILE.search(line)
        or _UNREADABLE_TARGET.search(line)
        or (env_names_file and _REDIRECTION.search(line))
    ]
    if not lines:
        return None
    kinds = []
    if _ENV_FILE.search(raw):
        kinds.append("GITHUB_ENV")
    if _PATH_FILE.search(raw):
        kinds.append("GITHUB_PATH")
    if env_names_file or any(_UNREADABLE_TARGET.search(line) for line in lines):
        kinds.append("a file named only at run time")
    ash = []
    if _ASH_NAME.search(raw):
        ash.append("exports an ASH_* variable to GITHUB_ENV")
    if _env_names_ash(step.get("env")):
        ash.append("names an ASH_* variable in its env")
    if _env_names_ash(inherited):
        ash.append("the job or workflow env holds an ASH_* name")
    seen = ash + _runtime_writes(step.get("run") or "")
    pinned = {entry.line for entry in allowlist if entry.step == where}
    listed = bool(pinned) and all(line in pinned for line in lines)
    if listed and not ash:
        return None
    status = "is on the allowlist but" if listed else "is not on the allowlist"
    return (
        f"{where} writes {' and '.join(kinds)} and {status}: "
        f"{'; '.join(seen) or 'no ASH_* name seen'}"
    )


@pytest.mark.unit
def test_no_layer_above_the_step_sets_an_ash_variable():
    """The env of the calling workflow, job and step reaches the action's steps too.

    So does anything an earlier step writes into the job's environment: a step of the
    calling job, a step of the action, or a step of any local composite either of
    them uses (setup-ash, tool-download-cache, prepull-base-image today), however
    deep. None of it is in the runs below, so each layer is read here: today the
    workflow sets COLUMNS, the job nothing, the calling step OCI_RUNNER and
    OCI_RUNNER_WRAPPER, and no step writes an ASH_* variable to GITHUB_ENV or
    exports one from github-script.
    """
    callers, findings = _ash_writers()
    assert "ash-unified-ci.yml" in callers, (
        f"no workflow uses {ACTION_USES}, so this reads nothing"
    )
    assert not findings, findings


def _plant(root: Path, job_steps: list[dict], actions: dict | None = None) -> Path:
    """A repository tree with run-scan-test, one workflow job, and other actions."""
    files = {
        ".github/actions/run-scan-test/action.yml": {
            "runs": {
                "using": "composite",
                "steps": [{"name": STEP_NAME, "shell": "bash", "run": "true"}],
            }
        },
        ".github/workflows/ci.yml": {"jobs": {"test": {"steps": job_steps}}},
    }
    for uses, spec in (actions or {}).items():
        files[f"{uses[2:]}/action.yml"] = spec
    for relative, document in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return root


_CALL = {"uses": ACTION_USES}

#: A step of the calling job for each way it can put an ASH_* variable into the
#: job's environment.
_PLANTED_WRITERS = {
    "GITHUB_ENV assignment": {"run": 'echo "ASH_CONFIG=x" >> "$GITHUB_ENV"'},
    "the github.env expression": {"run": 'echo "ASH_CONFIG=x" >> "${{ github.env }}"'},
    "printf with the name apart": {
        "run": "printf '%s=%s\\n' ASH_CONFIG x >> \"$GITHUB_ENV\""
    },
    "github-script, a literal name": {
        "uses": "actions/github-script@v8",
        "with": {"script": "core.exportVariable('ASH_SCANNERS', 'bandit')"},
    },
    "github-script, a name it cannot read": {
        "uses": "actions/github-script@v8",
        "with": {"script": "const name = pick()\ncore.exportVariable(name, 'bandit')"},
    },
}


@pytest.mark.unit
@pytest.mark.parametrize("shape", sorted(_PLANTED_WRITERS))
def test_a_planted_writer_in_the_calling_job_is_found(tmp_path, shape):
    root = _plant(tmp_path, [_PLANTED_WRITERS[shape], _CALL])

    callers, findings = _ash_writers(root)

    assert callers == ["ci.yml"]
    assert len(findings) == 1 and "exports an ASH_* variable" in findings[0], findings


@pytest.mark.unit
def test_a_planted_writer_in_a_nested_composite_is_found(tmp_path):
    nested = "./.github/actions/setup"
    root = _plant(
        tmp_path,
        [{"uses": nested}, _CALL],
        {
            nested: {
                "runs": {
                    "using": "composite",
                    "steps": [_PLANTED_WRITERS["printf with the name apart"]],
                }
            }
        },
    )

    _, findings = _ash_writers(root)

    assert len(findings) == 1 and findings[0].startswith(".github/actions/setup/"), (
        findings
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "spelling",
    [
        ACTION_USES,
        f"{ACTION_USES}/",
        "./.github/actions/./run-scan-test",
        "./.github/actions/../actions/run-scan-test",
    ],
)
def test_a_caller_is_found_however_the_path_is_spelled(tmp_path, spelling):
    root = _plant(
        tmp_path, [_PLANTED_WRITERS["GITHUB_ENV assignment"], {"uses": spelling}]
    )

    callers, findings = _ash_writers(root)

    assert callers == ["ci.yml"], callers
    assert len(findings) == 1, findings


@pytest.mark.unit
def test_another_local_action_is_not_a_caller(tmp_path):
    other = "./.github/actions/run-scan-test-other"
    root = _plant(
        tmp_path,
        [{"uses": other}],
        {other: {"runs": {"using": "composite", "steps": []}}},
    )
    assert _ash_writers(root) == ([], [])


@pytest.mark.unit
def test_a_local_action_that_is_not_composite_is_not_skipped(tmp_path):
    """A JavaScript or Docker action has no steps to read, so the walk must say so."""
    script_action = "./.github/actions/exporter"
    root = _plant(
        tmp_path,
        [{"uses": script_action}, _CALL],
        {script_action: {"runs": {"using": "node20", "main": "index.js"}}},
    )
    with pytest.raises(AssertionError, match="node20"):
        _ash_writers(root)


@pytest.mark.unit
def test_a_clean_plant_has_no_findings(tmp_path):
    root = _plant(tmp_path, [{"run": 'echo "COLUMNS is ${COLUMNS}"'}, _CALL])
    assert _ash_writers(root) == (["ci.yml"], [])


@pytest.mark.unit
def test_the_composite_walk_reaches_nested_actions():
    """Control: run-scan-test's own composites are walked, each once."""
    steps = _composite_steps(ACTION_USES, set())
    files = {where.split(":", 1)[0] for where, _ in steps}
    assert {
        ".github/actions/run-scan-test/action.yml",
        ".github/actions/tool-download-cache/action.yml",
        ".github/actions/prepull-base-image/action.yml",
    } <= files, sorted(files)


@pytest.mark.unit
def test_the_github_env_reader_sees_an_export():
    """Control for _exports_ash_to_github_env on the shapes a step would use."""
    assert _exports_ash_to_github_env('echo "ASH_CONFIG=x" >> "${GITHUB_ENV}"')
    assert _exports_ash_to_github_env("echo ASH_SCANNERS=bandit >> $GITHUB_ENV")
    assert _exports_ash_to_github_env(
        'echo "ASH_CONFIG<<EOF" >> "$GITHUB_ENV"\necho x >> "$GITHUB_ENV"\n'
    )
    assert _exports_ash_to_github_env(
        '{\n  echo "COLUMNS=160"\n  echo "ASH_CONFIG=x"\n} >> "$GITHUB_ENV"\n'
    )
    assert _exports_ash_to_github_env('echo "ASH_CONFIG=x" >> "${{ github.env }}"')
    assert _exports_ash_to_github_env(
        "printf '%s=%s\\n' ASH_CONFIG x >> \"$GITHUB_ENV\""
    )
    assert not _exports_ash_to_github_env('# echo "ASH_CONFIG=x" >> "$GITHUB_ENV"')
    assert not _exports_ash_to_github_env('echo "COLUMNS=160" >> "$GITHUB_ENV"')
    assert not _exports_ash_to_github_env('echo "ASH_CONFIG=x"')
    # Reading an ASH_TEST_* input to write another variable writes no ASH_* name.
    assert not _exports_ash_to_github_env(
        'echo "COLUMNS=${ASH_TEST_OS}" >> "$GITHUB_ENV"'
    )
    assert not _exports_ash_to_github_env('echo "X=$ASH_TEST_OS" >> "$GITHUB_ENV"')


def _script_step(script: str, uses: str = "actions/github-script@v8") -> dict:
    return {"uses": uses, "with": {"script": script}}


@pytest.mark.unit
def test_the_github_script_reader_sees_an_export():
    """Control for _exports_ash_from_github_script."""
    for script in (
        "core.exportVariable('ASH_SCANNERS', 'bandit')",
        'core.exportVariable("ASH_CONFIG", path)',
        "core.exportVariable(`ASH_${suffix}`, value)",
        "core.exportVariable(name, value)",
        "const { exportVariable } = core\nexportVariable('ASH_CONFIG', 'x')",
    ):
        assert _exports_ash_from_github_script(_script_step(script)), script
    for step in (
        _script_step("core.exportVariable('ACTIONS_RUNTIME_TOKEN', token)"),
        _script_step("// core.exportVariable('ASH_CONFIG', 'x')"),
        _script_step("core.setOutput('ASH_CONFIG', 'x')"),
        _script_step(
            "core.exportVariable('ASH_CONFIG', 'x')", uses="actions/checkout@v6"
        ),
        {"run": "echo hi"},
    ):
        assert not _exports_ash_from_github_script(step), step


posix_only = pytest.mark.skipif(
    os.name == "nt", reason="runs the step's bash script, which CI runs on Linux"
)


@pytest.mark.integration
@posix_only
def test_the_stand_in_records_ash_variables_and_skips_the_test_inputs(tmp_path):
    """Control for the recorder: an empty record must mean none was set."""
    calls, path = _install_stand_in(tmp_path)
    subprocess.run(
        [shutil.which("bash") or "bash", "-c", "ash scan --x"],
        cwd=tmp_path,
        env={
            "PATH": path,
            "ASH_CONFIG": ".ash/no-grype.yaml",
            "ASH_SCANNERS": "bandit",
            # A name no list could have anticipated: the recorder must match the
            # prefix, not a set of known variables.
            "ASH_ANY_FUTURE_OPTION": "1",
            "ASH_TEST_OFFLINE": "true",
            "NOT_ASH": "1",
        },
        check=True,
    )

    assert _records(calls) == [
        [
            "scan",
            "--x",
            _ENV_MARK,
            "ASH_ANY_FUTURE_OPTION=1",
            "ASH_CONFIG=.ash/no-grype.yaml",
            "ASH_SCANNERS=bandit",
        ]
    ]


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("config_file", ["default", "community"])
def test_the_offline_leg_leaves_npm_audit_out(tmp_path, config_file):
    """Exactly npm-audit: no other scanner left out, by argument or environment."""
    (scan,) = _scans(_scan_argv(tmp_path, "true", config_file))

    assert scan == _expected_scan(True, config_file), scan


@pytest.mark.integration
@posix_only
@pytest.mark.parametrize("config_file", ["default", "community"])
def test_an_online_leg_runs_npm_audit(tmp_path, config_file):
    (scan,) = _scans(_scan_argv(tmp_path, "false", config_file))

    assert scan == _expected_scan(False, config_file), scan


@pytest.mark.unit
@pytest.mark.parametrize(
    "calling_step, composite_step",
    [
        (
            {"uses": "./.github/actions/wrapper", "env": {"F": "${{ github.env }}"}},
            {"shell": "bash", "run": 'echo "COLUMNS=1" >> "$F"'},
        ),
        (
            {
                "uses": "./.github/actions/wrapper",
                "with": {"file": "${{ github.env }}"},
            },
            {
                "shell": "bash",
                "env": {"FILE": "${{ inputs.file }}"},
                "run": 'echo "COLUMNS=1" >> "$FILE"',
            },
        ),
        (
            {
                "uses": "./.github/actions/wrapper",
                "with": {"file": "${{ github.env }}"},
            },
            {"shell": "bash", "run": 'echo "COLUMNS=1" >> "${{ inputs.file }}"'},
        ),
    ],
    ids=["env-on-the-calling-step", "with-into-a-step-env", "with-as-the-target"],
)
def test_a_file_handed_to_a_composite_is_followed(
    tmp_path, calling_step, composite_step
):
    """A composite's steps see the env, and the inputs, of the step that runs it."""
    root = _plant_job(
        tmp_path,
        {"steps": [calling_step]},
        {_WRAPPER: {"runs": {"using": "composite", "steps": [composite_step, _CALL]}}},
    )

    callers, findings = _ash_writers(root)

    assert callers == ["ci.yml"], callers
    assert len(findings) == 1 and "not on the allowlist" in findings[0], findings


@pytest.mark.unit
@pytest.mark.parametrize("using", ["Composite", "COMPOSITE", " composite "])
def test_a_composite_named_in_another_case_is_still_walked(tmp_path, using):
    """`using` is compared without regard to case or space, so no wrapper hides."""
    root = _plant_job(
        tmp_path,
        {"steps": [_PLANTED_WRITERS["GITHUB_ENV assignment"], {"uses": _WRAPPER}]},
        {_WRAPPER: {"runs": {"using": using, "steps": [_CALL]}}},
    )

    callers, findings = _ash_writers(root)

    assert callers == ["ci.yml"], callers
    assert len(findings) == 1, findings


@pytest.mark.unit
def test_this_file_states_its_rules_rather_than_citing_review_ids():
    """The file ships in a public repository; an internal rule id means nothing there."""
    text = Path(__file__).read_text(encoding="utf-8")
    assert not re.search(r"\bruling\s+R\d|\bR\d+\s+\([a-z]\)", text)


@pytest.mark.unit
def test_the_step_points_at_the_faq_entry():
    """The exclusion is the documented answer, so the comment says where it is."""
    script = _step()["run"]
    assert "docs/content/faq.md" in script, script


# ---------------------------------------------------------------------------
# More ways into the job's environment, each planted in a tree of its own.


def _plant_job(root: Path, job: dict, actions: dict | None = None) -> Path:
    """Like _plant, with the calling job given whole (steps, env, container)."""
    files = {
        ".github/actions/run-scan-test/action.yml": {
            "runs": {
                "using": "composite",
                "steps": [{"name": STEP_NAME, "shell": "bash", "run": "true"}],
            }
        },
        ".github/workflows/ci.yml": {"jobs": {"test": job}},
    }
    for uses, spec in (actions or {}).items():
        files[f"{uses[2:]}/action.yml"] = spec
    for relative, document in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return root


def _script(script: str, uses: str = "actions/github-script@v8") -> dict:
    return {"uses": uses, "with": {"script": script}}


#: A step of the calling job for each further way it can reach the offline step's
#: environment, or the `ash` it runs.
_MORE_WRITERS = {
    "env | grep the ASH_ prefix": {"run": "env | grep '^ASH_' >> \"$GITHUB_ENV\""},
    "printf building the name": {
        "run": "printf 'ASH_%s=%s\\n' CONFIG x >> \"$GITHUB_ENV\""
    },
    "the name in the step's own env": {
        "run": 'echo "${NAME}=x" >> "$GITHUB_ENV"',
        "env": {"NAME": "ASH_CONFIG"},
    },
    "a GITHUB_PATH shim": {
        "run": 'echo "${RUNNER_TEMP}/shim" >> "$GITHUB_PATH"',
    },
    "PATH through GITHUB_ENV": {
        "run": 'echo "PATH=${RUNNER_TEMP}/shim:${PATH}" >> "$GITHUB_ENV"',
    },
    "BASH_ENV through GITHUB_ENV": {
        "run": 'echo "BASH_ENV=${RUNNER_TEMP}/env.sh" >> "$GITHUB_ENV"',
    },
    "github-script appending to the file": _script(
        "fs.appendFileSync(process.env.GITHUB_ENV, 'ASH' + '_CONFIG=x\\n')"
    ),
    "github-script with an aliased exportVariable": _script(
        "const ev = core.exportVariable\nev('ASH_CONFIG', 'x')"
    ),
    "github-script with core['exportVariable']": _script(
        "core['exportVariable']('ASH_CONFIG', 'x')"
    ),
    "github-script named in another case": _script(
        "core.exportVariable('ASH_CONFIG', 'x')", uses="Actions/GitHub-Script@v8"
    ),
    "github-script adding to PATH": _script("core.addPath(process.env.RUNNER_TEMP)"),
}


@pytest.mark.unit
@pytest.mark.parametrize("shape", sorted(_MORE_WRITERS))
def test_a_further_planted_writer_is_found(tmp_path, shape):
    root = _plant_job(tmp_path, {"steps": [_MORE_WRITERS[shape], _CALL]})

    callers, findings = _ash_writers(root)

    assert callers == ["ci.yml"]
    assert len(findings) == 1, findings


@pytest.mark.unit
def test_the_job_containers_env_is_read(tmp_path):
    root = _plant_job(
        tmp_path,
        {"container": {"image": "img", "env": {"ASH_CONFIG": "x"}}, "steps": [_CALL]},
    )

    _, findings = _ash_writers(root)

    assert findings == ["ci.yml: job container env sets ['ASH_CONFIG']"], findings


@pytest.mark.unit
def test_a_docker_step_fails_the_walk(tmp_path):
    """A docker:// step can write GITHUB_ENV from inside an image nothing here reads."""
    root = _plant_job(tmp_path, {"steps": [{"uses": "docker://alpine:3.20"}, _CALL]})

    with pytest.raises(AssertionError, match="docker://"):
        _ash_writers(root)


_WRAPPER = "./.github/actions/wrapper"


@pytest.mark.unit
def test_a_caller_through_a_wrapper_composite_is_found(tmp_path):
    root = _plant_job(
        tmp_path,
        {"steps": [_PLANTED_WRITERS["GITHUB_ENV assignment"], {"uses": _WRAPPER}]},
        {_WRAPPER: {"runs": {"using": "composite", "steps": [_CALL]}}},
    )

    callers, findings = _ash_writers(root)

    assert callers == ["ci.yml"], callers
    assert len(findings) == 1 and "exports an ASH_* variable" in findings[0], findings


@pytest.mark.unit
def test_env_on_the_way_to_the_action_is_read(tmp_path):
    """A composite passes a step's env on to its own steps, the offline step's too."""
    root = _plant_job(
        tmp_path,
        {"steps": [{"uses": _WRAPPER, "env": {"ASH_SCANNERS": "bandit"}}]},
        {
            _WRAPPER: {
                "runs": {
                    "using": "composite",
                    "steps": [{**_CALL, "env": {"ASH_CONFIG": "x"}}],
                }
            }
        },
    )

    _, findings = _ash_writers(root)

    assert len(findings) == 2, findings
    assert all("on to the action's steps" in finding for finding in findings), findings


@pytest.mark.unit
def test_env_on_a_step_that_does_not_lead_to_the_action_is_not_a_finding(tmp_path):
    other = "./.github/actions/cache"
    root = _plant_job(
        tmp_path,
        {"steps": [{"uses": other, "env": {"ASH_TOOL_DOWNLOAD_CACHE": "d"}}, _CALL]},
        {other: {"runs": {"using": "composite", "steps": []}}},
    )
    assert _ash_writers(root) == (["ci.yml"], [])


@pytest.mark.unit
@pytest.mark.parametrize(
    "options",
    [
        "--env ASH_CONFIG=x",
        "-e ASH_CONFIG=x",
        "--env=ASH_CONFIG=x",
        "--cpus 2 -e COLUMNS=160",
        "--env-file .env",
        "--env-file=.env",
        # docker's flag parser takes the value joined to the short flag, a short
        # flag inside a cluster, and any whitespace after the long one.
        "-eASH_CONFIG=x",
        "-ie ASH_CONFIG=x",
        "--env\tASH_CONFIG=x",
    ],
)
def test_env_set_through_the_job_containers_options_is_read(tmp_path, options):
    """docker run's own flags set the container's env; a name there is not read."""
    root = _plant_job(
        tmp_path,
        {"container": {"image": "img", "options": options}, "steps": [_CALL]},
    )

    _, findings = _ash_writers(root)

    assert len(findings) == 1 and "container options" in findings[0], findings


@pytest.mark.unit
def test_other_job_container_options_are_not_a_finding(tmp_path):
    root = _plant_job(
        tmp_path,
        {
            "container": {"image": "img", "options": "--cpus 2 --label x-e=1"},
            "steps": [_CALL],
        },
    )
    assert _ash_writers(root) == (["ci.yml"], [])


#: Writes of the environment or PATH file that no name reader here can tie to an
#: ASH_* variable. Each is a finding unless the allowlist names it.
_UNLISTED_WRITES = {
    "a plain variable": {"run": 'echo "COLUMNS=160" >> "$GITHUB_ENV"'},
    "PYTHONPATH": {"run": 'echo "PYTHONPATH=/x" >> "$GITHUB_ENV"'},
    "LD_PRELOAD": {"run": 'echo "LD_PRELOAD=/x.so" >> "$GITHUB_ENV"'},
    "a name from vars": {"run": 'echo "${{ vars.X }}=x" >> "$GITHUB_ENV"'},
    "a nested expression as the target": {
        "run": 'echo "COLUMNS=1" >> "${${{ env.X }}}"'
    },
    "printenv as the target": {"run": 'echo "COLUMNS=1" >> "$(printenv X)"'},
    "an indirect expansion as the target": {"run": 'echo "COLUMNS=1" >> "${!X}"'},
    "the file named in the step's env": {
        "run": 'echo "COLUMNS=1" >> "$F"',
        "env": {"F": "${{ github.env }}"},
    },
    "a GITHUB_PATH write": {"run": 'echo "/opt/bin" >> "$GITHUB_PATH"'},
    "tee --append to an indirect target": {
        "run": 'echo "COLUMNS=1" | tee --append "${!X}"'
    },
    "a clobbering redirect to an indirect target": {
        "run": 'echo "COLUMNS=1" >| "${!X}"'
    },
    # The commented line is uncommented and run by the shell it is piped to.
    "a commented write run through a heredoc": {
        "run": "sed 's/^#//' <<'EOF' | bash\n# echo \"COLUMNS=1\" >> \"$GITHUB_ENV\"\nEOF"
    },
}


@pytest.mark.unit
@pytest.mark.parametrize("shape", sorted(_UNLISTED_WRITES))
def test_a_write_not_on_the_allowlist_is_found(tmp_path, shape):
    root = _plant_job(tmp_path, {"steps": [_UNLISTED_WRITES[shape], _CALL]})

    _, findings = _ash_writers(root)

    assert len(findings) == 1 and "not on the allowlist" in findings[0], findings


@pytest.mark.unit
def test_a_name_held_in_the_job_env_is_named_in_the_finding(tmp_path):
    root = _plant_job(
        tmp_path,
        {
            "env": {"NAME": "ASH_CONFIG"},
            "steps": [{"run": 'echo "${NAME}=x" >> "$GITHUB_ENV"'}, _CALL],
        },
    )

    _, findings = _ash_writers(root)

    assert len(findings) == 1 and "holds an ASH_* name" in findings[0], findings


@pytest.mark.unit
def test_the_file_named_in_the_job_env_is_found(tmp_path):
    root = _plant_job(
        tmp_path,
        {
            "env": {"F": "${{ github.env }}"},
            "steps": [{"run": 'echo "COLUMNS=1" >> "$F"'}, _CALL],
        },
    )

    _, findings = _ash_writers(root)

    assert len(findings) == 1 and "not on the allowlist" in findings[0], findings


_LISTED = EnvWrite(
    step="ci.yml: Set the column width",
    variable="COLUMNS",
    line='echo "COLUMNS=160" >> "$GITHUB_ENV"',
    reason="a planted entry",
)


def _listed_step(run: str, name: str = "Set the column width") -> dict:
    return {"name": name, "run": run}


@pytest.mark.unit
def test_an_allowlisted_write_passes(tmp_path):
    root = _plant_job(tmp_path, {"steps": [_listed_step(_LISTED.line), _CALL]})

    assert _ash_writers(root, allowlist=(_LISTED,)) == (["ci.yml"], [])
    # The same write with no entry is a finding.
    assert len(_ash_writers(root)[1]) == 1


@pytest.mark.unit
def test_a_write_beside_an_allowlisted_one_is_still_found(tmp_path):
    run = _LISTED.line + '\necho "PYTHONPATH=/x" >> "$GITHUB_ENV"'
    root = _plant_job(tmp_path, {"steps": [_listed_step(run), _CALL]})

    _, findings = _ash_writers(root, allowlist=(_LISTED,))

    assert len(findings) == 1 and "not on the allowlist" in findings[0], findings


@pytest.mark.unit
def test_an_allowlisted_step_that_also_names_an_ash_variable_is_found(tmp_path):
    """The entry admits its line; an ASH_* name elsewhere in the script still counts."""
    run = "ASH_SCANNERS=bandit\n" + _LISTED.line
    root = _plant_job(tmp_path, {"steps": [_listed_step(run), _CALL]})

    _, findings = _ash_writers(root, allowlist=(_LISTED,))

    assert len(findings) == 1, findings
    assert "is on the allowlist but" in findings[0], findings
    assert "exports an ASH_* variable" in findings[0], findings


@pytest.mark.unit
def test_a_group_write_cannot_be_allowlisted(tmp_path):
    """`{ ...; } >> "$GITHUB_ENV"` names its variables on lines an entry cannot pin."""
    group = '{\n  echo "ASH_CONFIG=x"\n  echo "COLUMNS=160"\n} >> "$GITHUB_ENV"'
    entry = EnvWrite(
        step="ci.yml: Set the column width",
        variable="COLUMNS",
        line='} >> "$GITHUB_ENV"',
        reason="a planted entry",
    )
    root = _plant_job(tmp_path, {"steps": [_listed_step(group), _CALL]})

    with pytest.raises(AssertionError, match="does not write COLUMNS"):
        _ash_writers(root, allowlist=(entry,))
    # With no entry, the write is a finding that names what the readers saw.
    _, findings = _ash_writers(root)
    assert len(findings) == 1 and "exports an ASH_* variable" in findings[0], findings


@pytest.mark.unit
def test_an_allowlist_entry_names_its_variable_and_a_reason():
    for entry in ENV_WRITE_ALLOWLIST:
        _check_entry(entry)
    for bad in (
        EnvWrite("x", "COLUMNS", 'echo "OTHER=1" >> "$GITHUB_ENV"', "r"),
        EnvWrite("x", "ASH_CONFIG", 'echo "ASH_CONFIG=1" >> "$GITHUB_ENV"', "r"),
        EnvWrite("x", "COLUMNS", 'echo "COLUMNS=1" >> "$GITHUB_ENV"', ""),
        # Brace expansion writes ASH_X=2 beside the listed name.
        EnvWrite(
            "x",
            "COLUMNS",
            "printf '%s\\n' COLUMNS=1 {ASH_X,}=2 >> \"$GITHUB_ENV\"",
            "r",
        ),
        # Not a variable name at all.
        EnvWrite("x", "}}", 'echo "A=1 }}=2" >> "$GITHUB_ENV"', "r"),
        # A heredoc: its body, which no entry pins, is what is written.
        EnvWrite("x", "cat", 'cat<<EOF >> "$GITHUB_ENV"', "r"),
        # Two writes on one line, and a write continued onto the next line.
        EnvWrite("x", "COLUMNS", 'echo "COLUMNS=1" >> "$GITHUB_ENV"; true', "r"),
        EnvWrite("x", "COLUMNS", 'echo "COLUMNS=1" \\', "r"),
        EnvWrite(
            "x", "COLUMNS", 'echo "COLUMNS=1" "PYTHONPATH=/x" >> "$GITHUB_ENV"', "r"
        ),
    ):
        with pytest.raises(AssertionError):
            _check_entry(bad)


@pytest.mark.unit
def test_a_write_continued_into_a_listed_line_is_found(tmp_path):
    """The listed line is the tail of a command that began a line earlier."""
    run = 'echo "PYTHONPATH=/x" \\\n  "COLUMNS=160" >> "$GITHUB_ENV"'
    entry = EnvWrite(
        step="ci.yml: Set the column width",
        variable="COLUMNS",
        line='"COLUMNS=160" >> "$GITHUB_ENV"',
        reason="a planted entry",
    )
    root = _plant_job(tmp_path, {"steps": [_listed_step(run), _CALL]})

    _, findings = _ash_writers(root, allowlist=(entry,))

    assert len(findings) == 1 and "not on the allowlist" in findings[0], findings


@pytest.mark.unit
def test_a_script_action_in_an_unrelated_job_does_not_fail_the_search(tmp_path):
    """Only a calling job is walked; a JavaScript action elsewhere runs no action."""
    script_action = "./.github/actions/js"
    root = _plant_job(
        tmp_path,
        {"steps": [_CALL]},
        {script_action: {"runs": {"using": "node20", "main": "index.js"}}},
    )
    other = root / ".github" / "workflows" / "other.yml"
    other.write_text(
        yaml.safe_dump({"jobs": {"lint": {"steps": [{"uses": script_action}]}}}),
        encoding="utf-8",
    )

    assert _ash_writers(root) == (["ci.yml"], [])


@pytest.mark.unit
def test_the_further_readers_see_their_shapes():
    """Controls for _runtime_writes, _env_names_ash and the github-script reader."""
    assert _runtime_writes('echo "${bin}" >> "$GITHUB_PATH"') == ["writes GITHUB_PATH"]
    assert _runtime_writes('echo "/x" >> "${{ github.path }}"') == [
        "writes GITHUB_PATH"
    ]
    assert _runtime_writes('echo "BASH_ENV=/f" >> "$GITHUB_ENV"') == [
        "writes PATH, BASH_ENV, PYTHONPATH or LD_PRELOAD to GITHUB_ENV"
    ]
    assert not _runtime_writes('echo "X=$PATH" >> "$GITHUB_ENV"')
    assert not _runtime_writes('echo "COLUMNS=160" >> "$GITHUB_ENV"')
    assert not _runtime_writes('# echo "/x" >> "$GITHUB_PATH"')
    assert _env_names_ash({"ASH_CONFIG": "x"})
    assert _env_names_ash({"NAME": "ASH_CONFIG"})
    assert not _env_names_ash({"OS": "${ASH_TEST_OS}", "COLUMNS": "160"})
    assert not _exports_ash_from_github_script(
        _script("core.setOutput('cache', process.env.ACTIONS_CACHE_URL)")
    )
