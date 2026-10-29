# Scale to large repositories

Three features help when one scan of one tree is too slow or too coarse:

- [Changed-files scans](#changed-files) gate a pull request on the files it changed.
- [Sharding](#sharding) splits the scanners of one scan across several runners, and
  `ash merge` recombines the results.
- [Workspace scans](#workspaces) scan the folders of a `.code-workspace` file as separate
  projects in one run, from the command line or over MCP.

None of them splits the files of a scan between runners. Each section ends with what the
feature does not do.

## Gate on the files a change touches {#changed-files}

`--changed-files-only` keeps only the findings in files that changed between `--base-ref`
(default `origin/main`) and `HEAD`. The environment variables `ASH_CHANGED_FILES_ONLY` and
`ASH_BASE_REF` set the same options.

These examples use a git repository whose `app.py` has a detect-secrets finding and whose
`notes.txt` has none. Change only `notes.txt` on a branch:

```bash
git switch -c edit-notes
echo "More notes." >> notes.txt
git commit -q -am "Edit the notes"
ash scan --scanners detect-secrets --changed-files-only --base-ref main
```

The scan exits 0. detect-secrets still scanned `app.py`, and its finding was dropped
because `app.py` is not in the change. The finding is gone from every report:

```python
import json

for name in ("ash.sarif", "ash.ghas.sarif"):
    with open(f".ash/ash_output/reports/{name}") as report:
        runs = json.load(report)["runs"]
    print(name, sum(len(run.get("results", [])) for run in runs))
```

```text
ash.sarif 0
ash.ghas.sarif 0
```

How the change is computed and applied:

- The changed files are `git diff --name-only <base-ref>...HEAD`: files changed in commits
  since the merge base. Staged, modified, and untracked files that are not committed are not
  included. A renamed file counts under its new name. When the change moves a submodule
  to another commit, `git diff` lists only the submodule's path, and every file inside the
  submodule counts as changed.
- Every scanner scans the whole tree, so the option does not make a scan faster.
- After the scan, ASH removes the findings whose file is not in the changed set before it
  writes any report, so they are gone from every report, from the summary table, and from
  `ash_aggregated_results.json`, and the exit code counts only what is left. Findings with
  no file location are kept. Each scanner's own output under `scanners/` still has them.
- `metadata.changed_files_only` in `ash_aggregated_results.json` is `true` when the
  findings were filtered this way, and `false` on a full scan, including the fallback
  below, so a reader can tell a filtered result from a full one.
- When the changed set is empty, every finding with a file location is discarded and the
  scan exits 0. If that discarded any findings, ASH logs a warning that the result is not
  evidence of a clean tree.

ASH falls back to reporting every finding, with a warning and the full scan's exit code,
when the base ref does not exist (in a shallow clone, for example), when there is no merge
base, when the directory is not in a git repository or git is not installed, and in
container mode. The warning says which, such as
`--changed-files-only was requested but git is not installed or not on PATH`. CI
clones are often shallow, so fetch the base branch's history first; the
[Run ASH in GitHub Actions](ci/github-actions.md#changed-files) and
[Run ASH in GitLab CI](ci/gitlab-ci.md#scan-only-what-a-merge-request-changes) show how.

The option is not available over MCP.

## Split a scan across runners {#sharding}

`--shard-index` and `--shard-count` (or `ASH_SHARD_INDEX` and `ASH_SHARD_COUNT`) give each
runner a share of the scanners. Every runner scans the whole tree with its share; `ash merge`
then combines the shards' results into one set of reports and one exit code.

ASH sorts the names of every registered scanner and deals them out in turn, so shard *i*
of *n* gets the scanners at positions *i*, *i + n*, and so on. Counts above about four save
little time: a scan is never faster than its slowest scanner, and the split balances the
number of scanners, not their run time.

Split the scan in two, writing each shard's output outside the repository so that the
second shard does not scan the first one's reports. The shards run with
`--no-fail-on-findings`, as they do in CI, so each exits 0 and the merge gives the verdict:

<!-- doctest: run fresh -->
```bash
ash scan --scanners detect-secrets --shard-index 0 --shard-count 2 --output-dir ../shard-0 --no-fail-on-findings
```

```bash
ash scan --scanners detect-secrets --shard-index 1 --shard-count 2 --output-dir ../shard-1 --no-fail-on-findings
```

`--scanners` narrows what a shard runs, not how the scanners are split, so detect-secrets
runs only on the shard it is dealt to, and the other shard runs no scanner. Each shard
records its share in `metadata.shard`:

```python
import json

for index in (0, 1):
    path = f"../shard-{index}/ash_aggregated_results.json"
    with open(path, encoding="utf-8") as results:
        shard = json.load(results)["metadata"]["shard"]
    print(f"shard {index}:", ", ".join(shard["selected_scanners"]) or "no scanner")
```

```text
shard 0: no scanner
shard 1: detect-secrets
```

Which shard is dealt detect-secrets depends on the scanner list of the ASH you run. Merge
the shards. The merge exits 2 for the finding in `app.py`, whichever shard found it:

<!-- doctest: run expect-exit=2 -->
```bash
ash merge --fail-on-findings --results ../shard-0 --results ../shard-1 --output-dir ../merged
```

```text
Scanners: 16 | Findings: 1 | Actionable: 1 | Suppressed: 0
```

`--results` takes a shard's `ash_aggregated_results.json` or its output directory, once per
shard. `ash merge` writes `ash_aggregated_results.json` and every report the shards'
configuration enables, including `ash.ghas.sarif` and `ash.gl-sast-report.json`, unless
`--output-formats`, or else the `output_formats` setting in the shards' configuration,
narrows them. It reads the fail-on-findings setting, the incomplete-scan
setting, the severity thresholds, and the suppressions from the configuration recorded in
the lowest-numbered shard; `--fail-on-findings` and
`--fail-on-incomplete-scanners` on the command line override the first two. A value the
shards' configuration read from the environment is recorded as its reference, and `ash merge`
does not read the environment for it: a field that takes a fixed choice, a boolean, or a
number, such as `severity_threshold`, cannot hold the reference, so the merge exits 3 naming
the field until you supply it with `--config-overrides` or in the file `--config` names
([Read values from the environment](configure.md#environment)). The AWS
reporters send the merged findings only with their `enabled` and destination options in
`ash merge`'s `--config-overrides`, not from a config file
([AWS reporters](../plugins/aws.md#ash-report)). Name their package for the merge too, with
`--config` or `--config-overrides`, and leave out `--output-formats`, which stops them. It combines
each converter's results across the shards, failed inputs included, so a notebook or
archive that one shard could not convert makes the merged scan incomplete.

Its exit codes:

| Exit code | When |
|---|---|
| 0 | Every shard is present and nothing actionable was found. |
| 1 | It refused to merge, a scanner in some shard was MISSING or failed, or a converter in some shard failed. |
| 2 | Actionable findings. |
| 3 | A fixed-choice, boolean, or number field the shards' configuration read from the environment, which the command line does not supply. Nothing was merged. |
| 3 | Two reporters that the merge loads have the same name or names that read as one ([Exit codes](../reference/exit-codes.md#merge)). Nothing was merged. |
| 5 | A usage error, such as a missing `--results`, a `--results` path that does not exist, or an output directory that is not a directory, cannot be created, entered, or written, or is not a valid path because it holds a NUL character, which a `--cli-json-input` document can carry ([Exit codes](../reference/exit-codes.md#merge)). Nothing was merged. |

It refuses to merge, and exits 1, when a shard index is missing or repeated, the shards
disagree about the count, two shards ran the same scanner, the shards split different sets
of scanners, a results file is not from a sharded scan, a `--results` directory holds no
results file, or a shard owned scanners and completed none of them. A shard that owned only
scanners that `--scanners` or `--exclude-scanners` left out counts as complete. It warns,
without refusing, when a scanner ran on no shard although a shard's selection asked for
it: the jobs of the matrix were given different `--scanners`, `--exclude-scanners`, or
configuration, and the shard that owned the scanner did not select it.

### Sharding in GitHub Actions {#sharding-github}

One matrix job per shard, then a job that merges and uploads:

<!-- doctest: config kind=github-actions -->
```yaml
name: ASH sharded
on:
  pull_request:
permissions:
  contents: read
env:
  INSTALL_SPEC: "automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"
jobs:
  shard:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        shard: [0, 1, 2, 3]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@18d369b23da25a81e9458561248e1aafff6a70fa # v10.3.1
        with:
          version: latest
      - uses: ruby/setup-ruby@b1da4809b005e0178fe08a1d57317bffc00b7b4c # v1.332.0
        with:
          ruby-version: "3.3"
      - name: Install ASH and the scanner tools
        run: |
          token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
          if [ "${#token}" -ne 32 ]; then
            echo "::error::no random token could be read for stop-commands, so the command did not run"
            exit 1
          fi
          printf '::stop-commands::%s\n' "${token}"
          status=0
          {
            uv tool install "${INSTALL_SPEC}" &&
              uv tool dir --bin >> "${GITHUB_PATH}" &&
              cd "${RUNNER_TEMP}" &&
              "$(uv tool dir --bin)/ash" dependencies install \
                --tool grype --tool syft --tool opengrep --tool cfn-nag \
                --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy
          } 2>&1 || status=$?
          printf '\n::%s::\n' "${token}"
          exit "${status}"
      - name: Scan one shard
        env:
          SHARD: ${{ matrix.shard }}
        run: |
          token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
          if [ "${#token}" -ne 32 ]; then
            echo "::error::no random token could be read for stop-commands, so the command did not run"
            exit 1
          fi
          printf '::stop-commands::%s\n' "${token}"
          status=0
          ash scan --mode local --no-progress --no-fail-on-findings --no-allow-stale-content-db \
            --shard-index "${SHARD}" --shard-count 4 \
            2>&1 || status=$?
          printf '\n::%s::\n' "${token}"
          exit "${status}"
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        if: ${{ !cancelled() }}
        with:
          name: ash-shard-${{ matrix.shard }}
          # Not the whole output directory: scanners/ and converted/ hold each
          # tool's raw output, which is not masked. `ash merge` reads each
          # shard's ash_aggregated_results.json.
          path: |
            .ash/ash_output/reports
            .ash/ash_output/ash_aggregated_results.json
          # Overwrite on re-runs only (run_attempt 2 and later), so the first
          # attempt still fails loudly on a name taken twice, while "Re-run failed
          # jobs" replaces its own earlier upload instead of failing on the name.
          overwrite: ${{ github.run_attempt != '1' }}
  merge:
    needs: shard
    if: ${{ !cancelled() }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read # private repositories only
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@18d369b23da25a81e9458561248e1aafff6a70fa # v10.3.1
        with:
          version: latest
      - name: Install ASH
        run: |
          token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
          if [ "${#token}" -ne 32 ]; then
            echo "::error::no random token could be read for stop-commands, so the command did not run"
            exit 1
          fi
          printf '::stop-commands::%s\n' "${token}"
          status=0
          {
            uv tool install "${INSTALL_SPEC}" &&
              uv tool dir --bin >> "${GITHUB_PATH}"
          } 2>&1 || status=$?
          printf '\n::%s::\n' "${token}"
          exit "${status}"
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          pattern: ash-shard-*
          path: shards
      - name: Merge the shards
        run: |
          token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
          if [ "${#token}" -ne 32 ]; then
            echo "::error::no random token could be read for stop-commands, so the command did not run"
            exit 1
          fi
          printf '::stop-commands::%s\n' "${token}"
          status=0
          ash merge --fail-on-findings --fail-on-incomplete-scanners --output-dir .ash/ash_output \
            --results shards/ash-shard-0 --results shards/ash-shard-1 \
            --results shards/ash-shard-2 --results shards/ash-shard-3 \
            2>&1 || status=$?
          printf '\n::%s::\n' "${token}"
          exit "${status}"
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        if: ${{ !cancelled() }}
        with:
          name: ash-merged
          # The merged reports and results file, beside the shards' artifacts.
          path: |
            .ash/ash_output/reports
            .ash/ash_output/ash_aggregated_results.json
          # As for the shards: overwrite on re-runs only.
          overwrite: ${{ github.run_attempt != '1' }}
      - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        if: ${{ !cancelled() }}
        with:
          sarif_file: .ash/ash_output/reports/ash.ghas.sarif
          category: ash
```

Each step that runs `uv` or `ash` stops workflow commands around it, as the steps in
[Write the steps yourself](ci/github-actions.md#plain-steps) do.

The shards run with `--no-fail-on-findings`, so a shard job fails only when one of its
scanners did not run, and the merge job decides the result. The merge job uploads the merged
reports and results file as `ash-merged`, beside the shards' `ash-shard-0` to `ash-shard-3`,
so the merged `ash_aggregated_results.json` and SARIF can be downloaded without rerunning the
merge. The merge reads its gate settings
from the configuration that the shards recorded, which on a pull request is the branch's own,
so it passes `--fail-on-findings` and `--fail-on-incomplete-scanners`, and the shards pass
`--no-allow-stale-content-db`. The thresholds and suppressions still come from the branch; to
keep those yours, run the shards with `--config` and a file outside the checkout. Each
shard installs every tool, because which scanners land on which shard depends on the
scanner list of the ASH it installs. Every shard must load the same plugin modules, or the merge
refuses them. Run `ash merge` with the ASH version the shards ran: an older `ash merge` refuses
the results of a newer ASH's shards.

What sharding does not do:

- It does not split files. Each shard scans the whole tree.
- It does not balance by run time.
- It does not combine with workspace scans (the scan exits 1) and is not available over MCP.
- `ash merge` does not remove duplicate findings that two scanners report for the same
  problem, and keeps the software bill of materials of one shard only.

## Scan a multi-project workspace {#workspaces}

`--workspace` takes a VS Code `.code-workspace` file and scans each of its folders as a
separate project, with that project's own configuration, in one run. Pass
`--workspace auto` to use the only `.code-workspace` file in the current directory.

Make two projects from that repository and a workspace file that names them:

<!-- doctest: run fresh -->
```bash
mkdir -p services/api services/web
git mv app.py services/api/app.py
printf 'def handler():\n    return "ok"\n' > services/web/main.py
cat > services.code-workspace <<'EOF'
{
  "folders": [
    {"path": "services/api"},
    {"path": "services/web"}
  ]
}
EOF
ash scan --workspace services.code-workspace --dry-run
```

`--dry-run` prints the plan, one entry per project with its path, configuration, threshold,
and scanners, and scans nothing. Before it prints the plan, it imports the plugin modules the
run loads (`--ash-plugin-modules` and each project's `ash_plugin_modules`) and refuses what
the run refuses before any project starts, with the run's exit 3 and message and no plan: a
module outside the plugin namespace, a module that does not import, and two plugins of one
type whose names are the same or that the config lookup reads as one, such as `csv_` beside
`csv`. Scan it:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --workspace services.code-workspace --scanners detect-secrets
```

<!-- doctest: output -->
```text
  FAIL     services-api -- 1 actionable of 1 at threshold MEDIUM (1.7s)
  pass     services-web -- 0 actionable of 0 at threshold MEDIUM (1.7s)
```

The workspace file:

- ASH reads only `folders[].path`. The file must be plain JSON: a comment in it is an error.
- Paths are relative to the workspace file. A folder outside the workspace file's directory,
  a path with `..`, a symbolic link, the directory itself (`.`), and overlapping or repeated
  folders are refused. The VS Code layout that lists sibling repositories as `../name` does
  not work; put the workspace file in the parent directory instead.
- A missing project fails the run, so a typo cannot pass as a clean scan.
  `--allow-missing-projects` skips missing projects and records them in the plan.

Each project uses its own ASH config file, with the file `--config` (or `ASH_CONFIG`) names
layered over it: every setting your file makes is final for every project, and a project's
own config fills only the settings yours leaves out. A project that has no config uses your
file alone, or ASH's defaults with no `--config`. `--config-overrides`, the command-line
flags, and the workspace policy apply after both. `--dry-run` prints an `operator:` line
under each project your file is layered over, and the threshold it prints is the layered
result. The config file beside the workspace file is not a fallback for the projects.
Keep your file outside every git checkout: ASH treats a file inside one as written by a
repository, so the settings only an operator may make, such as sandbox grants and the AWS
reporters' destinations, are not final from it, and the plugin modules it may add are
limited the same way as a repository's
([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided)).
Container mode gives your file the same tier: the host mounts a file from another git
checkout and tells the workspace scan inside that a repository wrote it, and that scan
limits the file, and every file it extends, for every project and for the plan, with the
same warnings ([The config file](run-in-a-container.md#config)).

Your file, and every base it `extends`, must be outside the workspace's tree: the outermost
git checkout around the workspace, or the workspace directory itself when it is in no
checkout. ASH cannot tell a file there from one the repository committed, so a `--config`
inside that tree, beside the workspace in the same checkout included, or under the MCP
workspace root, is refused with exit code 3 and the file named, before any project is
resolved. Container mode refuses it the same way, with the same error, before anything is
built or mounted, a file under the workspace root included.
`ash dependencies install` reads
only the configuration of the directory it runs in, so name the tools the projects need
with `--tool`, or run it in each project's directory.

The output directory, `.ash/ash_output` next to the workspace file by default, holds:

- combined reports for the workspace in `reports/`;
- each project's full output, as from a single scan, in `projects/<project>/`. GitHub code
  scanning, GitLab SAST, and CycloneDX reports exist only there, one per project, because
  each describes one repository. A project's `output_formats` setting narrows its own
  reports; the combined reports follow `--output-formats` only;
- the combined `ash_aggregated_results.json`, whose `workspace` member lists each project
  with its status, its finding counts, `incomplete_scanners`, and `incomplete_converters`,
  which names each converter that lost coverage and why.

A link at `projects` or `.workspace-spool` stops the whole run, and a link at
`projects/<project>` fails that project; see
[Links are refused](../reference/output-files.md#links).

A workspace policy file applies to every project: a severity threshold that projects can
tighten but not relax, suppressions and ignore paths for every project, and extra scanners.
ASH finds `ash-workspace.yaml`, `.yml`, or `.json`, with or without a leading dot, in the
workspace directory or its `.ash` directory, or takes the path from `--workspace-config`; the
[configuration reference](../reference/configuration.md#workspace-policy-file) lists its
keys. Its suppressions and ignore paths are written relative to the workspace and rebased
into each project, keeping a trailing slash: `api/vendor/` is `vendor/` in project `api`. A
pattern with no exact form inside a project, such as `**/vendor/**` or `**/vendor/`,
refuses the workspace with exit code 4.

The exit code is the most severe of the projects' results, ranked 3, then 2, then 1, then
0, so a workspace with findings in one project and a missing scanner in another exits 2.
Codes 4 and 5 are not part of that ranking: ASH gives them when it refuses the workspace
before any project runs. Exit code 4 means the workspace itself is wrong: the workspace file
or policy file cannot be used, a project is missing, or the projects need different plugin
modules or incompatible scanner versions. `--workspace` and `--source-dir` together also exit
4. Exit code 5 is a usage error, such as a `--scanners` list that names no scanner or that
`--exclude-scanners` cancels:

<!-- doctest: run expect-exit=5 -->
```bash
ash scan --workspace services.code-workspace --scanners detect-secret
```

`--changed-files-only` works per project, against that project's own git repository. A
project with no changes is skipped, and a project that is not in a git repository is
scanned in full, with a warning. Each project's reports are filtered as a single scan's
are. `--mode precommit` changes only the output in a workspace: it does not narrow the
scanners or select changed files.

### Workspace scans over MCP {#workspaces-mcp}

`ash mcp` offers the same scans to an MCP client through two tools:

- [`resolve_ash_workspace`](../reference/mcp-tools.md#resolve_ash_workspace) returns the plan,
  like `--dry-run`, except that it does not check plugin names: it runs in the server and
  scans nothing, so it imports no project's plugin module, and its response says
  `plugin_names_checked` false. `run_ash_workspace_scan` refuses two plugins whose names read
  as one before it scans anything, as `--dry-run` does.
- [`run_ash_workspace_scan`](../reference/mcp-tools.md#run_ash_workspace_scan) runs it and
  returns the exit code, the output directory, the path of the combined results, and a scan
  ID per project. To read one project's findings, pass that project's output directory to
  `get_scan_results`.

Both tools return `exit_code`, the code the CLI would exit with, and `exit_code_meaning`, its
description. When `run_ash_workspace_scan` returns `success` true, `exit_code` is the
workspace's verdict, ranked as above; `success` says only that the call completed. The codes
go to different people:

| `exit_code` | Meaning | Who acts |
|---|---|---|
| `0` | Success: the plan resolved, or the scan ran and no project has actionable findings. | No one |
| `1` | A project failed or is incomplete; the server stopped the scan because it was cancelled or ran past `scan_timeout_seconds`; or an error inside ASH. An unexpected error is reported as 1, not 4, so that it does not send you to a workspace file that is correct. | The owner of the incomplete project; for an error inside ASH, report it as a bug in ASH |
| `2` | Actionable findings at or above a project's threshold. The scan ran. | The owners of the projects listed with `exceeds_threshold` true |
| `3` | A project's own config is invalid, or a config an MCP client delivered sets a field the server's policy denies; also a `profile` the server has not registered, or `config_overrides` the server's allowlist does not allow. | That project's owner, or the caller for `profile` and `config_overrides` |
| `4` | The workspace file or policy file cannot be used; the workspace file, the policy file, `output_dir`, or a project folder is outside the roots the server allows (see below); an MCP client delivered the policy file; an enabled reporter cannot write a workspace report; or no project could be scanned. | Whoever owns the workspace file or the server's allowed roots |
| `5` | A usage error: a `scanners` selection that matches no scanner, or one that `excluded_scanners` cancels. Only `run_ash_workspace_scan` takes these. | The caller |

To stop one project, pass its scan ID to `cancel_scan`: the other projects carry on, and the
response reports that project as `failed`. The server's `max_concurrent_scans` and
`scan_timeout_seconds` treat a workspace scan as one scan; see [Limit how many scans run and
for how long](mcp-server.md#limit-how-many-scans-run-and-for-how-long).

The scan tool refuses the whole workspace, with exit code 4, when any project folder
resolves outside the roots the server allows (`ASH_MCP_ALLOWED_ROOTS`); see [Run the MCP
server](mcp-server.md). Both tools use a workspace policy file only when it is in a
directory that `ASH_MCP_ALLOWED_CONFIG_ROOTS` names, whether `workspace_config` names it or
ASH finds it in the workspace file's directory or its `.ash` directory. Any other policy file
refuses the workspace with exit code 4. A policy file an MCP client delivered that also sets a
field the server's policy denies is refused first, with exit code 3. In a workspace inside source an MCP
client delivered, each project's config file is a delivered config: if one sets a field the
server's policy denies, both tools fail with exit code 3, with `error_type`
`ASHConfigValidationError` and a message that names the project (see [What a delivered
config cannot set](mcp-server.md#what-a-delivered-config-cannot-set)). Over MCP there are
no changed-files, sharding, or fail-gate parameters.

Config profiles come from the operator. `ash mcp --profile NAME=path/to/ash.yaml`, which
can be repeated, registers one; the server loads and validates each file when it starts,
and a file that does not load stops it with exit code 3. Clients see the names with the
`list_profiles` tool. A workspace call's `profile` names one for that call; without it,
the call uses the profile the session bound with `select_profile`, if any. The profile
is the configuration of each project that has none of its own, and an unknown name is
refused with exit code 3. `config_overrides` applies only what the server's
`global_settings.mcp.runtime_overrides` allowlist allows, and that allowlist is off by
default, so a call it denies is refused with exit code 3.

What workspace scans do not do:

- They do not run projects on separate machines, and cannot be sharded.
- They do not accept `..` paths or a workspace file with comments.
- They do not write a workspace-level GitHub code scanning or GitLab SAST report.
