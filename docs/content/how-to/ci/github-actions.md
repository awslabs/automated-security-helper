# Run ASH in GitHub Actions

ASH ships two reusable workflows. `run-ash-security-scan.yml` installs ASH and its scanner
tools, scans the repository, and reports the result on the pull request.
`upload-ash-sarif.yml` uploads the SARIF report to code scanning. You can call them, or
write the steps yourself. For a first setup, follow
[Add ASH to a GitHub Actions pipeline](../../getting-started/ci.md).

## Call the reusable workflows {#reusable}

<!-- doctest: config kind=github-actions -->
```yaml
name: ASH
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  ash:
    uses: awslabs/automated-security-helper/.github/workflows/run-ash-security-scan.yml@v3.7.1
    permissions:
      contents: read
      checks: write
      pull-requests: write
    with:
      ash-version: v3.7.1
      ash-args: --fail-on-incomplete-scanners --no-allow-stale-content-db
      collect-sarif-report: false
  sarif:
    needs: ash
    if: ${{ !cancelled() && needs.ash.outputs.artifact-id != '' }}
    uses: awslabs/automated-security-helper/.github/workflows/upload-ash-sarif.yml@v3.7.1
    permissions:
      contents: read
      security-events: write
```

One thing in this file is required: grant the scan job `contents: read`,
`checks: write`, and `pull-requests: write`. The called workflow declares all three, and
GitHub refuses to start the run when the calling job grants less, even if you turn off
the comment and the check.

The `uses:` ref selects the workflow file only. The ASH it installs is `ash-version` from
`ash-repo`, which default to `main` of `awslabs/automated-security-helper`, so pass the
same tag or commit as `ash-version`, as the example does, to run the ASH the workflow was
written for. The `install-*` inputs default to `true`, so a call that sets none of them
installs every tool that the scanners on by default need from the runner.

To leave a tool out, turn its scanner off and do not install the tool, for example with
`--exclude-scanners trivy` in `ash-args` and `install-trivy: false`. In local mode, an
input set to `false` while its scanner is on leaves that scanner MISSING when the
repository has files it scans, and the incomplete-scan gate fails the job with exit
code 1.

ASH's zizmor scanner reports each `uses:` line that names a tag as `zizmor/unpinned-uses` at
HIGH, so a scan of a repository that holds this file fails until you pin both lines to a
commit. `git ls-remote https://github.com/awslabs/automated-security-helper refs/tags/v3.7.1`
prints the commit that `v3.7.1` names. Replace the `v3.7.1` after each `@`, and the
`ash-version` value, with that SHA, and end each `uses:` line with the comment
`# v3.7.1`.

A pull request scan reads the configuration in the branch it scans, so the branch can change
the gate. The workflow passes the `fail-on-findings` choice on the command line, and the
`ash-args` line above does the same for incomplete scans and stale content databases, so the
branch cannot turn those three off. It can still raise a severity threshold, add
suppressions, or turn scanners off, and the `config` input names a file in the checkout,
which the branch can edit too. To read the config from a commit the branch cannot change,
such as the pull request's base commit, pass that commit as `config-ref` (see the table
below). [Who can change the gate](../set-the-gate.md#who) lists what a repository can still
affect.

### Inputs of run-ash-security-scan.yml {#inputs}

<!-- doctest: options of=github-inputs:.github/workflows/run-ash-security-scan.yml complete -->
| Input | Defaults to | Effect |
|---|---|---|
| `ash-version` | empty | Git tag, branch, or commit of ASH to install. When empty, the job installs the ASH of the commit it was called at: a caller of a release tag gets that release, and a caller of `@main` gets that commit of main. The job resolves the value to one commit before it installs anything, and every step uses that commit; the job summary names it. A value that starts with `-` or holds a space, that names nothing in `ash-repo`, or that is both a branch and a tag on different commits fails the job. Every run installs it again. |
| `ash-repo` | empty | Repository (`owner/repo`) to install ASH from. When empty, the job uses the repository the workflow file comes from. A value other than that repository needs `ash-version` too. The owner and the name may hold letters, digits, `.`, `_`, and `-`; any other form fails the job. |
| `ash-mode` | `local` | Value of `--mode`. `container` builds ASH's image on the runner and scans inside it; see [Run ASH in a container](../run-in-a-container.md). |
| `config` | empty | Path to an ASH config file, passed as `--config` and as `ASH_CONFIG`. When empty, ASH finds the config in the checkout. |
| `config-ref` | empty | Commit, branch, or tag of the scanned repository to read the `config` file from, instead of the checkout. Needs `config`. The workflow writes the file under `$RUNNER_TEMP` and passes it as `--config`, and the tool config files it names by a relative path (`config_file`, and opengrep's and semgrep's `config`) come from the same commit. ASH treats it as the operator's config only while `$RUNNER_TEMP` is outside every git checkout and outside the scanned directory, as it is on GitHub-hosted runners; on a self-hosted runner, keep `$RUNNER_TEMP` outside them. A config that `extends` another file fails, and so does one at that commit that is missing, unless `config-ref-missing` is `defaults`. A value that starts with `-` or holds a space fails the job before git reads it. |
| `config-ref-missing` | `refuse` | What `config-ref` does when that commit has no `config` file: `refuse` fails the job, and `defaults` scans with ASH's default config and logs a warning, for the pull request that adds a repository's first config. |
| `skip-unknown-tools` | `false` | With `config-ref`, lets `ash dependencies install` name and skip a requested tool that the installed ASH has no plugin for, instead of failing the install. |
| `output-dir` | `.ash/ash_output` | Output directory. The reporting job downloads the scan's artifact into the same path. |
| `fail-on-findings` | `true` | Passes `--fail-on-findings` or `--no-fail-on-findings`. Either one overrides `fail_on_findings` in the repository's config. |
| `verbose` | `true` | Passes `--verbose`. |
| `ash-args` | empty | More `ash scan` options, on one line; a value of more than one line fails the job (see [How the workflow checks its inputs](#input-checks)). They are split on spaces with no quoting or glob expansion, and passed last, so they override the workflow's own `--mode`, `--config`, `--base-ref`, and fail-on-findings choice. |
| `collect-sarif-report` | `true` | Upload `ash.ghas.sarif` to code scanning from the reporting job. It works on pull requests from branches of the same repository only, and is skipped on `merge_group`; for other events set it to `false` and call `upload-ash-sarif.yml`, as in [Upload SARIF](#sarif). |
| `collect-junit-xml-report` | `true` | Publish `ash.junit.xml` as the check run **ASH Scan JUnit Test Report** from the reporting job. Every actionable finding is a failed test, so the check is red when there are findings. This step does not fail the job. |
| `post-pr-comment` | `true` | Post `ash.summary.md` as a pull request comment, and update that comment on later runs. |
| `repository-owner` | `${{ github.repository_owner }}` | Post the comment only when the repository owner equals this value. |
| `python-version` | `3.12` | Python version that `actions/setup-python` installs. |
| `install-grype` | `true` | Install grype, and cache its vulnerability database. |
| `install-syft` | `true` | Install syft. |
| `install-opengrep` | `true` | Install opengrep, and cache the binary for a week. |
| `install-cfn-nag` | `true` | Set up Ruby and install cfn-nag from the `Gemfile` and `Gemfile.lock` of the ASH commit the workflow installs. |
| `install-actionlint` | `true` | Install actionlint. |
| `install-cfn-guard` | `true` | Install cfn-guard and the rule files it evaluates. |
| `install-gitleaks` | `true` | Install gitleaks. |
| `install-trivy` | `true` | Install trivy. trivy downloads its vulnerability database during each scan. |
| `changed-files-only` | `false` | Passes `--changed-files-only` and `--base-ref`, and checks out the repository's whole history to compute the changed files; see [Scan only the files a pull request changes](#changed-files). Not supported with `ash-mode: container`: the scan stops with exit code 5. |
| `base-ref` | `origin/main` | The base for `changed-files-only` on events other than `pull_request` and `merge_group`, which use their own base commit. |
| `artifact-name` | `ash_output` | Name of the artifact the scan's output directory is uploaded as. A matrix, or a caller that calls this workflow more than once in one run, must give each call its own name: in the first attempt a second upload under a name already taken fails, and in a re-run it replaces the earlier upload. |

The workflow has one output, `artifact-id`: the ID of the `ash_output` artifact the scan
job uploaded, or empty when the scan failed before ASH wrote its reports. Start a job that
reads the artifact, such as one calling `upload-ash-sarif.yml`, only when it is set.

The workflow at v3.7.0 and v3.7.1 has fewer inputs: no `config-ref`, `config-ref-missing`,
or `skip-unknown-tools`, and of the `install-*` inputs only `install-grype`,
`install-syft`, and `install-opengrep`, which default to `false` there. The `install-*`
steps other than cfn-nag's run `ash dependencies install --tool`, which ASH 3.7.1 and
earlier do not have, so with `ash-version` set to one of those releases, set those inputs
to `false`.

The binary tools come from `ash dependencies install`, which downloads the versions that
the installed ASH pins and checks each download against its pinned SHA256 before
installing it. bandit, checkov, and semgrep need no input: ASH installs
them from PyPI with `uv tool install` during the scan. detect-secrets is part of ASH, and
cdk-nag and npm-audit use the Node.js and npm that GitHub's Ubuntu runners include.

Each install runs on every run, apart from what the workflow caches (see
[Cache tools and databases](#caching)). For the versions ASH pins, each one downloads:

| Input | Downloads |
|---|---|
| `install-grype` | grype, about 32 MB, and during the scan its vulnerability database, about 190 MB compressed on 2026-10-12, unless the workflow restores a cached copy inside grype's bound |
| `install-syft` | syft, about 31 MB |
| `install-opengrep` | opengrep, about 46 MB, unless the workflow restores the cached binary |
| `install-cfn-nag` | Ruby, and the gems that cfn-nag's `Gemfile.lock` pins |
| `install-actionlint` | actionlint, about 2.4 MB |
| `install-cfn-guard` | cfn-guard, about 3.4 MB, and its rules |
| `install-gitleaks` | gitleaks, about 8.2 MB |
| `install-trivy` | trivy, about 52 MB, and during the scan its vulnerability database, about 133 MB compressed on 2026-10-12 |

Set an input to `false` when the scan does not need its tool, for example with
`ash-mode: container` or with the scanner turned off.

### How the workflow checks its inputs {#input-checks}

The scan job's first step checks every string input before any other step can print one.
The runner reads a line of a step's log as a workflow command when the line starts with
`::` or holds `##[`, and it starts a new line at a carriage return as well as at a line
feed, so an input holding either could add a command of its own to a line that shows it.

The step drops one line feed at the end of a value. YAML ends a block of one line, such as
`ash-args: |` or `ash-args: >` followed by one line of options, with that line feed, so
such a block works. The step then refuses a value that holds a carriage return, a line
feed, another control character, a Unicode line or paragraph separator, or `##[`, so a
value of more than one line, or one that ends in two line feeds, is refused. It checks the
value byte by byte, so the answer does not depend on the runner's locale. The error names
the input and does not print its value:

`the ash-args input holds a line break, another control character or the legacy command marker, so it is refused without being printed. A block scalar of one line is fine; more than one line is refused.`

A value that is only a line feed is refused with:

`the ash-args input is only a line feed; leave it empty instead.`

Every later step, and the reporting job, uses the checked value, not the input as given.

The step that resolves `ash-version` to a commit refuses two more values first, without
printing them. An `ash-repo` that is not `owner/name` fails with:

`ash-repo must be owner/name: letters, digits, '.', '_' and '-', one '/' between them.`

An `ash-version` that is empty, starts with `-`, or holds a space fails with:

`ash-version is not a branch, tag or commit name: it is empty, starts with '-', or holds a space or a control character.`

With `config-ref` set, the step that reads the config refuses a `config-ref` that starts
with `-` or holds a space, before git reads it as an option:

`config-ref is not a branch, tag or commit name: it starts with '-', or holds a space or a control character.`

Each of these refusals fails the job before it installs anything.

ASH, and the `git`, `uv`, `curl`, `bundle`, `gem`, and cfn-nag commands the job runs, run
with workflow commands stopped. Before each one, the step prints `::stop-commands::` with a
new random token, and after it, on a line of its own, the token, also when the step is
cancelled, as GitHub describes under "Stopping and starting workflow commands" in
[Workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).
A file name or a finding's text from the scanned tree in their output is then shown as
text, not read as a command. When no random token can be read, the command does not run,
and the step logs the error:

`no random token could be read for stop-commands, so the command did not run`

The job also checks that each commit ID and `git ls-tree` entry git reports has the form
git gives it before printing it, and fails the step on one that does not.

### What the workflow does {#steps}

The workflow runs two jobs on `ubuntu-latest`; neither the runner nor the timeouts are
inputs. The scan job, `SAST, SCA, and IaC Scan`, has a 30-minute timeout and holds only
`contents: read`, so nothing it runs, ASH and the scanners included, holds a token that can
write.

Its first step checks the inputs, as [How the workflow checks its inputs](#input-checks)
says. Before the checkout, a step resolves `ash-version` in `ash-repo` to one commit
with `git ls-remote`. A full commit ID is used as given, and a tag gives the commit it
points to. Every later step installs ASH from that commit, and cfn-nag's `Gemfile` comes
from it too, so a branch that moves during the run cannot give two steps two different
versions of ASH. The job summary names the commit.

The job then checks out the calling repository, with the whole history when
`changed-files-only` is `true`, reads the config from `config-ref` when that is set, and
installs the tools that the `install-*` inputs select.
It runs ASH with `uvx --reinstall`, passing `--source-dir .`, the output directory,
`--no-progress`, the fail-on-findings choice, `--build-target ci`, `--mode`, and
`--config` when a config is set; `--verbose` unless `verbose` is `false`;
`--changed-files-only` and `--base-ref` when `changed-files-only` is `true`; and then
`ash-args`.

After the scan, whether it passed or failed, the scan job appends `ash.summary.md` to the
job summary and uploads the artifact `ash_output`, kept for 7 days. The artifact holds
`reports/` and `ash_aggregated_results.json` from the output directory, and the same two
from each project of a workspace scan. The rest of the output directory, such as each
scanner's raw output under `scanners/`, is left out, because ASH does not mask secrets
there.

The reporting job, `Report ASH results`, runs after a scan that passed or failed and
uploaded its artifact, and only when `post-pr-comment`, `collect-junit-xml-report`, or
`collect-sarif-report` is `true`. It holds `checks: write` and `pull-requests: write`,
runs nothing from the scan, and downloads the artifact to:

- post `ash.summary.md` as a pull request comment;
- publish the JUnit check run;
- upload `ash.ghas.sarif` to code scanning with category `ash`, when
  `collect-sarif-report` is `true` and the event is not `merge_group`.

Its result is a check run of its own, so a reporting failure does not fail the scan's
check.

On a pull request from a fork, `GITHUB_TOKEN` is read-only, so the reporting job skips the
comment and the check run and prints a notice. The scan, its exit code, the job summary,
and the artifact are unchanged. On a push, the comment goes to the pull request that the
pushed commit came from, if there is one.

## Upload SARIF with upload-ash-sarif.yml {#sarif}

`run-ash-security-scan.yml` does not declare `security-events: write`, and a called workflow
can only narrow the token its caller grants, so the upload step inside it never holds that
permission. Its upload works on pull requests from branches of the same repository; on
`workflow_dispatch`, for example, the step fails with `Resource not accessible by
integration`, which fails the reporting job's check but not the scan's. It is skipped on
`merge_group`. `collect-sarif-report: true` is enough in a workflow that runs on pull
requests from the same repository alone. The workflow does not declare the permission,
because GitHub checks every permission a called workflow declares when the run starts, so
every caller that does not grant it would fail before any job ran.

To upload on every trigger, set `collect-sarif-report: false` and add a job that calls
`upload-ash-sarif.yml`, as in the [example above](#reusable). That workflow:

- downloads the artifact that the scan job uploaded in the same workflow run, and uploads
  `reports/ash.ghas.sarif` from it with category `ash`;
- takes two optional inputs: `artifact-id`, the scan workflow's `artifact-id` output,
  which names exactly the artifact that scan uploaded, and `artifact-name`, the name to
  download by when `artifact-id` is empty, `ash_output` by default;
- skips `merge_group` events;
- declares `contents: read` and `security-events: write`, which the calling job must grant.

Give the calling job `if: ${{ !cancelled() && needs.ash.outputs.artifact-id != '' }}`. The
scan job sets `artifact-id` once it has uploaded its reports, which it does when the scan
fails on findings too. A job-level `if:` with no status function such as `!cancelled()` or
`always()` is skipped whenever a job it needs failed, so the condition alone would never
let the upload run after a scan with findings.

Code scanning is available for public repositories. A private repository needs a GitHub
Code Security license. GitHub's SARIF upload documentation also lists `actions: read` for
workflows in private repositories; `upload-ash-sarif.yml` does not declare it.

## Permissions {#permissions}

| Job | Permission | Needed for |
|---|---|---|
| Scan | `contents: read` | Checking out the repository |
| Scan | `checks: write` | The JUnit check run |
| Scan | `pull-requests: write` | The pull request comment |
| SARIF upload | `contents: read` | The checkout in the upload job |
| SARIF upload | `security-events: write` | Uploading to code scanning |
| SARIF upload | `actions: read` | Private repositories only, per GitHub's upload documentation |

Set `permissions: contents: read` at the top of the workflow, as the example does, and grant
the rest per job. Inside `run-ash-security-scan.yml`, only the reporting job holds
`checks: write` and `pull-requests: write`; the scan job, which runs ASH and the scanners,
holds `contents: read` alone.

## Write the steps yourself {#plain-steps}

This job does what the reusable workflows do, without the comment, the check run, and the
job summary:

<!-- doctest: config kind=github-actions save-as=.github/workflows/ash.yml -->
```yaml
name: ASH
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  ash:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read # private repositories only
    env:
      INSTALL_SPEC: "automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@18d369b23da25a81e9458561248e1aafff6a70fa # v10.3.1
        with:
          version: latest
          enable-cache: true
      - uses: ruby/setup-ruby@b1da4809b005e0178fe08a1d57317bffc00b7b4c # v1.332.0
        with:
          ruby-version: "3.3"
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
      - name: Install scanner tools
        working-directory: ${{ runner.temp }}
        run: |
          token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
          if [ "${#token}" -ne 32 ]; then
            echo "::error::no random token could be read for stop-commands, so the command did not run"
            exit 1
          fi
          printf '::stop-commands::%s\n' "${token}"
          status=0
          ash dependencies install \
            --tool grype --tool syft --tool opengrep --tool cfn-nag \
            --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy \
            2>&1 || status=$?
          printf '\n::%s::\n' "${token}"
          exit "${status}"
      - name: Run ASH
        run: |
          token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
          if [ "${#token}" -ne 32 ]; then
            echo "::error::no random token could be read for stop-commands, so the command did not run"
            exit 1
          fi
          printf '::stop-commands::%s\n' "${token}"
          status=0
          ash scan --mode local --no-progress \
            --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db \
            2>&1 || status=$?
          printf '\n::%s::\n' "${token}"
          exit "${status}"
      - name: Upload the reports and the results file
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: ash-output
          # Not the whole output directory: scanners/ and converted/ hold each
          # tool's raw output, which is not masked.
          path: |
            .ash/ash_output/reports
            .ash/ash_output/ash_aggregated_results.json
      - name: Upload SARIF to code scanning
        if: ${{ !cancelled() }}
        uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          sarif_file: .ash/ash_output/reports/ash.ghas.sarif
          category: ash
```

Notes on the steps:

- `version: latest` installs the newest uv, as the reusable workflow does. Without it,
  `astral-sh/setup-uv` installs the uv version that a `required-version` in a `uv.toml`
  or `pyproject.toml` at the repository root asks for.
- Install ASH outside the checkout, as `uv tool install` does. ASH does not run tools it
  finds inside the directory it scans, so an ASH installed into a virtual environment in the
  repository loses the scanners that need `uv`; see
  [Tools inside the scanned directory](../../docs/advanced-usage.md#tools-inside-the-scanned-directory).
- Run `ash dependencies install` outside the checkout too, as `working-directory` does
  here, so a config in the repository cannot change what it installs.
- ASH installs bandit, checkov, and semgrep during the scan with the `uv`
  installed with it, or with a `uv` on `PATH`.
- `ruby/setup-ruby` is there for cfn-nag, which `ash dependencies install` installs with
  `gem` and which builds native extensions.
- The three gate flags keep a pull request's own config from turning off the gate for
  findings, incomplete scans, and stale content databases. A branch's config can still
  raise thresholds, add suppressions, and turn scanners off; to keep those yours, pass
  `--config` with a file outside the checkout. See
  [Who can change the gate](../set-the-gate.md#who).
- `if: ${{ !cancelled() }}` keeps both uploads running when the scan step fails, which is
  what it does when it finds something.
- Each step that runs `uv` or `ash` stops workflow commands around it, as the reusable
  workflow does ([How the workflow checks its inputs](#input-checks)): it prints
  `::stop-commands::` with a new random token before the command, sends the command's
  error output to the same stream, and prints the token on a line of its own after it, so
  the runner reads workflow commands again once the command ends. The step exits with the
  command's exit code. Install ASH runs `uv tool dir --bin` only when `uv tool install`
  succeeds. The caching and changed-files steps below do the same.

## Cache tools and databases {#caching}

The reusable workflow caches three things:

- uv's package cache, through `astral-sh/setup-uv`. It is saved from any push.
- The opengrep binary, for a week. A restored binary is used only if it hashes to the SHA256
  that ASH pins.
- grype's vulnerability database. The cache key changes daily, and a restored database older
  than ASH's bound for it (120 hours) is deleted before the scan, so grype downloads a new
  one.

It restores them on every event except `pull_request` and `merge_group`. On those two,
another job that runs the pull request's code in the same cache scope could have written
the entry, so the workflow downloads and checks each one as on a cache miss. Every other
tool that the workflow installs, and trivy's database, is downloaded each time. It saves the opengrep binary and grype's
database only from a push to the repository's default branch, so pull requests do not each
write a copy. A repository that never runs the workflow on such a push never saves those
two, and every run downloads them.

In your own steps, cache ASH's tool directory and grype's database. These steps replace
the install and scan steps of the job above:

<!-- doctest: config kind=github-actions extends=.github/workflows/ash.yml -->
```yaml
- name: Restore ASH's scanner tools
  id: tools
  uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
  with:
    path: ~/.ash/bin
    key: ash-tools-${{ runner.os }}-${{ runner.arch }}-v3.7.1
- name: Install scanner tools
  working-directory: ${{ runner.temp }}
  run: |
    token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    if [ "${#token}" -ne 32 ]; then
      echo "::error::no random token could be read for stop-commands, so the command did not run"
      exit 1
    fi
    printf '::stop-commands::%s\n' "${token}"
    status=0
    ash dependencies install \
      --tool grype --tool syft --tool opengrep --tool cfn-nag \
      --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy \
      2>&1 || status=$?
    printf '\n::%s::\n' "${token}"
    exit "${status}"
- name: Save ASH's scanner tools
  if: steps.tools.outputs.cache-hit != 'true'
  uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
  with:
    path: ~/.ash/bin
    key: ${{ steps.tools.outputs.cache-primary-key }}
- name: Today's date, for the grype database cache key
  id: date
  run: echo "today=$(date -u +%F)" >> "${GITHUB_OUTPUT}"
- name: Restore grype's database
  id: grype-db
  uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
  with:
    path: ~/.cache/grype/db
    key: grype-db-${{ runner.os }}-${{ steps.date.outputs.today }}
- name: Run ASH
  run: |
    token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    if [ "${#token}" -ne 32 ]; then
      echo "::error::no random token could be read for stop-commands, so the command did not run"
      exit 1
    fi
    printf '::stop-commands::%s\n' "${token}"
    status=0
    ash scan --mode local --no-progress \
      --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db \
      2>&1 || status=$?
    printf '\n::%s::\n' "${token}"
    exit "${status}"
- name: Save grype's database
  if: ${{ !cancelled() && steps.grype-db.outputs.cache-hit != 'true' }}
  uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
  with:
    path: ~/.cache/grype/db
    key: ${{ steps.grype-db.outputs.cache-primary-key }}
```

Keep `ash dependencies install` after the restore. It checks each binary it finds against
the pinned SHA256, skips the ones that match, and installs again over any that do not, so a
restored cache cannot substitute a different tool. Key the tool cache on the ASH version,
because each version pins its own tool versions. cfn-nag is the exception: it is a Ruby gem,
not a pinned binary, so it is installed again on every run. Cache `~/.ash/bin` and nothing
else under `~/.ash`: `ash dependencies install` downloads the cfn-guard rules into
`~/.ash/share/cfn-guard-rules` again on each run, and keeps its install records in
`~/.ash/install-receipts`.

The save steps are separate because the combined `actions/cache` action saves only when the
job succeeds, and a scan with findings fails the job. Do not add `restore-keys` to the
database cache: a database past its bound only makes grype download a new one.

Do not cache trivy's database. Its bound is 24 hours, and ASH declares it not cacheable in
CI. Before each online scan that runs trivy, ASH updates it in `$TRIVY_CACHE_DIR`, or,
when that is not set, in `trivy` under the user cache directory (`$XDG_CACHE_HOME` or
`~/.cache` on Linux, `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on Windows), and passes
that directory to trivy with `trivy --cache-dir`. Leave it out of your cache steps.

[Content databases](../../concepts/content-databases.md) explains the bounds and what
happens when a database is past one.

## Scan only the files a pull request changes {#changed-files}

`--changed-files-only` runs every scanner on the whole tree, then keeps only the findings in
files changed between the merge base with `--base-ref` and `HEAD`. It does not make the scan
faster. The filter applies to every report, the summary, and the exit code.
[Scale to large repositories](../scale-large-repos.md#changed-files) has the details.

It needs the base branch's history. `actions/checkout` fetches a single commit unless told
otherwise, and without the base ref ASH logs a warning and scans in full. The
`changed-files-only` input of `run-ash-security-scan.yml` fetches that history itself. It
diffs a pull request against its base commit and a merge group against the queue's base
commit, and on other events against `base-ref`. The job fails before the scan when that
base is not in the checkout, or names a ref with characters ASH does not accept, rather
than scanning in full. In your own steps, fetch the history and name the base branch.
These two steps replace the checkout and `Run ASH` steps of the job in
[Write the steps yourself](#plain-steps):

<!-- doctest: config kind=github-actions extends=.github/workflows/ash.yml -->
```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0
    persist-credentials: false
- name: Run ASH
  env:
    BASE_REF: ${{ github.base_ref }}
  run: |
    token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    if [ "${#token}" -ne 32 ]; then
      echo "::error::no random token could be read for stop-commands, so the command did not run"
      exit 1
    fi
    set --
    if [ -n "${BASE_REF}" ]; then
      set -- --changed-files-only --base-ref "origin/${BASE_REF}"
    fi
    printf '::stop-commands::%s\n' "${token}"
    status=0
    ash scan --mode local --no-progress \
      --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db \
      "$@" \
      2>&1 || status=$?
    printf '\n::%s::\n' "${token}"
    exit "${status}"
```

`github.base_ref` is set on a pull request and empty on a push, so the one step filters
a pull request to its changed files and scans a push in full, and the SARIF upload has
its file on both events.

Code scanning already shows a pull request only the alerts on lines it changed, so for the
SARIF upload alone you do not need this option.
