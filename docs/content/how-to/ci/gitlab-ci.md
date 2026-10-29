# Run ASH in GitLab CI

This page adds an ASH job to `.gitlab-ci.yml` that publishes ASH's findings as a GitLab SAST
report and its JUnit file as a test report, and a second job that fails the pipeline when
ASH found something.

Prerequisites:

- A runner with the Docker executor, or any runner whose job image is based on Debian or
  Ubuntu, runs as root, and has Python 3.10 or later and git. The `before_script` below
  installs packages with `apt-get`.
- Network access from the job to GitHub, PyPI, and the scanners' download sites.

GitLab reads the SAST report on every tier, and offers it as a download. Showing the
findings in the merge request widget, the vulnerability report, and the security dashboard
needs GitLab Ultimate.

## Add the jobs

<!-- doctest: config kind=gitlab-ci save-as=.gitlab-ci.yml -->
```yaml
ash-scan:
  stage: test
  image: python:3.12
  variables:
    INSTALL_SPEC: "automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1"
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends nodejs npm ruby ruby-dev libyaml-dev
    - python -m venv /opt/ash
    - /opt/ash/bin/pip install --quiet "$INSTALL_SPEC"
    - export PATH="/opt/ash/bin:$PATH"
    - >-
      (cd "$(mktemp -d)" && ash dependencies install
      --tool grype --tool syft --tool opengrep --tool cfn-nag
      --tool actionlint --tool cfn-guard --tool gitleaks --tool trivy)
  script:
    - ash_exit=0
    - >-
      ash scan --mode local --no-progress
      --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
      || ash_exit=$?
    - echo "$ash_exit" > ash-exit-code.txt
  artifacts:
    when: always
    paths:
      - .ash/ash_output/reports/
      - .ash/ash_output/ash_aggregated_results.json
      - ash-exit-code.txt
    reports:
      sast: .ash/ash_output/reports/ash.gl-sast-report.json
      junit: .ash/ash_output/reports/ash.junit.xml

ash-gate:
  stage: test
  image: python:3.12
  needs: [ash-scan]
  script:
    - exit "$(cat ash-exit-code.txt)"
```

Why two jobs: GitLab always uploads report artifacts, but it ingests a security report's
findings only when the job that produced it succeeds. A failed job does not count, even with
`allow_failure`. So `ash-scan` records ASH's exit code and succeeds, and `ash-gate` reads the
code and fails with it: 2 for actionable findings, 1 for a scan that did not complete, 5
for a command line ASH refused. The [exit codes](../../reference/exit-codes.md) page lists
them all.

What the `before_script` does:

- Installs Node.js and npm, which cdk-nag and npm-audit need when the repository has files
  they scan, and Ruby with its headers and libyaml, which `ash dependencies install` needs
  to build cfn-nag. Without them, those scanners are SKIPPED in a repository with nothing
  for them to scan, and MISSING in one that has something.
- Installs ASH into a virtual environment at `/opt/ash`, outside the checkout. ASH does not
  run tools it finds inside the directory it scans, and the virtual environment carries the
  `uv` that ASH uses to install bandit, checkov, semgrep, cfn-lint, and zizmor during the
  scan.
- Installs the binary scanner tools at the versions that ASH pins, checking each download
  against its pinned SHA256. It runs in an empty directory, so a config in the repository
  cannot change what it installs.

To skip a scanner instead of installing what it needs, drop it from the install list and
name it in `--exclude-scanners` on `ash scan`, for example
`ash scan --mode local --no-progress --exclude-scanners cfn-nag`.

A merge request pipeline scans the configuration in the branch it scans, so the branch's
author can change the gate. The three gate flags on `ash scan` keep the branch from turning
off the gate for findings, incomplete scans, and stale content databases. The branch's
config can still raise thresholds, add suppressions, and turn scanners off; to keep those
yours, pass `--config` with a file outside the checkout. See
[Who can change the gate](../set-the-gate.md#who).

## The report files

| File in `.ash/ash_output/reports/` | GitLab keyword | What GitLab does with it |
|---|---|---|
| `ash.gl-sast-report.json` | `artifacts:reports:sast` | SAST findings (schema 15.2.2) |
| `ash.junit.xml` | `artifacts:reports:junit` | Test summary in the merge request and the pipeline's **Tests** tab, one failed test per actionable finding |
| `ash.gl-dependency-scanning-report.cdx.json` | `artifacts:reports:cyclonedx` | Dependency list (Ultimate); built from syft's SBOM, so it is empty when syft did not run |

The SAST report keeps suppressed findings at severity Info, with the reason in their
`solution` field. [Export reports](../export-reports.md#gitlab) shows how to leave them out
and how the other formats map to other tools.

`--output-formats` takes the GitLab reporters' names, `gitlab-sast` and
`gitlab-cyclonedx`. A list you pass writes only the reports it names, so include them when
you set the option. This scan writes the SAST report and the JUnit file and no other
report:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --mode local --no-progress --offline --scanners detect-secrets \
  --output-formats gitlab-sast,junitxml
```

It exits 2 here because detect-secrets finds a hardcoded password in `app.py`. Both
files are in `reports/`:

```bash
ls .ash/ash_output/reports/ash.gl-sast-report.json .ash/ash_output/reports/ash.junit.xml
```

[Choose which reports to write](../export-reports.md#formats) lists every format name.

## Use your own ASH image

Instead of installing ASH in every job, build ASH's container image once, push it to your
registry, and use it as the job image. The image has every scanner tool, so the job only
runs the scan. Build the `ci` target, which runs as root like most job images, and see
[Build and host your own image](../run-in-a-container.md#own-image):

<!-- doctest: config kind=gitlab-ci -->
```yaml
ash-scan:
  stage: test
  image: registry.example.com/security/automated-security-helper:ci
  script:
    - ash_exit=0
    - >-
      ash scan --mode local --no-progress
      --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
      || ash_exit=$?
    - echo "$ash_exit" > ash-exit-code.txt
  artifacts:
    when: always
    paths:
      - .ash/ash_output/reports/
      - .ash/ash_output/ash_aggregated_results.json
      - ash-exit-code.txt
    reports:
      sast: .ash/ash_output/reports/ash.gl-sast-report.json
      junit: .ash/ash_output/reports/ash.junit.xml

ash-gate:
  stage: test
  image: registry.example.com/security/automated-security-helper:ci
  needs: [ash-scan]
  script:
    - exit "$(cat ash-exit-code.txt)"
```

`ash-gate` is the first example's job on this example's image, so the pipeline pulls no
other image. The scanners download their vulnerability databases during the scan, as they
do in the first example. An image built with `OFFLINE=YES` carries the databases instead.
It holds trivy's database to `warn`: past trivy's 24-hour bound its scans still pass, and
the reports record the stale database.
grype's database and the offline rulesets still fail the scan past their bounds, so rebuild
the image within them; see [Refresh cadence](../run-offline.md#refresh).
`--no-allow-stale-content-db`, as in the job above, holds trivy's database to its bound too.
The bound counts from when the database was built upstream, so with that flag scans that
include trivy start failing less than a day after the image build.

## Scan only what a merge request changes

`--changed-files-only` keeps only the findings in files changed since the merge base with
`--base-ref`. GitLab clones 20 commits by default, which may not reach the merge base, and
ASH then scans everything and logs a warning. In a merge request pipeline, clone the full
history and pass GitLab's diff base, which is that merge base.

Add this to the `ash-scan` job, and give `ash-gate` the same `rules:`. GitLab does not
create a pipeline in which a job's `needs:` names a job that the rules left out, so with the
rule on `ash-scan` alone, branch pipelines stop starting:

<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml event=merge_request -->
```yaml
ash-scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"
  script:
    - ash_exit=0
    - >-
      ash scan --mode local --no-progress
      --fail-on-findings --fail-on-incomplete-scanners --no-allow-stale-content-db
      --changed-files-only --base-ref "$CI_MERGE_REQUEST_DIFF_BASE_SHA"
      || ash_exit=$?
    - echo "$ash_exit" > ash-exit-code.txt

ash-gate:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

Both jobs then run in merge request pipelines only. To scan branch pipelines as well, keep
the jobs from the first example under other names, with the opposite rule.

The option filters every report, including `ash.gl-sast-report.json` and
`ash.junit.xml`, so they list only findings in changed files. On a branch that adds one
clean file, the password finding in `app.py`, a file the branch did not change, is left
out:

<!-- doctest: run -->
```bash
git switch -q -c add-version
echo 'VERSION = "1.0"' > version.py
git add version.py
git commit -q -m "Add version.py"
ash scan --mode local --no-progress --offline --scanners detect-secrets \
  --changed-files-only --base-ref main
```

The scan exits 0, and the SAST report lists no vulnerabilities:

```bash
python3 -c "import json; report = json.load(open('.ash/ash_output/reports/ash.gl-sast-report.json')); assert not report['vulnerabilities'], report['vulnerabilities']"
```

[Scale to large repositories](../scale-large-repos.md#changed-files) has the details.
