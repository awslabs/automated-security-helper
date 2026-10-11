# Export reports

Every scan writes its reports to `reports/` in the output directory
(`.ash/ash_output/reports/` by default). Thirteen reporters are on by default, and each
writes its own file (`unused-suppressions` writes two), so the usual way to export is to
pick the file your destination reads:

| Destination | File in `reports/` |
|---|---|
| GitHub code scanning | `ash.ghas.sarif` |
| Other SARIF consumers (IDEs, code review tools) | `ash.sarif` |
| GitLab security reports | `ash.gl-sast-report.json`, `ash.gl-dependency-scanning-report.cdx.json` |
| CI test results | `ash.junit.xml` |
| SBOM tools | `ash.cdx.json` (CycloneDX), `ash.spdx.json` (SPDX, off by default) |
| Security data lakes, SIEMs | `ash.ocsf.json` |
| Spreadsheets | `ash.csv` |
| A person | `ash.html`, `ash.summary.md`, `ash.summary.txt` |
| Your own scripts | `ash.flat.json` |

[Reporters reference](../reference/reporters.md) lists every reporter with its options, and
[Output files](../reference/output-files.md) describes the rest of the output directory.

## Choose which reports to write {#formats}

To write fewer files, pass `--output-formats` (or `-f`) with a comma-separated list:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --scanners detect-secrets --output-formats sarif,junitxml
```

When detect-secrets finds a secret, the scan exits 2, and `reports/` holds only the two
files you asked for:

```bash
ls .ash/ash_output/reports
```

```text
ash.junit.xml
ash.sarif
```

The option has limits:

- It accepts `text`, `flat-json`, `yaml`, `csv`, `html`, `junitxml`, `markdown`, `sarif`,
  `ocsf`, `cyclonedx`, and `spdx`. It also accepts `aggregated`, `dict`, `asff`, and
  `custom`, which write nothing.
- It cannot name `github-ghas`, `gitlab-sast`, `gitlab-cyclonedx`, or
  `unused-suppressions`. A scan that names one stops with a usage error before scanning,
  and exits 2, the same code as a scan with findings. Any `--output-formats` list turns
  those four reporters off.
- `yaml` and `spdx` are disabled by default. Naming one writes nothing until you enable
  its reporter; ASH logs an error in `ash.log` that names the setting.
- A config file has no output-formats key, and ASH ignores an `output_formats:` line
  in one.

To control reporters from configuration, turn each one on or off. This adds SPDX to the
default set and drops HTML:

<!-- doctest: config kind=ash -->
```yaml
reporters:
  spdx:
    enabled: true
  html:
    enabled: false
```

On the command line, the same settings are
`--config-overrides reporters.spdx.enabled=true --config-overrides reporters.html.enabled=false`.

To produce one more format after a scan, render it from the saved results with
`ash report`. It runs any loaded reporter, including the four that `--output-formats`
cannot name and reporters that are disabled, and prints the report to standard output:

```bash
ash report --format gitlab-sast --log-level QUIET > gl-sast-report.json
```

## GitHub code scanning {#github}

Upload `ash.ghas.sarif`. It is SARIF 2.1.0 in which every rule a scanner declares gets a
`security-severity`, so GitHub shows those findings as Critical, High, Medium, or Low. A
scanner that declares no rules, such as detect-secrets, gives results with no rule entry,
and GitHub shows those by their SARIF level. The file leaves out suppressed findings
(`exclude_suppressed`, default `true`), because GitHub has its own dismissal workflow. The
job needs `security-events: write`, and the upload step has to run when the scan step
fails, because a scan with findings exits 2:

<!-- doctest: config kind=github-actions -->
```yaml
- name: Upload ASH results to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: .ash/ash_output/reports/ash.ghas.sarif
    category: ash
```

[Run ASH in GitHub Actions](ci/github-actions.md) has the complete workflow, including
the reusable workflows ASH ships.

## GitLab {#gitlab}

GitLab reads three of the files, each under its own `artifacts:reports` keyword:

| File in `reports/` | Keyword |
|---|---|
| `ash.gl-sast-report.json` (GitLab SAST report, schema 15.2.2) | `sast` |
| `ash.gl-dependency-scanning-report.cdx.json` (CycloneDX) | `cyclonedx` |
| `ash.junit.xml` | `junit` |

GitLab uploads report artifacts whatever the job's result, but it ingests the findings of a
security report such as `sast` only when the job that produced it succeeds. A scan with
findings exits 2, so the job that runs ASH has to succeed and leave the verdict to a later
job. [Run ASH in GitLab CI](ci/gitlab-ci.md) has the two jobs that do this.

The SAST report keeps suppressed findings at severity Info with the reason in their
`solution` field. Set `reporters.gitlab-sast.options.exclude_suppressed: true` to leave
them out.

## JUnit {#junit}

`ash.junit.xml` has one test suite per scanner and one test case per finding. Suppressed
findings and findings below the severity threshold are written as skipped test cases, so
a CI test view shows the same verdict as the scan. Actionable findings are written as
`<error>` elements. To report those below the threshold as errors too, set `reporters.junitxml.options.respect_severity_threshold: false`.

## CycloneDX and SPDX {#sbom}

`ash.cdx.json` is the software bill of materials that syft produces. When syft did not
run, the file contains `{}`, which is not a valid CycloneDX document. `ash.spdx.json`
converts the same SBOM to SPDX 2.3 and is written only when you enable the `spdx`
reporter.

## CSV, HTML, and the summaries {#other}

- `ash.csv` has one row per finding, with suppression status and justification columns.
- `ash.html` is a single page with inline styles, suitable for an artifact viewer.
- `ash.summary.md` is a Markdown summary for pull request comments. `--compact-report`
  shortens it.
- `ash.summary.txt` is plain text for logs.

## Before you share a report {#share}

- Reports can contain source text. ASH masks secrets in finding messages, but a scanner
  that includes the matching source lines in its result passes them through to the SARIF,
  CSV, flat JSON, GitLab SAST, and YAML reports. Treat report files as you treat the code.
- Findings in files that ASH extracted from archives or converted from notebooks carry
  absolute paths from the machine that ran the scan.
- A reporter that fails does not change the exit code. ASH logs the error and the file is
  missing, so check that the file you upload exists.
- The AWS reporters send data off the machine. They are operator-only and off unless
  loaded; see [AWS reporters](../plugins/aws.md).
