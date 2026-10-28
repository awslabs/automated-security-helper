# Suppressions, ignore paths, and scanner exclusions

ASH has three ways to keep a finding from failing a scan, and they differ in what they leave behind. A suppression keeps the finding in the results and marks it suppressed, with your reason. An ignore path removes the finding from the results. A scanner's own exclusion keeps the scanner from looking at the file, so there is no finding at all. This page explains how each one works and how it shows up in the gate and the reports. To write them, see [Suppress findings](../how-to/suppress-findings.md).

## How they differ

| | Suppression | Ignore path | Scanner exclusion |
|---|---|---|---|
| Set in | `global_settings.suppressions`, or an inline `ash-ignore` comment | `global_settings.ignore_paths` | the scanner's options, such as bandit `excluded_paths`, checkov `skip_path`, semgrep and opengrep `exclude`, syft `exclude`, and guarddog `excluded_paths` |
| Matches | a path, optionally narrowed by rule ID, line range, package, or symbol | a path | what the scanner's tool matches |
| Is the file scanned? | Yes | Passed to every scanner; some skip the files, others scan them | No |
| Is the finding in the results? | Yes, marked suppressed with the reason | No | No, it never existed |
| Counts toward the gate? | No | No | No |
| Expiration | Enforced | Enforced | Enforced for bandit `excluded_paths`, checkov `skip_path`, and syft `exclude`; none for the others |

A scanner's own inline suppression comment works one of two ways, depending on the tool. bandit (`# nosec`) and detect-secrets (`# pragma: allowlist secret`) drop the finding, so ASH never sees it, as with a scanner exclusion. semgrep and opengrep (`# nosemgrep`) and checkov (`checkov:skip=<check>:<reason>`) report the finding with a SARIF suppression, and ASH keeps it in the results as a suppressed finding with the tool's justification, which can be empty. Either way the finding does not count toward the gate. For other scanners, see the tool's own documentation.

## How a suppression matches

Paths are matched relative to the scanned directory and case-sensitively, so `tests/**` does not match `Tests/`, and a path that starts with `./` matches nothing. In a pattern without `**`, `*` also matches across directory separators, so `src/*.py` matches `src/sub/deep/app.py`. `**` matches any depth. A trailing slash is literal, unlike in an ignore path, so `tests/` matches no finding, and neither does a bare directory name such as `tests`; `tests/**/*` matches the files below the directory.

A suppression with a `rule_id` matches only findings with that rule ID. The rule ID is a case-insensitive pattern with no scanner prefix, so it matches whichever scanner reports that ID. A suppression without `rule_id` matches every rule in its path. With `line_start` and `line_end`, a finding matches when its lines overlap the range; `line_start` alone runs to the end of the file, and a finding with no line never matches a line-scoped suppression. A finding gets only the first suppression that matches it.

Because ASH does not deduplicate findings, the same problem reported by two scanners is two findings with two rule IDs. A suppression written for one scanner's rule ID leaves the other one in place. See [How ASH works](how-ash-works.md#findings-are-merged-not-deduplicated).

## Order of application

ASH applies these rules to each scanner's SARIF as it arrives, and again to the merged SARIF before the reporters run:

1. Findings located in ASH's own output directory are dropped, except in its `converted/` work directory and in files git tracks there. The rest are ASH's reports, not part of the code.
2. Ignore paths are checked against every location of a finding. A match drops the finding. ASH adds no ignore paths of its own here, so a dependency finding located in `node_modules/` stays unless you ignore that path. bandit and checkov skip `.venv/`, `venv/`, and `node_modules/` themselves.
3. Configured suppressions are checked against the finding's first location.
4. Inline `ash-ignore` comments are checked: `ash-ignore` on the finding's line, or `ash-ignore-next-line` on the line above it.
5. An npm-audit finding about a package that is only reachable through other findings is suppressed when every one of those findings is suppressed.

## Expiration

A suppression's `expiration` is a date. On that date, by the host's local clock, the suppression stops matching, and the finding counts toward the gate again on the next scan. The config stays valid: the scan fails on the finding, and a warning at the start of the scan lists every suppression and ignore path that has expired. ASH also logs a warning at the start of a scan for the entries that expire within the next 30 days, and `ash config lint` reports suppressions and ignore paths that have already expired.

An ignore path's `expiration` works the same way: on that date it stops applying, and the findings it dropped come back on the next scan. The entries of bandit `excluded_paths`, checkov `skip_path`, and syft `exclude` expire the same way, and stop excluding their files. An expired entry stays in the config file and in the results; only its effect stops.

Results written by another ASH version can hold an entry that this version refuses in a config file, such as one with an unknown key or a date in another format. `ash report`, `ash merge`, and the other commands that read results still load them, with a warning that names the problem, and never apply that entry.

## The gate

Only unsuppressed findings at or above the severity threshold count toward `fail_on_findings`. Suppressed findings, findings under an ignore path, and findings a scanner never reported do not count, whatever their severity. [Set the gate](../how-to/set-the-gate.md) covers thresholds.

`--ignore-suppressions` turns ASH's whole suppression step off. Configured suppressions, ignore paths, and inline `ash-ignore` comments stop applying, so their findings come back and count toward the gate. So do [client-supplied entries](#client-supplied-entries), scanner exclusions from an MCP client's config included: ASH applies those itself, so the findings they would have marked are ordinary findings. For ignore paths this goes back to the files: ASH gives the scanners and converters no ignore paths, so every scanner reads the files under one and the converters convert the archives and notebooks there. It does not touch what the scanners did themselves: files a scanner skipped through its own exclusion options, and findings its inline comments hid, stay unreported, and findings a scanner reported as suppressed stay suppressed. The repository's `.gitignore` and `.ignore` files still remove files from the set ASH hands several scanners ([Coverage](../reference/coverage.md#what-decides-the-files)), and findings in ASH's own output directory stay out of the results. In container mode the flag reaches the scan inside the container and works there as in a local scan.

## In the reports

| Output | A suppressed finding |
|---|---|
| `ash.sarif` and `ash_aggregated_results.json` | Kept, with a `suppressions` entry: `kind: inSource` and a justification that starts with `(ASH)` for a configured suppression or `(ASH inline)` for an `ash-ignore` comment. A suppression the scanner reported keeps the scanner's own justification. |
| `ash.flat.json`, `ash.csv` | Kept, with `is_suppressed` and the justification |
| `ash.html` | Listed in a separate table of suppressed findings, with the justification |
| `ash.junit.xml` | A `<skipped type="suppression">` test case with the justification |
| `ash.ocsf.json` | Kept, with a suppressed status |
| `ash.gl-sast-report.json` | Kept at severity Info, unless `exclude_suppressed` is set |
| `ash.ghas.sarif` | Left out, unless `exclude_suppressed` is turned off |
| `ash.summary.md`, `ash.summary.txt` | Counted in the suppressed column only |

Findings under an ignore path appear in none of these. The `unused-suppressions` reporter writes `ash.unused-suppressions.json` and `.md`, which list the configured suppressions that matched no finding.

## Client-supplied entries

When a scan's config includes a file an MCP client delivered, each suppression and ignore path that file sets is marked `client_supplied`, unless it matches an entry from an operator source, and so are scanner exclusions from that file. A marked ignore path or exclusion does not keep files from being scanned: the files are scanned, and each finding it covers is kept as a suppressed finding with a `(ASH, client-supplied config)` justification and `clientSupplied: true` in the SARIF. Marked findings do not count toward the gate, like other suppressed findings. [Configuration trust model](trust-model.md#client-supplied) explains when entries are marked and where the mark appears.

ASH marks entries only in configs an MCP client delivered. In a CLI scan, a repository's own suppressions, ignore paths, and inline suppressions apply the same way yours do, which matters when the repository is not yours; see [Scanning untrusted code](scanning-untrusted-code.md).
