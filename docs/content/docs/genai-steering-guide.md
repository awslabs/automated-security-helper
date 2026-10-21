# ASH GenAI integration guide

This file tells an AI agent how to run ASH (Automated Security Helper), read its results,
and propose suppressions without hiding real problems. Give it to your agent as context,
for example as a rules file or a steering file. To save a copy in the current directory:

```bash
ash get-genai-guide --output ash-genai-guide.md
```

The command writes the guide for the ASH version you have installed, without network access.
Every installation carries it: a wheel or source distribution, an install from a git URL, a
clone of the repository, and the container images ASH builds. In a clone, the command copies
the clone's `docs/content/docs/genai-steering-guide.md`. An installation without a readable
copy exits with code 1 and names `--from-github`, which downloads the guide from GitHub
instead, from `main` or from the branch or tag that `--branch` names.

The rest of this file is written for the agent.

## Rules

- Never report a project as clean unless every selected scanner ran and there are zero
  actionable findings. A scan that ended `incomplete`, or with exit code 1, did not run every
  scanner: name the scanners that did not run, and why.
- Fix before you suppress. Propose a suppression only for a false positive or a risk the user
  accepts, with a reason the user agrees with, and never to make a scan pass.
- Do not change what the scan checks to get a passing result: do not disable scanners, raise
  severity thresholds, set `fail_on_findings: false`, add broad `ignore_paths`, or pass
  `--ignore-suppressions`, `--no-fail-on-findings`, or `--no-fail-on-incomplete-scanners`,
  unless the user asks for that change.
- Do not set `client_supplied` in a config. ASH sets it.
- Do not add sandbox grants or plugin modules to the repository's config to make a scanner
  work. They are the operator's settings, and ASH ignores sandbox grants from a config inside
  the scanned repository.
- When a scanner is MISSING because its tool is installed only inside the project, install
  the tool outside the project. Do not pass `--allow-in-tree-tools` or set
  `ASH_ALLOW_IN_TREE_TOOLS` unless the user asks you to.
- Do not make `.ash`, `.ash/ash_output`, or any directory under it a symbolic link. ASH refuses
  to write through one.
- Do not repeat a detected secret's value in your answers. Refer to the file and line.
- If a tool, option, or field named here does not exist, the installed ASH is older than this
  guide. Tell the user, and use what the installed version reports (`ash --help`, the MCP
  server's tool list).

## Run a scan with the MCP tools

When the ASH MCP server is connected, a scan takes three steps:

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns
   at once with a `scan_id` and status `running`.
2. Call `get_scan_progress` with the `scan_id` about every 5 seconds until `is_complete` is
   true. It is true for every final status: `completed`, `incomplete`, `failed`, or
   `cancelled`.
3. When `results_available` is true, which it is for `completed` and `incomplete`, read the
   results from `output_directory`, an absolute path in the progress response.

| Final status | Meaning | What to do |
|--------------|---------|------------|
| `completed` | Every selected scanner ran. | Read the results. |
| `incomplete` | The scan finished and its results are readable, but a selected scanner did not run or did not finish, or a content database was too old. | Read the results, report `incomplete_scanners` and `stale_content_databases`, and say the coverage is partial. |
| `failed` | The scan crashed, left no readable results, or ran longer than the server allows. | Report `error_message`. |
| `cancelled` | The scan was canceled. | Say so. |

After `failed` or `cancelled`, `results_available` is false, so do not report results for that
scan. Once ASH has put the previous scan's results back in the output directory,
`output_holds_previous_results` is true, and the results tools refuse that directory with
`error_category` `scan_incomplete` until another scan finishes there.

The examples in this section call each tool as a function that takes the tool's arguments
and returns its response, a dictionary. A response with `success` false has an `error`
message instead of the keys below. Adapt the calls to your MCP client:

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import time

# LOW is stricter than the default MEDIUM, so LOW findings count as actionable too.
# Leave severity_threshold out to use the config's threshold.
scan = run_ash_scan(source_dir="/path/to/project", severity_threshold="LOW")
if scan.get("success") is False:
    raise RuntimeError(scan["error"])

while True:
    progress = get_scan_progress(scan_id=scan["scan_id"])
    if progress.get("success") is False:
        raise RuntimeError(progress["error"])
    if progress["is_complete"]:
        break
    time.sleep(5)

if progress["results_available"]:
    results = get_scan_results(
        output_dir=progress["output_directory"], actionable_only=True
    )
    print(progress["status"], results["findings_count"], "actionable findings")
else:
    print(progress["status"], progress.get("error_message"))
```

What to know about the tools:

- `run_ash_scan` takes no scanner list. The project's ASH config chooses the scanners and
  the severity thresholds.
- Its `severity_threshold` argument can make the config's `global_settings.severity_threshold`
  stricter for that scan, never looser: `LOW` over a configured `MEDIUM` makes LOW findings
  actionable, and `CRITICAL` over `MEDIUM` changes nothing. It tightens a scanner's own
  `severity_threshold` option the same way, and a scanner without one follows the tightened
  global threshold. The threshold decides which findings are actionable and whether a
  scanner reports FAILED, not which findings are reported. `get_scan_progress` returns the
  argument as `requested_severity_threshold` and, once the scan has results, the threshold
  it was judged by as `severity_threshold`.
- Each scan writes `.ash/ash_output` inside `source_dir`. Once its options and config are
  accepted, it sets the previous scan's results there aside, and it deletes them once it has
  results of its own; a scan that fails or is canceled puts them back, and a scan refused
  for its scanner selection or its config leaves them as they were. Copy `ash_aggregated_results.json` before the next scan
  if you need it for a comparison.
- `cancel_scan` stops a running scan: the scanner tool running at the time is stopped, and no
  further scanner, phase, or reporter starts, so a scan canceled before its report phase
  writes no reports. A scanner that is already reading its tool's output can still write its
  own files, but `ash_aggregated_results.json` is not written after the cancel. Previous
  results that the output directory held are put back in place of the results the scan
  wrote; the scan's log, `ash.log`, stays, and an `ash.log.jsonl` already there is left as it
  was. With none to put back, what the scan wrote before it stopped stays, though a cancel
  during the report phase removes that phase's reports, all but
  `reports/ash.unused-suppressions.md`. Its status is `cancelled` at once. Until the scan has stopped, `run_ash_scan`
  refuses another scan of that directory.
- `get_scan_results` returns counts and per-scanner summaries. With `actionable_only` set, a
  response at the default `filter_level`, `full`, also has a `findings` list of the
  actionable findings, without their IDs, and its `findings_count`. Those are the findings
  that are not suppressed and are at or above the threshold their scanner was judged by, the
  ones that fail the scan. Findings below it are left out. A `summary` or `minimal` response
  has no list. Read the IDs, and the suppressed findings, from `reports/ash.flat.json` in the
  output directory.
  `get_scan_result_paths` returns the absolute paths of the main reports and of
  `ash_aggregated_results.json`.
- The server's operator limits how many scans it holds at once, running or waiting
  (`max_concurrent_scans`), and how long one may run (`scan_timeout_seconds`). A scan over
  the first limit is refused with an `error` that names it; start it again when another scan
  has finished. A scan over the second is stopped and ends `failed`.
- The server keeps its list of scans in memory. After it restarts, `get_scan_progress`
  fails with `error_category` `scan_not_found` for older scan IDs; read their results from the
  output directory.

After a scan, `get_scan_progress` reports `scanner_statuses` for every scanner ASH considered
and `skipped_scanners` for the ones that did not run. Use them to tell "ran and found nothing"
from "never ran". `check_installation` reports whether each built-in scanner's tool is
installed: `ready` is false when a scanner that ASH enables by default cannot run and no scan
will install its tool, and `missing_dependencies` names those scanners. It does not read the
project's config, and it installs and downloads nothing. When the tool of a scanner that ASH
installs with uv is missing, the first scan installs it if the server is online and has uv;
such a scanner is listed in `installs_on_first_scan` and counts toward `ready`, and otherwise
it is in `missing_dependencies`. Offline, semgrep is also missing when it has no rules cache.

The [MCP tools reference](https://github.com/awslabs/automated-security-helper/blob/main/docs/content/reference/mcp-tools.md)
lists every tool and its parameters.

### Stop a scan that runs too long

A canceled scan's status is `cancelled` at once, so the next poll ends the loop, and
`results_available` is false:

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import time


def scan_or_cancel(source_dir):
    scan = run_ash_scan(source_dir=source_dir)
    if scan.get("success") is False:
        return {"error": scan["error"]}
    deadline = time.monotonic() + 20 * 60
    canceled = False
    while True:
        progress = get_scan_progress(scan_id=scan["scan_id"])
        if progress.get("success") is False:
            return {"error": progress["error"]}
        if progress["is_complete"]:
            break
        if not canceled and time.monotonic() > deadline:
            cancel_scan(scan_id=scan["scan_id"])
            canceled = True
        time.sleep(5)
    if not progress["results_available"]:
        return {"status": progress["status"], "error": progress.get("error_message")}
    return get_scan_results(
        output_dir=progress["output_directory"], filter_level="summary"
    )
```

### Pattern 1: fail a build on critical or high findings

Run from the scanned directory after the scan has ended with results:

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
import sys
from pathlib import Path

results = get_scan_results(
    output_dir=str(Path(".ash/ash_output").resolve()),
    actionable_only=True,
    severities="critical,high",
)
if results.get("success") is False:
    print(results["error"])
    sys.exit(1)
if results["findings_count"] > 0:
    print(f"{results['findings_count']} actionable critical or high findings")
    sys.exit(1)
```

The list holds the findings that the scan's own exit code and `summary_stats.actionable`
count, those at or above each scanner's severity threshold, narrowed here to critical and
high.

### Pattern 2: list the findings to fix

<!-- doctest: illustrative reason="calls the MCP tools, which need a client connected to ash mcp" -->
```python
from pathlib import Path

results = get_scan_results(
    output_dir=str(Path(".ash/ash_output").resolve()),
    actionable_only=True,
    severities="critical,high",
)
for finding in results["findings"]:
    print(
        finding["severity"],
        finding.get("scanner"),
        finding.get("rule_id"),
        f"{finding.get('file_path')}:{finding.get('line_start')}",
        finding.get("message"),
    )
```

The list leaves out suppressed findings. `reports/ash.flat.json` in the output directory has
every finding, with `is_suppressed`.

### When the server is remote

A server on another host cannot read the user's files. Deliver the source first with
`set_source_git` or `set_source_zip_chunk` and `set_source_zip_finalize`, then call
`run_ash_scan` without `source_dir`. A config file inside delivered source is checked against
the server's policy: if it sets a field the server does not let clients set, such as
`fail_on_findings`, the scan is refused with `error_type` `config_field_denied` and a message
naming the field. Remove the field and deliver again. Suppressions and ignore paths in
delivered source are applied and marked as client-supplied in the results.

## Run a scan with the command line

From the project's root directory:

<!-- doctest: illustrative reason="runs every scanner, which needs the scanner tools and network access" -->
```bash
ash --source-dir . --no-progress
```

`ash` and `ash scan` are the same command. The scan runs on this machine and writes its
output to `.ash/ash_output` under the scanned directory unless you pass `--output-dir`.
`--scanners` runs only the named scanners and `--exclude-scanners` skips them; use them only
when the user asks for a narrower scan. This scan runs detect-secrets alone, without network
access:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

| Exit code | Meaning |
|-----------|---------|
| 0 | No actionable findings, or the config does not fail on findings. |
| 1 | The scan is incomplete: a scanner was MISSING or ended in ERROR, a converter failed, a rule could not be evaluated, a content database was too old, or ASH itself failed. |
| 2 | Actionable findings. |
| 3 | The config is invalid. |
| 4 | A workspace definition or workspace policy is invalid. |
| 5 | The command line is wrong: an unknown option or argument, a value ASH does not accept, such as a mistyped scanner name, or options that cannot be combined. No scanner ran. |

A value ASH does not accept is a usage error, and no scanner runs:

<!-- doctest: run expect-exit=5 -->
```bash
ash --source-dir . --scanners detect-secrets --min-severity urgent --offline --no-progress
```

To print a summary of the last scan:

```bash
ash report --output-dir .ash/ash_output
```

## Read the results

The output directory, `.ash/ash_output` by default, contains:

| Path | Use it for |
|------|------------|
| `reports/ash.flat.json` | Findings, one record each. Start here. |
| `ash_aggregated_results.json` | Each scanner's status and the scan's totals. |
| `reports/ash.summary.md` | A readable summary to show the user. |
| `reports/ash.sarif` | SARIF, for tools that read it. |
| `reports/ash.unused-suppressions.json` | Suppressions that matched no finding, including expired ones. |
| `ash.log` | The scan's log, for errors. |

`reports/ash.flat.json` is an object. Its `findings` list holds one record per finding with
these fields: `id`, `title`, `description`, `severity`, `scanner`, `rule_id`, `file_path`,
`line_start`, `line_end`, `is_suppressed`, `code_snippet`, and, for suppressed findings,
`suppression_kind` and `suppression_justification`. Fields with no value are left out, so
read them with a default. `tags`, `properties`, and `raw_data` hold JSON encoded as strings.

```python
import json
from pathlib import Path

report = json.loads(Path(".ash/ash_output/reports/ash.flat.json").read_text())
for finding in report["findings"]:
    if finding.get("is_suppressed"):
        continue
    print(
        finding["severity"],
        finding["scanner"],
        finding["rule_id"],
        f"{finding.get('file_path')}:{finding.get('line_start')}",
        finding["id"],
    )
```

In `ash_aggregated_results.json`, `metadata.summary_stats` holds the totals:

- `severity_counts` counts findings by severity (`critical`, `high`, `medium`, `low`,
  `info`) and counts suppressed findings separately in `suppressed`.
- `total` is the number of findings that are not suppressed.
- `actionable` is the number of findings that are not suppressed and are at or above the
  severity threshold. The threshold comes from `global_settings.severity_threshold` in the
  config, MEDIUM by default, or from a scanner's own `severity_threshold` option, which
  replaces it for that scanner.
- `passed`, `failed`, `missing`, `skipped`, and `error` count scanners by status.

The config sets both:

<!-- doctest: config kind=ash -->
```yaml
global_settings:
  severity_threshold: MEDIUM  # ALL, LOW, MEDIUM, HIGH, CRITICAL
scanners:
  bandit:
    options:
      severity_threshold: HIGH
```

```python
import json
from pathlib import Path

results = json.loads(Path(".ash/ash_output/ash_aggregated_results.json").read_text())
stats = results["metadata"]["summary_stats"]
print("actionable:", stats["actionable"], stats["severity_counts"])
for name, scanner in results["scanner_results"].items():
    if scanner["status"] in ("MISSING", "ERROR"):
        print(name, scanner["status"], scanner.get("missing_reason"))
```

`scanner_results` has one entry per scanner, with its `status`, `finding_count`,
`actionable_finding_count`, `suppressed_finding_count`, and `severity_counts`. A MISSING
scanner also has a `missing_reason`. The statuses are:

| Status | Meaning |
|--------|---------|
| PASSED | It ran and found nothing at or above its threshold. |
| FAILED | It ran and found something at or above its threshold. This is a result, not an error. |
| MISSING | It had files to scan, but its tool is not installed, or was found only inside the scanned tree. It did not run. |
| ERROR | It started and failed. |
| SKIPPED | It did not run: it is disabled or excluded, or there was nothing for it to scan. |

A finding that a scanner reports with no severity of its own, only the SARIF level `error`, as
detect-secrets does, is CRITICAL in `ash.flat.json`, `ash.summary.md`, `summary_stats`, the
MCP counts, and the threshold check alike.

## Explain a finding

Take the finding's `id` from `ash.flat.json` and call `explain_finding` with it and
`results_path` set to the output directory. The answer has the scanner's description, the
severity and why it is or is not actionable, CWE and CVE identifiers when the scanner gives
them, and the matched code. Without MCP, use the record in `ash.flat.json` and read the code
at `file_path` and `line_start`.

An `id` is the scanner, the rule, and 12 hexadecimal digits of a hash of where the finding is:
its file and lines, or the fingerprints its scanner reports. For example,
`bandit-B602-e1cb79ce5694`. Findings at different places have different `id`s.

## Suggest a suppression

Call `suggest_suppression` with the finding's `id`, `results_path` set to the
`ash_aggregated_results.json` file (not the directory), and the user's reason as
`justification`. It writes nothing and returns one entry as `yaml` and `json`. Its
`expiration` defaults to 90 days from today. Leave out the `client_supplied` key it includes,
and put the entry under `global_settings.suppressions` in the project's config:

```yaml
global_settings:
  suppressions:
    - rule_id: "SECRET-SECRET-KEYWORD"
      path: "app.py"
      line_start: 3
      line_end: 3
      reason: "Test fixture value, not a real credential"
      expiration: "2027-06-30"
```

- `path` and `reason` are required. `path` is relative to the scanned directory and may use
  glob patterns such as `tests/**`. Do not start it with `./`, which matches nothing.
- `rule_id` matches without regard to case and may use glob patterns.
- `line_start` and `line_end` tie the suppression to those lines. Leave them out to match the
  rule anywhere in the path.
- Write `expiration` as a quoted `YYYY-MM-DD` date. From that date on, the suppression no
  longer applies and the finding counts again. An expired suppression is listed in
  `reports/ash.unused-suppressions.json`, with the ones that matched nothing.
- `ignore_paths` entries also need `path` and `reason`, and drop every finding in the matching
  files. Prefer a suppression for one rule.

Edit the config file the scan used, or create `.ashrc.yaml` in the scanned directory if it
has none. ASH uses the first of these it finds in the scanned
directory: `.ash.yml`, `.ash.yaml`, `.ash.json`, `ash.yml`, `ash.yaml`, `ash.json` (each in the
directory, then in `.ash/`), then `.ashrc.toml`, `.ashrc.yaml`, `.ashrc.yml`, `.ashrc.json`,
`ashrc.toml`, `ashrc.yaml`, `ashrc.yml`, and `ashrc.json` in the directory, then the
`[tool.ash]` table of `pyproject.toml`. If the config has an `extends` key, its own
`suppressions` list replaces the base config's list instead of adding to it; keep the base's
entries by adding yours with a `patch` operation `add` at `/global_settings/suppressions/-`.

Check the edited config before you scan. `ash config validate`, run in the scanned directory,
checks the config a scan there would use the way the scan loads it: it names each field the
scan would refuse, such as a suppression without a `reason` or with a misspelled key, and
exits with code 3 when there is one. `--config` names another file. Over MCP,
`validate_config` with `config_path` gives the same verdict: `errors` lists what the scan
would refuse, `warnings` what it accepts but is probably a mistake, and `valid` is true when
there are no errors.

```bash
cat > .ashrc.yaml <<'EOF'
global_settings:
  suppressions:
    - rule_id: "SECRET-SECRET-KEYWORD"
      path: "app.py"
      reason: "Test fixture value, not a real credential"
      expiration: "2027-06-30"
EOF
ash config validate
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

After the next scan, the finding has `is_suppressed` true and the scan's suppressed count
includes it. Tell the user which suppressions you added and why, so they can review them.

## Compare two scans

Copy `ash_aggregated_results.json` before the next scan replaces it. Then call
`diff_scan_results` with `before_path` and `after_path` set to the two files. It returns
`new`, `resolved`, and `severity_changed`, each a list of finding records shaped like those in
`ash.flat.json`. It matches findings by `id`:

- A finding that was only suppressed between the two scans appears in none of the lists.
  Compare `is_suppressed` in the two `ash.flat.json` files to see it.
- An `id` comes from where the finding is. When a finding's lines move, because code above it
  was added or removed, it gets a new `id` and appears once in `resolved` and once in `new`,
  unless its scanner reports fingerprints. When two findings share a place, their column and
  message tell them apart, so a changed message can change those `id`s too. Compare
  `rule_id`, `file_path`, and the code before you report a finding as new or fixed.

## Errors

A failed MCP call returns `success` false, an `error` message, and an `error_type`; some also
return an `error_category`. The names below appear in one of those two fields.

| You see | Do this |
|---------|---------|
| Exit code 1, or status `incomplete`, with MISSING scanners | Tell the user. `ash dependencies install` installs the scanner tools for the user that runs ASH. A tool installed only inside the project does not count. |
| Exit code 3 | Run `ash config validate` in the scanned directory to see each invalid field, and fix it. |
| Exit code 5 | The command line is wrong. Check the option names and values with `ash --help`. |
| `scan_target_not_permitted`, or `invalid_path` from a results tool | The MCP server does not allow that directory. Ask the user to add it to the server's `ASH_MCP_ALLOWED_ROOTS`, or deliver the source. |
| `config_input_not_permitted` | The server does not allow reading that config file. Use the project's own config, or ask the user. |
| `config_field_denied` | A delivered config sets a field the server does not let clients set. Remove the field it names. |
| `output_dir_not_permitted` | `.ash` or `.ash/ash_output` in the project is a symbolic link. Ask the user to replace it with a directory. |
| `no_source_delivered` | Pass `source_dir`, or deliver the source first. |
| `source_delivery_busy` | A scan of this session is running, or its source is being replaced. Call the tool again once the scan has finished. |
| `session_workspace_busy` | The server is removing this session's workspace, which nobody used for longer than its time to live. Call `select_profile` again if the session had a profile, and send an upload again from chunk 0. |
| `clone_host_not_permitted` | The server does not clone from that host. Deliver the source as a zip, or ask the user to add the host to the server's `ASH_MCP_GIT_ALLOWED_HOSTS`. |
| `clone_url_not_permitted` or `clone_ref_not_permitted` | `set_source_git` takes only an `https` or `ssh` URL, and no URL or ref that begins with `-` or uses the `ext::` transport. Fix the URL or ref. |
| `local_clone_source_refused` | `set_source_git` never clones a local path or `file://` URL. Pass the directory as `run_ash_scan`'s `source_dir`. |
| `ssh_key_not_registered` | Call `set_source_git` without `ssh_key_id`; the server registers no SSH keys. |
| `invalid_clone_depth` | Pass a `depth` of 1 or more, or leave it out for the latest commit. |
| `git_clone_failed` or `git_checkout_failed` | git ran and failed, and `error` has its message. Check the URL and ref, or deliver the source as a zip. |
| `clone_timed_out` | A git command ran past 10 minutes and was stopped. Deliver the source as a zip. |
| `invalid_session_id` | The server refused the session ID the call carries. Tell the user. |
| `session_identity_required` | The server is stateless and cannot tell which session the call belongs to. Tell the user; the server needs a session to scan, deliver source, or track scans. |
| `scan_start_failure` | `run_ash_scan` did not start a scan, and `error` says why. If it names `max_concurrent_scans`, start the scan again when another scan has finished. If it says a scan of the directory is still stopping, try again in a few seconds. |
| `scan_incomplete` with `output_holds_previous_results` true | The last scan of that directory failed or was canceled, and its output directory holds the scan before it. Run the scan again. |
| `scan_not_found` | The server restarted or the ID is wrong. Read the results from the output directory. |

More detail for people is in the
[ASH documentation](https://github.com/awslabs/automated-security-helper/blob/main/docs/content/index.md).
