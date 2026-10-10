# ASH GenAI integration guide

This file tells an AI agent how to run ASH (Automated Security Helper), read its results,
and propose suppressions without hiding real problems. Give it to your agent as context,
for example as a rules or steering file. To save a copy in the current directory:

```bash
ash get-genai-guide --output ash-genai-guide.md
```

From a source checkout of ASH the command copies this file. From an installed ASH it
downloads the file from the `main` branch on GitHub, so it can describe tools and fields
that are newer than your installed version; `--branch` names another branch or tag.

The rest of this file is written for the agent.

## Rules

- Never report a project as clean unless every selected scanner ran and there are zero
  actionable findings. A scan that ended `incomplete`, or with exit code 1, did not run every
  scanner: name the scanners that did not run, and why.
- Fix before you suppress. Propose a suppression only for a false positive or a risk the user
  accepts, with a reason the user agrees with, and never to make a scan pass.
- Do not change what the scan checks to get a passing result: do not disable scanners, raise
  severity thresholds, set `fail_on_findings: false`, add broad `ignore_paths`, or pass
  `--ignore-suppressions`, `--no-fail-on-findings` or `--no-fail-on-incomplete-scanners`,
  unless the user asks for that change.
- Do not set `client_supplied` in a config. ASH sets it.
- Do not add sandbox grants or plugin modules to the repository's config to make a scanner
  work. They are the operator's settings, and ASH ignores sandbox grants from a config inside
  the scanned repository.
- When a scanner is MISSING because its tool is installed only inside the project, install
  the tool outside the project. Do not pass `--allow-in-tree-tools` or set
  `ASH_ALLOW_IN_TREE_TOOLS` unless the user asks you to.
- Do not make `.ash`, `.ash/ash_output` or any directory under it a symbolic link. ASH refuses
  to write through one.
- Do not repeat a detected secret's value in your answers. Refer to the file and line.
- If a tool, option or field named here does not exist, the installed ASH is older than this
  guide. Tell the user, and use what the installed version reports (`ash --help`, the MCP
  server's tool list).

## Run a scan with the MCP tools

When the ASH MCP server is connected, a scan takes three steps:

1. Call `run_ash_scan` with `source_dir` set to the absolute path of the project. It returns
   at once with a `scan_id` and status `running`.
2. Call `get_scan_progress` with the `scan_id` about every 5 seconds until `status` is
   `completed`, `incomplete`, `failed` or `cancelled`. Decide on `status`, not on
   `is_complete` alone.
3. Read the results from `output_directory`, an absolute path in the progress response.

| Final status | Meaning | What to do |
|--------------|---------|------------|
| `completed` | Every selected scanner ran. | Read the results. |
| `incomplete` | The scan finished and its results are readable, but a selected scanner did not run or did not finish, or a content database was too old. | Read the results, report `incomplete_scanners` and `stale_content_databases`, and say the coverage is partial. |
| `failed` | The scan crashed or left no readable results. | Report `error_message`. |
| `cancelled` | The scan was cancelled. | Do not treat any results as final. |

What the tools do not do:

- `run_ash_scan` takes no scanner list. The project's ASH config chooses the scanners and
  thresholds.
- Its `severity_threshold` argument is recorded with the scan and does not change what the
  scan reports. Which findings are actionable comes from the config's thresholds.
- Each scan writes `.ash/ash_output` inside `source_dir`, and deletes the previous
  `ash_aggregated_results.json` there before it starts. Copy that file first if you need it
  for a comparison.
- `cancel_scan` marks a scan cancelled, but the scan keeps running and can still write its
  results.
- `get_scan_results` returns counts and per-scanner summaries, not a list of findings with
  their IDs. With `actionable_only` set, its `findings` list is always empty, whatever the
  scan found. Read findings from `reports/ash.flat.json` in the output directory instead.
  `get_scan_result_paths` returns the absolute path of every report.
- The server keeps its list of scans in memory. After it restarts, `get_scan_progress`
  fails with `error_category` `scan_not_found` for older scan ids; read their results from the
  output directory.

After a scan, `get_scan_progress` reports `scanner_statuses` for every scanner ASH considered
and `skipped_scanners` for the ones that did not run. Use them to tell "ran and found nothing"
from "never ran".

The [MCP tools reference](https://github.com/awslabs/automated-security-helper/blob/main/docs/content/reference/mcp-tools.md)
lists every tool and its parameters.

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
output to `.ash/ash_output` under the current directory unless you pass `--output-dir`.
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
| 1 | The scan is incomplete: a scanner was MISSING or ended in ERROR, a converter failed, or ASH itself failed. |
| 2 | Actionable findings. |
| 3 | The config is invalid. |
| 4 | A workspace definition or workspace policy is invalid. |

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
`line_start`, `line_end`, `is_suppressed`, `code_snippet` and, for suppressed findings,
`suppression_kind` and `suppression_justification`. Fields with no value are left out, so
read them with a default. `tags`, `properties` and `raw_data` hold JSON encoded as strings.

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
  config, MEDIUM by default, or from a scanner's own `severity_threshold` option. Its values
  are `ALL`, `LOW`, `MEDIUM`, `HIGH` and `CRITICAL`.
- `passed`, `failed`, `missing`, `skipped` and `error` count scanners by status.

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
`actionable_finding_count`, `suppressed_finding_count` and `severity_counts`. A MISSING
scanner also has a `missing_reason`. The statuses are:

| Status | Meaning |
|--------|---------|
| PASSED | It ran and found nothing at or above its threshold. |
| FAILED | It ran and found something at or above its threshold. This is a result, not an error. |
| MISSING | Its tool is not installed, or was found only inside the scanned tree. It did not run. |
| ERROR | It started and failed. |
| SKIPPED | It did not run: it is disabled or excluded, or there was nothing for it to scan. |

The same finding can carry two severities. When a scanner reports a finding with only the
SARIF level `error` and no severity of its own, as detect-secrets does, `summary_stats`, the
MCP counts and the threshold check treat it as CRITICAL, while `ash.flat.json` and
`ash.summary.md` show it as HIGH. Use the severity in `ash.flat.json` when you describe a
finding, and the counts in `summary_stats` when you report whether the scan passes.

## Explain a finding

Take the finding's `id` from `ash.flat.json` and call `explain_finding` with it and
`results_path` set to the output directory. The answer has the scanner's description, the
severity and why it is or is not actionable, CWE and CVE identifiers when the scanner gives
them, and the matched code. Without MCP, use the record in `ash.flat.json` and read the code
at `file_path` and `line_start`.

An `id` is the scanner, the rule and a hash of the finding's message, for example
`bandit-B602-e9f369ff`. It does not include the location, so two findings with the same rule
and message share one `id`, and `explain_finding` and `suggest_suppression` use the first
match. Check that the `path` and lines they return are the finding you meant.

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

Edit the config file the scan used. ASH uses the first of these it finds in the scanned
directory: `.ash.yml`, `.ash.yaml`, `.ash.json`, `ash.yml`, `ash.yaml`, `ash.json` (each in the
directory, then in `.ash/`), then `.ashrc.toml`, `.ashrc.yaml`, `.ashrc.yml`, `.ashrc.json`,
`ashrc.toml`, `ashrc.yaml`, `ashrc.yml` and `ashrc.json` in the directory, then the
`[tool.ash]` table of `pyproject.toml`. If the config has an `extends` key, its own
`suppressions` list replaces the base config's list instead of adding to it; keep the base's
entries by adding yours with a `patch` operation `add` at `/global_settings/suppressions/-`.

Check the edited config before you scan. `ash config get` loads it the way a scan does and
exits with code 3, naming the field, when it is invalid. Over MCP, `get_config` with
`config_path` does the same check. `ash config validate`, `ash config lint` and the MCP
`validate_config` tool miss some errors, such as a suppression without a `reason`.

```bash
mkdir -p .ash
cat > .ash/.ash.yaml <<'EOF'
global_settings:
  suppressions:
    - rule_id: "SECRET-SECRET-KEYWORD"
      path: "app.py"
      reason: "Test fixture value, not a real credential"
      expiration: "2027-06-30"
EOF
ash config get .ash/.ash.yaml > /dev/null
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

After the next scan, the finding has `is_suppressed` true and the scan's suppressed count
includes it. Tell the user which suppressions you added and why, so they can review them.

## Compare two scans

Copy `ash_aggregated_results.json` before the next scan replaces it. Then call
`diff_scan_results` with `before_path` and `after_path` set to the two files. It returns
`new`, `resolved` and `severity_changed`, each a list of finding records shaped like those in
`ash.flat.json`. A finding that was suppressed between the two scans appears in none of the
lists; compare `is_suppressed` in the two `ash.flat.json` files to see it.

## Errors

A failed MCP call returns `success` false, an `error` message, and an `error_type`; some also
return an `error_category`. The names below appear in one of those two fields.

| You see | Do this |
|---------|---------|
| Exit code 1, or status `incomplete`, with MISSING scanners | Tell the user. `ash dependencies install` installs the scanner tools for the user that runs ASH. A tool installed only inside the project does not count. |
| Exit code 3 | Run `ash config get` on the config to see the invalid field, and fix it. |
| `scan_target_not_permitted` | The MCP server does not allow that directory. Ask the user to add it to the server's `ASH_MCP_ALLOWED_ROOTS`, or deliver the source. |
| `config_input_not_permitted` | The server does not allow reading that config file. Use the project's own config, or ask the user. |
| `config_field_denied` | A delivered config sets a field the server does not let clients set. Remove the field it names. |
| `output_dir_not_permitted` | `.ash` or `.ash/ash_output` in the project is a symbolic link. Ask the user to replace it with a directory. |
| `no_source_delivered` | Pass `source_dir`, or deliver the source first. |
| `scan_not_found` | The server restarted or the id is wrong. Read the results from the output directory. |

More detail for people is in the
[ASH documentation](https://github.com/awslabs/automated-security-helper/blob/main/docs/content/index.md).
