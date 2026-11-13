# ASH for security analysts

You answer questions that span repositories: what is our exposure, is it
getting better, which teams carry the debt, and can we prove any of it to an
auditor. For that you need every repository scanned under one policy, results
in formats your systems ingest, and a way to compare scans over time. ASH's
unit of work is one scan of one tree, so the fleet view is built from three
parts: a rollout that pins the policy, reports that feed your stores, and
merge and diff tools that combine and compare results.

## One policy, many repositories

[Roll out across repositories](../getting-started/platform-teams.md) is the
tutorial for this: build an ASH container image from a pinned release, push it
to your registry, and write one operator config that every scan uses. The key
property is that the config is yours, not the repository's: passed with
`--config` from a file outside every git checkout, it is the only config ASH
reads, so a repository cannot turn off `fail_on_findings`, raise thresholds,
disable scanners, or add suppressions through its own file. The tutorial
includes the scan that proves it. Runners that cannot run containers roll out a
pinned ASH with uv instead
([Pin ASH with uv](../getting-started/platform-teams.md#uv-rollout)).

The same page covers the part that ages: grype and trivy read vulnerability
databases with age bounds, and ASH fails a scan whose database is stale, so
image rebuilds go on a schedule rather than waiting for the first failed scan.

## Reports your systems read

Every scan writes its reports to `reports/` in the output directory; thirteen
reporters are on by default, and each writes its own file
([Export reports](../how-to/export-reports.md)):

| Where the findings go | File in `reports/` |
|---|---|
| GitHub code scanning | `ash.ghas.sarif` |
| Other SARIF consumers | `ash.sarif` |
| GitLab security dashboards | `ash.gl-sast-report.json` |
| Security data lakes and SIEMs | `ash.ocsf.json` |
| SBOM tooling | `ash.cdx.json` (CycloneDX), `ash.spdx.json` (SPDX, off by default) |
| CI test views | `ash.junit.xml` |
| Spreadsheets | `ash.csv` |
| People | `ash.html`, `ash.summary.md`, `ash.summary.txt` |
| Your own scripts | `ash.flat.json` |

`--output-formats` narrows what a scan writes:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --scanners detect-secrets --output-formats sarif,junitxml
```

Suppressed findings ride along in the data formats with their reasons, so your
store can report accepted risk as well as open findings. For delivery into AWS,
the operator-loaded reporters send to Security Hub, S3, CloudWatch Logs, or
Amazon Bedrock for a generated summary; each page says exactly what leaves the
machine before you turn one on ([AWS reporters](../plugins/aws.md)). Anything
else is a [reporter plugin](../plugins/write-a-reporter.md) away.

## Aggregate and compare

Two built-in combiners produce one result from several scans:

- `ash merge` recombines the shards of one scan that ran across several
  runners, recomputing the verdict and every report over all of them, and
  refuses mismatched shards rather than merging a hole into the results
  ([Split a scan across runners](../how-to/scale-large-repos.md#sharding)).
- `--workspace` scans the folders of a `.code-workspace` file as separate
  projects in one run: per-project reports for the systems that want one
  repository per report, plus combined reports and a combined results file
  whose `workspace` member lists each project's status and counts
  ([Scan a multi-project workspace](../how-to/scale-large-repos.md#workspaces)).
  A workspace policy file sets a threshold projects can tighten but not relax,
  with suppressions and ignore paths applied to every project.

Across repositories, the aggregation is yours: each scan's
`ash_aggregated_results.json` and `ash.ocsf.json` are machine-readable and
stable places to build from, and `ash.flat.json` is the one-record-per-finding
file for quick scripts.

For trend questions, compare results files directly: `diff_scan_results`
returns the resolved, new, and severity-changed findings between two scans
([MCP tools reference](../reference/mcp-tools.md#diff_scan_results)). Keep the
results file of each scan of record (it is one JSON file per scan) and the
fleet's history is a directory listing.

## AI-assisted triage over MCP

`ash mcp` exposes scans and results to any MCP client, which turns triage from
file-reading into a conversation: an agent runs or re-runs a scan, pulls the
findings, explains one with its code context (`explain_finding`), drafts a
suppression with a reason and a default 90-day expiration
(`suggest_suppression`), and diffs two scans
([Connect an AI agent](../getting-started/agents.md)). The
[tool reference](../reference/mcp-tools.md) lists every tool.

The server is built to be operated, not just started:

- `ASH_MCP_ALLOWED_ROOTS` limits which directories it will scan and read.
- Config profiles are registered by the operator at startup
  (`ash mcp --profile NAME=path/to/ash.yaml`), so a client picks a policy by
  name instead of shipping its own
  ([Config profiles](../how-to/mcp-server.md#config-profiles)).
- A config file a client delivers cannot loosen the server's gate: the server
  refuses a delivered file that sets `fail_on_findings`,
  `fail_on_incomplete_scanners`, or the staleness policy to anything but its
  own values ([What a delivered config cannot set](../how-to/mcp-server.md#what-a-delivered-config-cannot-set)).

[Run the MCP server](../how-to/mcp-server.md) covers transports, limits on
concurrent scans, and running it as a shared HTTP service, including the AWS
deployment targets in [Deploy on AWS](../how-to/deploy-on-aws.md).
