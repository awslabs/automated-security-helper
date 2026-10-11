# Configuration Guide

ASH v3 uses a YAML configuration file to control its behavior. This guide explains how to configure ASH for your project.

## Configuration File Location

ASH reads its configuration from one source. When `--config` (or the
`ASH_CONFIG` environment variable) names a file, that file is used. Otherwise
ASH looks in the source directory in this order and uses the first source it
finds:

1. `.ash.yml`
2. `.ash/.ash.yml`
3. `.ash.yaml`
4. `.ash/.ash.yaml`
5. `.ash.json`
6. `.ash/.ash.json`
7. `ash.yml`
8. `.ash/ash.yml`
9. `ash.yaml`
10. `.ash/ash.yaml`
11. `ash.json`
12. `.ash/ash.json`
13. `.ashrc.toml`
14. `.ashrc.yaml`
15. `.ashrc.yml`
16. `.ashrc.json`
17. `ashrc.toml`
18. `ashrc.yaml`
19. `ashrc.yml`
20. `ashrc.json`
21. `pyproject.toml`

Items 1-12 are checked per filename, not per directory: for each name ASH checks
the source directory and then its `.ash/` subdirectory, so `.ash.yml` in the
source directory beats `.ash/.ash.yaml`. Items 13-21 are checked in the source
directory only. A `pyproject.toml` counts only when it has a `[tool.ash]` table;
one without that table is not a config source. The lists come from
`ASH_CONFIG_FILE_NAMES`, `ASH_RC_FILE_NAMES` and `ASH_PYPROJECT_FILE_NAME` in
`automated_security_helper/core/constants.py`.

Sources are never merged. If more than one exists, ASH logs which one it used
and logs a warning naming each one it ignored. The names in items 1-12 are
deprecated in favor of an `ashrc` file or `[tool.ash]`, and the warning says so
when one of them shadows a newer source. They still take precedence, so adding a
`[tool.ash]` table to a repository that already has `.ash/.ash.yaml` does not
change which settings a scan uses until the older file is removed.

Scan results are written to `.ash/ash_output` whichever source is used.

You can also specify a custom configuration file path using the `--config` option:

```bash
ash --config /path/to/my-config.yaml
```

### Configuring ASH in pyproject.toml

`[tool.ash]` holds the same settings as `.ash.yaml`, written as TOML, and is
validated by the same schema:

```toml
[tool.ash]
project_name = "my-service"
fail_on_findings = true

[tool.ash.global_settings]
severity_threshold = "MEDIUM"
ignore_paths = [{ path = "tests/fixtures/**", reason = "Test fixtures" }]

[[tool.ash.global_settings.suppressions]]
rule_id = "B101"
path = "tests/**"
reason = "assert is expected in tests"

[tool.ash.scanners.bandit]
enabled = true
```

A validation error names the table and its line, for example
`pyproject.toml [tool.ash] (line 12)`. String values beginning with `${` are
resolved from the environment by the same rule as in YAML, including the limit
on which variable names may be read; see the `!ENV` notes in
[Configuration Overrides](config-overrides.md).
`ash config update`, `ash config wizard`, `ash config lint --fix` and the
suppression dialog in `ash inspect` edit YAML, so they refuse a TOML file rather
than rewrite it; edit `[tool.ash]` by hand.

A `pyproject.toml` that is not valid TOML is skipped, unless its text declares a
`[tool.ash]` table, in which case the scan fails instead of running with the
default configuration.

## Creating a Configuration File

The easiest way to create a configuration file is to use the `config init` command:

```bash
ash config init
```

This creates a default configuration file at `.ash/.ash.yaml` with recommended settings.

## Configuration Structure

The ASH configuration file has the following main sections:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: my-project
global_settings:
  severity_threshold: MEDIUM
  ignore_paths: []
fail_on_incomplete_scanners: true
converters:
  # Converter plugins configuration
scanners:
  # Scanner plugins configuration
reporters:
  # Reporter plugins configuration
ash_plugin_modules: []
```

### Failing on an incomplete scan

`fail_on_incomplete_scanners` is a top-level key, and it is on by default. ASH exits
1 when a scanner you selected did not complete — status `ERROR` (it ran and failed)
or `MISSING` (its dependencies were unavailable, so it never ran) — and prints which
ones.

It is on rather than off because a scanner recorded `ERROR` or `MISSING` produces no
findings, so with the gate off that scan reports the exit code of a clean one. That is
the one failure a reader cannot see: the crash is visible in the log, the false
all-clear is not. A host that genuinely cannot provide a scanner's tool says so once,
with the key below or `--no-fail-on-incomplete-scanners`, and keeps its old exit codes.

It selects on status, so it covers a failure only once that failure has reached the
status. A tool that exits non-zero but writes an empty report is graded `PASSED` from
its zero findings, and this key does not change that in any position.

`SKIPPED` scanners are ones you did not select and never trip it, which is what
keeps a sharded scan working: each shard excludes the scanners its siblings own,
and those are recorded as `SKIPPED`. Narrowing a run with `--scanners` or
`--exclude-scanners` also records the scanners you left out as `SKIPPED`, so
selecting a subset does not fail the gate.

To accept a partial scan's exit code, set it to `false`:

```yaml
fail_on_incomplete_scanners: false
```

Prefer excluding the scanner whose tool you do not have. `false` makes ASH exit 0
for a scan where nothing ran, which is the same code as a scan where everything
ran and found nothing; excluding the scanner records it as `SKIPPED` and says so
in the report, so the next reader can see what was and was not measured.

It is independent of `fail_on_findings` in both directions. `fail_on_findings:
false` still reports an incomplete scan, and when both would fail the exit code is
1 rather than 2, because clearing the findings that were reported would not make
the scan complete. See
[An incomplete scan is not a clean scan](cli-reference.md#an-incomplete-scan-is-not-a-clean-scan).

### Failing on a stale content database

`content_db_staleness` is a top-level key, and it defaults to `fail`. After each
scanner that matches against a content database, ASH reads that database's own
build time and compares it to the bound declared for it in
`automated_security_helper/utils/content_databases.py`. Past the bound, the scan
exits 1 and names the database, when it was built, how old it is, the bound, and
how to refresh it. This happens in online and offline mode alike.

| Database | Scanner | Bound | Where the bound comes from | Age read from |
| --- | --- | --- | --- | --- |
| `grype-db` | grype | 120h (5 days) | grype's own default, `db.max-allowed-built-age` | `built` in `grype db status -o json` |
| `trivy-db` | trivy-repo | 24h | trivy's own rule: a database is current until its `NextUpdate`, which the published database sets 24h after `UpdatedAt` | `VulnerabilityDB.UpdatedAt` in `trivy version --format json` |
| `semgrep-offline-rules` | semgrep (offline only) | 720h (30 days) | ASH's own choice; semgrep has no staleness notion for local rules | `.ash-rules-fetched-at` in `$SEMGREP_RULES_CACHE_DIR`, else the oldest rules file's mtime |
| `opengrep-offline-rules` | opengrep (offline only) | 720h (30 days) | ASH's own choice; opengrep has no staleness notion for local rules | `.ash-rules-fetched-at` in `$OPENGREP_RULES_CACHE_DIR`, else the oldest rules file's mtime |

A database whose build time cannot be read is treated as stale, because an
unmeasurable database is not evidence of a fresh one.

To let one scan run against a stale database, pass `--allow-stale-content-db`, or
set:

```yaml
content_db_staleness: warn
```

Under `warn` the scan proceeds, and the warning is written to the log and into the
reports: a `### Stale content databases` section in `ash.summary.md`, a `STALE
CONTENT DATABASES` section in `ash.summary.txt`, a `toolConfigurationNotifications`
entry with descriptor id `ASH-CONTENT-DB-STALE` on the scanner's invocation in
`ash.sarif`, and a `content_databases` list in `ash.flat.json` with `stale: true`
and `enforced: false`. A reader of any of those can see the scan ran against an
out-of-date database.

To relax one database without relaxing the others, for example while an upstream
publisher is not publishing, name it in `content_db_staleness_overrides`:

```yaml
content_db_staleness: fail
content_db_staleness_overrides:
  - database: trivy-db        # a name from the table above
    policy: warn
    expiration: "2026-10-11"  # YYYY-MM-DD; required
    reason: "Upstream trivy-db publishing is failing"  # required
```

The entry applies only to the database it names, so every other database is
still held to `content_db_staleness`. It stops applying at 00:00 UTC on its
expiration date: from then on it is ignored, with a warning in the log, and the
database is held to `content_db_staleness` again. A stale database relaxed this
way is reported the same as under `warn`, and the message names the entry and its
expiry. Each database can appear in at most one entry, and an unknown database
name is a config error. The list is empty by default.

The CLI flag takes precedence over the config value in both directions:
`--no-allow-stale-content-db` restores `fail` for one scan even when the config
says `warn`, and either form of the flag also clears
`content_db_staleness_overrides` for that scan. Like `fail_on_incomplete_scanners`,
neither key can be changed by an MCP runtime patch.

This gate is independent of `fail_on_incomplete_scanners` and does not need it
turned on. When the scan also has actionable findings, the exit code is 1 rather
than 2: clearing the reported findings would not make a scan against a stale
database trustworthy.

### Global Settings

The `global_settings` section controls general behavior:

```yaml
global_settings:
  # Minimum severity level to consider findings actionable
  # Options: CRITICAL, HIGH, MEDIUM, LOW, INFO
  severity_threshold: MEDIUM

  # Paths to ignore during scanning
  ignore_paths:
    - path: 'tests/test_data'
      reason: 'Test data only'
    - path: 'node_modules/'
      reason: 'Third-party dependencies'

  # Findings to suppress based on rule ID, file path, and line numbers
  suppressions:
    - rule_id: 'RULE-123'  # Scanner-specific rule ID
      path: 'src/example.py'  # File path (supports glob patterns)
      line_start: 10  # Optional starting line number
      line_end: 15  # Optional ending line number
      reason: 'False positive due to test mock'  # Reason for suppression
      expiration: '2025-12-31'  # Optional expiration date (YYYY-MM-DD)
```

Omitting `line_end` does **not** suppress only `line_start`. A suppression with
`line_start` and no `line_end` matches every finding from that line to the end of
the file, including findings introduced later. To suppress a single line, set
`line_end` to the same value as `line_start`. To follow a function or class
when lines move, use `symbol` instead; see
[Suppressing by symbol](suppressions.md#suppressing-by-symbol).

```yaml
    - rule_id: 'RULE-123'
      path: 'src/example.py'
      line_start: 10
      line_end: 10  # Without this, lines 10 onwards are all suppressed
      reason: 'False positive due to test mock'
    - rule_id: 'RULE-456'
      path: 'src/*.js'  # Glob pattern matching all JS files in src/
      reason: 'Known issue, planned for fix in v2.0'
    - rule_id: 'B602'
      path: 'src/deploy.py'
      symbol: 'Deployer.run_hook'  # Only findings inside this method; needs the [symbols] extra
      reason: 'Hook command comes from the signed manifest'

  # Whether to fail with non-zero exit code if actionable findings are found
  fail_on_findings: true
```

### Converters Configuration

The `converters` section configures file converters that transform files before scanning:

```yaml
converters:
  jupyter:
    enabled: true
    options:
      tool_version: null      # Version constraint for the conversion tool
      install_timeout: 300    # Seconds allowed for tool installation
  archive:
    enabled: true             # The archive converter exposes no options
```

### Scanners Configuration

The `scanners` section configures security scanners:

```yaml
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high     # all | low | medium | high (lowercase)
      severity_threshold: MEDIUM # ALL | LOW | MEDIUM | HIGH | CRITICAL (uppercase)

  semgrep:
    enabled: true
    options:
      config: 'p/ci'        # Ruleset, directory, or URL passed to --config
      exclude_rule: []      # Rule IDs to skip
      tool_version: null    # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation

  detect-secrets:
    enabled: true
    options:
      baseline_file: null   # Path to a detect-secrets baseline, relative to the source directory

  checkov:
    enabled: true
    options:
      frameworks: ['all']   # Note the plural; 'framework' is not a field
      skip_path: []         # Paths to skip, matched as regular expressions
      tool_version: null    # Version constraint (e.g., '>=3.2.0,<4.0.0')
      install_timeout: 300  # Timeout in seconds for tool installation

  cfn-nag:
    enabled: true
    options:
      severity_threshold: MEDIUM

  cdk-nag:
    enabled: true
    options:
      nag_packs:            # An object of per-pack booleans, not a list
        AwsSolutionsChecks: true
        HIPAASecurityChecks: false

  npm-audit:
    enabled: true
    options:
      severity_threshold: MEDIUM

  grype:
    enabled: true
    options:
      severity_threshold: MEDIUM

  syft:
    enabled: true
    options:
      exclude: []           # Paths to skip, matched as regular expressions
```

Two conventions differ between fields, and both are enforced: `severity_threshold`
accepts only uppercase (`ALL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), while bandit's
`confidence_level` accepts only lowercase (`all`, `low`, `medium`, `high`). The wrong
case is rejected with a validation error rather than coerced.

#### An unrecognized option is accepted and ignored

Scanner option models allow extra keys, so a misspelled or invented option does not
raise an error -- it is stored and never read. `severity_level: medium` on bandit
validates cleanly and changes nothing, because bandit reads `severity_threshold`.
When a setting appears to have no effect, check the option name against
[the built-in scanner reference](plugins/builtin/scanners.md) before assuming the
scanner ignored the value.

#### Bounding how long a scanner may run

Every scanner accepts `scan_timeout`, the number of seconds its tool invocation may
run before it is killed. The default is `1800` (30 minutes). Set it to `null` to leave
a scanner unbounded:

```yaml
scanners:
  semgrep:
    options:
      scan_timeout: 3600  # An hour for a large repository
  syft:
    options:
      scan_timeout: null  # No limit
```

A scanner killed by its timeout produces no results file, so the scan fails with an
error naming the scanner and the limit (`<scanner> timed out after 1800.0s`) rather
than silently reporting zero findings for it. Whatever the tool wrote before it was
killed is kept in `scanners/<name>/<target>/<Scanner>.stderr.log` under the output
directory. While a scanner runs, ASH logs `<scanner> still running on <target>
(<N>s elapsed)` at INFO once a minute, so a hung scanner is named in a CI log without
any extra flag. `scan_timeout` bounds the scan itself; `install_timeout` separately
bounds tool installation and defaults to `300`.

### Reporters Configuration

The `reporters` section configures output report formats:

```yaml
reporters:
  markdown:
    enabled: true
    options:
      include_detailed_findings: true

  html:
    enabled: true             # The HTML reporter exposes no options

  flat-json:                  # Note the hyphen; there is no 'json' reporter
    enabled: true
    options:
      include_metadata: true
      include_scanner_metrics: true

  csv:
    enabled: true             # The CSV reporter exposes no options

  sarif:
    enabled: true             # The SARIF reporter exposes no options

  github-ghas:
    enabled: true
    options:
      exclude_suppressed: true  # Exclude ASH-suppressed findings (default)
```

### Custom Plugin Modules

The `ash_plugin_modules` section allows you to specify custom Python modules containing ASH plugins:

```yaml
ash_plugin_modules:
  - my_custom_ash_plugins
  - another_ash_plugins
```

The top-level package must be inside ASH's plugin namespace: either under
`automated_security_helper.`, or a top-level package whose name ends in `ash_plugins`.
A module outside that namespace is skipped with a warning rather than imported, so a
name like `another_plugin_module` silently registers nothing. When the list comes from
a config file inside the scanned tree, only installed modules are imported; see
[Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose).

## Settings a repository's config cannot choose

ASH reads its configuration from the repository it scans unless `--config` names a
file elsewhere. When any file the configuration was built from is inside the scanned
tree (a discovered `.ash/.ash.yaml`, a `--config` path inside the tree, an `extends`
base, or the file `ASH_CONFIG` names), a few settings are limited, because they decide
what ASH installs, imports or hands a scanner as its own configuration. The scanned
tree is the outermost git checkout around the source directory, or the source
directory itself outside a checkout.

Under the MCP server, a config file a client delivered (an upload or a file in a
delivered tree, named as `config_path`) is limited the same way, wherever it is. A
file any MCP client delivered also counts as inside the scanned tree for the path
and module checks below: everything under the MCP workspace root
(`$ASH_MCP_WORKSPACE_ROOT`, by default `~/.cache/ash-mcp/`) except each session's
`config/` directory, which only the server writes. A profile a client patched with
`select_profile` is written to the session's `client-config/` directory instead, so
it counts as the client's.

| Setting | From a config file inside the scanned tree |
|---|---|
| `scanners.<name>.options.tool_version`, `converters.jupyter.options.tool_version` | Must be a PEP 440 version specifier set such as `>=1.2,<2` or `==1.4.1`. This applies from every source, including `--config-overrides`. Any other value is replaced by the scanner's default constraint. |
| `scanners.opengrep.options.version` | Must be a release tag such as `v1.15.1`, from every source. Any other value is replaced by the pinned version. |
| `ash_plugin_modules` | An entry is imported only if it names an installed module that Python finds outside the scanned tree. An entry that is not importable, or that would be imported from a file in the tree, is skipped. So are `automated_security_helper.plugin_modules.ash_aws_plugins` and `automated_security_helper.plugin_modules.ash_snyk_plugins`, and any module inside either: the AWS reporters send findings to AWS with the operator's credentials, and the Snyk Code scanner sends the scanned source to Snyk with the operator's Snyk token, so only `--ash-plugin-modules` (or `ASH_PLUGIN_MODULES`), `--config-overrides` or a config file outside the tree can add them. |
| `scanners.checkov.options.config_file`, `scanners.ferret-scan.options.config_file` | Taken from the defaults, `--config-overrides` or a config file outside the tree, and passed to the tool only when the file is outside the scanned tree. The same applies to the `.checkov.yaml` and `ferret.yaml` files these scanners look for by name. ferret-scan then uses its bundled config. checkov and ferret-scan also read such a file from their working directory on their own, so ASH runs both from the filesystem root and always passes ferret-scan a `--config`; finding paths are unchanged. |
| `scanners.detect-secrets.options.scan_settings` plugins and filters, `scanners.detect-secrets.options.baseline_file` | An entry that names a file (`file://...`) is kept only when the operator's config or `--config-overrides` has it and the file is outside the scanned tree; `baseline_file` likewise comes from the defaults, `--config-overrides` or a config file outside the tree. This includes entries read from a baseline file. detect-secrets' built-in plugins and filters are unaffected. |
| trivy-repo's ignore file and secret config | trivy-repo always gets `--ignorefile` and `--secret-config`, so trivy does not read a `.trivyignore` or `trivy-secret.yaml` from the scanned repository. `scanners.trivy-repo.options.ignore_file` and `secret_config_file` (from the defaults, `--config-overrides` or a config file outside the tree), or `TRIVY_IGNOREFILE` and `TRIVY_SECRET_CONFIG`, name the files to use; each is passed only when it is outside the scanned tree, and a file that sets nothing is passed otherwise. |
| `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.mode` | See [Scanner sandbox](scanner-sandbox.md). |
| `scanners.bandit.options.config_file`, `scanners.grype.options.config_file`, `scanners.syft.options.config_file` | Taken from the defaults, `--config-overrides` or a config file outside the tree; a file named that way is used even inside the tree. ASH does not look for `.bandit`, `bandit.yaml`, `bandit.toml`, `.grype.yaml`, `.grype/config.yaml`, `.syft.yaml` or their `.ash/` copies by name, and otherwise passes each tool an empty config (`--ini` for bandit, `--config` for grype and syft), so the tool does not read one from the tree on its own. |
| `scanners.opengrep.options.config`, `scanners.semgrep.options.config`, `scanners.opengrep.options.patterns`, `scanners.opengrep.options.metrics`, `scanners.semgrep.options.metrics` | Taken from the defaults (`p/ci`, no patterns and `auto`), `--config-overrides` or a config file outside the tree. `config` chooses the rules, from the registry, a URL the tool fetches or a path it reads; opengrep's `patterns` runs the patterns in place of every rule config; and `metrics` chooses whether the tool sends usage data. `metrics: off`, which only stops it sending any, applies from every config. To run a repository's own rules, name them with `--config-overrides`. |
| A `.semgrepignore` in the scanned tree | Not honored by semgrep or opengrep: ASH passes `--x-ignore-semgrepignore-files` with the tools' default exclusions, so the same paths are scanned as with no `.semgrepignore`, and the file is named in the results as a `config_warning` validation checkpoint. List the files to leave out in `global_settings.ignore_paths`. |
| `scanners.ferret-scan.options.profile`, `scanners.ferret-scan.options.use_default_config` | Taken from the defaults, `--config-overrides` or a config file outside the tree. A profile chooses which checks ferret-scan runs and the lowest confidence it reports, and the bundled `redaction` and `secure-redaction` profiles also have it write redacted copies of the files it scans. `use_default_config: false` replaces the bundled config with an empty one, which drops the bundled validators' patterns. ferret-scan's other options, `checks` and `confidence_levels` among them, still apply. |
| `scanners.snyk-code.options.honor_tree_exclusions` | Taken from the defaults, `--config-overrides` or a config file outside the tree. `snyk code test` leaves out the files that the `.snyk` and `.dcignore` files in the tree it tests exclude, and has no option to stop it, so while this is `false` (the default) snyk-code does not run on a tree that has one, and its error names the files. See [Exclusion files in the scanned tree](plugins/community/snyk-plugin.md#exclusion-files-in-the-scanned-tree). |
| `reporters.<name>.extension` | Must be a filename suffix such as `json`, from every source, including `--config-overrides`: the report is written to `ash.<extension>` in the reports directory. A value containing `/`, `\`, `..` or NUL is replaced by the reporter's default. ASH also writes a report, and the files some reporters write beside it, only when the resolved file is directly inside the reports directory. When the reports directory, or a file an enabled reporter writes there, is already a symlink or a directory junction, the run exits 1 before any reporter writes, and the error names the link. |
| Reporter destinations and credentials: `aws_region` and `aws_profile` of `aws-security-hub`, `bedrock-summary-reporter` and `s3`; `aws-security-hub`'s `account_id`; `bedrock-summary-reporter`'s `model_id`, `output_file`, `output_executive_file` and `output_technical_file`; `s3`'s `bucket_name` and `key_prefix`; `cloudwatch-logs`' `aws_region`, `log_group_name` and `log_stream_name` (all under `reporters.<name>.options`) | Taken from the defaults, `--config-overrides` or a config file outside the tree, whichever spelling of the reporter's section the file uses (`BedrockSummary` is read as `bedrock-summary-reporter`, for example). These options choose where findings are sent or written and which credentials send them. The reporters' other options, including `enabled`, still apply. The same holds for the options a reporter from a plugin module declares in `destination_options`, once the scan has imported the module; see [Declaring destination options](plugins/reporter-plugins.md#declaring-destination-options). |

Each setting that is not honored is named in a warning when the config is
resolved.

A repository's config may still choose a scanner's `tool_version` and opengrep's
`version`, within the limits above: a version specifier for the tool's own
package, or a tag of opengrep's own releases, whose binary ASH installs only when
it matches its SHA-256 digest. Workspace projects pin scanner versions this way.

To set any of these for a repository you trust, use `--config-overrides`,
`--ash-plugin-modules`, or a config file outside the scanned tree. A file path set
that way still has to point outside the tree, except a bandit, grype or syft config
file. Under `--sandbox`, a file outside the
system paths the sandbox already reads also has to be listed in
`sandbox.extra_read_paths`, or the tool cannot open it and the scanner reports an
error.

### Configs an MCP client delivered

ASH's configuration can come from three places, and how far it is trusted depends
on which:

- **The operator**: ASH's defaults, a config file outside the scanned tree (named
  by `--config` or `ASH_CONFIG`), `--config-overrides`, `--ash-plugin-modules`, and, under the MCP
  server, the profiles the server registers. Everything applies.
- **The repository being scanned**: a config file inside the scanned tree. The
  table above applies.
- **An MCP client**: a file the client delivered, such as an upload named as
  `config_path`, a delivered tree's own `.ash/.ash.yaml`, or a project config in
  a delivered workspace. So is any other config path a client names, unless it
  is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or in the session's own
  `config/` directory: a config in another checkout the server may scan is that
  checkout's, not the operator's. A path is judged where it sits as well as by
  the file it reaches, so a link a client delivered is the client's wherever it
  points. A file under the MCP workspace root is a client's whoever names it: a
  `--config` or `ASH_CONFIG` naming one, on the CLI as well, gets the limits of a
  config inside the scanned tree, and the server's runtime-override policy is
  never read from it (the built-in defaults apply instead). A profile after the
  client's `select_profile` `patch_ops` or `override_yaml` is the client's too,
  held to the registered profile as its trusted base, and so are the MCP
  workspace tools' `config_overrides`, even for keys the runtime-override
  allowlist lets the client change. The table above applies, and so does the
  session's runtime-override policy, `global_settings.mcp.runtime_overrides`:

  - The file may not change a field that `denied_paths` or
    `denied_value_patterns` denies. Entries match either `-` or `_`, every
    spelling of a plugin's section, and globs such as
    `/scanners/trivy-*/options/ignore_file`. A value equal to the server's is
    accepted, so a file `ash config init` wrote scans. A file that changes a
    denied field is refused with `error_type: config_field_denied`, naming each
    field. When the policy cannot be established, a scan that reads such a file is
    refused with `error_type: config_policy_unreadable`.
  - It may restrict the server's `sandbox` and `ash_plugin_modules` settings but
    not ask for more than they give: a `network_scanners` entry for a scanner the
    server's config gives no network, an `extra_read_paths` entry the server's
    config does not grant, a `mode` other than the server's when the server sets
    one, or a module the server's config does not load that is inside the scanned
    tree or sends findings off the host. A file that does is refused the same
    way, naming the setting; an equal or tighter value scans.
  - What chooses a scanner's own config, which version of a tool ASH installs, or
    where findings go is in the default `denied_paths` too, so a file that sets
    one is refused rather than scanned without it: each scanner's own config file
    (`config_file` for bandit, checkov, ferret-scan, grype and syft, and
    trivy-repo's `secret_config_file`), snyk-code's
    `honor_tree_exclusions`, every scanner's and the jupyter converter's
    `tool_version`, opengrep's `version` and `sha256`, opengrep's and semgrep's
    `metrics` (their `config` is in the table below), the AWS reporters'
    destinations and credentials listed in the table above, and the GitLab SAST
    reporter's `exclude_suppressed`, which would leave the findings a client's
    suppressions are marked on out of that report. The options a reporter from a
    plugin module declares in `destination_options` are not default entries,
    because the file is checked before the module is imported: a file that sets
    one is scanned with the server's value, as a config inside the scanned tree
    is.
  - Its own `global_settings.suppressions` and `global_settings.ignore_paths`
    apply. Each entry the operator did not supply is marked `client_supplied: true`,
    the files under a client-supplied ignore path are still scanned, and a finding
    either one hides is reported suppressed and marked rather than dropped. See
    [Suppressions an MCP client's config supplied](suppressions.md#suppressions-an-mcp-clients-config-supplied).
  - An exclusion it adds to one of the scanner options below is not passed to
    the scanner. Each finding of that scanner the entry would have left out is
    reported suppressed and marked in the same way. The operator's own entries
    apply as before.

    | Option | Matched as |
    |---|---|
    | `scanners.bandit.options.excluded_paths` | The `**/<path>/**` glob ASH passes bandit, against the file's absolute path |
    | `scanners.checkov.options.skip_path` | As checkov's own filter reads it: a regular expression found in, or a substring of, the absolute path of the file or of a directory above it |
    | `scanners.opengrep.options.exclude`, `scanners.semgrep.options.exclude`, `scanners.ferret-scan.options.exclude_patterns` | A glob matching the file's path or any directory in it |
    | `scanners.syft.options.exclude` | The same glob; each SBOM component it would have dropped carries an `ash:clientSuppliedExclusion` property |
    | `scanners.trivy-repo.options.ignore_file` | Each unexpired ID in the file, against the trivy finding's rule ID, when the file is a regular file inside the scanned tree (not a link); any other file is not read |

  - The scanner options below drop findings by rule ID, by a baseline, or by a
    whole category (a framework, a severity, a rule set, a detector, a confidence
    level, a cap on how many are reported) rather than by path. They are in the
    default `denied_paths`, so a delivered file that changes one is refused, and
    one that leaves it at its default scans. All are under `scanners.<name>.options`:

    | Scanner | Options |
    |---|---|
    | bandit | `confidence_level` |
    | cdk-nag | `nag_packs.AwsSolutionsChecks` (turning on another pack reports more, and is allowed) |
    | checkov | `frameworks`, `skip_frameworks` |
    | detect-secrets | `baseline_file`, `scan_settings` |
    | ferret-scan | `checks`, `confidence_levels`, `disable_ip_types`, `enable_preprocessors`, `finding_limit`, `max_live_bytes` (which bounds how much extracted content it holds), `profile`, `recursive`, `respect_gitignore`, `use_default_config`, `validator_budget` |
    | opengrep | `config`, `exclude_rule`, `patterns`, `severity` |
    | semgrep | `config`, `exclude_rule`, `severity` |
    | trivy-repo | `license_full`, `scanners` |
    | every scanner | `offline`: a scanner set offline runs on cached data, and npm audit offline reports no advisories at all |

    Options that only tune output or performance, or whose default already
    reports the least they can (trivy-repo's `ignore_unfixed`, bandit's
    `ignore_nosec`, detect-secrets' `skip_generated_lockfiles`), are not listed.
    `scan_timeout` and `install_timeout` are not either: a scanner that runs out
    of time or cannot be installed is reported as not completing.

See [Config files in delivered source](mcp/streamable-http.md#config-files-in-delivered-source)
for the details, including which profile the policy comes from.

## Validating Configuration

To validate your configuration file:

```bash
ash config validate
```

## Viewing Current Configuration

To view the current configuration:

```bash
ash config get
```

## Updating Configuration

To update configuration values:

```bash
ash config update --set 'scanners.bandit.enabled=true'
ash config update --set 'global_settings.severity_threshold=LOW'
```

## Configuration Overrides

You can override configuration values at runtime using the `--config-overrides` option:

```bash
# Enable a specific scanner
ash --config-overrides 'scanners.bandit.enabled=true'

# Change severity threshold
ash --config-overrides 'global_settings.severity_threshold=LOW'

# Append to a list
ash --config-overrides 'ash_plugin_modules+=["my_ash_plugins"]'

# Add a complex value
ash --config-overrides 'global_settings.ignore_paths+=[{"path": "build/", "reason": "Generated files"}]'
```

## Extending another configuration

A config can build on one or more base configs with `extends`, and adjust the
result with RFC 6902 JSON-Patch operations under `patch`:

```yaml
# .ash/.ash.yaml
extends: ../shared/ash-base.yaml     # or a list: [org.yaml, team.yaml]
project_name: my-service
global_settings:
  severity_threshold: HIGH
patch:
  - op: add
    path: /global_settings/suppressions/-
    value:
      rule_id: B101
      path: "tests/**"
      reason: "assert is expected in tests"
```

The same keys work in `[tool.ash]` (`extends = "ash-base.yaml"`,
`patch = [{op = "add", path = "/fail_on_findings", value = false}]`) and in an
`ashrc` file. A base can be YAML, JSON, TOML, or a `pyproject.toml`, whose
`[tool.ash]` table is used.

How a config is resolved:

1. Each base is resolved the same way, so bases can extend other bases.
2. The bases are merged in the order listed, a later base winning over an
   earlier one.
3. The file's own settings are merged over the bases. The file always wins.
4. The file's `patch` operations run, in order, on the result.
5. `--config-overrides` apply last, on top of everything above.

Merge rules:

- Mappings merge key by key, at every level. A base's `scanners.bandit.options`
  and a child's `scanners.bandit.enabled` both survive.
- Lists, scalars and `null` replace. A child that sets
  `global_settings.suppressions` replaces the base's list. To keep the base's
  entries and add more, use `patch` with `op: add` and a path ending in `/-`.
- To delete something a base set, use `patch` with `op: remove`.
- A key spelled with `-` and the same key spelled with `_` (`cdk-nag` and
  `cdk_nag`) are one key, in merges and in `patch` paths.
- `patch` accepts `add`, `remove`, `replace` and `test`. `move` and `copy` are
  refused. A failing operation, including a failing `test`, fails the load.

Where a base may live:

- A relative path is relative to the file that names it. An absolute path is
  also accepted.
- Every base must be inside the scan's source directory (or, for a `--config`
  file kept outside it, inside that file's own directory, or the parent of
  `.ash/` for a file in `.ash/`). `..` is fine while it stays inside. A path, or
  a symlink, that resolves outside is an error. In workspace mode each project
  is scanned with its own directory as the source directory, so a project's
  bases must be inside that project.
- URLs are refused. ASH never downloads a base config; copy the file into the
  repository instead.

Errors stop the scan rather than falling back to the default configuration: a
missing or unreadable base, a cycle (the error prints the chain, for example
`.ash.yaml -> b.yaml -> c.yaml -> b.yaml`), a chain more than 10 levels deep,
or more than 50 files read in total. `${VAR}` references in every file of the
chain are resolved under the same allowlist as a single file.

`ash config validate` and `ash config lint` follow the chain, report extends
errors, and print the files the config was built from, lowest precedence first.
`ash config update`, `ash config wizard` and the `ash inspect` suppression dialog
refuse to rewrite a file in a way that would copy its bases into it or drop their
suppressions.

## Scanner-Specific Configuration

Each scanner has its own configuration options. Here are some examples:

### Bandit

```yaml
scanners:
  bandit:
    enabled: true
    options:
      confidence_level: high      # all | low | medium | high -- lowercase only
      severity_threshold: MEDIUM  # ALL | LOW | MEDIUM | HIGH | CRITICAL -- uppercase only
      ignore_nosec: false         # true scans lines carrying a '# nosec' comment anyway
      excluded_paths: []          # Paths to exclude, each with a reason
      config_file: null           # The operator's bandit config file; see below
      scan_timeout: 1800          # Seconds before the bandit invocation is killed
      # Bandit is installed via UV tool management with the constraint
      # '>=1.7.0,<2.0.0' for SARIF support.
```

Selecting individual bandit tests is done in a bandit configuration file rather than
through ASH options. ASH does not look for one by name in the scanned tree. Name it
with `config_file`, set with `--config-overrides` or in a config file outside the
tree; a config file inside the tree does not set it (see
[Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)). Without one, bandit gets an empty config, so it
does not read a `.bandit` file from the tree either. For the file's format, refer to
the Bandit [documentation](https://bandit.readthedocs.io/en/latest/config.html).

### Semgrep

```yaml
scanners:
  semgrep:
    enabled: true
    options:
      config: 'p/ci'        # Ruleset, directory of YAML rules, or URL, passed to --config (operator only)
      exclude: ['*-converted.py', '*_report_result.txt']  # Paths to skip
      exclude_rule: []      # Rule IDs to skip (singular; 'exclude_rules' is not a field)
      severity: []          # Report only findings from rules of these severities
      metrics: 'auto'       # How usage metrics are sent to the Semgrep server ('off' from any config)
      offline: false        # Use locally cached rules only
      scan_timeout: 1800    # Seconds before the semgrep invocation is killed
      tool_version: null    # Version constraint (e.g., '>=1.125.0')
      install_timeout: 300  # Timeout in seconds for tool installation
```

### Detect-Secrets

```yaml
scanners:
  detect-secrets:
    enabled: true
    options:
      baseline_file: null   # Explicit .secrets.baseline path, relative to the source directory
      scan_timeout: 1800    # Seconds before the detect-secrets invocation is killed
```

Which plugins and filters run, and which findings are already accepted, live in the
detect-secrets baseline rather than in ASH options. Point `baseline_file` at one, or
rely on the discovery described below. The `scan_settings` option takes the same
structure as a baseline's own settings block if you would rather inline it.

If you have been using detect-secrets separately and have an existing baseline file you would like to use with ASH, ASH can automatically use it. ASH automatically searches your current directory and the ```.ash``` directory for a ```.secrets.baseline``` file. For more details on baseline files, refer to the detect-secrets [documentation](https://github.com/Yelp/detect-secrets/tree/master).

### Checkov

```yaml
scanners:
  checkov:
    enabled: true
    options:
      frameworks: ['all']  # Frameworks to scan (plural; 'framework' is not a field)
      skip_frameworks: []  # Frameworks to exclude
      skip_path: []  # Paths to skip, matched as regular expressions
      skip_ash_output_dir: true  # Skip ASH's output directory when it is inside the source (not on Windows)
      offline: false  # Run in offline mode
      additional_formats: ['cyclonedx_json']  # Additional output formats
      tool_version: null  # Version constraint (e.g., '>=3.2.0,<4.0.0')
      install_timeout: 300  # Timeout in seconds for tool installation
      # Note: Checkov is automatically downloaded and run via UV tool management
      # with version constraint >=3.2.0,<4.0.0 for enhanced stability
```

A Checkov configuration file is passed to checkov only when it is outside the
scanned tree: name it with `config_file`, set with `--config-overrides` or in a
config file outside the tree (see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)).
A `.checkov.yaml` or `.checkov.yml` in the scanned tree, or in its `.ash`
directory, is not used, and checkov runs from outside the tree so it does not
read one on its own. For the file's format, refer to the Checkov
[documentation](https://github.com/bridgecrewio/checkov?tab=readme-ov-file#configuration-using-a-config-file).

### Grype

```yaml
scanners:
  grype:
    enabled: true
    options:
      config_file: null # The operator's grype config file; see below
      severity_threshold: MEDIUM # Options: ALL, LOW, MEDIUM, HIGH, CRITICAL
      offline: false # Run in offline mode
```

ASH does not look for a Grype configuration file by name in the scanned tree. Name
one with `config_file`, set with `--config-overrides` or in a config file outside
the tree (see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)). Without
one, grype gets an empty config, so it does not read a `.grype.yaml` from the tree
either. For the file's format, refer to the Grype
[documentation](https://github.com/anchore/grype?tab=readme-ov-file#configuration).

### Syft

```yaml
scanners:
  syft:
    enabled: true
    options:
      config_file: null # The operator's syft config file; see below
      exclude:                # Each entry needs a path and a reason
        - path: 'tests'
          reason: 'Test fixtures are not shipped'
      additional_outputs: ["syft-json"] # List of additional output formats for Syft. Options:
      # "cyclonedx-json", "cyclonedx-xml","github-json", "spdx-json",
      # "spdx-tag-value", "syft-json", "syft-table", "syft-text"
```

ASH does not look for a Syft configuration file by name in the scanned tree. Name
one with `config_file`, set with `--config-overrides` or in a config file outside
the tree (see [Settings a repository's config cannot choose](#settings-a-repositorys-config-cannot-choose)). Without
one, syft gets an empty config, so it does not read a `.syft.yaml` from the tree
either. For the file's format, refer to the Syft
[documentation](https://github.com/anchore/syft/wiki/Configuration).

## UV Tool Management

ASH v3 uses UV's tool isolation system to automatically manage scanner dependencies. This provides several benefits:

- **Automatic Installation**: Tools like Bandit, Checkov, and Semgrep are automatically installed when needed
- **Version Constraints**: ASH ensures compatible tool versions with sensible defaults:
  - **Bandit**: `>=1.7.0` (enhanced SARIF support and security fixes)
  - **Checkov**: `>=3.2.0,<4.0.0` (improved stability, avoiding potential breaking changes)
  - **Semgrep**: `>=1.125.0` (comprehensive rule support and performance improvements)
- **Isolation**: Tools run in isolated environments without affecting your project dependencies
- **Retry Logic**: Automatic retry with exponential backoff for network issues
- **Comprehensive Logging**: Detailed installation and execution logging for troubleshooting
- **Fallback Support**: If UV tool installation fails, ASH falls back to system-installed tools when available

### UV Tool Configuration Options

Each UV-managed scanner supports these configuration options:

```yaml
scanners:
  checkov:  # or bandit, semgrep
    enabled: true
    options:
      tool_version: ">=3.2.0,<4.0.0"  # Override default version constraint
      install_timeout: 300             # Installation timeout in seconds (default: 300)
```

### Environment Variables

Control UV tool behavior globally:

```bash
# Disable automatic tool installation (use pre-installed tools)
export ASH_OFFLINE=true

# Custom UV executable path (if needed)
export UV_EXECUTABLE=/custom/path/to/uv
```

### Troubleshooting UV Tool Issues

If you encounter UV tool installation issues:

1. **Check UV availability**: `uv --version`
2. **Enable verbose logging**: `ash --verbose` for detailed installation logs
3. **Use offline mode**: `ASH_OFFLINE=true` to skip installations
4. **Pre-install tools manually**:
   ```bash
   uv tool install bandit>=1.7.0,<2.0.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0,<2.0.0
   ```
5. **Increase timeout** for slow networks:
   ```yaml
   scanners:
     checkov:
       options:
         install_timeout: 600  # 10 minutes
   ```

For more detailed information about UV tool management, see the [UV Tool Management Developer Guide](../developer-guide/uv-tool-management.md).
- **Flexible Version Management**: Scanners can optionally specify version constraints, with sensible defaults provided

### UV Tool Behavior

- **Bandit**: Automatically installed via `uv tool install bandit>=1.7.0,<2.0.0` (default version constraint)
- **Checkov**: Automatically installed via `uv tool install checkov>=3.2.0,<4.0.0` (default version constraint) with fallback to `uv tool run`
- **Semgrep**: Automatically installed via `uv tool install semgrep>=1.125.0,<2.0.0` (default version constraint) with fallback to `uv tool run`

### Version Constraint Configuration

Each UV-managed scanner can specify version constraints in two ways:

1. **Default Constraints**: Built-in version constraints ensure compatibility and stability
2. **Custom Constraints**: Override defaults via configuration options (where supported)

For scanners that support custom version constraints (like Semgrep and Checkov), you can specify them in your configuration:

```yaml
scanners:
  semgrep:
    options:
      tool_version: ">=1.130.0,<2.0.0"  # Custom version constraint
  checkov:
    options:
      tool_version: ">=3.3.0"  # Custom version constraint
```

### Troubleshooting UV Tool Issues

If you encounter issues with UV tool management:

1. **Check UV Installation**: Ensure UV is installed and available in your PATH
2. **Network Connectivity**: UV tool installation requires internet access
3. **Offline Mode**: Use `ASH_OFFLINE=true` to skip tool downloads and rely on pre-installed tools
4. **Manual Installation**: You can pre-install tools manually if needed:
   ```bash
   uv tool install bandit>=1.7.0,<2.0.0
   uv tool install checkov>=3.2.0,<4.0.0
   uv tool install semgrep>=1.125.0,<2.0.0
   ```

## Advanced Configuration

For advanced configuration options, refer to the [JSON Schema](https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json) that defines all available configuration options.

You can add this schema reference to your configuration file for editor autocompletion:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
```
