# Configuration trust model

ASH reads its configuration from places with different owners. You, the person or pipeline running ASH, control the command line, the environment, and the files outside the repository. The repository being scanned controls every file inside it, including the `.ash/.ash.yaml` that ASH discovers without being asked. A client of the ASH MCP server controls the files it delivers to the server. ASH sorts configuration into three tiers by owner, and limits what the repository and MCP clients can set for a short list of settings: the ones that grant access, send data off the host, or choose code for a tool to run.

## The three tiers {#tiers}

| Tier | Where the configuration comes from |
|---|---|
| Operator | Command-line flags, including `--config-overrides`, `--ash-plugin-modules`, and `--sandbox`; the environment, including `ASH_PLUGIN_MODULES`; a config file outside every git checkout and outside the scanned directory, named with `--config` or `ASH_CONFIG`. |
| Repository | Any config file inside a git checkout or inside the scanned directory: the discovered `.ash/.ash.yaml` and its siblings, a `--config` or `ASH_CONFIG` that points into the repository being scanned, and a config file kept in a checkout of its own, such as an ops or dotfiles repository. |
| MCP client | Any file under the MCP server's workspace root, where delivered source trees and uploads are stored, except each session's `config/` directory, which only the server writes. Also any other config file a client names as a tool's `config_path`, wherever it is, unless it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or in its session's `config/` directory, which only the server writes. |

The MCP workspace root is `ASH_MCP_WORKSPACE_ROOT` when set, read against the current directory when it is relative; else `$XDG_CACHE_HOME/ash-mcp` when `XDG_CACHE_HOME` is an absolute path, since a relative one is ignored; else `~/.cache/ash-mcp` when `HOME` is an absolute path. A file there is an MCP-client file whether or not a server is running, so a CLI scan of a delivered tree, with that tree as `--source-dir`, gets the same treatment. With an empty or relative `HOME` and neither variable, or with an `ASH_MCP_WORKSPACE_ROOT` under `~`, there is no workspace root, and no file is an MCP-client file because of where it is. `ash mcp` still starts, with a warning that ASH uses nothing under `~`.

## How a file's tier is decided {#how-the-tier-is-decided}

The tier depends on where a file is, not on who names it. Passing a repository's file with `--config` does not make it an operator file.

The repository tier exists because the scanned target is untrusted relative to the operator. Nothing the target ships, whether committed or only present in its checkout, may grant itself reads, tool options, or sandbox exceptions. A config file inside any git checkout, the scanned one or a separate one such as an ops or dotfiles repository, may have been written by someone other than the operator, so it is repository-tier, and so is a config file inside the scanned directory when that directory is in no checkout. When ASH ignores a setting from such a file, it names the file in a warning that says how to keep the setting: pass it with `--config-overrides`, or move it to a config file outside every git checkout and outside the scanned directory.

A file is inside a git checkout when it, or any directory above it, holds a `.git` entry: a directory, or the `.git` file of a submodule or linked worktree. ASH checks the path as you named it, its resolved path, and every symbolic link it passes through on the way, so a symbolic link into or out of a checkout counts either way. For a scanned directory that is not in a checkout, a file inside it counts under any of the directory's names: as given, resolved, or as the shell's `$PWD` names it.

In this example the scanned directory, `../app`, is a checkout of its own, and your config is in `../ops`, a separate checkout. ASH ignores its sandbox grant, names the setting in a warning, and leaves the grant out of the configuration it uses:

```bash
git init --quiet ../app
git init --quiet ../ops
printf 'project_name: app\nsandbox:\n  extra_read_paths:\n    - /opt/shared-rules\n' > ../ops/ash.yaml
ash config get --source-dir ../app --config ../ops/ash.yaml > ../ops-config.txt 2>&1
grep -F 'sandbox.extra_read_paths' ../ops-config.txt
! grep -F -- '- /opt/shared-rules' ../ops-config.txt
```

The same file outside every git checkout is the operator's, and the grant is kept:

```bash
mkdir -p ../plain
cp ../ops/ash.yaml ../plain/ash.yaml
ash config get --source-dir ../app --config ../plain/ash.yaml | grep -F -- '- /opt/shared-rules'
```

The rule applies to every file a config is built from, which means the root file and every base it `extends`, each judged by the path its `extends` entry names as well as by the file it resolves to. If any of them is inside a git checkout or the scanned directory, the whole config is treated as repository-tier for the restricted settings, and ASH names those files in the warning. An operator file outside every checkout that extends a base inside one keeps the sandbox settings it writes in its own `sandbox` section, and for some scanners the tool file paths it writes itself, but nothing it inherits from a base. Its other restricted settings come from the trusted base described below, so set them with `--config-overrides`. A base reached through a symbolic link that leaves the config file's own directory is refused before anything is granted.

ASH reads one config file per scan, plus the files it `extends`. When you pass `--config` to a scan of one directory, ASH does not read the repository's own config file. In workspace mode, the file `--config` (or `ASH_CONFIG`) names is layered over each project's own config: every setting your file makes is final for every project, and a project's own config fills only the settings yours leaves out ([Scan a multi-project workspace](../how-to/scale-large-repos.md#workspaces)). `--dry-run` shows it in an `operator:` line under each project. Here the project's config sets `LOW` and yours sets `HIGH`, which wins:

```bash
mkdir -p ../ws/api
printf 'global_settings:\n  severity_threshold: LOW\n' > ../ws/api/.ash.yaml
printf '{"folders": [{"path": "api"}]}\n' > ../ws/project.code-workspace
printf 'global_settings:\n  severity_threshold: HIGH\n' > ../operator.yaml
ash scan --workspace ../ws/project.code-workspace --config ../operator.yaml --dry-run > ../plan.txt
grep -F '(the fields it sets are final)' ../plan.txt
grep -E 'threshold: +HIGH' ../plan.txt
```

When a config is repository-tier, ASH takes the restricted settings from a trusted base instead: the file `ASH_CONFIG` names, if it is outside every git checkout and the scanned directory, otherwise the defaults, with your `--config-overrides` applied on top. In workspace mode, the scanned tree is the checkout that holds the workspace root, or the root itself, and the `--config` file given to the workspace scan is the trusted base when it is outside every git checkout. That file, and every base it `extends`, must be outside that tree: one inside it, or under the MCP workspace root, is refused with exit code 3, naming the file, before any project is resolved. Under the MCP server, the trusted base is the server's own configuration, the file `ASH_CONFIG` names, under the same rule: when that file is inside a git checkout or the scanned directory, the restricted settings come from the defaults. An `ASH_CONFIG` that is unset or empty means the defaults. One that names a path that is not a file, a file that cannot be read, or a config that does not load stops a scan with exit code 3, and stops `ash mcp` from starting, with exit code 3.

Two setups surprise people. A config you trust but keep in a git checkout of its own, such as an ops repository, cannot make the restricted settings below, because it is in a checkout. If your home directory is itself a git checkout (a common dotfiles setup), the outermost checkout above a project under it is your home directory, so a scan of that project counts your whole home directory as the scanned tree. Every config file under your home directory, yours included, is then repository-tier for that scan. Keep your operator config outside it, for example under `/etc/ash`.

### The scanned tree {#scanned-tree}

One rule looks only at the scanned tree: where a tool file the operator names may be. The scanned tree is the git checkout that holds the scanned directory: the outermost directory at or above it that holds a `.git` entry. When the scanned directory is not in a checkout, the scanned tree is the scanned directory itself. ASH finds the tree from the scanned directory as you named it, from its resolved path, and, when you scan the working directory or one below it, from the shell's `$PWD`. A file is inside the tree when it or a directory above it is the tree's directory, compared by file identity rather than by name, and a symbolic link inside the tree counts as inside it wherever it points.

A tool file you name as the operator, with `--config-overrides`, in a config file outside every git checkout and the scanned directory, or in an environment variable, is used unless it is inside the scanned tree and the scanner does not allow one there, so it may be in a checkout of your own, such as an ops repository. A tool file that any other config file names, one in an ops checkout included, or that ASH finds by name, is used only from outside every git checkout and the scanned directory. To keep such a path, move the config file outside every git checkout and the scanned directory, or pass the option with `--config-overrides`. [Options only the operator can set](../how-to/choose-scanners.md#operator-only) lists the scanners this covers. ASH names each refused path in a warning of this form, where `<option>` is the option or the file it looked for, and `<reason>` says where the file is, such as `it is inside the git checkout at /home/me/ops`:

```text
Ignoring <option> (<path>): <reason>. A file that a config file inside a git checkout or the scanned directory names, or that ASH finds in the scanned directory, is passed to the tool only from outside every git checkout and the scanned directory. To keep a setting, move the file outside every git checkout, or pass the setting with --config-overrides. A file inside the scanned directory has to move out of it as well.
```

For a path you named, the warning ends instead: "A file inside the scanned tree, or one an MCP client delivered, is not passed to the tool; name one outside it."

## What each tier may set {#what-each-tier-may-set}

Settings not listed here can be set from any tier. The repository tier's limits also apply to MCP-client files, which have further limits of their own (next section).

| Kind of setting | From the operator | From a repository file |
|---|---|---|
| Sandbox grants: `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`, `sandbox.env_scanners`, and `sandbox.environment` | Honored | Ignored. A `network_scanners` list is kept as a limit: scanners it does not name get no network. |
| The sandbox mode, `sandbox.mode` | Honored. A mode in `ASH_CONFIG`'s file, or in the `--config` file of a workspace scan, counts even when that file is inside a git checkout or the scanned directory, because a mode other than `off` grants nothing. | Applies only when no operator source turns the sandbox on. It cannot turn off, or switch away from, a mode the operator chose. In workspace mode this includes a project's own config file. |
| Plugin module lists, `ash_plugin_modules` | Honored | Only ASH's own plugin modules and modules installed outside every git checkout and the scanned directory. A third-party package in a virtual environment inside a checkout counts as inside it. Never `ash_aws_plugins` or `ash_snyk_plugins`, or any module inside either, whose plugins send findings or source off the host. |
| Where the AWS reporters send results, and with which credentials: the region, profile, and account of `aws-security-hub`; the region, profile, model, and output files of `bedrock-summary-reporter`; the region, log group, and stream of `cloudwatch-logs`; the region, profile, bucket, and key prefix of `s3`; and whether each of these reporters runs | Honored | Replaced by the trusted value. |
| Whether the scanned repository's own `.gitignore` and `.ignore` files decide what is scanned, `honor_ignore_files` | Honored | Replaced by the trusted value. |
| Letting trivy send anonymous usage data to its vendor on an online trivy-repo scan, `scanners.trivy-repo.options.disable_telemetry: false` | Honored | Replaced by the trusted value: the default `true`, which passes `trivy repository --disable-telemetry`, unless the operator set `false`. A file may set `true`. |
| The archive extraction limits, `max_members`, `max_member_bytes`, `max_total_bytes`, and `max_compression_ratio` under `converters.archive.options` | Honored | A value at or below the trusted one is kept; a higher one is replaced by the trusted value. |
| detect-secrets' verification filter, which sends each candidate secret to the service that issued it, and plugins or filters it loads from a `file://` path | Honored, except from a baseline inside the scanned tree | Removed, unless the trusted settings name the same filter or file. A baseline's own copies of these count only when the baseline is outside the scanned tree and any checkout that holds it, and an operator source names the same `baseline_file`. |
| Which release of a scanner's or converter's tool runs, `tool_version`, in every scanner and converter section | Honored | Replaced by the trusted value, or by the tool's default constraint where the trusted settings set none. |
| Relaxing the stale content database check: `content_db_staleness: warn`, and `content_db_staleness_overrides` entries with `policy: warn` | Honored, as is `--allow-stale-content-db` | A value equal to the trusted one, or one that makes the check stricter (`fail`), is kept. Any other policy is replaced by the trusted value, and any other entry is dropped. |
| Scanner options that name a tool config file, ignore file, rules or plugin directory, or a program for a tool to run, or that choose which part of a tool's own config applies | Honored. For some scanners the file may not be inside the scanned tree. | Limited for some scanners only: some ignore the repository's value, and the others accept only a path outside every git checkout and the scanned directory. Set these options from an operator source, and pass your config with `--config` so the repository's config is not read. |

[Options only the operator can set](../how-to/choose-scanners.md#operator-only) lists the scanners that limit the options in the last row. The reporter limits apply to a reporter's section under any spelling ASH reads as that reporter, so a repository's reporter section spelled `BedrockSummary` is limited like `bedrock-summary-reporter`. The table is how a scan reads the reporter settings. `ash report` and `ash merge` read stored results, which do not record which tree was scanned, so any config file they read, even one outside every git checkout, is held to the repository column for whether each AWS reporter runs and where it sends: those come only from `--config-overrides` ([Rendering a reporter from saved results](../plugins/aws.md#ash-report)). Two rules apply from every tier: `reporters.<name>.extension` must be a plain filename suffix, and report files are written only inside the reports directory.

## When a lower tier sets something it may not {#denied-settings}

From a repository file, ASH ignores the value, uses the trusted one, logs a warning that names the settings and the file and says how to keep them, and runs the scan. For example:

```text
Ignoring sandbox.network_scanners, sandbox.extra_read_paths from /work/repo/.ash/.ash.yaml: that config is inside a git checkout or the scanned tree, or was delivered by an MCP client. A network_scanners list there still removes network from scanners it does not name, and a sandbox mode there still applies when nothing else turns the sandbox on. To keep a setting, move the file outside every git checkout, or pass the setting with --config-overrides. A file inside the scanned directory has to move out of it as well.
```

Here the repository's config gave grype a network and a read path. To give grype a network yourself, pass `--config-overrides 'sandbox.network_scanners=[grype]'`.

An MCP-client file is also checked against the server's runtime-override policy, the `denied_paths` and `denied_value_patterns` of `global_settings.mcp.runtime_overrides`, whether or not `runtime_overrides.enabled` is set. The policy comes from the server's own configuration: the file `ASH_CONFIG` names when the server starts, or the built-in defaults when `ASH_CONFIG` is unset or empty. An `ASH_CONFIG` that names a path that is not a file, or a file that does not load, stops `ash mcp` from starting, with exit code 3. By default the list covers the gate settings (`fail_on_findings`, `fail_on_incomplete_scanners`, `content_db_staleness` and its overrides, and `content_db_staleness_offline_image_default`), the scanner options that drop findings by rule ID, by a baseline, or by a whole category, options that limit how much a scanner reads or that turn on its own network calls, each scanner's `offline` option, each scanner's own config file, which version of a tool runs, every setting of the reporters that send findings off the host (`aws-security-hub`, `bedrock-summary-reporter`, `cloudwatch-logs`, and `s3`), their `enabled` included, and the `gitlab-sast` reporter's `exclude_suppressed`; [What a delivered config cannot set](../how-to/mcp-server.md#what-a-delivered-config-cannot-set) lists them. If a delivered file sets any of them to a value other than the trusted one, ASH refuses the whole file rather than trimming it. The error names each field, the MCP tools report it with `error_type: config_field_denied`, and on the CLI it is a configuration error (exit 3). If the policy itself cannot be read, because the file `ASH_CONFIG` names exists but does not load, or has two sections that ASH reads as the same plugin, a config with an MCP-client file is refused with `config_policy_unreadable`. The server meets that case only when the file changed after it started.

The check follows where the file is, not whether a server is running. In this example the parent directory is the workspace root, so the scanned directory is a delivered tree, and its config turns off `fail_on_findings`:

<!-- doctest: save-as=.ash/.ash.yaml -->
```yaml
project_name: delivered
fail_on_findings: false
```

The CLI refuses the config with exit code 3:

<!-- doctest: run expect-exit=3 -->
```bash
ASH_MCP_WORKSPACE_ROOT="$(dirname "$PWD")" ash --source-dir . --scanners detect-secrets --offline --no-progress
```

Outside the workspace root the same file is a repository file, which may turn the gate off, so the same scan exits 0 although detect-secrets reports a finding:

<!-- doctest: run expect-exit=0 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

The default list also names `sandbox`, `ash_plugin_modules`, `global_settings.mcp`, suppressions, and ignore paths, and delivered files are checked differently for those. Sandbox settings and plugin modules may restrict the server's own but not widen them: a delivered file whose own `sandbox` section gives a scanner a network or an `extra_read_paths` entry the server's config does not, or sets a sandbox mode other than the server's when the server's mode is not `off`, or whose own `ash_plugin_modules` list loads a module the table above keeps out, is refused the same way. Any other sandbox grant or module a delivered file asks for is dropped, as for a repository file. A delivered file's `global_settings.mcp` section has no effect, and suppressions and ignore paths are honored and marked, as described next. Under the default policy a delivered config can still disable scanners, turn the reporters that write only local files on or off and set their options, apart from `gitlab-sast`'s `exclude_suppressed`, and raise severity thresholds. It cannot turn a reporter that sends findings off the host on or off: its `enabled: false` for one of them is not refused, but it has no effect, and each runs as the server's config says, or by the reporter's own default where that config sets nothing. [Run the MCP server](../how-to/mcp-server.md) covers running the server.

## Client-supplied suppressions and ignore paths {#client-supplied}

In a scan whose config includes an MCP-client file, each suppression and ignore path that file sets is marked `client_supplied: true`, unless it matches an entry from an operator source. Per-scanner path exclusions that file sets (bandit `excluded_paths`, checkov `skip_path`, semgrep and opengrep `exclude`, syft `exclude`, and ferret-scan `exclude_patterns`) are taken out of the scanner's options and handled the same way. Each is matched the way its scanner reads it: a bandit entry as the `**/<path>/**` glob ASH passes bandit, against the file's absolute path; a checkov entry as a regular expression found in, or a substring of, the absolute path of the file or of a directory above it; and the others as globs that match the path or any directory in it. A finding the matching misses is reported unsuppressed, never hidden. A delivered `scanners.trivy-repo.options.ignore_file` is not passed to trivy. When it is a regular file inside the scanned tree, each unexpired ID in it suppresses and marks the trivy-repo findings with that rule ID; any other file, including a symbolic link, is not read.

The mark changes what the entry does. A client-supplied ignore path or exclusion does not keep files from being scanned or converted. The files are scanned, and each finding the entry would have hidden is kept in the results as a suppressed finding. Like every suppressed finding, it does not count toward `fail_on_findings`.

The mark shows up in:

- `ash_aggregated_results.json`, on each entry of `ash_config.global_settings.suppressions` and `ignore_paths`;
- the SARIF, where the suppression's justification starts with `(ASH, client-supplied config)` and, for a scanner exclusion, names the entry it came from, such as `scanners.bandit.options.excluded_paths entry 'tests'`, and its properties carry `clientSupplied: true`. A suppression entry has `kind: inSource`; an ignore path or scanner exclusion has `kind: external`;
- the reports that show suppression justifications: CSV and flat JSON, HTML, JUnit (`<skipped>`), OCSF, and GitLab SAST (which keeps suppressed findings at severity Info unless `exclude_suppressed` is set).

The GitHub code scanning SARIF leaves suppressed findings out by default, and the Markdown and text summaries show only counts, so the mark is not visible there. Syft's SBOM components get an `ash:clientSuppliedExclusion` property instead. Each exclusion taken out of a scanner's options is also logged as a warning and recorded in the results as a `config_warning` validation checkpoint.

ASH marks entries only in MCP-client files and, in an `ash --workspace` scan, in a workspace policy file under the MCP workspace root, whose entries are also checked against the runtime-override policy as each project gets them. The MCP workspace tools do not use such a policy file at all ([Workspace scans over MCP](../how-to/scale-large-repos.md#workspaces-mcp)). Only ASH sets the mark: a `client_supplied` value written in a config file, or set with `--config-overrides`, is ignored. In a CLI scan, a repository's own suppressions look the same as yours.

## What the trust model does not protect against {#not-protected}

The tiers decide who may change the settings above. They do not make every setting the operator's, and they do not make scanning a hostile repository safe on their own.

- A repository-tier config on the CLI can still turn off `fail_on_findings` and `fail_on_incomplete_scanners`, raise severity thresholds, disable scanners and reporters, and add suppressions, ignore paths, and per-scanner exclusions. None of this is marked. To keep these choices yours in a scan of one directory, pass your own config with `--config`, so that the repository's config is not read. You can also override the repository's values on the command line: `--config-overrides` replaces any setting (for example `scanners.bandit.enabled=true` or `global_settings.suppressions=[]`), flags such as `--fail-on-findings`, `--fail-on-incomplete-scanners`, and `--no-allow-stale-content-db` take precedence over a config file, and `--ignore-suppressions` stops the repository's suppressions and ignore paths from applying. In workspace mode every setting your `--config` makes is final for every project, and a project's own config fills only the settings yours leaves out.

    With `--ignore-suppressions`, every scanner reads the files under the repository's ignore paths, and their findings come back. It does not lift a scanner's own exclusion options, such as bandit's `excluded_paths`, or the repository's `.gitignore` and `.ignore` files ([See every finding](../how-to/suppress-findings.md#ignore-suppressions)). In a repository where detect-secrets reports a password in `app.py`, a repository config that ignores `app.py` keeps the scan passing:

    <!-- doctest: save-as=.ash/.ash.yaml -->
    ```yaml
    global_settings:
      ignore_paths:
        - path: app.py
          reason: Fixture value, not a real password
    ```

    <!-- doctest: run expect-exit=0 -->
    ```bash
    ash --source-dir . --scanners detect-secrets --offline --no-progress
    ```

    `--ignore-suppressions` brings the finding back, and the scan fails:

    <!-- doctest: run expect-exit=2 -->
    ```bash
    ash --source-dir . --scanners detect-secrets --offline --no-progress --ignore-suppressions
    ```

    To drop only the repository's ignore paths and keep its suppressions, replace the ignore paths with `--config-overrides`, and the finding fails the scan too:

    <!-- doctest: run expect-exit=2 -->
    ```bash
    ash --source-dir . --scanners detect-secrets --offline --no-progress \
      --config-overrides 'global_settings.ignore_paths=[]'
    ```

    A suppression of the same finding is lifted the same way, and the scan fails:

    <!-- doctest: save-as=.ash/.ash.yaml -->
    ```yaml
    global_settings:
      suppressions:
        - path: app.py
          rule_id: SECRET-SECRET-KEYWORD
          reason: Fixture value, not a real password
    ```

    <!-- doctest: run expect-exit=2 -->
    ```bash
    ash --source-dir . --scanners detect-secrets --offline --no-progress --ignore-suppressions
    ```

- Some scanners read configuration files from the scanned directory by name. For actionlint, bandit, cfn-lint, checkov, ferret-scan, gitleaks, grype, opengrep, semgrep, syft, trivy, trivy-repo, and zizmor, ASH gives the tool its own configuration instead, or keeps the repository's file from being read, a `.semgrepignore` included. detect-secrets reads a `.secrets.baseline` or `.ash/.secrets.baseline` in the source directory and uses the plugins and filters it lists, unless your config sets `plugins_used` in detect-secrets' `scan_settings`. The table above says which of the baseline's settings ASH drops. Apart from those settings, ASH does not limit or mark these files, or any other file a tool reads from the scanned directory on its own.
- Inline suppression comments in the source, ASH's `ash-ignore` and each scanner's own (for example bandit's `# nosec`), are written by the repository and honored in every tier.
- Only ASH's own AWS reporters and off-host plugin packages are covered. A third-party reporter declares its destination options in the class attribute `destination_options`; ASH reads the declaration from the class and admits a destination only from the trusted base: the defaults, an operator config outside the tree, and `--config-overrides`. A third-party plugin package installed outside every git checkout and the scanned directory, named in a repository config, is imported and runs with ASH's access.
- Once you load `ash_aws_plugins`, a repository config still sets the Bedrock reporter's content options, such as `include_code_snippets` and `custom_prompt`. A config an MCP client delivers can also turn the reporters that write only local files on or off and set their options. Once you load `ash_snyk_plugins`, a repository config can switch snyk-code off and set its options.
- The MCP-client tier limits what a delivered config can change in a scan. It is not a boundary between MCP clients; see [Run the MCP server](../how-to/mcp-server.md) for the deployment it supports.

[Scanning untrusted code](scanning-untrusted-code.md) covers the other defenses.
