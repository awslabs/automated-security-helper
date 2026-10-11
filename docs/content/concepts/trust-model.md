# Configuration trust model

ASH reads its configuration from places with different owners. You, the person or pipeline running ASH, control the command line, the environment, and the files outside the repository. The repository being scanned controls every file inside it, including the `.ash/.ash.yaml` that ASH discovers without being asked. A client of the ASH MCP server controls the files it delivers to the server. ASH sorts configuration into three tiers by owner, and limits what the repository and MCP clients can set for a short list of settings: the ones that grant access, send data off the host, or choose code for a tool to run.

## The three tiers {#tiers}

| Tier | Where the configuration comes from |
|---|---|
| Operator | Command-line flags, including `--config-overrides`, `--ash-plugin-modules`, and `--sandbox`; the environment, including `ASH_PLUGIN_MODULES`; a config file outside every git checkout and outside the scanned directory, named with `--config` or `ASH_CONFIG`. |
| Repository | Any config file inside a git checkout or inside the scanned directory: the discovered `.ash/.ash.yaml` and its siblings, a `--config` or `ASH_CONFIG` that points into the repository, and a config file kept in a checkout of its own, such as an ops or dotfiles repository. |
| MCP client | Any file under the MCP server's workspace root, where delivered source trees and uploads are stored, except each session's `config/` directory, which only the server writes. Also any config file a client names as a tool's `config_path`, wherever it is, unless it is in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names. |

The MCP workspace root is `ASH_MCP_WORKSPACE_ROOT` when set, else `$XDG_CACHE_HOME/ash-mcp`, else `~/.cache/ash-mcp`. A file there is an MCP-client file whether or not a server is running, so a CLI scan of a delivered tree, with that tree as `--source-dir`, gets the same treatment.

## How a file's tier is decided {#how-the-tier-is-decided}

The tier depends on where a file is, not on who names it. Passing a repository's file with `--config` does not make it an operator file.

A file is inside a git checkout when it, or any directory above it, holds a `.git` entry: a directory, or the `.git` file of a submodule or linked worktree. ASH checks the path as you named it, its resolved path, and every symbolic link it passes through on the way, so a symbolic link into or out of a checkout counts either way. For a scanned directory that is not in a checkout, a file inside it counts under any of the directory's names: as given, resolved, or as the shell's `$PWD` names it.

The rule applies to every file a config is built from, which means the root file and every base it `extends`, each judged by the path its `extends` entry names as well as by the file it resolves to. If any of them is a repository file, the whole config is treated as repository-tier for the restricted settings. An operator file outside every checkout that extends a base inside one keeps the sandbox settings it writes in its own `sandbox` section, and for some scanners the tool file paths it writes itself, but nothing it inherits from a base. Its other restricted settings come from the trusted base described below, so set them with `--config-overrides`. The warning names the base.

ASH reads one config file per scan, plus the files it `extends`. When you pass `--config` to a scan of one directory, ASH does not read the repository's own config file. In workspace mode, `--config` is only the default for projects that have no config of their own; use `--config-overrides` there.

When a config is repository-tier, ASH takes the restricted settings from a trusted base instead: the file `ASH_CONFIG` names, if it is outside every checkout and the scanned directory, otherwise the defaults, with your `--config-overrides` applied on top. In workspace mode, the `--config` file given to the workspace scan takes the place of `ASH_CONFIG`'s file when it is outside every checkout and the workspace root. Under the MCP server, the trusted base is the server's own configuration, the file `ASH_CONFIG` names, under the same rule: when that file is inside a git checkout, the restricted settings come from the defaults.

Two setups surprise people. A config you trust but keep in a git checkout of its own cannot make any of the restricted settings below, because it is in a checkout. And if your home directory is itself a git checkout (a common dotfiles setup), every file under it, including the MCP workspace root's default location, counts as inside a checkout.

## What each tier may set {#what-each-tier-may-set}

Settings not listed here can be set from any tier. The repository tier's limits also apply to MCP-client files, which have further limits of their own (next section).

| Kind of setting | From the operator | From a repository file |
|---|---|---|
| Sandbox grants: `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`, and `sandbox.env_scanners` | Honored | Ignored. A `network_scanners` list is kept as a limit: scanners it does not name get no network. |
| The sandbox mode, `sandbox.mode` | Honored. A mode in `ASH_CONFIG`'s file, or in the `--config` file of a workspace scan, counts even when that file is inside a git checkout, because a mode other than `off` grants nothing. | Applies only when no operator source turns the sandbox on. It cannot turn off, or switch away from, a mode the operator chose. In workspace mode this includes a project's own config file. |
| Plugin module lists, `ash_plugin_modules` | Honored | Only ASH's own plugin modules and modules installed outside every git checkout and the scanned directory. A third-party package in a virtual environment inside a checkout counts as inside it. Never `ash_aws_plugins` or `ash_snyk_plugins`, or any module inside either, whose plugins send findings or source off the host. |
| Where the AWS reporters send results, and with which credentials: the region, profile, and account of `aws-security-hub`; the region, profile, model, and output files of `bedrock-summary-reporter`; the region, log group, and stream of `cloudwatch-logs`; the region, profile, bucket, and key prefix of `s3` | Honored | Replaced by the trusted value. |
| Scanner options that name a tool config file, ignore file, rules or plugin directory, or a program for a tool to run | Honored. For some scanners the file may not be inside the scanned directory or the git checkout that holds it, and for some it may not be inside any checkout. | Limited for some scanners only: a path a repository's config names must then be outside every git checkout and the scanned directory. Set these options from an operator source, and pass your config with `--config` so the repository's config is not read. |

[Options only the operator can set](../how-to/choose-scanners.md#operator-only) lists the scanners that limit the options in the last row. The reporter limits apply to a reporter's section under any spelling ASH reads as that reporter, so a repository's reporter section spelled `BedrockSummary` is limited like `bedrock-summary-reporter`. Two rules apply from every tier: `reporters.<name>.extension` must be a plain filename suffix, and report files are written only inside the reports directory.

## When a lower tier sets something it may not {#denied-settings}

From a repository file, ASH ignores the value, uses the trusted one, logs a warning that names the settings and the file, and runs the scan. For example:

```text
Ignoring sandbox.network_scanners, sandbox.extra_read_paths from the config built on /work/repo/.ash/.ash.yaml: the file is inside a git checkout or the scanned directory, so someone other than the operator may have written it, and it cannot grant sandbox access.
```

That is the start of the warning. The rest says that only the sandbox settings a file outside every git checkout and the scanned directory writes itself are kept, that the file's `network_scanners` list still removes network from scanners it does not name, that its sandbox mode still applies when nothing else turns the sandbox on, and how to grant the setting: with `--config-overrides`, or from a config file outside every git checkout and the scanned directory.

An MCP-client file is also checked against the server's runtime-override policy, the `denied_paths` and `denied_value_patterns` of `global_settings.mcp.runtime_overrides`, whether or not `runtime_overrides.enabled` is set. The policy comes from the server's own configuration: the file `ASH_CONFIG` names when the server starts, or the built-in defaults when it names none or names a file that does not exist. By default the list covers the gate settings (`fail_on_findings`, `fail_on_incomplete_scanners`, and `content_db_staleness` and its overrides), the scanner options that drop findings by rule ID, by a baseline, or by a whole category, each scanner's `offline` option, each scanner's own config file, which version of a tool runs, and the AWS reporters' destinations and credentials; [What a delivered config cannot set](../how-to/mcp-server.md#what-a-delivered-config-cannot-set) lists them. If a delivered file sets any of them to a value other than the trusted one, ASH refuses the whole file rather than trimming it. The error names each field, the MCP tools report it with `error_type: config_field_denied`, and on the CLI it is a configuration error (exit 3). If the policy itself cannot be read, because the file `ASH_CONFIG` names exists but does not load, or has two sections that ASH reads as the same plugin, a config with an MCP-client file is refused with `config_policy_unreadable`.

The default list also names `sandbox`, `ash_plugin_modules`, `global_settings.mcp`, suppressions, and ignore paths, and delivered files are checked differently for those. Sandbox settings and plugin modules may restrict the server's own but not widen them: a delivered file that gives a scanner a network or a read path the server's config does not, sets a sandbox mode other than the server's when the server sets one, or loads a module the table above keeps out, is refused the same way. A delivered file's `global_settings.mcp` section has no effect, and suppressions and ignore paths are honored and marked, as described next. Under the default policy a delivered config can still disable scanners and reporters and raise severity thresholds. [Run the MCP server](../how-to/mcp-server.md) covers running the server.

## Client-supplied suppressions and ignore paths {#client-supplied}

In a scan whose config includes an MCP-client file, each suppression and ignore path that file sets is marked `client_supplied: true`, unless it matches an entry from an operator source. Per-scanner path exclusions that file sets (bandit `excluded_paths`, checkov `skip_path`, semgrep and opengrep `exclude`, syft `exclude`, and ferret-scan `exclude_patterns`) are taken out of the scanner's options and handled the same way. Each is matched the way its scanner reads it: a bandit entry as the `**/<path>/**` glob ASH passes bandit, against the file's absolute path; a checkov entry as a regular expression found in, or a substring of, the absolute path of the file or of a directory above it; and the others as globs that match the path or any directory in it. A finding the matching misses is reported unsuppressed, never hidden. A delivered `scanners.trivy-repo.options.ignore_file` is not passed to trivy. When it is a regular file inside the scanned tree, each unexpired ID in it suppresses and marks the trivy-repo findings with that rule ID; any other file, including a symbolic link, is not read.

The mark changes what the entry does. A client-supplied ignore path or exclusion does not keep files from being scanned or converted. The files are scanned, and each finding the entry would have hidden is kept in the results as a suppressed finding. Like every suppressed finding, it does not count toward `fail_on_findings`.

The mark shows up in:

- `ash_aggregated_results.json`, on each entry of `ash_config.global_settings.suppressions` and `ignore_paths`;
- the SARIF, where the suppression's justification starts with `(ASH, client-supplied config)`, for a scanner exclusion followed by the entry it came from, such as `scanners.bandit.options.excluded_paths entry 'tests'`, and its properties carry `clientSupplied: true`. A suppression entry has `kind: inSource`; an ignore path or scanner exclusion has `kind: external`;
- the reports that show suppression justifications: CSV and flat JSON, HTML, JUnit (`<skipped>`), OCSF, and GitLab SAST (which keeps suppressed findings at severity Info unless `exclude_suppressed` is set).

The GitHub code scanning SARIF leaves suppressed findings out by default, and the Markdown and text summaries show only counts, so the mark is not visible there. Syft's SBOM components get an `ash:clientSuppliedExclusion` property instead. Each exclusion taken out of a scanner's options is also logged as a warning and recorded in the results as a `config_warning` validation checkpoint.

ASH marks entries only in configs an MCP client delivered, and in a workspace policy file an MCP client delivered, whose entries are also checked against the runtime-override policy as each project gets them. Only ASH sets the mark: a `client_supplied` value written in a config file, or set with `--config-overrides`, is ignored. In a CLI scan, a repository's own suppressions look the same as yours.

## What the trust model does not protect against {#not-protected}

The tiers decide who may change the settings above. They do not make every setting the operator's, and they do not make scanning a hostile repository safe on their own.

- A repository-tier config on the CLI can still turn off `fail_on_findings` and `fail_on_incomplete_scanners`, set `content_db_staleness: warn`, raise severity thresholds, disable scanners and reporters, and add suppressions, ignore paths, and per-scanner exclusions. None of this is marked. To keep these choices yours in a scan of one directory, pass your own config with `--config`, so that the repository's config is not read. You can also override the repository's values on the command line: `--config-overrides` replaces any setting (for example `scanners.bandit.enabled=true` or `global_settings.suppressions=[]`), flags such as `--fail-on-findings`, `--fail-on-incomplete-scanners`, and `--no-allow-stale-content-db` take precedence over a config file, and `--ignore-suppressions` stops suppressions and ignore paths from applying. In workspace mode a project's own config replaces your `--config`, so use `--config-overrides` there.
- Some scanners read configuration files from the scanned directory by name. For actionlint, bandit, cfn-lint, checkov, ferret-scan, gitleaks, grype, hadolint, syft, trivy, trivy-repo, and zizmor, ASH gives the tool its own configuration instead, or keeps the repository's file from being read. detect-secrets reads a `.secrets.baseline` or `.ash/.secrets.baseline` in the source directory and uses the plugins and filters it lists, unless your config sets `plugins_used` in detect-secrets' `scan_settings`. semgrep and opengrep read a `.semgrepignore` in the source directory. ASH does not limit or mark these files, or any other file a tool reads from the scanned directory on its own.
- Inline suppression comments in the source, ASH's `ash-ignore` and each scanner's own (for example bandit's `# nosec`), are written by the repository and honored in every tier.
- Only ASH's own AWS reporters and off-host plugin packages are covered. A third-party reporter's destination options are not known to ASH, and a third-party plugin package installed outside every checkout and the scanned directory, named in a repository config, is imported and runs with ASH's access.
- Once you load `ash_aws_plugins`, a repository config still decides whether each AWS reporter is enabled and sets the Bedrock reporter's content options, such as `include_code_snippets` and `custom_prompt`. Once you load `ash_snyk_plugins`, it can switch snyk-code off and set its options.
- The MCP-client tier limits what a delivered config can change in a scan. It is not a boundary between MCP clients; see [Run the MCP server](../how-to/mcp-server.md) for the deployment it supports.

[Scanning untrusted code](scanning-untrusted-code.md) covers the other defenses.
