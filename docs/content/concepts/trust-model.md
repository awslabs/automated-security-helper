# Configuration trust model

ASH reads its configuration from places with different owners. You, the person or pipeline running ASH, control the command line, the environment and the files outside the repository. The repository being scanned controls every file inside it, including the `.ash/.ash.yaml` that ASH discovers without being asked. A client of the ASH MCP server controls the files it delivers to the server. ASH sorts configuration into three tiers by owner and lets only the operator make a short list of settings: the ones that grant access, send data off the host, or choose code for a tool to run.

## The three tiers {#tiers}

| Tier | Where the configuration comes from |
|---|---|
| Operator | Command-line flags, including `--config-overrides`, `--ash-plugin-modules` and `--sandbox`; the environment, including `ASH_PLUGIN_MODULES`; a config file outside every git checkout and outside the scanned directory, named with `--config` or `ASH_CONFIG`. |
| Repository | Any config file inside a git checkout or inside the scanned directory: the discovered `.ash/.ash.yaml` and its siblings, a `--config` or `ASH_CONFIG` that points into the repository, and a config file kept in a checkout of its own, such as an ops or dotfiles repository. |
| MCP client | Any file under the MCP server's workspace root, where delivered source trees and uploads are stored, except each session's `config/` directory, which only the server writes. |

The MCP workspace root is `ASH_MCP_WORKSPACE_ROOT` when set, else `$XDG_CACHE_HOME/ash-mcp`, else `~/.cache/ash-mcp`. A file there is an MCP-client file whether or not a server is running, so a CLI scan of a delivered tree gets the same treatment.

## How a file's tier is decided {#how-the-tier-is-decided}

The tier depends on where a file is, not on who names it. Passing a repository's file with `--config` does not make it an operator file.

A file is inside a git checkout when it, or any directory above it, holds a `.git` entry: a directory, or the `.git` file of a submodule or linked worktree. ASH checks both the path as you named it and its resolved path, so a symbolic link into or out of a checkout counts either way. For a scanned directory that is not in a checkout, a file inside it counts under any of the directory's names: as given, resolved, or as the shell's `$PWD` names it.

The rule applies to every file a config is built from, which means the root file and every base it `extends`. If any of them is a repository file, the whole config is treated as repository-tier for the restricted settings. An operator file outside every checkout that extends a base inside one loses its own restricted settings too, and the warning names only the base.

ASH uses one config source per scan and never merges sources. When you pass `--config`, ASH does not read the repository's own config file at all.

When a config is repository-tier, ASH takes the restricted settings from a trusted base instead: the file `ASH_CONFIG` names, if it is outside every checkout and the scanned directory, otherwise the defaults, with your `--config-overrides` applied on top. In workspace mode the workspace's default config takes the place of `ASH_CONFIG`'s file when it is outside every checkout, and under the MCP server the trusted base is the server's own configuration.

Two setups surprise people. A config you trust but keep in a git checkout of its own cannot make any of the restricted settings below, because it is in a checkout. And if your home directory is itself a git checkout (a common dotfiles setup), every file under it, including the MCP workspace root's default location, counts as inside a checkout.

## What each tier may set {#what-each-tier-may-set}

Settings not listed here can be set from any tier. The repository tier's limits also apply to MCP-client files, which have further limits of their own (next section).

| Setting | Operator | Repository |
|---|---|---|
| Sandbox grants: `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`, `sandbox.env_scanners` | Yes | Ignored. A `network_scanners` list is kept as a limit: scanners it does not name get no network. |
| `sandbox.mode` | Yes | Applies only when no operator source turns the sandbox on. It cannot turn off, or switch away from, a mode the operator chose. |
| `ash_plugin_modules` | Yes | Only installed modules outside every checkout and the scanned directory, and never `ash_aws_plugins` or `ash_snyk_plugins`, whose plugins send findings or source off the host. |
| AWS reporter destinations and credentials: the region, profile and account of `aws-security-hub`; the region, profile, model and output files of `bedrock-summary-reporter`; the region, log group and stream of `cloudwatch-logs`; the region, profile, bucket and key prefix of `s3` | Yes | Replaced by the trusted value. |
| Scanner options that name a tool config file, ignore file, rules or plugin directory, or a program for a tool to run | Yes, though some must point outside every checkout and the scanned directory | A path inside a checkout or the scanned directory is never passed to the tool. For several scanners the option is honored only from the operator. |

The scanner options in the last row are listed per scanner in the [scanner reference](../reference/scanners.md). Two rules apply from every tier: `reporters.<name>.extension` must be a plain filename suffix, and report files are written only inside the reports directory.

## When a lower tier sets something it may not {#denied-settings}

From a repository file, ASH ignores the value, uses the trusted one, logs a warning that names the settings and the file, and runs the scan. For example:

```text
Ignoring sandbox.network_scanners, sandbox.extra_read_paths from /work/repo/.ash/.ash.yaml: the file is inside a git checkout or the scanned directory, so someone other than the operator may have written it, and it cannot grant sandbox access.
```

That is the start of the warning. The rest says how to grant the setting: with `--config-overrides`, or from a config file outside every git checkout and the scanned directory.

An MCP-client file is also checked against the server's runtime-override policy, `global_settings.mcp.runtime_overrides.denied_paths`. By default that list covers `fail_on_findings`, `fail_on_incomplete_scanners`, `content_db_staleness` and its overrides, `global_settings.mcp`, the semgrep and opengrep `exclude_rule` options, the detect-secrets `baseline_file`, the Bedrock reporter's `aws_*` options and every `cloudwatch-logs` option. If a delivered file sets any of them to a value other than the trusted one, ASH refuses the whole file rather than trimming it. The error names each field, the MCP tools report it with `error_type: config_field_denied`, and on the CLI it is a configuration error (exit 3). If the policy itself cannot be read, the error type is `config_policy_unreadable`.

The default list also names `sandbox`, `ash_plugin_modules`, suppressions and ignore paths. With the default list, delivered files are not refused for those: sandbox settings and plugin modules are limited as in the table above, and suppressions and ignore paths are honored and marked, as described next. Under the default policy a delivered config can still disable scanners and raise severity thresholds. The [MCP server guide](../how-to/mcp-server.md) covers running the server.

## Client-supplied suppressions and ignore paths {#client-supplied}

In a scan whose config includes an MCP-client file, every suppression and ignore path that does not match an entry from an operator source is marked `client_supplied: true`. Per-scanner path exclusions from the delivered file (bandit `excluded_paths`, checkov `skip_path`, semgrep and opengrep `exclude`, syft `exclude`, ferret-scan `exclude_patterns`) are taken out of the scanner's options and handled the same way.

The mark changes what the entry does. A client-supplied ignore path or exclusion does not keep files from being scanned or converted. The files are scanned, and each finding the entry would have hidden is kept in the results as a suppressed finding. Like every suppressed finding, it does not count toward `fail_on_findings`.

The mark shows up in:

- `ash_aggregated_results.json`, on each entry of `ash_config.global_settings.suppressions` and `ignore_paths`;
- the SARIF, where the suppression's justification starts with `(ASH, client-supplied config)` and its properties carry `clientSupplied: true`. A suppression entry has `kind: inSource`; an ignore path or scanner exclusion has `kind: external`;
- the reports that show suppression justifications: CSV and flat JSON, HTML, JUnit (`<skipped>`), OCSF and GitLab SAST (which keeps suppressed findings at severity Info).

The GitHub code scanning SARIF leaves suppressed findings out by default, and the Markdown and text summaries show only counts, so the mark is not visible there. Syft's SBOM components get an `ash:clientSuppliedExclusion` property instead.

Outside the MCP workspace root nothing is marked: in a CLI scan, a repository's own suppressions look the same as yours.

## What the trust model does not protect against {#not-protected}

The tiers decide who may change the settings above. They do not make every setting the operator's, and they do not make scanning a hostile repository safe on their own.

- A repository-tier config on the CLI can still turn off `fail_on_findings` and `fail_on_incomplete_scanners`, set `content_db_staleness: warn`, raise severity thresholds, disable scanners and reporters, and add suppressions, ignore paths and per-scanner exclusions. None of this is marked. To keep these choices yours, pass your own config with `--config`, so that the repository's config is not read at all, or override the repository's values on the command line: `--config-overrides` replaces any setting (for example `scanners.bandit.enabled=true` or `global_settings.suppressions=[]`), flags such as `--fail-on-findings` and `--no-allow-stale-content-db` take precedence over a config file, and `--ignore-suppressions` stops suppressions and ignore paths from applying.
- Configuration that scanners read from the scanned directory by name, such as `.bandit`, `bandit.yaml`, `.grype.yaml`, `.syft.yaml` and `.semgrepignore`, is not limited or marked by ASH.
- Inline suppression comments in the source, ASH's `ash-ignore` and each scanner's own (for example bandit's `# nosec`), are written by the repository and honored in every tier.
- Only ASH's own AWS reporters and off-host plugin packages are covered. A third-party reporter's destination options are not known to ASH, and an installed third-party plugin package named in a repository config is imported and runs with ASH's access.
- Once you load `ash_aws_plugins`, a repository config still decides whether each AWS reporter is enabled and sets the Bedrock reporter's content options, such as `include_code_snippets` and `custom_prompt`. Once you load `ash_snyk_plugins`, it can switch snyk-code off.
- The MCP-client tier limits what a delivered config can change in a scan. It is not a boundary between MCP clients; see the [MCP server guide](../how-to/mcp-server.md) for the deployment it supports.

[Scanning untrusted code](scanning-untrusted-code.md) covers the other defenses and a recommended setup.
