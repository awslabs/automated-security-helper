# Automated Security Helper - CHANGELOG
- [v3.2.7](#v327)
    - [Fixes](#fixes)
    - [Features](#features)
    - [Maintenance](#maintenance)
- [v3.2.6](#v326)
    - [Fixes](#fixes-1)
    - [Maintenance](#maintenance-1)
- [v3.2.5](#v325)
    - [Fixes](#fixes-2)
- [v3.2.4](#v324)
    - [Maintenance](#maintenance-2)
- [v3.2.3](#v323)
    - [Fixes](#fixes-3)
- [v2.0.1](#v201)
    - [What's Changed](#whats-changed)
- [v2.0.0](#v200)
    - [Breaking Changes](#breaking-changes)
    - [Features](#features)
    - [Fixes](#fixes)
- [v1.5.1](#v151)
    - [What's Changed](#whats-changed-1)
- [v1.5.0](#v150)
    - [What's Changed](#whats-changed-2)
    - [New Contributors](#new-contributors)
- [v1.4.1](#v141)
    - [What's Changed](#whats-changed-3)
- [v1.4.0](#v140)
    - [What's Changed](#whats-changed-4)
- [v1.3.3](#v133)
    - [What's Changed](#whats-changed-5)
- [v1.3.2](#v132)
    - [What's Changed](#whats-changed-6)
    - [New Contributors](#new-contributors-1)
- [1.3.0 - 2024-04-17](#130---2024-04-17)
    - [Features](#features-1)
    - [Fixes](#fixes-1)
    - [Maintenance / Internal](#maintenance--internal)
- [1.2.0-e-06Mar2024](#120-e-06mar2024)
- [1.1.0-e-01Dec2023](#110-e-01dec2023)
- [1.0.9-e-16May2023](#109-e-16may2023)
- [1.0.8-e-03May2023](#108-e-03may2023)
- [1.0.5-e-06Mar2023](#105-e-06mar2023)
- [1.0.1-e-10Jan2023](#101-e-10jan2023)


## Unreleased

### Features

- **Opt-in OS sandboxing for scanners: `--sandbox auto|bwrap|firejail|landlock|sandbox-exec|off`**,
  or `sandbox.mode` in the config file. Off by default. With a sandbox, every scanner
  subprocess, including version probes and the detect-secrets and cdk-nag workers,
  runs with:
  - the source tree read-only, and only its own `<output>/scanners/<name>/`
    directory writable;
  - a private, empty `$HOME` and `/tmp`;
  - an environment filtered to an allowlist, so cloud credentials and tokens are not
    passed in;
  - no network under `--offline`, and online only for the scanners that fetch rules,
    databases or audit data. detect-secrets' secret verification gets a network only
    when `sandbox.network_scanners` names it, because the settings that enable it
    can come from the scanned repository.

  `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`
  and `sandbox.env_scanners` grant access, so they come only from `--config-overrides`
  or a config file outside every git checkout. **A config file inside any git
  checkout cannot set them**, whether ASH discovered it, it was passed with
  `--config`, it is an `extends` base, or `ASH_CONFIG` names it. That includes a
  trusted config kept in an ops or dotfiles repository: its grants are dropped with a
  warning naming the file and the setting, and have to be passed with
  `--config-overrides`. A config file outside every checkout that extends one inside
  it, such as an operator's `--config` built on the repository's own config, keeps
  the sandbox settings it writes itself, `mode` included, and loses what it inherits
  from any base and what it changes with `patch`. An `extends` base is judged by the
  path its entry names as well as by the file it resolves to. For a
  scanned directory outside any checkout, a config file
  inside that directory cannot set them either. Such a file's `network_scanners` can
  still remove network. `sandbox.mode` is a floor: when `--sandbox`, `ASH_CONFIG` or
  the operator's config turns the sandbox on, no repository config can turn it off or
  switch backends. A plugin scanner whose options ask for extra read paths or
  environment variables declares them with `read_paths_require_grant` or
  `env_requires_grant` and gets them only when `sandbox.read_path_scanners` or
  `sandbox.env_scanners` names it; none of the scanners ASH ships declares either.
  In workspace mode, an operator `--config` that does not validate is now refused
  (exit 3) even for projects that have their own config file, because the sandbox
  mode is read from it. Under a sandbox, a detect-secrets `baseline_file` outside the
  source tree is read only when `sandbox.read_path_scanners` names detect-secrets
  and the file is inside a `sandbox.extra_read_paths` entry,
  and a scanner whose config section is renamed to another scanner's name is not run
  sandboxed.

  Under sandbox-exec, no program runs from the source tree, the output directory or
  the results directory, apart from a tool path inside one (the virtualenv ASH runs
  from, say) and the spawn's own private uv cache. That holds for checkov and
  ferret-scan too, which run from the filesystem root.

  An offline sandboxed semgrep or opengrep scan reads its rules from the directory
  `SEMGREP_RULES_CACHE_DIR` or `OPENGREP_RULES_CACHE_DIR` names: the sandbox mounts it
  read-only for that scanner, wherever it is (the documented `$HOME/.cache/ash/...`
  included), and under sandbox-exec no program runs from it. Before, no grant
  covered it, so semgrep exited 7
  ("unable to find a config") behind ASH's own cache check, which had already passed.
  Only the variable in ASH's environment grants it; a rules path in the scanner's
  options does not, an empty variable grants nothing, and one naming `/`, `$HOME` or a
  directory above `$HOME` is not mounted.

  Converters are covered too. Under a sandbox the jupyter converter installs nothing
  (it used to install nbconvert when it was missing and ASH was online) and runs
  nbconvert, its version probe and its dependency check sandboxed, with a scanner's
  confinement: only `<output>/converted/jupyter/` writable, no network unless
  `sandbox.network_scanners` names `jupyter`. nbconvert reads a staged copy of the
  notebook and its tools, not the source tree or the output directory; under
  Landlock and firejail a tree inside a directory those backends show (such as
  `/opt`) stays readable. The convert phase applies the same
  scope to every converter. A notebook the sandbox refused (no backend can be used,
  or the backend cannot plan its run) is listed in the converter's `refused_inputs`;
  that notebook and one nbconvert failed on are listed in its `failed_inputs`, and
  any converter process the sandbox refused is named in the converter row's
  `failure`, so the scan exits 1 while `fail_on_incomplete_scanners` is on. A
  notebook nbconvert fails on (one that is not JSON, a timeout, a run that writes no
  output) counts this way with or without a sandbox; under a sandbox its reason says
  so, and a conversion that raises is recorded by the exception's type, not its
  message, which can quote the notebook. Exclude a notebook that is malformed on
  purpose with `ignore_paths`. A scanner's own version probe at construction,
  which a sandboxed scan refused with a misleading "renamed by a config file" reason,
  now runs sandboxed as documented. A probe the sandbox refused never ran, so its
  outcome is not remembered for the rest of the process: uv's availability, a
  tool's version, and the check of a pre-installed tool against the scan's
  requirement are probed again by the next check that asks.

  ASH's own writes below the output directory (`ash.log` and `ash.log.jsonl`, worker
  request files, stream logs, results files, reports, the aggregated results,
  extracted archive members) no longer follow a symlink, with or without a sandbox;
  a link at `ash.log` stops the scan with exit 3 before it starts. The default
  output directory is inside the scanned tree, so a link committed at one of those
  paths used to redirect the write when the sandbox was off. A link at any
  component of the path now stops the write (`OutputLinkRefused`) and the scanner is
  `ERROR`; under a sandbox, a link already below a results directory when its
  scanner starts is refused the same way, where the sweep after the spawn used to
  remove it. A file at one of those paths that another name also refers to (a hard
  link, which an archive can carry) is refused too (`OutputHardLinkRefused`), before
  it is truncated: the file was opened with `O_TRUNC`, so a hard link to a file
  elsewhere on the filesystem was emptied and overwritten. On Windows, where these
  writes were plain `open()` calls, each component is now checked by name first
  (symlinks and reparse points such as junctions), so a link already in place is
  refused; one created between that check and the open is not.

  If a sandbox was requested and cannot be provided, the scanner is recorded
  `MISSING` with the reason and the scan exits 1. ASH never falls back to running it
  unsandboxed. `auto` picks bubblewrap, then firejail, then Landlock on Linux, and
  sandbox-exec on macOS. There is no Windows backend: use WSL2 or container mode.
  Landlock needs ABI 3 (Linux 6.2) or later, because older ABIs cannot stop a
  scanner from truncating files it may only read; below that it counts as
  unavailable.
  firejail counts as available only when a test command it runs lands in a sandbox:
  inside a container with its own PID namespace firejail runs commands without one,
  so there it is unavailable and `auto` moves on to Landlock.
  Container mode ignores the setting, because the container is the boundary.

  Two timeout behaviors change with the worker move, sandbox or not. cdk-nag now
  honors `scanners.cdk-nag.options.scan_timeout` (1800 seconds by default) for the
  whole batch of templates; it had no timeout before, and templates not evaluated by
  the cutoff are reported as failed targets. A detect-secrets scan that times out
  now keeps only its baseline's entries, where the in-process scan kept whatever it
  had found before the cutoff; either way the scan is reported as timed out. See
  `docs/content/docs/scanner-sandbox.md` for the threat model and per-scanner
  policy. Two scanners that ran inside the ASH process now run as worker
  subprocesses so the sandbox can cover them: detect-secrets and cdk-nag. Their
  findings are unchanged.
- **Six new builtin scanners: actionlint, cfn-lint, cfn-guard, gitleaks, trivy (`trivy
  fs`) and zizmor.** They live with the other builtins in
  `automated_security_helper/plugin_modules/ash_builtin/scanners`, have declared
  entries in the config schema, and are enabled by default (see Behavior changes).
  `scanners.<name>.enabled: false` turns one off. The container image ships every
  tool, pinned, digest-verified and with its license files; `ash dependencies install`
  installs the same pinned binaries locally, and the uv tools (cfn-lint and zizmor)
  within their `tool_version` ranges; and nix mode supplies them (cfn-guard from its
  pinned release asset, its rules installed by the shell on first entry and again whenever they are not the pinned bundle, and trivy's
  database refreshed on every entry). A tool that is absent is MISSING, as for every builtin scanner.
  `--python-only` runs cfn-lint and zizmor, which ASH runs through uv, and does not run
  actionlint, cfn-guard, gitleaks or trivy, which are native binaries. Under
  `--sandbox` each gets what it declares, listed in
  `docs/content/docs/scanner-sandbox.md`. See
  [Built-in Scanners](docs/content/docs/plugins/builtin/scanners.md).
  - actionlint 1.7.12 on `.github/workflows` files, skipping `node_modules`,
    `.venv` and `venv` as zizmor does. Script
    injection from untrusted event data and hard-coded container credentials are
    HIGH, always-true `if:` conditions, invalid `permissions:` and
    `set-env`/`add-path` MEDIUM, other lint findings LOW. Its shellcheck and pyflakes
    integrations are off unless configured, so results do not depend on the host.
    A workflow whose local `uses: ./...` resolves outside the scanned repository is
    skipped with a warning, since actionlint would read that file into its findings.
  - cfn-lint (`>=1.43.3,<2.0.0`, uv tool; E to MEDIUM, W to LOW,
    I to INFO) and cfn-guard 3.2.1 against the AWS Guard Rules Registry 1.0.2,
    default rule set `wa-Security-Pillar`, every violation HIGH. Both read the
    templates cfn-nag reads, and neither needs the network. cfn-lint checks
    against us-east-1 unless `regions`, the template or the operator's
    `.cfnlintrc` names other regions; it does not read `AWS_REGION`. A
    template's own `Metadata` `ignore_checks` and `configure_rules` do not
    apply unless the operator sets
    `scanners.cfn-lint.options.honor_inline_ignores`, and then only to that
    template, which runs alone; they never reach the parse errors of another
    template. Until then the operator's `.cfnlintrc` `configure_rules` are
    passed on the command line, one the command line cannot carry is left out
    with a warning, and a `.cfnlintrc` that sets `merge_configs`, or that uses a
    YAML alias (ASH reads it with aliases refused, and cfn-lint would read the
    aliased values ASH could not check), fails the scan. A cfn-guard rule in
    two selected rule sets is reported once.
  - gitleaks 8.30.1 (`gitleaks dir`, working tree only),
    CRITICAL findings with values redacted (`--redact=100`), beside detect-secrets,
    which stays on and unchanged. gitleaks is a secrets scanner, so its findings
    are secret findings: the lines they report are masked in every report, and the
    Bedrock summary reporter counts them rather than sending them. An operator's `options.config_file` and
    `options.baseline_path` apply. gitleaks runs with `--ignore-gitleaks-allow`,
    so a `gitleaks:allow` comment in the scanned tree hides nothing unless the
    operator sets `options.honor_inline_ignores`. `options.max_target_megabytes`
    is honored only from the operator, as `config_file` is.
  - zizmor (`>=1.29.0,<2.0.0`) on workflows and composite
    actions, run with `--offline`; GitHub tokens are withheld unless the operator
    sets `options.online_audits` (a config in the scanned tree cannot). A workflow
    or action that resolves outside the scan root, or is a broken symlink, is
    skipped with a warning.
  - trivy: `trivy fs` (0.75.0), `vuln` only by default, held to
    the trivy database's 24h bound; offline with no database it is MISSING with the
    reason. A scanner-level `severity_threshold` gates the verdict as for every
    scanner, and lower findings are still reported; it is not passed to trivy as
    `--severity`, and neither is trivy-repo's any longer. `scanners.trivy.options.scanners`
    is honored only from the operator; set by a config in the scanned tree, any set
    but the default `[vuln]` is ignored with a warning. trivy and trivy-repo share trivy's cache and run at the same time, so
    online ASH updates the database once per scan, under a lock in that cache, and
    both scanners then run with `--skip-db-update` and `--skip-java-db-update` (and
    `--skip-check-update` when `misconfig` is on), pointed at that cache with
    `--cache-dir`. The update is the one sandboxed scans already use
    (`utils/content_db_refresh.py`): it runs from a directory outside the
    scanned tree with an explicit `--config` (the operator's config file when the
    scan uses one, otherwise an empty one ASH ships), so a `trivy.yaml` in the
    scanned repository cannot change where the database comes from. Both scanners
    take their `--config` the same way: `config_file` from the operator, else
    `TRIVY_CONFIG` for a file outside the scanned tree, else the empty config. An image built with `OFFLINE=YES`
    ships the database (its build fails if the download does) and holds it to `warn` rather than `fail`: from a day after it
    was published that image's scans still pass, and every report records the stale
    database, while grype's database and the offline rulesets keep `fail`.
    `content_db_staleness_offline_image_default: false`, or either form of
    `--allow-stale-content-db`, turns that off (see
    `docs/content/docs/building-your-own-image.md`). The nix shell updates the
    database on every entry. trivy and trivy-repo keep the database where trivy
    itself does on the host (`TRIVY_CACHE_DIR`, else `$XDG_CACHE_HOME/trivy` on
    Linux, else `~/.cache/trivy`, `~/Library/Caches/trivy` on macOS and
    `%LocalAppData%\trivy` on Windows), and name it to the update, to every scan
    with `--cache-dir`, online and offline, and to the post-scan check, so all three
    read one database, sandboxed or not.
    Both scanners run with `--exit-code=0`, so `TRIVY_EXIT_CODE` or an `exit-code`
    in the operator's trivy.yaml no longer turns a scan with findings into a failure.
    An operator's `TRIVY_SKIP_DB_UPDATE=true` (or `db.skip-update: true` in the
    operator's config file) turns ASH's database update off too, with a warning;
    the scan reads the cached database, and the staleness check still applies.
    Both scanners pass `--offline-scan` on every scan, online too: trivy scans never
    contact package registries, and the database refresh is a separate step. Maven
    dependencies are resolved from the scanned tree and `~/.m2/repository` only.
    trivy does not check for new versions either: online every scan passes
    `--skip-version-check`, and offline `TRIVY_SKIP_VERSION_CHECK=true` turns the
    same check off. Offline with `misconfig` in `scanners`, trivy leaves out its
    Terraform checks as trivy-repo does (see "Offline, trivy-repo does not run
    trivy's Terraform checks" under Behavior changes).

  Options that name something a tool executes or loads are not taken from a config
  file inside the scanned tree: actionlint's `shellcheck` and `pyflakes` accept only
  their own names there, and cfn-lint's and trivy's `config_file` (a `.cfnlintrc`
  can import Python rules, a `trivy.yaml` can load WASM modules) are honored only
  from `--config-overrides` or a config file outside the tree, for a file outside
  it. cfn-lint's and zizmor's `tool_version` must be a version constraint.
  zizmor's and cfn-lint's `tool_version`, which pick the release that is installed
  and accepted, cfn-lint's `ignore_checks` and cfn-guard's `rule_sets`, which narrow
  what is reported, are honored only from the operator; from a config in the scanned
  tree each is ignored with a warning and the default applies.

  None of the six reads its tool's own config from the scanned repository: see
  "The scanned repository's own scanner configs are not read" under Behavior
  changes.

  ASH does not deduplicate across scanners, so overlapping pairs (gitleaks and
  detect-secrets, trivy and grype or trivy-repo, zizmor and actionlint) report a
  shared finding once per scanner; each scanner page says where.
- **`--scanners` names the module to add for a community scanner that is not loaded.**
  `--scanners snyk-code` without `ash_snyk_plugins` listed is refused with a message
  naming the module, rather than reading as a typo; a selection in which other names
  resolved warns with the same advice and runs those, as any partly unresolved
  `--scanners` list does. `ash dependencies install --tool <name>` gives the same hint.
- **The container image ships license files for the new scanners' tools.**
  actionlint, gitleaks, and cfn-guard with the Guard Rules Registry bundle it reads
  get `THIRD_PARTY_LICENSES` entries, as do the uv tools cfn-lint (MIT-0) and zizmor,
  read from each installed wheel's dist-info and checked against its RECORD. Every
  uv install in the image now runs with `UV_NO_CACHE=1`, so uv's cache is no longer
  kept in any layer.

### Behavior changes

- **An ignore path ending in `/` ignores the directory.** `global_settings.ignore_paths`
  entries are globs matched against a file's path below the source directory, and
  a file's path never ends in `/`, so `vendor/` matched nothing: every file there
  was scanned and reported. It is now matched as `vendor/*/**`, what is inside a
  directory named `vendor` and never a file of that name, wherever ignore paths
  are matched: dropping findings, the converters, detect-secrets, the exclusions
  each tree-walking scanner is given, and snyk-code's refusal. So `**/.*/` covers
  the files in dot-directories, not dotfiles such as `.env`, which detect-secrets
  keeps scanning. It stays anchored at the source directory (`**/vendor/` for any
  depth). `ash config lint` no longer warns about such an ignore path, and `ash
  config validate` no longer reports one as invalid. For a path that names an
  existing directory and no file in it, both now suggest `<dir>/` for an ignore
  path and `<dir>/**/*` for a suppression path, where they suggested `<dir>/**`
  for either. Suppression paths keep their meaning:
  `build/` still matches no file, and ASH now warns once after the scan for each
  suppression path ending in `/` that matched nothing, naming `build/**/*`, which
  covers every file below `build` and not a file named `build`. bandit's
  and checkov's own exclusions, `node_modules/`, `.venv/` and `venv/`, were also
  passed to that step as ignore paths, written the same way, and matched nothing.
  They are no longer passed, so nothing changes for them: read as directories they
  would have dropped every finding the dependency scanners report there, all of
  npm-audit's (located at `node_modules/<package>/package.json`) among them.
- **An output directory inside the scanned tree gets a `.gitignore`.** snyk-code
  read ASH's default output directory, `.ash/ash_output`, with the rest of the
  tree, and `snyk code test` uploaded an earlier run's reports and logs and the
  converted files, unless the tree's own `.gitignore` left them out (`ash config
  init` writes `.ash/.gitignore` for that, but a tree that never ran it had
  none). ASH now writes `<output_dir>/.gitignore` holding `*` when the output
  directory is inside the source directory, before any scanner starts: from the
  CLI in every run mode (in container mode, on the host), and from the
  orchestrator for MCP and API scans. An existing `.gitignore` there is never
  overwritten, nothing is written for an output directory outside the tree, and a
  link at that name is refused, never followed, and stops the scan with exit code
  3. git, and any other tool that honors `.gitignore`, now leaves the output
  directory out too. The file does not count among the files already in the
  output directory that the scan-set warning reports. snyk-code does not rely on
  it (see the next entry).
- **snyk-code does not scan a source directory that holds ASH's output
  directory.** With the default `.ash/ash_output`, snyk-code is now `ERROR` for the
  source, `snyk code test` is not started, and the error names the output
  directory. snyk would upload ASH's own output with the source, and that it
  honors the output directory's `.gitignore` is read from snyk's sources, not
  measured. Pass `--output-dir` with a directory outside the scanned tree to run
  snyk-code on the source; the converted files are still scanned as their own
  target. The examples on the Snyk plugin page now pass one.
- **A config file does not interpolate an `ASH_` variable named for a
  credential.** A reference to an `ASH_` name that ends in `_KEY`, `_TOKEN`,
  `_SECRET`, `_PASSWORD`, `_CREDENTIAL`, `_CREDENTIALS` or `_HEADER_VALUE`,
  compared case-insensitively, or to `ASH_MCP_AUTH_HEADER_VALUE`, is left as
  written, as a reference to an unlisted name is. The warning names the
  variable, never its value. Every other `ASH_` name, and `AWS_REGION`,
  `AWS_DEFAULT_REGION` and `AWS_PROFILE`, resolves as before.
- **A validation error no longer repeats the value it refused.** pydantic's text for
  one quoted every refused input (`input_value='...'`). A config value can be a
  secret read from the environment, and the text reached the console, `ash.log`,
  results files and MCP responses wherever an error was shown. These models now hide
  inputs in their errors: the config, results and workspace models, every plugin
  class and its config and options classes, and the SARIF, CycloneDX and other
  models ASH validates on their own. The field and the problem are still named. A
  workspace policy file's refusal still shows the value the file wrote, since nothing
  in it is read from the environment. A client's runtime patch that the patched
  config refuses is answered without the inputs, which hold the registered
  profile's values. ASH's own validators name the field and the rule in their
  messages, not the value, and so do the warnings logged when a plugin option is
  replaced by its default (a `tool_version`, opengrep's `version`, a report file
  name, a reporter's `extension`). For example, a suppression's expiration is
  refused with "Invalid expiration date format. Use YYYY-MM-DD", and a
  `denied_paths` entry by its position.
- **Only the operator turns trivy-repo's telemetry on.** A config file inside a git
  checkout or the scanned directory could set
  `scanners.trivy-repo.options.disable_telemetry: false`, and trivy then sent
  anonymous usage data to its vendor on every online scan. Such a value is now
  ignored with a warning, and trivy gets `--disable-telemetry`. `true` still
  applies from any config, and `false` from `--config-overrides` or a config file
  outside every git checkout and the scanned directory; a file that leaves the
  option out keeps the operator's value. An MCP client's config was already
  refused for setting it.

- **`ash report` takes an off-host reporter's `enabled` and destination from
  `--config-overrides` only.** Stored results do not record which tree was scanned,
  so a `--config` file, or the file `ASH_CONFIG` names, may be the scanned
  repository's own `.ash/.ash.yaml`: a CI job that scanned a directory and ran
  `ash report --format s3 --config <that directory>/.ash/.ash.yaml` from another
  one sent the findings to the bucket the repository chose, when that directory
  was not a git checkout. Now such a file's `enabled` and destination options for
  the S3, CloudWatch Logs, Security Hub and Bedrock summary reporters (and for a
  plugin reporter's declared destination options) are ignored with a warning that
  names the override to pass, as for a config file inside the scanned tree. Its
  other settings, such as a local reporter's options, still apply. An operator who
  enabled one of these reporters for `ash report` in a config file passes
  `--config-overrides reporters.<name>.enabled=true` and its destination options
  instead. `ash merge --config` is held the same way, since the shards do not
  record which tree was scanned either: a merge run beside such a directory with
  `--config <that directory>/.ash/.ash.yaml` uploaded to the repository's bucket.

- **A `${VAR}` reference with no default now reads the variable, and a
  configuration that references an unset one is refused with exit code 3.** This
  applies to both spellings, a bare `${ASH_MY_BUCKET}` and `!ENV ${ASH_MY_BUCKET}`,
  in a YAML, TOML or `pyproject.toml` config. Such a reference was never read: it
  loaded as the literal text `${ASH_MY_BUCKET}` whether or not the variable was
  set, and when it was unset ASH also logged "Environment variable ASH_MY_BUCKET
  not set, using default value of" and still used that text. The reference now
  resolves to the variable's value. When the variable is not set, `ash scan
  --config`, `ash merge --config` and every other reader of the file refuse it
  instead, with an error that names the variable and, for the file itself, the
  file; for a reference in a file it `extends`, the error names the chain's root
  and not the base. Write `${VAR:None}`, or another default, for a variable that
  may be unset: a reference with a default behaves as before. Which variables a
  config may read is unchanged: names beginning with `ASH_`, plus `AWS_REGION`,
  `AWS_DEFAULT_REGION` and `AWS_PROFILE`. A reference to any other name, with or
  without a default, is still left as written and never read.
- **What ASH writes of a configuration holds a value read from the environment as
  its reference, never the value.** A scan records its configuration in
  `ash_aggregated_results.json`, and with `${VAR}` now read, that record held
  the variable's value. `ash merge` then copied the value into the merged results,
  and `--debug` printed it. Now the record holds each value and key a config file
  read from the environment exactly as the file wrote it: `${VAR}`,
  `${VAR:default}`, or `!ENV ${VAR}`, with any text after the reference. The
  reference is replaced only at its own position, so another field that happens
  to hold the same text keeps it. A reference whose variable is unset records the
  default the file wrote, and one that resolves to nothing records null. A `scanners`
  key read from the environment is recorded the same way in
  `metadata.expected_scanners`, and the body an off-host reporter sends holds
  references too. The scan itself, and the reports it renders, use the values.
  `ash merge` and `ash report` do not read the environment for a recorded
  reference. A free-text field loads back as the reference. A field that takes a
  fixed choice, a boolean or a number cannot hold one, so those commands exit 3,
  naming the field and the reference, unless `--config-overrides` or the file
  `--config` names supplies the field. Any other reader of the results takes that
  field's default, with a warning. Also changed:
  - MCP `get_config` shows such a value as `<from ${VAR}>`.
  - `ash config get` shows the reference.
  - `ash config update` and `ash config wizard` write the reference back, tagged
    `!ENV`.
  - The profile copies the MCP server writes for a session hold the reference.
    The scan reads the value from the environment when it loads the operator's
    copy, and from the operator's copy for the copy a client patched.
  - Debug and info lines that showed a config section, an override or the plugin
    context now name the keys and never the values. Lines naming a reporter's
    destination or a Bedrock model name the option or the reference instead.
  - A `patch` operation that fails names its op and path and no value.
- **`--mode container` and `--mode nix` refuse an unusable config before anything
  starts.** The config file the scan inside the image or Nix shell will use (`--config`,
  the file `ASH_CONFIG` names, or the one found in the source directory) is read on the
  host the way a local scan reads it. One that a local scan refuses with exit 3 (missing,
  not a regular file, unreadable, not UTF-8, not valid YAML, JSON or TOML, YAML aliases,
  not a valid config, or a discovered name that is a link to nothing) now refuses the run
  with exit 3 and the local scan's `Invalid configuration: ...` message, before any image
  is built or run, any mount, and any clearing of the previous run's output. The scan
  inside used to refuse it only after all of those. `--config-overrides` are applied on
  the host as well, so an override that does not parse or sets a value the config does
  not accept is refused the same way. The same read gives the host its
  `fail_on_findings` and `fail_on_incomplete_scanners`, so `ASH_CONFIG`'s file and an
  override that sets either now count in container and nix mode as they do in a local
  scan: nix mode used to decide the exit code without them, and container mode handed
  the scan inside the config file's value in place of the override's. A missing `--config` in container
  mode now reports `Invalid configuration: Configuration file not found: <path>`, where
  it said `Config file not found: <path>`. Plugin options are still checked by the scan
  inside, which loads the plugin. The `Invalid configuration` message no longer drops
  bracketed text, such as the `[type=..., input_value=...]` detail of a validation error.
- **A config file in an ops checkout no longer names tool config paths as the
  operator.** A config file inside any git checkout or the source directory may not
  grant sandbox access or choose the other limited settings, and that includes a
  checkout of your own. The tool config and plugin paths it names (such as
  `scanners.checkov.options.config_file`) now follow the same rule: they are passed
  to the tool only from outside every git checkout and the source directory. A config
  file in an ops checkout could point a tool at a file in that checkout before. Paths
  named with `--config-overrides`, by an environment variable, or in a config file
  outside every checkout keep the operator's rule and may be in an ops checkout. The
  warning for a refused path now ends "To keep a setting, move the file outside every
  git checkout, or pass the setting with --config-overrides."
- **semgrep, opengrep and bandit report PASSED only when they scanned a file.**
  Each now records how many files it scanned: semgrep and opengrep from the
  `--json-output` they are given (with `--verbose`, for the skipped paths), bandit
  from the per-file metrics in its SARIF. None scanned because the `--exclude`
  patterns (semgrep, opengrep) left out every file the tool found, or while bandit
  had Python files it was not told to exclude, is `ERROR`, naming the count. None
  scanned with nothing to scan, such as bandit on a tree with no Python file or
  with all of it excluded on purpose, or detect-secrets with every file of the
  scan set ignored, is `SKIPPED`. Both used to be `PASSED` with no findings.
- **A run in which no selected scanner had a file to scan exits 1.** A scanner
  with nothing of its kind to scan is now `SKIPPED` instead of `PASSED`, and a run
  in which every scanner is `SKIPPED` already exited 1 under
  `fail_on_incomplete_scanners` (the default), since it scanned nothing. So a scan
  whose config ignores every file, or `--scanners bandit` on a tree with no Python
  file, now exits 1 where it exited 0, and `ash merge` over such shards does the
  same. `--no-fail-on-incomplete-scanners` (config:
  `fail_on_incomplete_scanners: false`) still gives 0. The error says which
  scanners had nothing to scan, names `global_settings.ignore_paths` and suggests
  narrowing it when the config sets it, and gives that remedy, where it said "Scan
  ran no scanners". A run whose scanners were all `SKIPPED` for another reason
  keeps that message.
- **A scan uses only the plugin modules it names.** A scan's converters,
  scanners, reporters and event handlers are ASH's built-in ones plus those of the
  modules its own `ash_plugin_modules` and `--ash-plugin-modules` name. This holds in
  a process that runs several scans, the MCP server included: a module named for an
  earlier scan, whether by a repository's config, the operator or one MCP session's
  profile, or loaded by the `list_scanners` tool, takes no part in a later scan that
  does not name it.
  - Embedding code that registers plugin classes itself should define them in a
    module inside the plugin namespace (a package named `ash_plugins` or ending in
    `_ash_plugins`) and name that module in the scan's `ash_plugin_modules`. A class
    registered from a module the scan does not name is not used by it.
  - Event handlers the embedding program subscribes from outside the plugin
    namespace are still notified in every scan it runs.
- **The AWS reporters are disabled by default.** The Security Hub, CloudWatch
  Logs, S3 and Bedrock summary reporters shipped `enabled: true`, so loading
  `ash_aws_plugins` (by any earlier scan in the process, an MCP server, or a config
  naming it) was enough for a scan to build each of them and run its dependency
  check, which contacts AWS with the host's credentials: Security Hub called
  `DescribeHub`, the others STS. Each now ships `enabled: false`; turn one on with
  `enabled: true` in its section of your config or with `--config-overrides`.
  - A run logs one warning for each of these reporters whose config section sets
    options but not `enabled`, naming the reporter and the key to set
    (`reporters.<name>.enabled: true`). It names no option value, changes
    nothing, and is not logged when the requested `--output-formats` leave the
    reporter out. `ash merge` names the operator's `--config` sections the same
    way.
  - A reporter's dependency check now runs only for the reporters a run will use:
    the requested `--output-formats` are applied first, so `-f sarif` checks no AWS
    reporter, and workspace reporting no longer checks a per-project reporter at
    workspace level.
  - `ash report --format <aws reporter>` refuses a reporter that is not enabled and
    exits 1, instead of sending the stored findings.
  - `ash merge` runs an AWS reporter only when the operator's own `--config`
    (new) enables it, and builds it from that config. The configuration the
    shards recorded is ignored for these reporters in both directions, with a
    warning where it disagrees: it came with the shard results, not from the
    operator of the merge, and the reporter would send the merged findings with
    the collector host's credentials.
  - A reporter class declares `sends_off_host = True` when it sends findings to
    a remote service, as the four AWS reporters now do. Such a reporter runs in
    a scan, `ash report` or a workspace report step only when its config section
    sets `enabled: true`, whatever its own default. `ash report` used to
    recognize these reporters by their package name.
  - A workspace scan's `reports/workspace-reports.json` lists the per-project
    reports of a per-project reporter that ASH's default config leaves off (S3,
    CloudWatch Logs) wherever a project's config enabled it, instead of recording
    it as `skipped: disabled`.
  - The AWS reporters read `AWS_REGION`, `AWS_PROFILE` and Bedrock's
    `ASH_BEDROCK_*` variables when their config is built, not when the module is
    imported, so a process whose environment changes after the import (an MCP
    server, a test) gets the current values.

- **The archive converter enforces extraction limits, and an archive over one makes
  the scan incomplete.** `converters.archive.options` gains `max_members` (100000),
  `max_member_bytes` (256 MiB), `max_total_bytes` (1 GiB) and
  `max_compression_ratio` (100, checked once the members declare more than 512 KiB
  in all), inclusive maximums checked against what every member of an archive
  declares before anything is written, each member counted as at least 512 bytes.
  All the archives of one scan share a budget of four times `max_members` and four
  times `max_total_bytes`. An archive over any of them is
  not extracted at all, is recorded in `converter_results.archive.refused_inputs`
  with the limit named in `limit`, and counts as incomplete conversion: with
  `fail_on_incomplete_scanners` on (the default) the scan exits 1 and names the
  archive and the limit. No member is written past the size it declares, on either
  tar extraction path; a sparse tar member whose map reaches past its size is
  refused. A config file in the scanned tree, a workspace project's own config and a
  config an MCP client supplied can lower these limits but not raise them (a higher
  value is replaced by the trusted one, with a warning), and MCP runtime overrides
  of them are refused: they are in the default `runtime_overrides.denied_paths`,
  and refused on top of it when a profile sets its own `denied_paths`, so a
  profile's list no longer lets a client raise them and a whole-config write at the
  root pointer is refused even with an empty list. Raise them
  with `--config-overrides` or a config file outside the tree.

- **A workspace project counts incomplete conversion as a single-directory scan
  does.** A project whose converter crashed, whose converter tool was absent with
  inputs to convert (a missing nbconvert with notebooks in the project, for
  example), or whose archive was refused for an extraction limit used to pass inside
  a workspace while `ash --source-dir <project>` exited 1 on it. It is now
  `scan_incomplete` under `fail_on_incomplete_scanners` and names the converter in
  `incomplete_converters`, in the unified results, the workspace reports and the MCP
  workspace tools' project coverage.

- **Parsing a tar's headers is bounded.** tarfile reads an extended header, a GNU
  long name or a sparse map into memory while parsing the header, before the
  extraction limits can be checked. The tar stream is now read through a reader that
  refuses any single read over 1 MiB and bounds the header pass to 4 MiB plus 2 KiB
  per member; the decompressor is chosen from the archive's leading bytes. An
  archive over either is a failed input, as an unreadable archive is, and a sparse
  member whose map entries overlap or are out of order is refused.

- **An archive the converter cannot read makes the scan incomplete.** A `.zip`,
  `.tar` or `.gz` that zipfile and tarfile cannot read (a bad CRC, a truncated or
  damaged stream, an empty file) used to leave a log line, and a zip that failed part
  way left its first members on disk, where the scanners read them. A tar cut off
  between members or inside a header, or with a damaged header after the first, was
  read as a shorter archive: its first members were extracted and nothing was
  recorded. A tar's members must now end at an end-of-archive block, which GNU tar,
  bsdtar, `git archive` and Python's tarfile all write. An archive with a file member
  named like a directory an earlier member made was dropped as "skipping directory",
  leaving the members before it on disk. Two archives whose names fold to one
  target directory (`a b.zip` and `a-b.zip`) shared it, so the second one's partial
  output was not removed when it failed; each archive now gets a directory of its
  own. Each of these is now
  recorded in `converter_results.archive.failed_inputs` (the record a converter's
  input that could not be converted gets); anything written from it is removed; and
  with `fail_on_incomplete_scanners` on the scan exits 1 naming it. The summaries,
  `ash.flat.json` and `ash.sarif` list failed inputs with the refusals.

- **A single-file `.gz` is decompressed and scanned.** A `.gz` that is one compressed
  file rather than a tarball, such as `data.json.gz`, used to be passed over. It is
  decompressed to `data.json` within the extraction limits and the scan's budget,
  and scanned. A `.tar.gz` that holds no tar is a failed input. This changes the
  verdict for a large single-file gzip with a scannable inner name, such as
  `dump.sql.gz` or `data.csv.gz`: one that decompresses to more than a limit
  (256 MiB for `max_member_bytes` by default) was passed over before, and is now
  refused for that limit, which fails a default scan. Raise the limit with
  `--config-overrides converters.archive.options.max_member_bytes=<bytes>`, or leave
  the file out with `global_settings.ignore_paths`.

- **A Git LFS pointer named like an archive is reported, not failed.** A checkout
  without its LFS objects holds a pointer file where each LFS-tracked `.zip` or
  `.tar.gz` should be. It is recorded as a refused input naming the file and the
  remedy (fetch the LFS objects before the scan), and does not fail the
  completeness gate. Only a whole file in the LFS pointer format counts.

- **An archive inside an archive is recorded as not scanned.** Extraction is one level
  deep, as before, but a member named as an archive or compressed file (`.zip`,
  `.tar`, `.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.jar`, `.whl`, `.7z`, `.rar` and the
  like, in any case) used to be left out without a trace. It is now a refused member
  of its archive, with a warning, and does not change the exit code. Past the first
  20 refusals of a reason in one archive, the rest are counted in one record
  (`unlisted_members`) rather than listed. The list also covers `.tar.Z`, `.lz4`,
  `.tzst`, `.apk`, `.deb`, `.rpm`, `.nupkg` and other package formats, and a name
  with a trailing dot (`lib.zip.`).

- **An archive in the tree that is not extracted is recorded.** Only `.zip`, `.tar`
  and `.gz` files are extracted. A `.tgz`, `.tar.bz2`, `.tar.xz`, `.7z`, `.jar` or
  `.whl` in the scanned tree used to get no record at all, so a tree whose only
  archive was `release.tgz` reported no archives. Each is now a refused input that
  says it was not extracted, with a warning; it does not change the exit code.

- **Every input a converter did not read is in the reports.** The console summary,
  `ash.summary.txt`, `ash.summary.md`, `ash.flat.json` (`converter_refusals`, always
  present) and `ash.sarif` (one execution notification per input, `error` for an
  archive over a limit, `warning` otherwise) list them; before, they were in `ash.log`
  and `ash_aggregated_results.json` only. Names from the archive are shown as inert
  text: a code span per refusal in `ash.summary.md`, and control and
  bidirectional-formatting characters escaped in the text summary, on the console
  and in the log.

- **npm-audit's package managers read none of the scanned repository's settings
  files, and run no file it names.** npm, pnpm and yarn ran in the package's
  directory, so the repository's `.npmrc` (and, for pnpm, `pnpm-workspace.yaml`),
  `.yarnrc` and `.yarnrc.yml` chose the registry the dependency list was sent to, the
  proxy, TLS settings and cache; and yarn ran the JavaScript file a `yarn-path` or
  `yarnPath` names in place of itself, ASH's own `yarn --version` included (measured
  with npm 10.9.4, pnpm 12.6.0 and yarn 1.22.22). npm and pnpm now run from a private
  copy of the package's `package.json` and lockfile, whose audit requests were
  identical to the in-tree ones, workspaces included; yarn runs from a copy outside
  the scanned tree of its lockfile and every `package.json` below it, with
  `YARN_IGNORE_PATH=1`. Your own `~/.npmrc`, global npmrc and `~/.yarnrc` still apply,
  so private registries and their credentials are unaffected. Under `--sandbox`,
  where the tool's home is private, yarn runs in place reading no settings file. A
  `pnpm.auditConfig` advisory ignore list in the repository's `package.json` counts
  as a repository suppression: it applies, and `--ignore-suppressions` removes it.
  Offline npm-audit still runs no package manager.

- **npm-audit does not audit a package whose files link out of the scanned tree.**
  ASH found a lockfile by name and npm, pnpm and yarn follow links, so a
  `package-lock.json` linking to a file elsewhere on the host, next to a real
  `package.json`, was read by each (measured offline under bwrap: npm counted its
  packages, pnpm parsed it, yarn quoted it in an error). Every file the tool reads
  from the package (`package.json`, its lockfiles including `npm-shrinkwrap.json`,
  and for yarn every workspace `package.json`) now has to resolve inside the scanned
  tree and be a regular file. A package with any other is not audited: the file is
  listed as not scanned ("link leaves the scanned tree") and npm-audit is ERROR, so
  the scan exits 1, as when an audit fails. Links within the scanned tree are
  followed as before, and a linked workspace member inside the tree is now copied
  for yarn, where it used to be left out.

- **A workspace with an incomplete project exits 1, even when another project has
  findings.** A project that failed, or whose scanners did not all complete
  (`scan_incomplete`), now ranks above actionable findings, as in a
  single-directory scan, so `ash --source-dir P` and P inside a workspace give the
  same code. A workspace that exited 2 with one project over its threshold and
  another incomplete now exits 1. Findings are still in each project's
  `exceeds_threshold` and counts, and in every summary; a gate that has to block on
  findings whatever else happened should read them there. A misconfigured project
  (3) still ranks first.
- **trivy-repo and syft read no config file from the scanned tree, online or
  offline.** A `trivy.yaml` in the scanned repository
  could turn on a VEX repository download or client/server mode, and a `.syft.yaml`
  remote license and package lookups; both reached the network with every offline flag
  ASH passed, and online both decided what was reported. trivy now always gets
  `--config` naming the operator's `scanners.trivy-repo.options.config_file`, else
  `TRIVY_CONFIG` when that is outside the tree, or an empty config ASH ships, and
  syft runs from outside the tree and is given only a `config_file` outside it. A repository that tuned trivy or syft through those files gets their
  defaults; put the settings in a file outside the tree (`TRIVY_CONFIG`,
  `scanners.syft.options.config_file`). Offline, trivy's version check and telemetry
  are turned off by `TRIVY_SKIP_VERSION_CHECK` and `TRIVY_DISABLE_TELEMETRY`, which an
  older trivy ignores, rather than by flags it would refuse.

- **Offline, npm-audit audits nothing, says so, and is MISSING instead of PASSED.**
  npm, pnpm and yarn audit only against the registry's advisory service: offline,
  `npm audit --json --offline` on a lockfile pinning a version with known advisories
  exited 0 with none, `pnpm audit --offline` sent the dependency list to the registry
  anyway, and `yarn npm audit` has no offline mode. npm-audit was graded PASSED with
  zero findings, and only a log line said a pnpm or yarn 2+ lockfile went unaudited.
  Offline, npm-audit now starts no package manager; every lockfile it would have
  audited is recorded as not scanned, with the reason, in the scanner's
  `inputs_not_scanned` in `ash_aggregated_results.json`, on the console after the
  summary table, and in a new "Inputs not scanned" section of `ash.summary.md` and
  `ash.summary.txt`. A workspace scan lists every project's, with workspace-relative
  paths: in a new `inputs_not_scanned` list on each project's entry in the workspace
  results, in the merged summaries, and after the per-project lines of the workspace
  console summary, whose line for an incomplete project now reads FAIL with the
  scanners that did not complete rather than `pass`. When there was a lockfile to audit, the scanner is MISSING, as
  snyk-code is offline, so an offline scan of a Node.js project now fails under the
  default completeness gate (`fail_on_incomplete_scanners`) with exit code 1. Pass
  `--exclude-scanners npm-audit` to scan offline without it. A project with no
  lockfile has nothing to audit and is SKIPPED. The same applies when
  `scanners.npm-audit.options.offline` is true with ASH online: npm-audit no longer
  runs `npm audit --offline` against a local cache.

- **Offline, trivy-repo does not run trivy's Terraform checks.** trivy downloads the
  source of every `module` block in the scanned Terraform, from the registry, with the
  host's `git` and its credentials, or over HTTPS, whatever offline flags it is given;
  in an offline scan with the trivy plugin enabled that was the only request left.
  Offline, ASH now passes `--misconfig-scanners` with the installed trivy's default
  list minus `terraform` (or, when that list cannot be read, leaves `misconfig` out),
  and logs a warning. checkov still checks Terraform. Any `git` a scanner tool runs
  offline gets `GIT_ALLOW_PROTOCOL=file`. See
  [What offline mode turns off](docs/content/docs/advanced-usage.md#what-offline-mode-turns-off).

- **detect-secrets verifies secrets only when the operator turns it on, and never
  offline.** Verification sends each candidate secret to the service that issued it;
  for an AWS key that is a request to `sts.amazonaws.com` signed with the key pair
  found in the scanned file. Its filter came from whatever settings the scan used, so
  a repository's `.secrets.baseline` (which `detect-secrets scan` fills with the
  filter), its `.ash/.ash.yaml`, a workspace project's config, an MCP client's config,
  or a `baseline_file` outside the tree named by any of them made the scanning host
  contact the issuer, and `--offline` did not stop it without `--sandbox`. Now the
  filter is kept only from the operator's own configuration (a config file outside the
  scanned tree and every git checkout, `--config-overrides`, the MCP session's
  profile, or a baseline such a config names outside the tree and the git checkout
  holding it, which may sit in another checkout), and only online;
  from any other source ASH removes it and logs a warning naming the source, and when
  verification is off the detect-secrets worker refuses every HTTP request. Candidates
  the issuer would have rejected are now reported, so a repository whose own baseline
  verified can show more detect-secrets findings. An MCP client's runtime overrides
  (`select_profile` patches and override YAML, workspace `config_overrides`) cannot set
  detect-secrets' `filters_used`, `plugins_used` or `baseline_file` either: the shipped
  `runtime_overrides.denied_paths` deny them, as they deny the sandbox and
  `ash_plugin_modules`. The same rule now decides which plugin and filter files
  detect-secrets imports: a `file://` entry in `plugins_used` or `filters_used` from a
  repository's config, its `.secrets.baseline`, an MCP client's config or a baseline
  any of them names is removed with a warning, wherever the file is (one outside the
  tree is any file on the host, and the worker imports it); the operator's own entries
  are kept. An operator's `--config-overrides` naming a baseline outside the tree and its checkout
  verifies beside a repository's own config, and an operator's verification filter is
  kept when the tree's `.secrets.baseline` supplies the plugins and other filters. To
  keep verifying, name the filter with its `min_level` in
  `scanners.detect-secrets.options.scan_settings.filters_used` of your own config:
  `{path: detect_secrets.filters.common.is_ignored_due_to_verification_policies,
  min_level: 2}`. detect-secrets reads `min_level` and the scan fails without it. See
  [Secret verification](docs/content/docs/configuration-guide.md#secret-verification).

- **Container mode builds ASH's own Dockerfile, never one in the working directory.**
  `ash --mode container` and `ash build-image` used to build a `Dockerfile` in the
  directory they were started from (with a `pyproject.toml` beside it, for an ASH
  installed from git), or the nearest such pair above it, with that directory as the
  build context, and tag the result as ASH's image. A pinned revision now always
  builds the packaged Dockerfile. A `LOCAL` revision builds the Dockerfile at the root
  of the ASH source tree the running package was installed from, found from the
  package itself or from the installer's `direct_url.json`; an installation with no
  such tree (for example, one from a wheel file) is refused with what to do instead.
  An installed package (in `site-packages`, or with its dist-info beside it) is not
  taken for a clone whatever files sit beside it (a `Dockerfile`, `docs/`, `tests/`
  and the like).
  See [Which Dockerfile ASH builds](docs/content/docs/building-your-own-image.md#which-dockerfile-ash-builds).
- **Container mode always mounts the source directory read-only.** `ash --mode
  container`, `./ash` and `Invoke-ASH` used to mount `/src` read-write whenever the
  output directory was inside the source directory, which the default
  `.ash/ash_output` is, and the test was a string prefix, so a sibling such as
  `<src>-out` counted as inside too (`Invoke-ASH` matched a substring anywhere in the
  path). The output directory has its own mount at `/out`, so `/src` is now read-only
  in every case. See [Running a scan in a container](docs/content/docs/cli-reference.md#running-a-scan-in-a-container).
- **CI variables no longer select the root `ci` image stage.** `ash --mode container`
  and `ash build-image` built and ran the `ci` stage, which runs as root, whenever
  `CI`, `IsCI`, `ISCI` or `CODEBUILD_BUILD_ID` was set to anything (`CI=false` and an
  empty value included), overriding an explicit `--build-target non-root`; `Invoke-ASH`
  defaulted to `ci` under `CI`, `IsCI` or `CODEBUILD_BUILD_ID` the same way. The stage
  is now the one `--build-target` (`-BuildTarget`) names, and `non-root` when none is
  given (`ci` on Windows, for `ash build-image`, `ash --mode container` and
  `Invoke-ASH` alike; `ash build-image` used to force `ci` there over an explicit
  `--build-target`, and `ash --mode container` built `non-root`). `ci` is also built
  on request and under `--custom-containerfile`. **What this changes for CI jobs:** a job
  that did not pass `--build-target` now gets the `non-root` image (and the
  `automated-security-helper:non-root` tag, and its own layer-cache scope on GitHub
  Actions). A job that runs as root (AWS CodeBuild, container-based GitLab or Jenkins
  jobs) cannot build `non-root`, whose user would get UID 0, and is refused before the
  build with that explanation (exit 3): pass `--build-target ci` there. `./ash` refuses
  it the same way, and so does `Invoke-ASH`, run as root or given `-ContainerUID 0`
  (exit 3, naming `-BuildTarget ci`); any spelling of zero such as `00` counts. A GID
  of 0, root's group, is refused for a `non-root` build in the same three places. A
  `--container-uid` or `--container-gid` holding anything but the digits 0-9 (`²`, `1x`)
  is refused as not numeric, by `./ash` and `Invoke-ASH` as well. All three refusals
  exit 3 from all three entry points; `ash --mode container` and `./ash` used to exit 1
  for them. See the breaking
  change above. This repository's
  validate-container action now passes `--build-target ci` to every build and scan.
- **Container mode refuses an output directory that is the source directory or above
  it.** `/out` is mounted read-write and `/src` read-only, so an `--output-dir` equal
  to `--source-dir`, or one of its parents, held the source tree writable through
  `/out`. `ash --mode container`, `./ash` and `Invoke-ASH` now refuse it with exit 3
  before anything is built or mounted, by real path. An output directory inside the
  source, such as the default `.ash/ash_output`, or outside it works as before; a run
  with `--no-run` mounts nothing and is not refused.
- **Container mode refuses an output directory that is a symlink or is reached through
  one.** The output directory is mounted read-write at `/out`, so with a linked one the
  scan inside the container wrote wherever the link led, and a repository committing
  `.ash -> /some/host/dir` chose that directory for the default `.ash/ash_output`.
  `ash --mode container`, `./ash` and `Invoke-ASH` now refuse, with exit 3, an output
  directory that is a symlink, wherever it is, and any symlink between the source
  directory and it, before the directory is created, written or mounted. That includes
  `--no-run`, since the output directory is created and `ash --mode container` opens
  `ash.log` in it either way. The source directory counts under the name it was given
  and its real path; links at or above it are your own spelling and are not examined.
  This is the rule a sandboxed local scan already applies.
- **The image pipeline's MCP container keeps the auth header value out of the
  environment.** `ash-container-init` exported the value it read from Secrets Manager
  as `ASH_MCP_AUTH_HEADER_VALUE`, so `ash mcp` and every process it started inherited
  it, and a config reference such as `${ASH_MCP_AUTH_HEADER_VALUE:}` copied it into the
  effective config. It now hands the value over in an in-memory file named by
  `ASH_MCP_AUTH_HEADER_VALUE_FD`; `ash-mcp-serve` reads and closes it, and removes that
  variable and a directly set `ASH_MCP_AUTH_HEADER_VALUE` before it starts `ash mcp`.
  A custom command run in place of `ash-mcp-serve` with `ASH_MCP_AUTH_SECRET_ARN` set
  gets the descriptor instead of the variable.
- **An explicit runner path is now used as given.** `Invoke-ASH -OCIRunner
  /path/to/podman` kept only the name `podman` and ran whichever `podman` came first on
  `PATH`. It now runs the file at the path, passed to `Invoke-Expression` by name like
  every other path, so a path with spaces or `$(...)` in it is that path. A bare name
  is looked up on `PATH` as before. `./ash` (`OCI_RUNNER`) and `ash --mode container`
  (`--oci-runner`) already ran the path they were given, and now have tests that
  pin it.
- **A container workspace scan limits a `--config` the repository could have written.**
  A one-directory container scan marks a config from outside `--source-dir` that is in
  a git checkout (`--config-from-scanned-repository`), and the scan inside limits it as
  repository-written. A workspace scan inside the container refused that mark, so in
  workspace mode the host passed such a config unmarked, and the scan inside gave it
  the operator's grants (`sandbox.extra_read_paths` and the other sandbox settings).
  `ash --mode container --workspace` now marks a config in another git checkout, such
  as an ops repository beside the workspace, and the workspace scan inside treats it,
  and every file it extends, as repository-written for every project and for the
  plan, as a local workspace scan does: the same five confinements and the same
  warnings. No file's `sandbox.mode` applies inside: container mode runs the scan
  there with `sandbox.mode=off` as the last override, because the container is the
  boundary. In a one-directory scan and a
  workspace scan alike, the scan inside holds that verdict as a mark on the mounted
  files, so its warnings call the file repository-written, as the host's do. A config
  in the checkout around the workspace root, or reached through a link there, is
  refused with exit 3 before anything is built, mounted or cleared. Keep `--config`,
  and every file it extends, outside every git checkout. A config inside the
  workspace root is refused as in a local workspace scan, because the operator's
  config may not be one of the workspace's files; one outside every checkout is used
  as before. `./ash` and
  `Invoke-ASH`, which scan one directory and hand the scan inside `--source-dir /src`,
  now refuse a `--workspace` passed through with exit 3 instead of starting a
  container that refused it.
- **In a container scan, an operator's config keeps its own sandbox settings when only
  a base it extends is in a git checkout.** On the host, a `--config` outside every
  checkout that extends a base inside one keeps the sandbox section it writes itself,
  and the base grants nothing. Container mode marked the whole chain for the scan
  inside, so there the config lost its own section too. The host now marks each base
  that is in a checkout on its own (`--config-file-from-scanned-repository`, by its
  path inside the container), in one-directory and workspace scans, and the scan
  inside applies the same split the host does. A config that is itself in a checkout
  is still marked with every file it extends, and one outside every checkout with no
  base in one is not marked. The scan inside refuses a mark for a file that is not in
  the config's chain, without `--config`, or outside local mode, with exit 3.
- **Container and nix mode read `ASH_CONFIG`'s file beside a `--config`, as a local scan
  does.** A local scan reads the file `ASH_CONFIG` names first, whatever names the
  config: it is the base the settings a repository-written config may not choose come
  from, and a file there that does not load refuses the scan with exit 3. Container and
  nix mode read it on the host only when nothing else named a config, so with a valid
  `--config` a broken `ASH_CONFIG` file started the image or the Nix shell, and the scan
  inside a container never saw the file, taking ASH's defaults as its base. The host now
  refuses such a file with exit 3 before anything is built, run, mounted or cleared, in
  both modes, and container mode hands the file to the scan inside, mounted under
  `/ash-env-config` and passed with `--ash-config-from-host`, which the scan inside
  reads as `ASH_CONFIG`. Each file of its chain a local scan would count as
  repository-written is marked on its own. The scan in a Nix shell reads `ASH_CONFIG`
  itself.
- **`./ash` and `Invoke-ASH` mark a `--config` reached through a link in a checkout.**
  A local scan, and `ash --mode container`, count a config as repository-written
  when a symlink its path follows sits in the scanned tree or in any git checkout,
  even though neither the path given nor the file it resolves to is in one: whoever
  wrote the link chose the file. The two wrappers checked only the path given and
  the resolved file, so a config named `ops/cfg.yaml`, linked to a link in the
  scanned checkout that leads to a file outside it, went to the scan inside unmarked
  and kept its sandbox grants there. Both wrappers now follow the path one component
  at a time, at most 40 links, and pass `--config-from-scanned-repository` when any
  link on the way sits in the scanned tree or a checkout. A chain of links outside
  every checkout is used as before.
- **Every warning that drops a setting from a config file says how to keep it.** A
  config file inside a git checkout, or inside the scanned directory, may not choose
  the sandbox grants, `ash_plugin_modules`, the reporters' destinations, the
  scanners' own config files, `tool_version`, the content database staleness
  policy, detect-secrets' verification and `file://` plugins, `honor_ignore_files`,
  or a higher archive extraction limit, and ASH warns when it drops one, naming the
  file and the setting. Each of those warnings now ends with the same remedy: "To
  keep a setting, move the file outside every git checkout, or pass the setting with
  --config-overrides. A file inside the scanned directory has to move out of it as
  well." Before, the warnings said to use a config file outside the scanned tree,
  which a file in another checkout is too, and detect-secrets' warning gave no
  remedy. Their reason now says the config is inside a git checkout or the scanned
  tree, or an MCP client delivered it. `ash merge`'s warnings about a shard's config
  say "To keep a setting, pass it with ash merge's --config-overrides or --config."
- **`Invoke-ASH` builds the non-root user with the caller's IDs on Linux and macOS.**
  Without `-ContainerUID` and `-ContainerGID` it built the Dockerfile's default UID 500
  and GID 100, which cannot write an output directory the caller owns, and checked
  only the IDs it was given. It now takes the caller's own (`id -u`, `id -g`), as
  `./ash` and `ash --mode container` do, and refuses a UID or GID of 0 from either
  source the same way, so a root caller with `-ContainerUID 1000` and GID 0 is refused
  too. Windows keeps the Dockerfile's defaults.
- **On Windows, container mode and `ash build-image` default to the `ci` stage.** The
  output directory is bind-mounted into the container, and on Windows the runtime does
  not map write permissions onto that mount, so the `non-root` user could not write
  its reports and logs there. With no `--build-target`, `ash --mode container`, `ash
  build-image` and `Invoke-ASH` therefore build `ci` on Windows (`ash --mode container`
  built `non-root` there before). An explicit `--build-target non-root` still builds
  `non-root` on Windows, and `ash build-image --build-target non-root`, which used to
  build `ci` there regardless, now builds what it names.
- **Container mode reads the config file you named.** `--config` (or `ASH_CONFIG`) was
  handed to the scan inside the container as the host path, which names nothing there,
  so that scan ran with the default config: none of the file's suppressions, scanner
  settings or thresholds applied. The file is now mounted read-only (with its `extends`
  chain, for one outside the source directory) and the inner scan is given the path it
  has in the container; one that is not an existing file refuses the scan with exit 3,
  as does an `extends` entry that names a base by absolute path, which inside the
  container is not the same file, a config named inside the scanned tree whose real
  path is outside it, a config file ASH cannot read, and a config outside
  `--source-dir` that extends a file inside it, or whose chain has a file of the
  scanned checkout extending a file outside it, or an entry whose written path would
  place its base outside `/ash-config` (one that leaves the config's directory and
  comes back by name, or climbs with `..` after a link to a directory at another
  depth; a local scan accepts such an entry). `./ash` and `Invoke-ASH`, which mount
  a config from outside the source directory without the files it extends, refuse one
  with an `extends` entry with exit 3.
  A config inside a git checkout (the scanned one or another) but outside
  `--source-dir` keeps the limits a local scan gives a repository-written config: the
  host decides with the local scan's rule, and passes the scan inside
  `--config-from-scanned-repository`, since it sees that file only at `/ash-config`.
  The same holds for `./ash --config` and `Invoke-ASH -Config`, which also honor
  `ASH_CONFIG` now, and for `run_ash_scan(mode=container)` called with no `config`,
  which hands `ASH_CONFIG`'s file to the container when the source directory has no
  config of its own, as a local scan uses it. In workspace mode, a `--workspace-config` policy outside the
  workspace root was not passed to the container at all, so its ceiling and policy
  scanners did not apply there; it is mounted and forwarded the same way, and a
  policy file named inside the workspace's tree whose real path is outside it, such as
  an `ash-workspace.yaml` that is a symbolic link out of the workspace, is refused with
  exit 3. A
  `config_base_gate` passed to `run_ash_scan` with container or nix mode is refused,
  because the ASH those modes run would read the config without it. See
  [Running a scan in a container](docs/content/docs/cli-reference.md#running-a-scan-in-a-container).
- **Container mode refuses a mounted path that `--mount` cannot carry.** A comma, a
  double quote, a carriage return or a line feed in the source or output directory, the
  config file or a file it extends, or the workspace policy now refuses the run with
  exit 3 before anything is built. `--mount` reads its value as comma-separated
  fields, so such a character was read as part of the mount options.
  The same holds for `./ash` and `Invoke-ASH`.
- **A container scan refused for its inputs keeps the previous run's output.** A
  `--config` that could not be handed to the container, or a path `--mount` cannot
  carry, refused the scan with exit 3 only after the previous run's results and reports
  had been cleared from the output directory. The inputs are now checked first.
- **`Invoke-ASH` refuses by throwing with `$LASTEXITCODE` set to 3, and passes each path
  as written.** Its refusals wrote their message with `Write-Error` and then ran
  `exit 3`. Under `$ErrorActionPreference = 'Stop'` (every `pwsh` step on GitHub
  Actions) the `Write-Error` ended the script with exit 1 first, and in a script that
  dot-sources `utils/ash_helpers.ps1` the `exit` ended that whole script before it
  could handle the refusal. Every refusal now sets `$LASTEXITCODE` (3, or 1 when no OCI
  runner is found) and throws; nothing in the helpers calls `exit`, so a caller can
  catch the error and go on, and a `-NoExit` session stays open. Any other error
  `Invoke-ASH` raises leaves `$LASTEXITCODE` non-zero too. Uncaught, `pwsh -File`
  exits 1, as PowerShell does for any uncaught error, so a CI step that needs exit 3
  wraps the call: `try { Invoke-ASH ... } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }`,
  and on GitHub Actions runs with `shell: pwsh -File {0}`, since the built-in
  `shell: pwsh` reports every non-zero exit as 1 (the CLI reference gives the full
  step). This repository's run-scan-test action does.
  It refuses a non-root build when it runs as root (`id -u` is 0) without
  `-ContainerUID`, or with `-ContainerUID 0` or `-ContainerGID 0`, exit 3, naming
  `-BuildTarget ci`; a `-ContainerUID` or `-ContainerGID` that is not a number, exit 3;
  and a `-Config` outside the source directory with an `extends` entry, exit 3, since
  it mounts such a config without the files it extends. The build and run commands it hands to
  `Invoke-Expression` had the source, output and config paths, the image name and the
  other values spliced into the string, which PowerShell parses. They are now passed
  by name, so each reaches the runner as written, `$(...)` included.
- **`./ash` mounts the directory you named, or stops.** A `--source-dir` it could not
  enter (one that does not exist) left the working directory in its place, and that
  was mounted and scanned; it now exits 1, as `ash --source-dir` does, and so does an
  `--output-dir` it cannot create. It also exits 1, before building, for a `non-root`
  build whose UID or GID would be 0 and for a `--container-uid` or `--container-gid`
  that is not a number. A config, source or output path starting with `-` is
  no longer read as options by `dirname`, `basename`, `readlink`, `cd` or `mkdir`, which
  resolved it to the wrong file or to none.
- **The container image no longer has directories every user can write.** `/deps`,
  the grype database cache and the offline semgrep and opengrep rule caches under it
  were mode 777, and `/.ash/bin`, first on `PATH`, was `chmod -R 777`. They are
  root-owned and writable by root only. The grype database
  cache is owned by the user the image runs as (root in `ci`, the unprivileged user in
  `non-root`), because its update writes it at scan time; in an offline image, which never
  updates it, it stays root's. A `non-root` image started under another UID than it
  was built with can therefore no longer update grype's database, and grype reports
  ERROR, failing the scan, where it used to write the shared cache. `/src` and `/out` stay
  writable by every user in the `ci` stage, now with the sticky bit. Files an
  installer left writable by every user elsewhere in the image (uv's lock files at 666,
  some gems' files under `/var/lib/gems` at 777) lose group and other write too. See
  [Who can write to the image's directories](docs/content/docs/building-your-own-image.md#who-can-write-to-the-images-directories).
- **`--log-level` is passed to the scan inside the container.** It was dropped; only
  the levels the host also expresses as `--debug`, `--verbose` or `--simple` got
  through, so `--log-level ERROR`, `QUIET` or `TRACE` left the inner scan at INFO.
- **`--ignore-suppressions` lifts `ignore_paths` for every scanner.** With the
  flag, the files under an ignore path are converted and read by every scanner,
  and their findings are reported. Before, the flag lifted ignore paths only in
  the results: a scanner that reads the whole directory, such as bandit, reported
  those findings, while a scanner ASH hands a file list, such as detect-secrets,
  never read the files, so the verdict on the same file depended on the scanner.
  Container mode now passes the flag to the scan inside the container, which
  applies the suppressions; before, suppressed findings stayed out of the reports
  and out of the exit code the host computes from them. A scanner
  from a plugin module is passed an empty `global_ignore_paths` under the flag.
  Findings located in ASH's own output directory, outside its `converted` work
  directory, stay out of the results with the flag, as they do without it;
  before, the flag let them through. A scan with the flag reads more files, and
  takes longer when an ignore path leaves out a large part of the tree.

- **An MCP client's `enabled: false` no longer turns off an AWS reporter the
  server runs.** Whether the Security Hub, Bedrock summary, CloudWatch Logs and S3
  reporters run, and a plugin reporter that declares `destination_options`, comes
  from the server's config in both directions, as it does for a repository's
  config (see Breaking changes). A client's `enabled: false` for one of them, in a
  config file it delivered or named, in `select_profile`'s `patch_ops` or
  `override_yaml`, or in the MCP workspace tools' `config_overrides`, is still
  accepted rather than refused, but it takes no effect: the server's `enabled`, or
  the reporter's own default where the server's config sets none, applies, and a
  warning names the client's value. Before, the client's value turned the reporter
  off. `enabled: true` is still refused, and so is a `patch` op in a delivered file
  that writes `enabled`, whatever value it writes, as every `patch` op on a denied
  path is. A server run with no operator config of its own gives each reporter its
  default.

- **Under the MCP server, a config file the operator did not set aside resolves no
  `!ENV` for a remote client.** `!ENV` reads the server's environment. For a remote
  caller, every file outside `ASH_MCP_ALLOWED_CONFIG_ROOTS`, other than the profile
  files the server writes in the session's own `config/` directory, is refused with
  a config error naming the file if it uses
  `!ENV` (`error_type: config_env_not_resolved`): a file the client delivered or
  names, one found in a directory it names, a scan target's own `.ash.yaml`, and
  every base such a file extends. Before, each resolved, and `get_config` returned
  the value. Over stdio only a file under the MCP workspace root is refused, and a
  repository config the local user names keeps `!ENV`. To use `!ENV` in a remote
  scan, move the setting into a registered profile or a file under
  `ASH_MCP_ALLOWED_CONFIG_ROOTS`. The session config `select_profile` writes, and a
  suppression `ash inspect` adds, keep a value shaped like `${VAR:default}` as
  written instead of resolving it when read.

- **A config file an MCP client delivered may not change a field the session's
  runtime-override policy denies.** That covers an upload named as
  `config_path`, a delivered tree's own `.ash.yaml`, a project config in a
  delivered workspace, and every such file in an `extends` chain. Before, only
  `patch_ops`, `override_yaml` and workspace `config_overrides` were checked
  against `denied_paths` and `denied_value_patterns`. A value equal to the
  server's is accepted, so an `ash config init` file scans. `sandbox` and
  `ash_plugin_modules` may restrict the server's settings, and a file that asks
  for more than they give (network for another scanner, another read path,
  another sandbox mode, a module inside the tree or one that sends findings off
  the host) is refused, where before the extra was left out with a warning. A
  file that changes a denied field is refused with the field named
  (`error_type: config_field_denied`), and `validate_config` reports it. If that
  check cannot finish on a client's file, `validate_config` reports the file
  invalid and `run_ash_scan` does not start the scan. A config
  path a client names counts as the client's unless it is in a directory
  `ASH_MCP_ALLOWED_CONFIG_ROOTS` names or is a profile file the server writes in
  the session's own `config/` directory (`ash.yaml`, or a per-call profile named
  `call-profile-` and 16 lowercase hex digits, or `call-profile.yaml`), so a
  config in another checkout the server may scan is checked the same way, and so
  is a link a client delivered, wherever it points. Neither the session's
  `config/` nor its `client-config/` directory may be a scan target or a
  workspace `output_dir`, so no scan writes a file there. To use such a file as
  the operator's, put it in a directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names. A
  profile whose `denied_paths` equals a default ASH shipped earlier gets the
  current default list. When
  the policy cannot be established, a config with a delivered file is refused
  with `error_type: config_policy_unreadable`. A delivered tree's own
  suppressions and ignore paths apply, marked `client_supplied` in the results,
  unless the profile's own `denied_paths` lists them. A profile's own
  `denied_paths` now adds to the default list rather than replacing it, so
  listing one more field lifts no default entry, and a warning names the default
  entries a list that holds some of them leaves out; set
  `replace_default_denied_paths: true` to use the list as written, and each
  default entry it leaves out is named in a warning. An entry, or a
  `denied_value_patterns` key, that does not start with `/` matched nothing and is
  now refused when the config is read. Files under a
  client-supplied ignore path are still converted and scanned, and each finding
  there is kept as a marked, suppressed result. ASH sets the mark: a
  `client_supplied` value written in any config file or override is ignored.
  A workspace policy file a client delivered gets the same treatment, under the
  MCP server or `ash --workspace`: its suppressions and ignore paths are marked,
  and they and the scanners it adds are checked against the runtime-override
  policy, as written and as each project gets them. The policy comes from the
  registered profile, never from the session's patched copy, and
  `/global_settings/mcp` joins the default `denied_paths`. Delivering source
  while a scan of the session runs is refused, and `set_source_git` and
  `set_source_zip_finalize` both report it with
  `error_type: SourceDeliveryBusyError`. See
  [Config files in delivered source](docs/content/docs/mcp/streamable-http.md#config-files-in-delivered-source).

- **A config file reached through a symlink is judged by the link as well as by
  the file it reaches.** The file a delivered tree's `.ash/.ash.yaml` links to,
  wherever it is, is checked against the session's runtime-override policy, its
  suppressions and ignore paths are marked `client_supplied`, its scanner
  exclusions are reported rather than applied, and it resolves no `!ENV`, as a
  file written in the tree would be. The same holds for a link anywhere on the
  way to a config file, such as a linked `.ash` directory, and for every base
  such a file extends, since the file that names a base chose it. A config that
  `--config` or `ASH_CONFIG` names through a link in a delivered tree may extend
  only files in that tree, not files beside the link's target. On the CLI, a
  repository config that links to a file outside the scanned tree is held to the
  limits of a config inside the tree. Workspace mode does the same when it plans
  and when it scans each project, and a project's `config_source` in the plan is
  the path in the project, not the file a link there reaches. A workspace policy
  file is judged the same way: a delivered `.ash/ash-workspace.yaml` that links
  elsewhere is the client's, so its entries are marked and the MCP workspace
  tools refuse it, one that reaches a file outside the directories the session
  may read config from is refused before it is read, and `workspace_config_source`
  is the path it was found or named at. A refusal names the path the client used,
  not the file the link reaches. A validation error for a config file an MCP
  client delivered or named gives the file and each problem's location without
  the values in the file (a key the schema does not have is shown as `<key>`),
  and a client's file that does not parse is reported by
  line and column without quoting it. The same holds for a workspace policy file
  a client delivered, and for any policy file under a remote MCP caller.

- **A value a client patched into its session profile is the client's.**
  `select_profile`'s `patch_ops` and `override_yaml` still change only the keys
  the profile's `runtime_overrides` allowlist permits, but a binding with either
  is now written to the session's `client-config/ash.yaml`, not `config/ash.yaml`,
  so `run_ash_scan`, `get_config`, `validate_config` and the workspace tools read
  it as a config the client delivered. A suppression or ignore path the patch
  added is marked `client_supplied`, a scanner exclusion it added (such as a
  `scanners.trivy-repo.options.ignore_file` in another checkout) is reported
  rather than applied, a bandit, grype or syft `config_file` it names is replaced
  by the profile's, and its sandbox settings are restrict-only. Before, the
  patched copy counted as the operator's, so all of these applied as the
  operator's would. The trusted base is the registered profile, written unpatched
  to `config/ash.yaml`, so the profile's own entries and grants still apply.
  The workspace tools' `config_overrides` are treated the same way: before, a
  value the allowlist accepted was honored as the operator's. A binding without
  a patch, or with an empty `patch_ops`, is still `config/ash.yaml` and the
  operator's, and it removes an earlier patched copy. A workspace tool's
  per-call `profile` is written to a file of its own per profile,
  `config/call-profile-<digest>.yaml`, and no longer replaces the session's bound
  config. A `denied_value_patterns` entry does not
  refuse the patched copy for a mapping key the server's config already has, so
  a patched profile that repeats the operator's keys is not refused for them; a
  key in any other delivered file is checked as before. See
  [A patched value is the client's](docs/content/docs/mcp/streamable-http.md#a-patched-value-is-the-clients).

- **A delivered config's exclusions in a scanner's own options are reported,
  not applied.** An entry it adds to bandit's `excluded_paths`, checkov's
  `skip_path`, opengrep's or semgrep's `exclude`, syft's `exclude` or
  ferret-scan's `exclude_patterns` is removed from the option before the scanner
  runs, and each finding of that scanner the entry would have left out is
  reported suppressed and marked client-supplied, like a finding under a
  client-supplied ignore path. syft lists every component and marks the ones an
  entry would have dropped with an `ash:clientSuppliedExclusion` property. A
  `scanners.trivy.options.ignore_file` or `scanners.trivy-repo.options.ignore_file`
  from a delivered config is not passed to trivy; the IDs in it are applied the
  same way, to that scanner's findings, when the file is a regular file inside
  the scanned tree, read without following a link. The operator's own entries
  apply as before. The scanner options that drop findings by rule ID, by a
  baseline or by category join the default `denied_paths`, so a delivered config
  that changes one is refused: bandit's `confidence_level`, cdk-nag's
  `AwsSolutionsChecks` pack, cfn-guard's `rule_sets`, cfn-lint's `ignore_checks`
  and `regions`, checkov's `frameworks` and `skip_frameworks`, detect-secrets'
  `baseline_file` and `scan_settings`, ferret-scan's `checks`,
  `confidence_levels`, `disable_ip_types`, `enable_preprocessors`,
  `finding_limit`, `profile`, `recursive`, `respect_gitignore`,
  `use_default_config` and `validator_budget`, gitleaks' `baseline_path`,
  opengrep's `config`, `exclude_rule`, `patterns` and `severity`, semgrep's
  `config`, `exclude_rule` and `severity`, trivy's `scanners` and
  `ignore_unfixed`, trivy-repo's `license_full` and `scanners`, ferret-scan's
  `max_live_bytes`, gitleaks' `max_target_megabytes`, and every scanner's
  `offline` (npm audit, which keeps no advisory data, checks none offline). So
  do each scanner's own config file (`config_file` of actionlint, bandit,
  cfn-lint, checkov, ferret-scan, gitleaks, grype, syft, trivy, trivy-repo and
  zizmor, and trivy's and trivy-repo's `secret_config_file`), trivy-repo's
  `module_dir`, cfn-guard's `rules_paths`, actionlint's `shellcheck` and
  `pyflakes`, zizmor's `online_audits`, the `honor_inline_ignores` of cfn-lint,
  gitleaks and zizmor, every `tool_version`, opengrep's `version` and `sha256`,
  the AWS reporters' destinations and credentials, and the GitLab SAST
  reporter's `exclude_suppressed`. Left at its default, each still scans.

- **A default scan runs six more scanners.** actionlint, cfn-lint, cfn-guard,
  gitleaks, trivy and zizmor are builtin and on by default, so a scan with an existing
  config now reports their findings too, and a run whose host lacks one of their tools
  records it MISSING, which fails the incomplete-scan gate (exit 1) exactly as a
  missing grype or semgrep does. Run `ash dependencies install`, use the container
  image, or set `scanners.<name>.enabled: false` for any you do not want. Their
  findings count toward `fail_on_findings` like any scanner's, so a scan that passed
  can now exit 2. The reusable workflow
  `.github/workflows/run-ash-security-scan.yml` installs every default scanner's
  tool by default: its new `install-actionlint`, `install-cfn-guard`,
  `install-gitleaks` and `install-trivy` inputs, and the existing `install-grype`,
  `install-syft`, `install-opengrep` and `install-cfn-nag`, which defaulted to
  false, all default to true, so a caller that sets none of them gets those
  scanners rather than MISSING ones. Each run therefore downloads them (measured on
  2026-10-11): trivy about 180 MB (a 52 MB archive and the 127 MB compressed
  database it fetches during the scan), grype about 32 MB and, unless a cached copy
  inside its bound is restored, a 190 MB compressed database, OpenGrep 46 MB unless
  its weekly cache matches, syft 31 MB, gitleaks, cfn-guard and actionlint about
  14 MB together, and Ruby 3.3 with cfn-nag's 2.1 MB of gems. A caller that does
  not need one, for example in `ash-mode: container` or with the scanner disabled,
  sets its input to false, and so does a caller whose `ash-version` predates a
  tool's pin, which cannot install it. trivy reads its vulnerability database, so online it downloads
  it, and offline it needs the database in its cache (`TRIVY_CACHE_DIR`). Configs that list the community Trivy
  plugin for `trivy-repo` now run trivy twice; set `scanners.trivy.enabled: false` to
  keep only `trivy-repo`.
- **The scanned repository's own scanner configs are not read.** A tool config
  committed to the repository can drop findings before ASH sees them, so they would
  be neither reported nor counted as suppressed. Tune findings with ASH
  suppressions, which are both. Unless the operator names a config, through
  `--config-overrides` or an ASH config file outside the scanned tree:
  - actionlint runs with an empty config ASH writes, not `.github/actionlint.yaml`;
  - cfn-lint runs with an empty config ASH writes, not a `.cfnlintrc` in the
    repository or the home directory, and in a new, empty, private directory
    outside the scanned tree, so a relative path in an operator's `.cfnlintrc`
    names nothing;
  - gitleaks runs with its default rules, not `.gitleaks.toml` or
    `.ash/.gitleaks.toml`, and ASH re-scans each file a root `.gitleaksignore`
    names (gitleaks always reads that file) and reports what it dropped;
    `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` from the environment still apply
    outside `--sandbox`;
  - zizmor runs with `--no-config`, not `zizmor.yml` or `.github/zizmor.yml`;
  - trivy runs with empty config, ignore and secret-config files, not
    `trivy.yaml`, `.trivyignore` or `trivy-secret.yaml`.

  Each of those scanners' `config_file` options and gitleaks' `baseline_path`, set
  by an ASH config inside the scanned tree, are ignored with a warning (a config
  an MCP client delivered that sets one is refused, as a default `denied_paths`
  entry), and so are trivy's and trivy-repo's `ignore_file` and
  `secret_config_file` and cfn-guard's `rules_paths` (cfn-guard prints a rules
  file it cannot parse, so a path the repository chose could put any readable file
  into the report); `TRIVY_IGNOREFILE` and `TRIVY_SECRET_CONFIG` still apply, for a
  file outside the scanned tree. trivy's and trivy-repo's `config_file`,
  `ignore_file` and `secret_config_file`, trivy-repo's `module_dir` and cfn-lint's
  `config_file` are also refused when the file is inside the scanned tree, or when
  the path is in the tree and leads out of it through a symbolic link, even when the
  operator names it; actionlint's, gitleaks' and zizmor's `config_file`, gitleaks'
  `baseline_path` and cfn-guard's `rules_paths` may name a file in the tree when the
  operator sets them, and such a path there that leads out of the tree through a
  symbolic link makes cfn-guard MISSING and the other three scanners ERROR, without
  running the tool. With `rules_paths` ignored and `rule_sets` empty,
  cfn-guard falls back to `wa-Security-Pillar`. In an operator's rules directory, a
  rules file that resolves outside it through a symlink is refused, and cfn-guard
  is given copies of the files ASH read. gitleaks runs with
  `--ignore-gitleaks-allow` and zizmor with `--no-ignores`, so `gitleaks:allow`
  and `# zizmor: ignore[...]` comments apply only when the operator sets that
  scanner's `honor_inline_ignores`. Tool output quoted in a scanner's error
  has terminal escape sequences removed and other control characters escaped.
- **trivy-repo names its own config file and modules directory.** It always passes
  `--config` and `--module-dir`: by default `TRIVY_CONFIG` when that names a file
  outside the scanned tree, or else an empty config ASH ships, and an empty
  directory that ASH makes outside the scanned tree for each run and removes when
  the run ends, so trivy does not load a `trivy.yaml` from the scanned repository.
  New options `scanners.trivy-repo.options.config_file` and
  `module_dir` name others; they are honored when set through `--config-overrides`
  or a config file outside the scanned tree, for paths outside that tree, and are
  ignored with a warning otherwise.

- **A repository-written config file can no longer choose where ASH installs a
  tool from, what it imports, or what it hands a scanner as its own
  configuration.** It applies to a discovered `.ash/.ash.yaml`, a `--config` path,
  an `extends` base, or `ASH_CONFIG`, when the file is repository-written (defined
  below):
  - `tool_version` (bandit, checkov, semgrep, ferret-scan, the jupyter converter)
    must be a PEP 440 version specifier set such as `>=1.2,<2`, from any source.
    Any other value is replaced by the default, with a warning naming the key.
    `scanners.opengrep.options.version` likewise has to be a release tag, and a
    version other than the pinned one needs its `sha256`. Within those limits a
    repository's config still chooses opengrep's version.
  - `tool_version` of every scanner and converter, including one a plugin module
    adds, is the operator's: it comes from the defaults, `--config-overrides` or a
    config file outside the tree. From the tree's config it is ignored with a
    warning naming the key, unless it equals the operator's value, and the
    operator's value or the tool's default constraint applies. A workspace
    project's config no longer pins a scanner version either, so projects whose
    pins conflict are no longer refused: every project gets the operator's
    value. To pin a version for a scan, set it with `--config-overrides` or in
    the operator's `--config`.
  - `ash_plugin_modules` entries such a file adds are imported only when they name
    an installed module in a location that is not repository-written.
    `--ash-plugin-modules`, `--config-overrides` and a config file that is not
    repository-written are unaffected.
  - checkov's and ferret-scan's `config_file`, the `.checkov.yaml` and `ferret.yaml`
    files they find by name, and detect-secrets plugins and filters that name a
    file are passed to the tool by the rule below.
    checkov and ferret-scan now run from the filesystem root, because each reads
    its config file from its working directory itself, and ferret-scan always
    gets a `--config`; the paths in their findings are unchanged.
  - trivy-repo no longer reads a `.trivyignore` or `trivy-secret.yaml` from the
    scanned repository, either of which could remove findings from the report. It
    gets an explicit `--ignorefile` and `--secret-config`: the
    `scanners.trivy-repo.options.ignore_file` / `secret_config_file` options, or
    `TRIVY_IGNOREFILE` / `TRIVY_SECRET_CONFIG`, by the rule below, otherwise one that
    sets nothing. A repository that relied on either file
    now sees those findings, with a warning naming the file. Under `--sandbox`, an
    operator file outside the system paths also has to be listed in
    `sandbox.extra_read_paths`.
  - For all of these, a path that reaches a file outside the scanned tree through
    a symbolic link inside it (a link at any depth, a linked directory, or a chain
    of links) counts as inside the tree, since the repository chose that file, and
    is not passed to the tool. A link outside the tree, and a path that leaves by
    `..`, are followed as before.
  - The empty config files ASH passes bandit, grype, syft, ferret-scan, trivy,
    trivy-repo, actionlint and cfn-lint when the operator names none, gitleaks'
    default-rules config, and the empty directories trivy-repo gets as its
    modules directory and gitleaks as its ignore path, are written in a new
    directory outside the scanned tree, one per scanner run, made with mode 0700 and
    removed when the run ends, instead of in `<output>/scanners/<name>/`, which
    is inside the tree with the default output directory. What the tools report
    is unchanged. The `commandLine` and `arguments` a scanner records in its
    SARIF invocation name the file as the tool was handed it, under a random
    `ash-tool-config-*` directory that no longer exists after the run. Under
    `--sandbox`, the scanner can read that directory and cannot write to it. It
    is never made under a directory another local
    account could change (one that account owns, or one other accounts can
    write without the sticky bit, anywhere up to `/`). With such a `TMPDIR` it
    goes under the output directory, with a warning when that is inside the
    tree, and when the output directory is no better the scanner fails with an
    error saying to set `TMPDIR` to a directory only you can write.
  - ferret-scan's `tool_version` no longer accepts a bare version or `latest`;
    write `==1.2.3`, or leave it unset for the supported range.
  - The AWS reporters' destinations and credentials come only from the defaults,
    `--config-overrides` or a config file outside the tree: `aws_region` and
    `aws_profile` of the Security Hub, Bedrock summary and S3 reporters, Security
    Hub's `account_id`, `findings_scope` and `archive_resolved_findings` (which
    findings it imports and whether it archives resolved ones), the Bedrock
    reporter's `model_id` and its three output files, S3's `bucket_name` and
    `key_prefix`, and CloudWatch Logs' `aws_region`, `log_group_name` and
    `log_stream_name`. This covers the section under any
    spelling ASH reads as that reporter's, such as `BedrockSummary`. The reporters'
    other options still apply from the tree.
  - A reporter names the options that choose where it sends or writes findings, or
    which credentials send them, in `destination_options`, and the AWS reporters now
    declare theirs. A reporter from `ash_plugin_modules`, `--ash-plugin-modules` or
    `ASH_PLUGIN_MODULES` gets the same treatment once the scan, or `ash report`, has
    imported its module: those options come only from the defaults,
    `--config-overrides` or a config file outside the tree. Under the MCP server a
    delivered file that sets one is scanned with the server's value rather than
    refused, since the file is checked before the module is imported.
  - Such a file can no longer add `automated_security_helper.plugin_modules.ash_aws_plugins`
    (or a module inside it) to `ash_plugin_modules`. Its reporters are enabled by
    default and send findings to AWS with the operator's credentials, so only
    `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides` or a config
    file outside the tree can add it.
  - The same applies to `automated_security_helper.plugin_modules.ash_snyk_plugins`
    (or a module inside it). Its Snyk Code scanner is enabled by default and sends
    the scanned source to Snyk with the operator's Snyk token, so only
    `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides` or a config
    file outside the tree can add it. This repository's
    `.ash/.ash_community_plugins.yaml` no longer lists it; its CI legs pass it with
    `--ash-plugin-modules`.
  - Nor can such a file select one of the AWS reporters or the Snyk Code scanner
    through another installed package that lists or imports it in its
    `ASH_REPORTERS` or `ASH_SCANNERS`: a class defined in either off-host package is
    selected only when `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`,
    `--config-overrides` or a config file outside the tree loads that package, the
    class's module, or the package that lists it. Each class left out is named in a
    warning, in a scan and in `ash report`.
  - A scan applies the same rule to those classes when an earlier scan in the same
    process loaded them, as the MCP server's scans do. A scan whose config files
    are all the operator's, or that has none, selects one only when that config's
    `ash_plugin_modules` or `--ash-plugin-modules` loads it; it used to select
    every one any earlier scan had loaded.
  - A class that another package defines as a subclass of one of those classes is
    held to the same rule. It is also selected when the trusted modules load the
    module or package that defines the off-host class it subclasses; it used to be
    selected whenever its own package was loaded.
  - Any other plugin class that such a file's `ash_plugin_modules` entry loaded is
    no longer selected by a later scan in the same process that does not load that
    module, under the MCP server and across a workspace run, nor by the
    workspace-level report step. Neither is one the MCP `list_scanners` tool
    loaded: trivy-repo and ferret-scan used to run in later scans after a client
    listed the scanners. A later scan used to select every class an earlier one
    had loaded, as a fresh process would not. The same now holds for a module
    that `--ash-plugin-modules`, `ASH_PLUGIN_MODULES`, `--config-overrides` or a
    config file outside the tree names: a later scan that does not name it takes
    none of its classes or event handlers (see "A scan uses only the plugin
    modules it names" under Behavior changes).
  - Known limit: the plugin registry is still the process's rather than each
    scan's. A module any scan loaded stays imported, and an event handler the
    program running the scans subscribes from outside the plugin namespace is
    notified in every scan.
  - bandit's, grype's and syft's own config files are the operator's.
    `scanners.bandit.options.config_file`, `scanners.grype.options.config_file`
    and `scanners.syft.options.config_file` from such a file are ignored; ASH no
    longer looks for `.bandit`, `bandit.yaml` or `bandit.toml` (or their `.ash/`
    copies), `.grype.yaml`, `.grype/config.yaml`, `.ash/.grype.yaml`,
    `.ash/grype.yaml`, `.syft.yaml` or `.syft.yml` in the source directory; and
    each tool is given an explicit config (`--ini` for bandit, `--config` for
    grype and syft), so it does not read one from the tree on its own. A
    repository that relied on one keeps it by naming it with `--config-overrides`,
    for example `--config-overrides scanners.bandit.options.config_file=.bandit`,
    or in a config file outside the tree; a file named that way is used even
    inside the tree. `scanners.syft.options.config_file` now accepts a path
    written as a string. opengrep's and semgrep's `config` (the rules they run,
    from the registry, a URL or a path), opengrep's `patterns` (run in place of
    every rule config) and their `metrics` are the operator's the same way: from
    such a file they are left at the default, `p/ci`, no patterns and `auto`, with
    a warning naming the key, and under the MCP server `metrics` joins the default
    `denied_paths` (`config` and `patterns` already are). `metrics: off`, which
    only stops the tool sending usage data, applies from any config, delivered
    ones included. The files other scanners read that ASH already refused
    inside the tree are the operator's too: checkov's and ferret-scan's
    `config_file`, detect-secrets' `baseline_file` and `file://` plugins and
    filters in `scan_settings`, and trivy-repo's `ignore_file` and
    `secret_config_file`. Such a file outside the tree is now passed only when the
    operator named it.
  - semgrep and opengrep no longer honor a `.semgrepignore` in the scanned tree.
    ASH passes `--x-ignore-semgrepignore-files` together with the tools' default
    exclusions, so the paths scanned are those scanned with no `.semgrepignore`.
    A `.semgrepignore` that either tool would have read is named in the results as
    a `config_warning` validation checkpoint, which in a tree an MCP client
    delivered says the file is client-supplied. To leave files out, list them in
    `global_settings.ignore_paths`; under the MCP server a client's entries there
    are marked `client_supplied`, as usual.
  - ferret-scan's `profile` and `use_default_config` are the operator's too. A
    profile chooses which checks ferret-scan runs and the lowest confidence it
    reports (with ferret-scan 2.5.3 on ASH's test files, the bundled config
    reported 111 findings with no profile, 30 with `quick` and none with six of
    its profiles), and `use_default_config: false` drops the bundled config's
    validator patterns. From such a file both are ignored, with a warning naming
    the key; set them with `--config-overrides`, for example
    `--config-overrides scanners.ferret-scan.options.profile=security-audit`, or
    in a config file outside the tree. ferret-scan's `checks`,
    `confidence_levels` and other options still apply from the tree.
  - snyk-code no longer runs on a tree whose own exclusion files would narrow it.
    `snyk code test` leaves out the files that the `exclude.code` and
    `exclude.global` entries of a `.snyk` file, or the rules of a `.dcignore`
    file, name, anywhere in the tree it tests, and it has no option to stop
    reading them (`code test` takes no `--policy-path`). When the tree has one,
    snyk-code now fails with an error naming the files. A `.snyk` with only open
    source `ignore` entries, and `.gitignore`, do not count. The operator accepts
    a repository's exclusions with the new
    `scanners.snyk-code.options.honor_tree_exclusions`, set with
    `--config-overrides` or in a config file outside the tree; a config file
    inside the tree, or one an MCP client delivered, does not set it.
  - A reporter's `extension` has to be a filename suffix, from any source: a value
    with `/`, `\`, `..` or NUL is replaced by the reporter's default, with a
    warning naming the key. Reports, the files the unused-suppressions, S3 and
    Bedrock summary reporters write beside them, and the workspace report
    manifest are written only when the resolved file is directly inside the
    reports directory, and a symlink at the file's name is replaced rather than
    written through. A file that cannot be written is logged and does not stop
    the reporter's main report or the other reporters; the S3 reporter's receipt
    then has `local_copy: null`. The Bedrock summary
    reporter's `output_file`, `output_executive_file` and `output_technical_file`
    are file names in the reports directory, from any source: a value with `/`,
    `\` or NUL, or one that is `.` or `..`, is replaced by the option's default,
    with a warning naming the key.

  For these checks and the sandbox grants alike, a file is repository-written when it
  is inside any git checkout, by its own path or its resolved path, or inside the
  source directory when that is outside a checkout. "The scanned tree" is narrower:
  the source directory, or the outermost git checkout holding it. A tool config or
  ignore file a setting names (checkov's and ferret-scan's `config_file`,
  detect-secrets `file://` plugins and filters, trivy-repo's `ignore_file` and
  `secret_config_file`, `TRIVY_IGNOREFILE` and `TRIVY_SECRET_CONFIG`) is judged by
  who named it. One the operator named, with `--config-overrides`, in a config file
  outside the scanned tree, or through `TRIVY_IGNOREFILE` or `TRIVY_SECRET_CONFIG`,
  is passed unless it is inside the scanned tree or an MCP client delivered it, so
  one kept in an ops repository works. One a config inside the scanned tree names
  has to be outside every git checkout as well. When the operator's config file extends one
  inside the tree, only the paths the operator's file writes itself count as the
  operator's. An MCP client's `config_overrides`, and a session profile its
  `select_profile` patch changed, are the client's, not the operator's. A
  virtualenv inside a git checkout counts as
  inside it for `ash_plugin_modules`, and the warning names the module's location
  and the checkout. A file a setting names is judged by the path as written, by the
  file it resolves to, and by every symlink resolving it follows, so a symlink the
  scanned repository planted counts as inside the tree wherever it points, and so
  does a path of the operator's that leads through one.

  Under the MCP server, a config a client delivered is limited the same way, and a
  file any MCP client delivered (under the MCP workspace root, except the profile
  files the server writes in each session's `config/` directory) counts as
  repository-written for these checks, as
  does a config path a client names outside the directories
  `ASH_MCP_ALLOWED_CONFIG_ROOTS` names. So does a `--config` or `ASH_CONFIG`
  naming a file under the MCP workspace root on the CLI, while scanning any
  directory, and the runtime-override policy is never read from such an
  `ASH_CONFIG`: the built-in defaults are the trusted config instead. Such a file
  is also checked against that policy as a delivered config is, so on the CLI one
  that changes a denied field, such as `fail_on_findings`, stops the run with
  exit 3. A detect-secrets baseline a client delivered, named or found by name, is
  not read. The workspace tools' `config_overrides` are checked against the session config's
  `runtime_overrides` allowlist, as `select_profile`'s `patch_ops` and
  `override_yaml` are, and are refused while runtime overrides are off (the
  default). Each override is checked by the key it names, so one whose value the
  session config already holds is checked too, and none of them sets what only
  the operator may, such as a reporter's destination or a scanner's config file,
  even where the session's allowlist lets it through. The workspace tools use a
  workspace policy file, named or found beside the definition, only from a
  directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names; one elsewhere, including one a
  client delivered, is refused.
  `/ash_plugin_modules` joins the default `denied_paths`, and `denied_paths` and
  `denied_value_patterns` now match a key spelled with either `-` or `_`, and a
  plugin's section under every spelling ASH reads as that plugin's config,
  including when the entry names plugins with a glob such as `trivy-*`.

  Each value that is not honored is named in a warning when the config is
  resolved. See
  [Settings a repository's config cannot choose](docs/content/docs/configuration-guide.md#settings-a-repositorys-config-cannot-choose).

- **A config file inside the scanned tree can no longer relax the stale content
  database check.** `content_db_staleness: warn`, and a
  `content_db_staleness_overrides` entry with `policy: warn`, now come from the
  defaults, `--allow-stale-content-db`, `--config-overrides` or a config file
  outside the tree. From a repository's or a workspace project's own config they
  are ignored with a warning naming the key, unless they equal the operator's
  value, and a stale database fails the scan as by default. `fail`, and an entry
  with `policy: fail`, still apply from any config. The same holds for
  `content_db_staleness_offline_image_default: true` where the operator's value is
  false: it is set back to false with a warning, and `false` applies from any
  config. `ash merge` still takes these keys from the shards. See
  [Failing on a stale content database](docs/content/docs/configuration-guide.md#failing-on-a-stale-content-database).

- **ASH no longer follows symlinks out of the scanned tree when it reads tree files
  into its own output.** This covers converter inputs (archives and notebooks), the
  JSON and YAML files cfn-nag and cdk-nag read to decide whether they are
  CloudFormation, the `.gitignore` and `.ignore` files copied into
  `ash-ignore-report.txt`, the files read for inline `ash-ignore` comments, and the
  `package-lock.json` files read for package identity. Each is read only when it is a
  regular file inside the scanned tree: not a symlink, not under a symlinked
  directory, not outside the tree, and with a single hard link. The inline-suppression
  and lockfile lookups, which read a file a scanner already reported, follow a symlink
  whose target is inside the tree. Anything else is skipped with one warning naming
  it. A converter records each skipped input under
  `converter_results.<name>.refused_inputs` in `ash_aggregated_results.json`, cfn-nag
  and cdk-nag record it in the scanner's error output, and a skipped ignore file is
  noted in `ash-ignore-report.txt`. Archive members that are symlinks, hard links or
  special files, or whose names are absolute or contain `..`, are skipped and
  recorded the same way, with the member's name. A tree that relied on a symlinked
  notebook, archive or ignore file loses that coverage or those ignore rules until
  the link is replaced with the file. cfn-nag and cdk-nag also stop quoting template
  content in their log messages: a parse or validation error is reported by file,
  error type and, where the parser knows it, line. `cfn_nag_scan` and cdk-nag's
  `CfnInclude` read a copy of the template text ASH checked, and findings keep the
  template's own path.

- **The Jupyter converter runs nbconvert outside the scanned tree, with an exporter
  ASH chooses.** nbconvert runs in a directory that holds only a copy of the
  notebook, so files in the scanned tree are not on its import path (nbconvert puts
  its working directory first on `sys.path`). The exporter is
  `python` for a Python notebook (or one that names no language) and `script`
  otherwise, and `language_info.nbconvert_exporter` is removed from the copy, so the
  notebook's metadata does not choose the exporter class. A Python notebook whose
  metadata named no exporter used to go through nbconvert's generic script template;
  it now goes through the Python exporter, which adds `# In[ ]:` cell markers to the
  converted file. Running outside the tree also keeps nbconvert from using templates
  found there (`extra_template_basedirs` defaults to its working directory). The copy
  is named `notebook.ipynb`, because nbconvert expands its notebook argument as a glob
  pattern and formats its output name with `str.format`, so notebooks named
  `[x].ipynb` or `{a,b}.ipynb` convert. The converted file is named after the
  original notebook, and a non-Python notebook's keeps the extension nbconvert gives
  it, such as `.r`. `language_info.file_extension` is kept in the copy only when it
  is a plain extension. When uv cannot run nbconvert, ASH runs `jupyter-nbconvert` by
  the absolute path it found for it. uv reporting that it cannot resolve nbconvert,
  as when offline with nbconvert not in its cache, counts as uv not running it.

- **A notebook or archive a converter could not convert counts as incomplete
  conversion.** A notebook nbconvert exits non-zero on, times out on or writes no
  output for, and an archive that cannot be extracted, are each recorded under
  `converter_results.<name>.failed_inputs` in `ash_aggregated_results.json` with the
  reason. With `fail_on_incomplete_scanners` on (the default) the scan exits 1
  naming the converter and the files, as it does for a converter that crashed. A
  `.gz` that is a single compressed file, such as `data.json.gz`, is decompressed
  and scanned, and is a failed input only when it cannot be decompressed. The
  progress line and the convert-complete event say how many
  files could not be converted. `ash merge` combines every shard's converter row
  (failures, failed and refused inputs, missing tools), and workspace mode applies
  the same converter check to each project, which gains `incomplete_converters`.

- **cfn-nag is given its staged template copy under a fixed name**: `template.json`
  for a `.json` template, `template.yml` for `.yml`, and `template.yaml` otherwise,
  so the `cfn_nag_scan` command line is the same whatever the template is called,
  including on Windows, where `cfn_nag_scan` is a `.bat` wrapper. Findings name the
  template itself.

- **ASH refuses an output directory reached through a symlink, whatever the sandbox
  mode.** Before a scan, ASH clears the `analysis`, `reports`, `scanners` and
  `converted` directories under the output directory, writes its logs and results
  there, and a sandbox mounts it. The scan stops, before anything is written, when
  any of these is a symlink or a directory junction (detected on every supported
  Python version): the output directory itself; a directory inside the scanned tree
  on the way to it, however either path is spelled, or an in-tree output directory
  whose real path is outside the tree; one of those four directories; or a file ASH
  writes there by a fixed name (`ash.log`, `ash.log.jsonl`,
  `ash_aggregated_results.json`, `ash-ignore-report.txt`,
  `ash-scan-set-files-list.txt`). In workspace mode a link at `projects/` or
  `.workspace-spool` stops the whole run, and a link at a project's
  `projects/<key>`, or in that project's own output tree, fails that project with
  the reason. The error names the link and says to pass `--output-dir`, and the exit
  code is 3, the same whichever check refuses it: container mode's own rule, the
  general check, or the log file's open. This holds in local, container, nix,
  workspace and MCP scans, and `ash report` and `ash merge` refuse the same links
  below the current directory, also with exit 3. An MCP scan whose
  `.ash` or `.ash/ash_output` is a link is refused up front with `error_type`
  `output_dir_not_permitted`; a link at a working directory or a fixed-name file
  fails the scan with `ASH exited with code 3:`, the reason and a remedy for the MCP
  caller. ASH opens the logs, the scan-set lists, the workspace results and the
  reports it writes in place without following a link at their names. Links above
  an output directory outside the scanned tree, such as `/tmp` on macOS, are
  allowed.

- **ASH does not start tools from its working directory or from the directory it
  scans.** Tool lookup searches anchored PATH entries (absolute, with a drive on
  Windows) and ASH's own bin directories only, and a program the operating system
  would start from the working directory, or a path like `./tool`, is refused and
  reported as a command that could not start. While a scan runs, a tool inside the
  scanned directory is refused too, however its path is spelled, and the next copy on
  PATH is used: under `uv run ash scan .` (which puts the repository's `.venv/bin`
  first on PATH) or `npm run` (`node_modules/.bin`), a project-installed scanner is
  skipped. With no other copy the scanner is MISSING, and its row's new
  `missing_reason` and the incomplete-scan message name the in-tree path. The YAML
  reporter and `ash report --format yaml` print `missing_reason` on every scanner row,
  `null` where it does not apply. Programs ASH and its scanners start get a PATH
  without the scanned directory's entries, unless in-tree tools are allowed, so a
  `#!/usr/bin/env node` or a binstub cannot reach them either; that includes the shell
  nix mode starts, where the inner scan is the running ASH's own interpreter, started
  by absolute path. To run in-tree tools, pass `--allow-in-tree-tools` (also the
  `allow_in_tree_tools` key of `--cli-json-input`) or set `ASH_ALLOW_IN_TREE_TOOLS` to
  `1`, `true`, `yes` or `on`; each one is then logged by path. That covers the
  programs the scanner sandbox starts (`bwrap`, `firejail`, `readlink`, `true`) too. A
  repository's config cannot set it, and `ash mcp` never honors it, so install
  scanners outside the repository for MCP use. Tools on anchored PATH entries are
  found by the path the entry gives: system package managers, Homebrew, nix profiles,
  uv and pipx shims, asdf and mise shims, conda, and on Windows Program Files,
  `%LOCALAPPDATA%`, scoop and Chocolatey, with `.exe`, `.cmd` and `.bat` names. git
  (for `--changed-files-only` and MCP source delivery), the Jupyter converter's direct
  `jupyter-nbconvert`, the `node` cdk-nag's jsii runtime starts, and the sandbox's own
  programs are run by absolute path.

- **`ash dependencies install --tool` selects the archive converter as `archive`.**
  Every plugin is now listed and selected by its config key. The archive converter
  was the one bundled plugin listed under its class name, so its canonical `--tool`
  name is now `archive`; the other converters, scanners and reporters keep the names
  they had. The old name `ArchiveConverter` is deprecated: it still selects the
  archive converter, with the same result and exit code, and prints a warning to
  stderr naming `archive`.

- **Plugin install commands start in an empty directory.** `ash dependencies install`
  takes the current directory as the source tree, and it used to run every plugin's
  install commands there, so a package manager read the repository's settings: npm a
  project `.npmrc`, `gem install -g` the Gemfile, Bundler `.bundle/config`, and
  `python -m pip` or a `python -c` script a `pip/` or `automated_security_helper/`
  package. Each command now starts in a new empty directory that is removed when it
  ends. Your own settings, in your home directory or set globally, still apply.
  - For plugin authors: an install command, from `get_installation_commands`,
    `custom_install_commands` or `uv_tool_install_commands`, can no longer rely on
    starting in the current directory. Name files by absolute path; a relative path,
    or an `npm install` into the repository's `node_modules`, now refers to the empty
    directory.
  - A command that starts ASH's own interpreter with `-m` or `-c` also gets `-P` on
    Python 3.11 and later. The detect-secrets worker starts the same way, in an
    empty directory under its work directory, instead of in the scanner's results
    directory.
  - A uv command other than `uv tool` or `uvx` also gets `UV_NO_PROJECT=1` and
    `UV_PYTHON` set to ASH's interpreter, because uv looks for a project and a
    `.venv` in every parent directory too. A command that names `--project`,
    `--python`, `-p` or `--system` keeps its own choice, and so does a `UV_PYTHON` or
    `UV_SYSTEM_PYTHON` you set.
  - `ASH_BIN_PATH` is made absolute where ASH reads it, so a relative value names
    the same directory for every command. An empty value now counts as unset; it
    used to mean the current directory. `--bin-path` shows its default as
    `~/.ash/bin`.

- **grype, opengrep, syft and trivy are bumped to v0.120.1, v1.30.2, v1.54.1 and
  v0.75.0** (from v0.111.0, v1.15.1, v1.42.4 and v0.69.3), with every archive and
  executable digest in `utils/tool_downloads.py` re-taken from the new releases. No
  flag, environment variable, database schema or `--version` format ASH relies on
  changed. Output does change in a few ways. syft writes CycloneDX 1.7 rather than 1.6,
  and names a SHA-pinned GitHub Action by the version in its trailing comment. trivy
  reports license names it cannot parse at UNKNOWN severity instead of dropping them,
  adds secret rules (Azure, Maven `settings.xml`, OpenAI, GitHub App tokens), and no
  longer panics on a single-line CloudFormation template that holds an IAM policy.
  grype stops matching the Go standard library by CPE and links each SARIF rule's
  `helpUri` to its advisory. opengrep parses Dockerfiles it used to report as syntax
  errors. The default `scanners.opengrep.options.version` is now `v1.30.2`; a
  configuration that names v1.15.1 explicitly has to bring its own `sha256`.

- **The container image pins bandit 1.9.4, checkov 3.3.26 and semgrep 1.180.0.**
  The image used to install the newest release each scanner's default version
  constraint allowed, which was whatever PyPI had on the day of the build. It now
  installs exactly the versions in their `THIRD_PARTY_LICENSES` entries in
  `utils/tool_downloads.py`, because the license files and the `SOURCE` file
  (release tag and commit) the image bundles for each scanner have to describe the
  release that is actually installed. `ash dependencies install` outside the image
  is unchanged and still takes the newest version the scanner's default allows. A new weekly workflow, ASH - Pinned Tool Versions, runs
  `scripts/check_pinned_tool_versions.py`, which compares every pin in
  `tool_downloads.py` (these three, the release binaries in `TOOL_VERSIONS`, the
  license files and the cfn-nag gem) with its upstream's latest release and fails
  when one is behind, listing what the bump has to change. It sends the job's
  `GITHUB_TOKEN` to the GitHub API only to lift the anonymous rate limit: a lookup
  refused with 403 is retried once without the token, with GitHub's error message in
  the job log, and the token goes with a redirect only when the redirect stays on the
  same scheme, host and port. A redirect to plain http, or to a host outside the
  script's allowlist, is refused.

- **npm-audit reports ERROR, and the scan exits 1, when the audit itself fails.** A
  scan whose `npm audit` could not get advisories (registry unreachable, a 5xx or 404
  from the audit endpoint, a response that is not JSON, or any npm `--json` error such
  as ENOLOCK) used to report npm-audit PASSED with 0 findings and exit 0. It now reports
  ERROR, naming each lockfile that was not audited and npm's reason, and the scan exits 1
  as incomplete. The same applies to a `pnpm audit` that exits non-zero without a report.
  Other lockfiles are still audited. Offline scans keep their previous behavior and log a
  warning instead. Pass `--no-fail-on-incomplete-scanners` to accept the partial scan.

- **npm-audit now reports yarn findings, and a failed yarn audit is ERROR.** A project
  with a `yarn.lock` always came out of npm-audit PASSED with 0 findings and exit 0,
  whatever its dependencies held. It now reports yarn's advisories as findings, so a
  vulnerable yarn project fails the scan (exit 2) the way an npm one does, and a yarn
  audit that could not get advisories reports ERROR and the scan exits 1 as incomplete.
  Under yarn 2 and later, npm-audit now runs `yarn npm audit --recursive`; offline, it
  does not run it at all, because that command has no offline mode, and logs a warning
  naming the lockfile, as it does for an npm audit that cannot run offline.

- **A scanner's `offline: false` no longer overrides ASH's offline mode.** ASH's
  offline mode (`--offline`, `ASH_OFFLINE`, or an image built with `--offline`) now
  applies to every scanner, and `options.offline: false` means "follow ASH". It used
  to win over `ASH_OFFLINE` in the container, which put a scanner back online during an
  air-gapped run; `ash config init` writes `offline: false` for every scanner that has
  the option, so generated configs did that by default. `options.offline: true` still
  runs one scanner offline while ASH is online. No scanner can now be opted back online
  under `ASH_OFFLINE`. A local `--offline` scan with no semgrep or opengrep rule cache
  now reports that scanner MISSING with the cache guidance and exits 1 as an incomplete
  scan, where it used to pass by going online. See
  [Which scanners run offline](docs/content/docs/advanced-usage.md#which-scanners-run-offline).
  To seed the cache, build the image with `ash build-image --offline`, or for a local
  scan download the rulesets from `https://semgrep.dev/c/<ruleset>` into the
  directories named by `SEMGREP_RULES_CACHE_DIR` and `OPENGREP_RULES_CACHE_DIR` and
  record the download time in `.ash-rules-fetched-at`; see
  [Seeding the semgrep and opengrep rule cache](docs/content/docs/advanced-usage.md#seeding-the-semgrep-and-opengrep-rule-cache).

- **OpenGrep is pinned and digest-verified, and nothing installs it unverified.**
  ASH now pins OpenGrep v1.30.2 with a SHA256 per platform (linux and macOS on
  amd64 and arm64, Windows on amd64) in `utils/tool_downloads.py`, and
  `ash dependencies install` verifies the download before it is put on disk,
  the same way grype, syft and trivy already were. It used to fetch the release
  asset by URL with no digest, so the binary a scan then trusted was whatever
  that URL served.

  **A custom `version` now needs its own `sha256`.** ASH carries digests only for
  the version it pins. To use another one, add the release asset's digest for
  each platform you install on:

  ```yaml
  scanners:
    opengrep:
      options:
        version: v1.14.0
        sha256:
          # Replace with the release asset's real SHA256 (64 hex characters).
          linux/amd64: "0000000000000000000000000000000000000000000000000000000000000000"
  ```

  GitHub lists a digest for every release asset (`gh api
  repos/opengrep/opengrep/releases/tags/<version> --jq '.assets[] | [.name,
  .digest]'`), or run `sha256sum` on the downloaded asset. A custom version with
  no digest for the platform is refused at install time with a message naming
  the key; it used to install unverified. A digest that does not match fails
  the install. The configuration still loads either way, so a host that already
  has opengrep on PATH can scan with it.

  **`run-ash-security-scan.yml` verifies OpenGrep too, and fails closed.** With
  `install-opengrep: true` the workflow installs OpenGrep through ASH at the
  pinned version, and hashes a binary restored from the Actions cache against the
  pin before putting it on PATH; a copy that does not match is deleted and
  re-installed. It used to run `gh release download` with no tag and no digest,
  and trusted a restored copy as long as it was executable. **A caller whose
  `ash-version` predates this change now fails the Install OpenGrep step**,
  because that revision has no pin to verify against. Set `ash-version` to a
  revision that pins OpenGrep (main, or the first release after v3.7.1), or set
  `install-opengrep: false`.

  **The container image pins uv and no longer runs `get-pip.py`.** uv is
  installed from its pinned release asset (0.12.23), verified against its SHA256,
  in both build stages, replacing `curl -LsSf https://astral.sh/uv/install.sh |
  sh`. The unpinned `get-pip.py` download is gone: it installed a pip the base
  image already ships, and the image still upgrades pip with `pip install
  --upgrade pip`.

- **`fail_on_incomplete_scanners` now defaults to `true`.** A scan in which a
  selected scanner did not complete — status `ERROR` (it ran and failed) or `MISSING`
  (its dependencies were unavailable, so it never ran) — exits 1 without anyone
  having to ask for it. It defaulted to `false`, on the argument that a host
  legitimately lacking a scanner's tool should keep its exit code.

  **A scan on a host missing some scanners' tools was exiting 0 and now exits 1.**
  Nothing about your code changed. A scanner recorded `MISSING` reports no findings,
  so with the gate off such a scan returned the exit code of a clean one — and unlike
  a crash, that outcome is invisible to whoever reads the result. The environments
  affected are the ones where it mattered most: a container or air-gapped host that
  can run one scanner out of ten was reporting success for scanning almost nothing.

  The gate selects on scanner status, so it covers a failure once that failure has
  reached the status. A tool that exits with a code its scanner does not accept now
  does: see the entry below on rejected exit codes.

  To keep the previous exit codes, set `fail_on_incomplete_scanners: false` or pass
  `--no-fail-on-incomplete-scanners`. Prefer `--exclude-scanners` for a tool you do
  not have: an excluded scanner is recorded `SKIPPED` rather than `MISSING`, does not
  trip the gate, and the report then says which scanners were not part of the run,
  where `false` returns to a 0 that carries no such information.

  `SKIPPED` never trips the gate, which is what keeps sharding working — each shard
  excludes the scanners its siblings own — and means narrowing a run with
  `--scanners` or `--exclude-scanners` does not fail it.

  **This default switches on several independent rules, not one.** Everything below
  was already written and already gated behind this field; all of it was previously
  unreachable without opting in, and all of it is now on the default path:

  - a selected scanner at `ERROR` or `MISSING` fails the scan (`incomplete_scanners`);
  - a scanner that ran but could not evaluate part of its input fails it, reported as
    `PASSED (n of m targets unevaluated)` — the partial-coverage arm of the same
    function, and the arm most likely to be new to an existing scan;
  - a run in which *every* scanner was `SKIPPED` fails, rather than reporting a tree
    it never examined as clean (`no_scanner_ran`, skipped for a single shard of a
    split scan, which legitimately can own nothing);
  - `ash merge` refuses a union in which some shard completed none of the scanners it
    owned, and applies both rules above to the merged model;
  - in workspace mode, a project whose scanners did not complete sets
    `scan_incomplete`, which fails the whole workspace run.

  `--no-fail-on-incomplete-scanners`, or `fail_on_incomplete_scanners: false`, turns
  off all of them together.

- **A scanner whose tool exits with a code it does not accept is `ERROR`, whatever
  its results file holds.** Each scanner accepts the exit codes its tool uses for a
  completed run (0, and the code some tools use for "findings found"). A tool that
  fails can still leave a results file: semgrep exits 7 and writes SARIF holding only
  error notifications when it cannot read its rules, and grype exits 1 and writes a
  zero-byte report when it cannot load its database. That file was read and graded,
  so both were `PASSED` with no findings and the scan exited 0, even with
  `--fail-on-findings` and the completeness gate on. The results file of such a run
  is no longer graded; the row is `ERROR`, keeps the exit code, and its error names the
  code, the accepted set and the tool's stderr, and quotes the error-level
  notifications the results file holds (semgrep reports an unreadable rule file only
  there) or names the files the tool wrote. Each target is judged by its own
  run's exit code, and its row reports that code: a target the scanner returns from
  before its tool runs (an empty converted tree, missing dependencies, or a target
  the sandbox refused) reports 0, where it had reported the previous target's code,
  and cfn-nag's and npm-audit's invocations record the largest code of that target's
  runs alone. The scanner's row in `scanner_results`, which stands for all its
  targets, now carries a code too, where it was always 0: the largest code among
  its `ERROR` targets, else the largest of any target. A tool a signal ended is recorded as `128 + N`, as a shell
  reports it; its absolute value had put SIGHUP, SIGINT and SIGQUIT inside common
  success sets. A run ASH itself failed to carry out (an error in its own runner,
  not the tool's) is recorded as 127, like a tool that could not start, where it had
  been 1, which most scanners accept. The accepted codes per scanner, with their sources, are in
  [A Scanner Is ERROR With an Exit Code It Does Not Accept](docs/content/docs/troubleshooting.md#a-scanner-is-error-with-an-exit-code-it-does-not-accept).

  The same rule now holds for the scanners that run their tool outside the template:
  trivy-repo, syft, ferret-scan and snyk-code. trivy-repo and syft accept only 0, where
  they accepted 0 and 1: neither tool has a "findings found" code, and 1 is how both
  report an error. trivy-repo passes `--exit-code=0` (see trivy under Features), which
  outranks an `exit-code` setting in the operator's trivy config or in
  `TRIVY_EXIT_CODE`, and reads no `trivy.yaml` from the scanned directory, so a run
  with findings still exits 0. snyk-code, which raised on every non-zero code, now accepts 1 ("issues
  found"), so a snyk run with findings reports them instead of failing, and its row
  and invocation keep the 1, which snyk-code used to reset to 0. ferret-scan's 3,
  which it exits with under `fail_on_incomplete` when a file could not be fully
  scanned, still reports the partial findings, and now counts the target as failed,
  so the row is `ERROR` and the completeness gate fails the scan, where the run had
  been graded like a complete one.

  More shapes that read as a clean scan are `ERROR` now, even with an accepted exit
  code. An empty results file (or JSON `null`) and SARIF with no run were graded
  `PASSED` with no findings; bandit, checkov and semgrep write one run even when
  there is nothing to scan (measured), and grype's and opengrep's SARIF writers
  always add one. A results file the template reads as JSON but not as SARIF was
  returned as it was and graded `PASSED` with no findings; a scanner that overrides
  `scan()` could return its tool's JSON the same way (ferret-scan and syft do when it
  does not parse). A result with no `status`, `severity_counts` or `findings` is no
  longer graded, nor is a result whose `status` is not `passed`, `completed`,
  `success` or `ok` (it used to take exactly `failed` to make the row `ERROR`), nor
  a result of a type the executor does not read (a list, a string or a number from
  a `scan()` override). The no-run check reads the report as the tool wrote it, so
  grype's run-less SARIF is `ERROR` too; grype's scanner used to add an empty run
  first. A results file whose SARIF ASH's schema rejects is affected too: its
  findings were dropped silently, and the scanner is now `ERROR` and says so.

  A scanner whose tool reports that its content database does not exist (grype's
  `database does not exist`, trivy with no `VulnerabilityDB`, an offline rules
  directory with no rules files) is `ERROR` too, under `content_db_staleness: fail`
  and `warn` alike. Measured: grype with an empty cache was `PASSED` with 0 findings,
  and with `--allow-stale-content-db` the scan exited 0. `warn` relaxes the age bound
  for a database that exists; it no longer makes a missing one acceptable. A
  trivy-repo scan whose `scanners` list names scanners but not `vuln` reads no
  trivy-db, so it is no longer held to that database's age or existence; an empty
  list leaves the choice to trivy, whose default includes `vuln`, and is held.

  **A scan that exited 0 can now exit 1.** That is a scanner whose tool was failing
  all along. With `fail_on_incomplete_scanners: false` the `ERROR` row does not fail
  the scan and the exit code comes from the findings alone, so such a scan still
  exits 0; that is what turning the gate off means.

- **`--fail-on-incomplete-scanners` now also fails a scan that lost only part of
  its input.** The flag selected on scanner status, and a scanner that failed on
  some of its targets keeps whatever status the severity gate gives it — `PASSED`
  or `FAILED`, decided only by what the targets it *did* read contained — because
  `determine_status` returns `ERROR` only once
  `targets_failed >= targets_attempted`. Neither value says anything about the
  targets that went unread, so the flag reported total coverage loss and stayed
  silent on partial loss, which is the more common case and the one operators turn
  it on to catch.

  **A build that was green will now exit 1 with no diff of your own.** Nothing about
  your code changed and nothing newly broke: the flag was blind to partial loss, and
  the coverage it was silently accepting is now reported. Expect to hit this in CI
  without warning the first time you upgrade. On its own this change affected only
  runs that had the gate on, which was then opt-in; read it together with the default
  flip above, which is what puts every run on that path.

  Measured on this repository's own tree, so the scale is concrete rather than
  hypothetical: cdk-nag **attempted 11 targets and could not evaluate 4** of them, a
  36% loss that nothing in the rendered output mentioned. That measurement is what
  the gate surfaced on first contact, and both causes behind it are fixed in the two
  cdk-nag entries under Fixes below — the same tree now reports 9 of 9 evaluated.
  The number is kept here because it is the reason the gate earns its keep: it found
  a real hole on the first repository it was pointed at, which happened to be ASH's
  own.

  Note that cdk-nag's status here is `FAILED`, on 16 actionable findings at the
  `MEDIUM` threshold, both before and after this change. The point is not that a
  passing row hid a problem; it is that the shortfall was absent from the summary
  table, from every report and from the exit code no matter which status the row
  carried. A scanner reports a **complete** scan of its input whether it passed or
  failed on the part it read.

  That 36% was not entirely spurious, and the split is worth knowing because the two
  halves needed different fixes. Two of the four were real CloudFormation templates
  that genuinely went unscanned (`test-yaml.template.json` and
  `cfn-and-python-test-yaml.template.json`); both are CDK-synthesized and collided
  with the wrapper's own bootstrap-version parameter. The other two — a
  `tsconfig.json` and a `mkdocs.yml` — were never templates at all and were
  misclassified as failed targets rather than skipped. So half the number was real
  lost coverage and half was noise, which is precisely why the counts are reported
  rather than folded into a single percentage. Both are fixed under Fixes below.

  A scanner that reports no target counts at all is unaffected — absent counters
  mean the scanner does not track targets, not that it lost them, so the nine
  scanners in that state cannot trip the gate.

  Partial coverage loss does **not** change a scanner's status. That is a
  deliberate limit on this entry and not a claim about the release: the separate
  breaking change below does change statuses, with no flag to opt into. Read the
  two together.

  To restore the previous behavior, set `fail_on_incomplete_scanners: false` or pass
  `--no-fail-on-incomplete-scanners` to accept a partial scan. To keep the gate and
  clear the failure, fix or exclude the targets the scanner could not read; the
  failure message names each scanner with the counts, whatever its status.

- **A rule that could not be evaluated now fails the scan, under default config.**
  This one changes the default exit code, so read it even if you pass no flags.

  A cdk-nag rule that raises mid-validation is reported as
  `kind: notApplicable` at `level: none` — see the reporting entry below for why
  that is the correct SARIF — and ASH's ladder reads `none` as INFO, which the
  default `MEDIUM` threshold does not count. Before that, the row arrived at
  whatever severity the rule declared and a scan containing one exited non-zero.
  Afterwards nothing gated it: `targets_failed` rises only when a validation report
  cannot be read or the scan raises, so a rule that throws on a template whose
  report still parses leaves the target counters clean and
  `--fail-on-incomplete-scanners` sees nothing either. The remaining signals were a
  warning log and a run-level notification, neither of which reaches an exit code.
  Net, a scan whose only defect was systematic rule-evaluation failure reported a
  clean exit 0.

  `_compute_exit_code` now reads `invocation.toolExecutionNotifications` at
  `level: error` — SARIF's own channel for "a runtime condition detected by the
  tool during the analysis", which the cdk-nag scanner already writes one of per
  rule that could not be evaluated — and **exits 1** when a scan carries any.

  **1 and not 2, deliberately.** 2 tells a reviewer that clearing the listed
  findings clears the scan, which is what is not true when a rule reached no
  verdict. 1 is ASH's "error during execution" code and is what the completeness
  gate and `ash merge`'s coverage refusals already use for the same reason: the
  findings that were reported are real, but the set is known to be partial.

  **This was not expressed as a finding, and could not be.** Giving the result a
  gating severity was the obvious alternative and is what the pre-existing behavior
  amounted to. SARIF section 3.27.10 requires `level` to be `none` whenever `kind`
  (3.27.9) is anything other than `fail`, and `fail` asserts the rule *was*
  evaluated and the target did not satisfy it. A severity-bearing result would
  therefore have to claim a verdict that was never reached — the report untrue in
  the opposite direction.

  **A rule that genuinely does not apply is unaffected**, and not by a carve-out.
  cdk-nag's validation report carries violations only, so a rule that does not
  apply to a target produces no row at all and therefore no notification. The only
  producer of the not-evaluated state is a rule that threw. A scan with no
  CloudFormation in it is likewise untouched: nothing was evaluated, no rule raised,
  and the scanner still reports `SKIPPED` at exit 0.

  **To accept a rule that cannot be evaluated, suppress it.** A suppression on the
  rule's not-evaluated results silences this gate — the gate reports a rule only
  when at least one such result is unsuppressed — so the existing mechanism is the
  escape hatch and no new flag was added. Suppressions are per finding: accepting
  the failure on one resource does not accept it on another. This repository's own
  `.ash/.ash.yaml` already carries fifteen such entries, under the heading "rules
  that threw and never ran", for rules that raise on its deliberately
  parameterized templates; measured on this tree, they keep its default scan at
  exit 0.

  Also worth knowing before treating this as cdk-nag-only: the gate reads SARIF
  rather than a cdk-nag counter, so any scanner — or any externally ingested SARIF
  — that reports an error-level runtime condition trips it. cdk-nag is the only
  builtin that writes one today.

- **The reusable scan workflow now installs the `cdk` extra, so cdk-nag runs for
  the repositories that call it. If you call this workflow, this change alone can
  turn a build that was green red.**

  This is a published surface, not an internal CI detail.
  `.github/workflows/run-ash-security-scan.yml` is `on: workflow_call`; it is the
  workflow other repositories invoke with `uses:`, and
  `.github/scripts/assert-publish-surfaces.py` tracks it as published.

  It installed ASH from a bare `git+https://` reference carrying no extra, and both
  of its `ash dependencies install` steps are scoped to a single `--tool` (`grype`
  and `syft`), so no step in the job ever installed cdk-nag. cdk-nag's availability
  check is a metadata read of `cdk_nag`, `aws-cdk-lib` and `constructs`, so it came
  up short on every run: the scanner reported `MISSING`, callers scanning
  CloudFormation got nothing from the only builtin scanner that reads it, and ASH's
  own `SAST, SCA, and IaC Scan` check failed for the same reason. The install is now
  `automated-security-helper[cdk] @ git+https://...`, a PEP 508 direct reference, so
  the extra's contents are read from `pyproject.toml` at the pinned `ash-version`
  ref — no second dependency list to drift — and the name still resolves from the
  git ref rather than from an index.

  Three things change for a caller, and the second one fails builds:

  - **You get cdk-nag findings on any CloudFormation in your tree**, where the
    scanner previously reported `MISSING` and contributed no findings at all.
  - **A build that was green can now exit 1 on this change alone.** Combined with
    the `fail_on_incomplete_scanners` default flip above, cdk-nag findings at or
    above your severity threshold now fail the scan. Nothing in your code changed
    and nothing newly broke; a scanner that was silently absent is now running and
    reporting. Expect to hit this on the first run after upgrading.
  - **The install grows by nine packages**, so the job spends longer installing:
    `aws-cdk-lib`, `cdk-nag`, `constructs`, `jsii`, `publication`, `typeguard`,
    `aws-cdk-asset-awscli-v1`, `aws-cdk-asset-node-proxy-agent-v6` and
    `aws-cdk-cloud-assembly-schema`.

  This ships in the same release as the `fail_on_incomplete_scanners` default flip
  deliberately. Landing it separately would break callers twice — once when the gate
  turns on, again when cdk-nag starts producing findings — so both arrive together
  in one breaking release.

  To keep the previous outcome, pass `ash-args: --exclude-scanners cdk-nag`. An
  excluded scanner is recorded `SKIPPED` rather than `MISSING`, which does not trip
  the completeness gate, and the report then says cdk-nag was not part of the run.

- **The reusable scan workflow refuses a string input that could start a workflow
  command, and prints no input before checking it.** The runner reads a line of a
  step's output as a workflow command when it starts with `::` or holds `##[`, and
  it ends a line at a carriage return as well as at a line feed. The workflow's
  first two refusals printed the value they refused, so `ash-repo` set to
  `a/b`, a line feed and `::warning::...` added a warning of the caller's choosing,
  and other inputs reached git's and ASH's error messages unchecked. The job's
  first step now fails, naming the input without printing it, when any string
  input holds a line break, another control character or `##[`. The control
  characters are the C0 and C1 controls, DEL, U+2028 and U+2029, matched byte by
  byte, so the runner's locale does not change the answer. A block scalar of
  one line (`ash-args: |`, which YAML ends with a line feed) is fine: that one
  trailing line feed is dropped. More than one line is refused, and that includes
  `ash-args`, which Run ASH read one line of: a multi-line `ash-args` used to lose
  every line after the first without a word. Every later step, and the reporting
  job, uses the checked value rather than the input as given. A `config-ref` that
  starts with `-` or holds a space is refused before `git fetch` reads it as an
  option. The `prepull-base-image` and
  `run-scan-test` actions check their inputs the same way, `prepull-base-image`
  refuses an `ARG BASE_IMAGE` or `ARG BASE_IMAGE_DIGEST` holding a carriage
  return, and the pull request title check refuses such a title before printing
  it.

- **The reusable scan workflow prints a value it did not check on one line, with no
  workflow command in it.** Values that do not come from an input, such as a
  restored grype database's build time, the paths `command -v` reports for Ruby and
  cfn-nag, the machine name and OpenGrep pin, and the scanner names in the config
  read from `config-ref`, now pass through a `one_line` helper before a step prints
  them. It turns every control character into a space, `::` into `: :` and `##[`
  into `# #[`. A traceback from the `config-ref` tool-config step, which can quote a
  line of a config that does not parse, goes through it too, as does the grype
  database cache job in `ash-repo-scan.yml`.
  `python -m automated_security_helper.utils.content_databases check-age` exits 2,
  without printing the value or a traceback, when `--built` is not an RFC 3339
  timestamp with a timezone.

- **`ash scan` refuses a `--source-dir` that does not exist.** A missing path, from
  `--source-dir` or `ASH_SOURCE_DIR`, used to be scanned anyway: every scanner found
  no files and the run could exit 0, the same answer as a clean scan of the directory
  you meant. It now prints `Source directory does not exist: <path>` on stderr and
  exits 1 before anything runs. A path that is not a directory is refused the same
  way. Exit 1 rather than 2, because 2 already means "actionable findings were found".

- **`ash scan --use-existing` with no existing results exits 1 with a message.** It
  raised an uncaught `ValueError` and printed a traceback. It now names the
  `ash_aggregated_results.json` it looked for, on stderr, and exits 1, like the other
  refused invocations above.

- **`ash config get` exits 3 on a configuration file that does not parse.** A file
  with a YAML or JSON syntax error used to be logged and replaced by the default
  configuration, so the command exited 0 and printed the defaults as though they
  were the file's contents. It now prints `Invalid configuration: could not parse
  <path>: <error>` and exits 3, the code for an invalid configuration and the one it
  already used for a file that parses but does not validate. With no configuration
  file at all it still prints the defaults. A named file that does not exist, and
  a discovered source discovery cannot read, now exit 3 too (they exited 1, the
  latter with a traceback, as `ash plugin list` did). `ash scan` now refuses such
  a file the same way; see the next entry. `ash config get` also takes
  `--config`/`-c` and reads `ASH_CONFIG`, as `ash scan` does, so
  `ash config get --config <missing>` exits 3 as `ash scan --config <missing>`
  does. It used to reject the option (exit 2, `No such option`) although the CLI
  reference showed it, and it printed the discovered file even when `ASH_CONFIG`
  named another one. The positional path still works and wins over
  `ASH_CONFIG`; a positional path and a different `--config` on one command line
  exit 2. `ash config validate` and `ash config lint` also exit 3, not 1, for a
  file that cannot be loaded at all (missing, a directory, unreadable, not UTF-8,
  not valid YAML, JSON or TOML, or using a YAML alias) and when discovery refuses
  a source; 1 still means a file that loads has problems. They, and
  `ash config update`, read the file as a scan does, so a FIFO at the config name
  is refused at once instead of blocking the command.

- **A config file that cannot be loaded stops the scan with exit 3 instead of
  being replaced by the default configuration.** A file named by `--config`,
  `ASH_CONFIG`, `run_ash_scan(config=...)` or an MCP `config_path` that does not
  exist, an empty `--config ""`, and a named or discovered file that is not valid
  YAML or JSON, is not UTF-8, cannot be read, or is a dangling symbolic link (for
  example `.ash/.ash.yaml` linked to a file that is not checked out) used to be
  logged and scanned with the defaults: no suppressions, no ignore paths,
  `fail_on_findings` on and the sandbox off, and the scan reported completed.
  `ASH_CONFIG` naming an unparseable file crashed with a traceback (exit 1). Each
  now exits 3 before any scanner runs, with a message naming the file, as a TOML
  syntax error and a schema error already did. A `pyproject.toml` that cannot be
  read is refused when it would be the source used. The defaults apply only when
  there is no config file at all; an empty `ASH_CONFIG` counts as unset. A config
  file is now opened without blocking and read only when it is a regular file, up
  to 1 MiB, so a FIFO or a device at a config name is refused at once instead of
  stalling the scan or exhausting memory, and a JSON config with a UTF-8 byte order
  mark is read as YAML and TOML already were. **YAML aliases (`*name`) are refused
  in every YAML ASH reads as configuration** (config files, `extends` bases,
  workspace policy files, MCP `--profile` files and `select_profile`'s
  `override_yaml`): a few hundred bytes of nested aliases expanded to gigabytes when
  the config was written into the results or returned by MCP `get_config`. The
  refusal names the alias and its line; an anchor nothing refers to still parses.
  Discovery tells a `pyproject.toml`
  that is not a regular file by its type and does not open it, and no config file
  is opened in a way that could make a tty the controlling terminal. Under the MCP
  server, a config source found in the scanned directory that is a symbolic link
  out of the session's config roots (a `pyproject.toml`, a config file or a linked
  `.ash/`) is refused before discovery opens it, by `scan_directory` before a scan
  starts and by the scan's own discovery, with the same response whether the
  target is missing, unreadable or readable; discovery used to open it, so a
  missing or unreadable target refused the scan and a readable one did not. A
  config name ASH cannot look for (one inside an `.ash/` directory that cannot be
  searched) is refused too; it used to count as no config, and the scan ran with
  the defaults. The same refusal applies to `ash report`, `ash plugin list` and `ash dependencies install`
  (each exits 3), to workspace mode (planning, `--dry-run` included, and execution;
  `--config` is now passed to planning and must name an existing file even when
  every project has its own config; the workspace execution settings read from the
  workspace root's config no longer fall back to their defaults), and to the MCP
  server, where `scan_directory` refuses the file (and an empty `config_path`)
  before starting a scan, including one that parses and does not validate (it
  used to start a scan that then failed), and `get_config` returns an error instead of the default
  configuration, also with `raw` and when discovery itself refuses; `raw` now
  parses a `.json` file as JSON, as a scan does, where it used to parse it as
  YAML (a tab-indented file failed, and `1e3` came back as a string). A config
  source that discovery found and ignored is now also reported as a
  `config_warning` in the scan's results and summary, since its settings are not
  applied. **A CI job that set `ASH_CONFIG` to a file it only sometimes writes now
  fails when the file is absent; unset the variable instead.** `ash config wizard`
  on a file it cannot load (or a link to nothing) exits 3 and leaves it alone; it
  used to start from the defaults and write them over the file. A results file
  that records no configuration (`"ash_config": null`) now loads with none,
  instead of with the defaults or the file `ASH_CONFIG` names in the process
  re-rendering it; the CloudWatch Logs and S3 payloads then carry
  `"ash_config": null`, and a recorded configuration with no settings set is sent
  as `{}`, never as the defaults. `ash merge` refuses a shard whose results record
  no configuration (exit 1), since the merged verdict and suppressions are read
  from it. The per-scanner severity threshold in reports and summary tables is
  read from the recorded configuration only; with none recorded, or one that
  cannot be read, it is the built-in threshold and its source is shown as
  `unavailable` (workspace results show `MEDIUM (unavailable)` where they showed
  `MEDIUM (global)`), never the threshold of the file `ASH_CONFIG` names.

- **A `**` at either end of a multi-segment `ignore_paths` or `suppressions` pattern
  now takes effect.** The matcher anchored the first and last segments of a pattern
  with two or more `**` to the start and end of the path, so `tests/**/__snapshots__/**`
  matched nothing, `a/**/b/**` did not match `a/x/b/c`, and `**/x/**/y` did not match
  `p/x/q/y`. Patterns written that way were silently inert; **they now suppress or
  ignore what they say, so a scan they apply to can report fewer findings and change
  its exit code.** A `**` inside a longer component, as in `src/**.py`, is now an
  ordinary `*` (as in gitignore); it used to match only a file literally named `.py`.
  Every other pattern shape matches exactly what it did.

- **A link already at a report path stops the run with exit 1, before any reporter
  writes.** That covers the reports directory itself, each enabled reporter's
  `reports/ash.<extension>`, the files reporters write beside their reports (the
  unused-suppressions reporter's markdown, the S3 reporter's local copy, the Bedrock
  summary reporter's files) and, in workspace mode, `reports/workspace-reports.json`,
  when any of them is a symlink or a directory junction. The error names the link. A
  link there that led out of the reports directory used to make that reporter's write
  fail with an error in the log while the scan exited 0, and the link stayed in place
  for the next step that read the report. The names checked come from the reporters
  that will run: a reporter declares the files it writes itself in
  `companion_file_names()`. The check runs when the report phase starts, so it covers
  `ash scan` (including `--use-existing`), `ash merge` and MCP scans, whose error
  message now carries the reason; `ash report` checks the files the chosen reporter
  writes itself, and refuses one whose name is not a file in `reports/`. A
  `reports/` that becomes a link while a run is under way is refused where the run
  creates it again (the scan phase's results write included), rather than failing
  with a `FileExistsError`. A workspace run is refused before any project is scanned, and again
  when its report step starts if a link appeared in the meantime. A link at
  `reports/` itself, to a directory or dangling, is refused the same way in every
  mode, before ASH creates or clears anything there, rather than failing with a
  traceback. A fresh scan removes `reports/` and anything in it while setting up its
  directories, so a link left inside `reports/` by an earlier run is cleared rather
  than refused, as before. In container and nix mode, where the outer process
  re-derives the verdict from the results file, it exits 1 too when a link is
  directly in `reports/` after the inner run, rather than reading the results back,
  and when the inner run refused a report file name, which leaves nothing in
  `reports/`; see the entry on container and nix read-back. The exit code is never counted
  from a `reports/ash.sarif` that is a link, even when `fail_on_findings` is off, and
  the `--changed-files-only` rewrite of `reports/ash.sarif` refuses a link there the
  same way. Each write checks again that `reports/` is not a link. A regular file at
  a report path is still replaced. A reporter without an `extension` now writes
  `ash.txt`, the name the workspace report step already gave it, rather than
  `ash.None`. A reporter whose report file name is not a file in the reports
  directory (an `extension` with a `/`, `\` or `..` that its config did not replace,
  as a third-party reporter's config may not) stops the run with exit 1 the same
  way, rather than leaving that report unwritten, and so does such a name among the
  files a reporter declares it writes beside its report. A workspace run refuses
  such a name before any project is scanned, for a reporter that writes only
  per-project reports too.

- **Two reporters that would write the same file stop the run with exit 1, before
  either writes.** A config whose `extension` named another reporter's file, such as
  `reporters.cyclonedx.extension: sarif`, used to let the reporter that ran last
  replace the other's report, so `reports/ash.sarif` could hold a CycloneDX document
  and `reports/ash.ghas.sarif` could be emptied. The error names both reporters and
  the file. A file a reporter writes beside its report counts too, and names are
  compared ignoring case and trailing dots and spaces, as case-insensitive file
  systems and Windows compare them. A reporter that writes one of its own files
  itself, as the Bedrock summary reporter does, is not refused. A workspace run is
  refused before any project is scanned, including for a name that collides with
  `reports/workspace-reports.json`.

- **`--use-existing` exits 3 on results that hold no scan.** A results file with
  neither scanner results nor findings, as a run that stopped before its scan
  recorded anything leaves
  (a release up to v3.7.1 writes such a file after its scan phase), or one that
  records a refused run, used to be reported on as a clean scan and exit 0. The
  error names the file, quotes nothing from it, and says to run the scan without
  `--use-existing`. 3, as for any other input ASH cannot use.

- **The exit code counts only the SARIF report this run's SARIF reporter wrote.**
  `--use-existing` keeps `reports/`, so when no SARIF reporter is selected the
  `ash.sarif` there is an earlier run's, and its findings, or its lack of them,
  used to decide the exit code: a clean earlier report made a run with actionable
  findings exit 0. A config could also move the SARIF report aside
  (`reporters.sarif.extension: sarif.orig`) and give another reporter its name, and
  the exit code was then counted from that reporter's file. The report phase now
  lists the report files it wrote with the format of the reporter that wrote each,
  as a `reports_written` validation checkpoint, and only the file the `sarif`
  reporter wrote is counted, under the name its extension gave it; otherwise the
  results' own findings are. A run without a report phase (`--phases` without
  `report`) records that it wrote no report file, and results with no record count
  none. The `--changed-files-only` rewrite replaces that same file and no other.
  `ash merge` counts its verdict the same way.

- **Container and nix mode read the inner run's results back only when that run
  completed.** The outer process gives the inner run an ID (`ASH_OUTER_RUN_ID`).
  The inner run writes it into `ash_aggregated_results.json` as a `run_completed`
  validation checkpoint when it completes, or with the refusal into
  `ash_inner_run_outcome.json` beside it when its reports are refused. With the
  refusal the outer process exits 1 with the inner run's message, giving paths as
  the host sees them; without either record for its own ID it exits 1, saying the
  inner run did not complete and naming the results file. That covers a refused
  report file name, which leaves nothing in `reports/`, a refusal whose record could
  not be written, a run refused before it wrote any results (a workspace run
  refused before any project is scanned, or `--phases report`), and an inner run
  that failed after the scan phase had written the results file, which used to be
  read back as a verdict. The refusal is never written into the results file, so no
  results file holding only a refusal is left behind. A refusal record or results
  file that is a link or not a regular file refuses the read-back without being
  read, and an earlier run's refusal record is removed before the inner run
  starts. A results file that does not parse is reported by the fields that
  failed, without the values the file held there. A record an earlier run
  left in a file read back with `--use-existing` is ignored, and is dropped when
  the file is loaded, so reports do not repeat it; `ash merge` drops each shard's
  records the same way. The inner run takes the ID out
  of its environment when it starts, and the scanner sandbox drops it, so the
  processes the inner run starts do not inherit it; a value that is not such an ID
  is reported and not used. Container mode passes it as `-e ASH_OUTER_RUN_ID` with
  the value in the runner's environment, so it is not on the host's command lines
  (with `OCI_RUNNER_WRAPPER` set, the value is on the command line, since a wrapper
  such as `sudo` need not pass the environment on). The ID is not a secret: code
  running as the inner run's user can read it. The marker says whether the file is
  a complete account of that run; it does not protect the file from code running
  as the inner run's user.

- **ASH finds tools through absolute PATH entries only.** A PATH entry that is
  relative (`bin`, `.`) or empty names a directory under the working directory, and
  ASH is usually run from, and starts its tools in, the repository it scans. Tool
  lookup now skips those entries, and a tool reachable only through one is reported
  as not installed: its scanner is MISSING, and a command that names it is reported
  as one that could not start (exit 127), with the copy it did not run named in the
  reason. A program path with a directory part, such as `./tool`, is run only when
  it is absolute. The same rule covers every lookup: the spawn helpers, the uv tool
  runner, git for `--changed-files-only` and MCP source delivery, the Jupyter
  converter's `jupyter`, the scanner sandbox's own programs (`bwrap`, `firejail`,
  `readlink`, `true`), the interpreter a tool's `#!` line names, and the image build's
  checks. Programs ASH starts get a PATH with only its absolute entries, so a
  `#!/usr/bin/env node` line or a binstub cannot reach a relative one either; when
  no absolute entry is left, they get the system default path. On Windows, a name
  ASH's own lookup does not find is not handed to the operating system's search,
  which looks in the working directory first. To use a tool that sits in a
  directory such as `node_modules/.bin`, put that directory on PATH by its absolute
  path.

### Breaking changes

- **A config that sets S3, CloudWatch Logs, Security Hub or Bedrock summary
  reporter options but not `enabled` stops uploading** until `enabled: true` is
  set in the operator's config, or with `--config-overrides` such as
  `reporters.s3.enabled=true`, because these reporters are now disabled by default
  (see Behavior changes).
- **A container scan that runs as root builds the root image only when asked.**
  `ash --mode container`, `ash build-image`, `./ash` and `Invoke-ASH` build the
  `non-root` stage by default, CI or not, and refuse that build before it starts when
  its user would get UID 0 or GID 0, which is what a job running as root gives it
  (AWS CodeBuild, container-based GitLab and Jenkins jobs). The refusal exits 3 from all
  three entry points and names the opt-in: `--build-target ci` (`-BuildTarget ci` for
  `Invoke-ASH`), the stage that runs as root. Another `--container-uid` and
  `--container-gid` work only when the output directory is writable by that UID. In AWS
  CodeBuild:
  `ash --mode container --build-target ci`. An unprivileged user, such as a
  GitHub-hosted runner's, builds `non-root` as before.

- **A relative path in the operator's settings is taken from where it was set,
  not from the source directory being scanned.** In a config file outside the tree (`--config`,
  `ASH_CONFIG`, a workspace's `--config`, an MCP profile) it is taken from that
  file's directory, in an `extends` base from the base's directory, and in
  `--config-overrides`, `TRIVY_IGNOREFILE`, `TRIVY_SECRET_CONFIG` and `TRIVY_CONFIG`
  from the working directory. Before, the scanners joined it to the source directory, so
  an operator config naming `bandit.yaml` had bandit read a `bandit.yaml` at the
  root of the scanned repository. It covers `config_file` of actionlint, bandit,
  cfn-lint, checkov, ferret-scan, gitleaks, grype, syft, trivy, trivy-repo and
  zizmor, gitleaks' `baseline_path`, each entry of cfn-guard's `rules_paths`,
  detect-secrets' `baseline_file` and `file://` plugin and filter paths, trivy's
  and trivy-repo's `ignore_file` and `secret_config_file`, trivy-repo's
  `module_dir`, opengrep's and semgrep's `config` when a file or directory is
  there, and `sandbox.extra_read_paths`, which ignored a relative path before.
  actionlint's `shellcheck` and `pyflakes` name a program, looked up on `PATH` by
  a bare name, and are not covered. An operator
  config that named a file in the scanned repository by a relative path now
  names one beside the config instead; to keep using the repository's file, give
  its absolute path, or a path relative to where ASH runs with
  `--config-overrides`. See
  [Relative paths in the operator's settings](docs/content/docs/configuration-guide.md#relative-paths-in-the-operators-settings).

- **In workspace mode, every field the operator's `--config` (or `ASH_CONFIG`)
  sets is final for every project.** Before, `ash --workspace ... --config <file>`
  used the file only for a project with no config of its own, and a project's own
  `.ash.yaml` replaced it, apart from the sandbox grants, plugin modules, scanner
  config files and reporter destinations, which already came from the operator's
  file. Now the operator's file is layered over each project's own config, by the
  `extends` merge rules with the operator's file as the child: a key present in it, or in a
  base it `extends`, wins whatever its value, mappings merge key by key, and a
  list it sets replaces the project's list whole (an operator
  `global_settings.suppressions` list drops each project's own suppressions). The
  project's config fills only the fields the operator's file leaves unset, a
  project with no config uses the operator's file alone, and
  `--config-overrides`, the CLI flags and the workspace policy apply after it, as
  before. So `fail_on_findings` and `fail_on_incomplete_scanners` set in the
  operator's file can no longer be turned off by a project. To keep a project's
  own value for a field, leave the field out of `--config`.

  - `--dry-run` and the plan now use `--config` too. They did not before, so they
    could report a threshold the scan did not run with. The plan names the
    layered file in a new `operator_config` field and an `operator:` line.
  - The MCP workspace tools do the same with the session's profile, the one
    `select_profile` bound or the call's `profile`. What is layered is the profile
    as the operator registered it, never a copy the client patched with
    `patch_ops` or `override_yaml`, so a client's value is never final over a
    project's own config. `resolve_ash_workspace`'s `projects` entries carry
    `operator_config`. The session's `config/ash.yaml` now holds only the fields
    the profile sets; it loads as the same values as before. A session that bound
    no profile layers the server's `ASH_CONFIG` file, unless it is under the MCP
    workspace root. A patched binding whose registered copy is gone is refused
    (exit 3), and a call's `profile` is written to a file of its own per profile.
  - Every file the operator's config is built from must be the operator's: a
    `--config` inside the workspace's tree (the outermost git checkout around the
    workspace, or the workspace itself when it is in no checkout), one that
    `extends` a base inside it, or one under the MCP workspace root is refused
    with exit 3 before any project is resolved, and the message names the file
    and the checkout (or directory) to move it out of. This narrows #780 for
    workspace mode: a `--config` inside the checkout around the workspace used to
    be used with its sandbox grants dropped and its sandbox mode kept, and is now
    refused. `ASH_CONFIG` for a single-directory scan is unchanged: inside the
    scanned checkout it still loses its sandbox grants and keeps its sandbox
    mode. Keep the config and its bases outside that tree.
  - The plan records a digest of the operator's config and its bases. A project
    whose operator config changed after the plan, or whose plan was resolved
    without the operator config the scan is given, fails with exit 3.
  - A project that spells a key another way (`cdk-nag` beside `cdk_nag`,
    `global-settings`, `ash-plugin-modules`) no longer keeps the operator's value
    from applying; see the `extends` fix under Fixes.
  - In container mode, the operator config refusals above are made on the host
    before a container starts, also for a plan handed to `run_ash_scan` directly.
    The operator's config and the bases it extends are then mounted
    read-only at `/ash-operator-config` and the scan inside the container is
    given that path; before, it was given the host path, which it could not read,
    and exited 3. Only the `--fail-on-findings` and
    `--fail-on-incomplete-scanners` values given on the command line are
    forwarded into the container now, not values the host read from a config,
    which beat every project's own value there.
  - Rejected: ignoring every project's own config when `--config` is given, which
    loses the per-project settings a workspace exists to keep; and taking the
    operator's file as the base with the project's merged over it, which would
    still let a project turn off `fail_on_findings` or
    `fail_on_incomplete_scanners` that the operator set.
  - A single-directory scan is unchanged: there `--config` replaces discovery, and
    the repository's own config is not read.

- **Container mode needs an image built from this ASH.** Container and nix mode
  read the inner run's results back only when the inner run recorded that it
  completed, which an ASH older than this one does not do. An image built from an
  older ASH, for example with `--ash-revision-to-install` naming an older release,
  or a `--no-build` run of an older image, now exits 1 (ASH's scan-error status,
  whatever the container's own status was) with an error that says the inner run
  did not complete and names the results file. Rebuild the image from this ASH (run
  without `--no-build`, with `--force` if the image is cached); the error says so
  first and names the revision the build installs. It offers
  `--ash-revision-to-install v<version>` only when this ASH is a release that
  records completion: v3.7.1 and earlier do not, so naming one of them would build
  an image that fails the same way. Nix mode now starts the inner run with this
  ASH's own interpreter rather than the first `ash` on `PATH` inside the Nix shell,
  so the two are the same ASH.

- **A `reports/` directory that is a symlink is refused.** `ash merge`,
  `ash scan --use-existing` and workspace runs used to write their reports through a
  `reports/` that was a symlink to a directory, into the link's target. They now
  exit 1 before writing any report, with an error naming the link, as a fresh scan
  does (it used to fail with a traceback). Point `--output-dir` at a real directory,
  or remove the link.

- **An MCP scan refuses a config file it finds that links outside the directories
  the caller may read config from.** `run_ash_scan` with no `config_path`, and the
  scan itself, check the file discovery selects in the scanned directory the way
  `get_config` already checks a file it finds: a `.ash/.ash.yaml` that is a symlink
  to a file outside the session's own sandbox, `ASH_MCP_ALLOWED_ROOTS` and
  `ASH_MCP_ALLOWED_CONFIG_ROOTS` is refused before it is read, with
  `error_type: config_input_not_permitted` and the file named by its path in the
  scanned directory. `resolve_ash_workspace` and `run_ash_workspace_scan` check each
  project's config file the same way, when they plan and again when each project is
  scanned, and refuse with exit code 4. They check every config source in the
  project's directory, a `pyproject.toml` included, before discovery opens any, so
  the refusal is the same whether a link's target is missing, unreadable or
  readable. Over stdio only the system-directory check
  applies, as for any other config input. A remote scan of a tree whose config links
  to a shared file now needs that file's directory in `ASH_MCP_ALLOWED_CONFIG_ROOTS`.

- **MCP scans can now end in a new terminal status, `incomplete`.** Clients
  should treat it as terminal with partial coverage: the run finished and its
  results are readable, but at least one selected scanner did not complete
  (`MISSING`, `ERROR`, or lost some of its targets), no scanner reached a verdict,
  a converter did not run, a rule could not be evaluated, or a content database
  was past its declared age bound. Before this, the MCP
  runner reported every exit 1 as `failed` with "ASH exited with code 1", so once
  `fail_on_incomplete_scanners` defaulted on, a scan with one uninstalled scanner
  could not be told apart from a crash.

  What a client sees:

  - `get_scan_progress` returns `status: "incomplete"` with `is_complete: true`.
    `is_complete` means "the run is over and results are readable", so poll loops
    that wait on it still terminate. The gap is reported in new keys:
    `coverage_complete` (`false`; `true` for a clean `completed` scan; `null`
    while running and for `failed` or `cancelled`), `incomplete_scanners` (each
    with `scanner`, `status`, `reason` and `detail`, where `reason` is
    `missing_dependencies`, `error`, `partial_coverage` or `unrecognized_status`),
    `no_scanner_ran`, `incomplete_converters`, `unevaluated_rules` and
    `stale_content_databases` (one record per database, the same fields as
    `ash.flat.json`'s `content_databases` list).
  - `get_scan_results` returns the findings in full, with `status` set to
    `completed` or `incomplete` by the same rule and the same keys. It used to
    report the literal `completed` for any results file that parsed.
  - A workspace project whose completeness gate fired closes its scan entry as
    `incomplete` instead of `completed`.
  - `failed` now means only that the run crashed or left no readable results.

  A loop that stops only on `status in ("completed", "failed", "cancelled")` and
  ignores `is_complete` will not stop on `incomplete`. Add it to the set.

  The status is decided from a structured signal and never from log text or
  the bare exit code. `run_ash_scan` raises `ScanIncompleteExit`, a `SystemExit`
  with code 1, only where `_compute_exit_code` returned 1 with results in hand,
  and it carries the coverage reasons that verdict was reached from. The CLI's
  exit codes do not change. Reading the results file to make the call was
  rejected: a run that crashes after the SCAN phase also exits 1, and the file it
  leaves behind can name the same MISSING scanners as a finished scan.

  With the gate off (`fail_on_incomplete_scanners: false`), a scan whose scanners
  did not run is still `completed`, as its exit code of 0 says, but it now reports
  `coverage_complete: false` and names those scanners.

- **`run_ash_scan` reports a refused config with the refusal's own `error_type`.**
  A config the server refuses before the scan starts returns `success: false` with
  `error_type` `config_input_not_permitted`, `config_field_denied`,
  `config_policy_unreadable` or `config_env_not_resolved`, and the reason in
  `error`, the same values `get_config` returns for that file. Before, a refusal
  found while starting the scan came back as `scan_start_failure` with the reason
  only in the text of `error`. A client that branches on `scan_start_failure` gets
  these values instead; `scan_start_failure` remains for every other reason a scan
  could not be started.

- **A scan against a content database past its declared age bound now exits 1 by
  default, online and offline. An air-gapped image stops passing once its database
  is too old: for grype, 5 days after the database was built.**

  Measured with grype 0.111.0 under ASH's offline settings (`GRYPE_DB_VALIDATE_AGE=false`,
  auto-update off), a database built 10 days earlier scanned with exit 0 and no
  warning; ASH's own offline check called it "0 days old" because it read file mtime.
  trivy's `--skip-db-update` did the same, and the offline semgrep and opengrep
  rulesets never aged out. For a security scanner a clean-looking result from a stale
  database is the worst outcome, because nothing distinguishes it from a clean target.

  After each scanner that reads one, ASH now reads the database's own build time and
  holds it to the bound declared in `automated_security_helper/utils/content_databases.py`:

  | Database | Bound | Source of the bound | Age read from |
  | --- | --- | --- | --- |
  | grype | 120h | grype's own default (`curator.go:58` at v0.120.1) | `built` in `grype db status -o json` |
  | trivy (trivy-repo plugin) | 24h | trivy's `NextUpdate` rule; the published database sets it 24h after `UpdatedAt` | `VulnerabilityDB.UpdatedAt` in `trivy version --format json` |
  | semgrep / opengrep offline rulesets | 30 days | ASH's own choice; neither tool has a staleness notion for local rules | `.ash-rules-fetched-at`, written by the offline image build, else the oldest rules file's mtime |

  Past the bound the scanner's findings are kept and the scan exits 1, with a message
  naming the database, its build time, its age, the bound, and how to refresh it. It
  does not depend on `fail_on_incomplete_scanners`, and it outranks findings (1, not 2).
  Workspace mode reports such a project `scan_incomplete: true`, and an MCP
  scan ends `incomplete` with the database in `stale_content_databases`, with the
  completeness gate on or off. A scanner flagged only for its database is reported
  there and not also as an incomplete scanner. A database whose build
  time cannot be read counts as stale.

  **Who it affects.** Anyone running offline images, or the trivy plugin, with
  databases older than the bounds above. Online grype and trivy scans already refresh
  a stale database themselves and fail if they cannot, so they are unaffected unless
  the refresh is disabled. An image built with `OFFLINE=YES` holds the trivy
  database to `warn` instead (see the trivy scanner under Features).

  **What to do.** Refresh the database: rebuild the offline image with
  `ash build-image --offline` (it downloads a current grype database and current
  rulesets, and records their download time), run `grype db update` or
  `trivy image --download-db-only` where there is network access, and move the result
  across the air gap at least every 5 days for grype. To scan with an older database
  anyway, pass `--allow-stale-content-db` or set `content_db_staleness: warn`: the scan
  then passes, and the warning is in the log, a `### Stale content databases` section
  of `ash.summary.md`, `ash.summary.txt`, a `toolConfigurationNotifications` entry
  (descriptor `ASH-CONTENT-DB-STALE`) on the scanner's invocation in `ash.sarif`, and
  the `content_databases` list in `ash.flat.json`. The CLI flag wins over the config in
  both directions; an MCP runtime patch cannot change it.

  **Which database is checked.** ASH resolves each tool's cache directory the way the
  tool does on the host: `GRYPE_DB_CACHE_DIR` or `TRIVY_CACHE_DIR`, else
  `$XDG_CACHE_HOME` when it is an absolute path (trivy reads it only on Linux, and
  uses `$TMPDIR/trivy` for a relative one), else `~/.cache` on Linux,
  `~/Library/Caches` on macOS and the local application-data directory on Windows
  (its `cache` subdirectory for grype). In every run, sandboxed or not, it names that one directory
  to the scan, to the age check and to the database update it runs before a
  sandboxed online scan, so all three read the same database. The age check and the update run from a directory
  outside the scanned tree with an empty config file ASH ships, so a `trivy.yaml` or
  grype config in the scanned repository cannot point them at another database. The
  scan gets the directory as `GRYPE_DB_CACHE_DIR` or `--cache-dir`, which beat a
  config file, so a `db.cache-dir` in a grype config is not used, and ASH logs a
  warning naming the file; set `GRYPE_DB_CACHE_DIR` to move the database. A
  `cache.dir` in a `trivy.yaml` is overridden the same way, without a warning; set
  `TRIVY_CACHE_DIR`.
  trivy-repo keeps its scan cache in memory (`--cache-backend=memory`) in every run,
  so a scan that does not update the database itself (offline, or sandboxed) also
  works from a cache it may only read, such as one shared between jobs or baked into
  an image.

- **A rule's CVSS base score is now authoritative over a scanner's SARIF `level`,
  for every scanner, and this changes gate outcomes with nothing to opt into.**

  When a finding carries no severity band of its own but its rule declares a
  numeric CVSS score (the SARIF `security-severity` property), ASH now grades the
  finding from that score — `>=9` Critical, `>=7` High, `>=4` Medium, `>0` Low —
  instead of falling back to the SARIF `level` (`error` → Critical, `warning` →
  Medium, `note` → Low). A score of `0` or a non-numeric/out-of-range value is
  ignored and the level fallback still applies.

  This began as a Grype fix: Grype writes its CVSS on the rule and leaves the
  result at `level: error`, so every Grype finding previously counted as Critical
  regardless of its real score. But the trigger is the *shape* of the data ("the
  rule has a valid score"), not the scanner name, so it governs any current or
  future scanner — or externally ingested SARIF — that puts a CVSS score on rules
  while leaving results at a coarse level.

  **It changes severity counts, the `--severity-threshold` gate, and the exit
  code, in both directions.** An `error`-level advisory with CVSS 5.0 now counts
  as Medium (down); a `note`-level rule with CVSS 9.1 counts as Critical (up). A
  downgrade can let a finding that used to trip the threshold pass; an upgrade can
  newly block a build. This is not cosmetic, and it is on by default with no flag.

  **It is a deliberate scoring policy:** the objective, cross-tool CVSS base score
  wins over a scanner's coarse four-level label when both are present. The two
  legitimately disagree — an ecosystem advisory may be labeled "high" while its
  base CVSS is lower, and base CVSS ignores environmental and temporal context —
  so ASH's reported severity can differ from a scanner's own report. To keep a
  finding's severity where it is, suppress it or set the finding's own
  `issue_severity`. See "How ASH determines a finding's severity" in the
  [scanner statistics guide](user-guide/scanner-statistics.md).

- **A scanner that lost every target on any one tree now reports `ERROR`, on every
  scan, with nothing to opt into.** This is wider than the flag change above and
  wants reading first.

  `ScanPhase` gives each scanner one task carrying the source tree and, where the
  convert phase produced one, the converted tree, and `ScanResultProcessor` writes
  one serialized container per target. `determine_status` already returned `ERROR` for a tree
  whose every attempted target failed, but `get_scanner_status_info` never
  consulted it: it read the scanner-level `"None"` report, else the
  `scanner_results` entry, else the `"source"` report. In a real run the
  `scanner_results` branch wins, so a per-target `ERROR` was written to disk,
  serialized into the aggregated results, and never read by anything. A scanner
  that passed on the source tree and evaluated nothing at all on the converted one
  rolled up to `PASSED`.

  It now rolls up to `ERROR`, and `error` is the first branch in both
  `get_scanner_status` and `get_unified_scanner_metrics`. So for an affected
  scanner:

  - the console summary table's status column changes;
  - the markdown, text and HTML reports change with it;
  - `ash.flat.json`'s `passed` flips from `true` to `false`, which is the field a
    machine consumer gates on.

  **What is not affected**, because the distinction is the useful part:

  - **The exit code of a run with the completeness gate off, by either of the two
    changes described here.** `_compute_exit_code` consults `incomplete_scanners`
    only once `--fail-on-incomplete-scanners` resolves true, so neither lost-target
    change moves the exit code of a run that set `fail_on_incomplete_scanners: false`.
    A scanner rolling up to `ERROR` does affect the exit code under the gate — but it
    did already, since `ERROR` was always a status the gate selected on.

    Read that scope literally rather than as a statement about the release. This said
    "the default exit code" while the gate was opt-in; the default flip above is what
    puts a default run on the gated path, so lost targets now do reach a default run's
    exit code — through that change rather than through these two. A separate entry
    below — "a rule that could not be evaluated now fails the scan" — reaches it a
    third way, through a different signal again.
  - **`ash merge`'s shard verification.** `_completed` reads the raw
    `ScannerTargetStatusInfo.status` off `scanner_results`, not the derived rollup,
    so a partial-coverage scanner still counts as having run and no healthy shard
    is refused.

  Measured on this repository, this change alters nothing: cdk-nag's only target
  report is the source tree, it carries `PASSED`, and the scanner rolls up to
  `FAILED` on its findings both before and after. A repository is affected only
  when some tree lost *all* of its targets, which is why the flag change above is
  the one ASH's own scan feels.

  There is no flag. To keep a previously-green pipeline green you must fix or
  exclude the targets the scanner could not read on the affected tree, or exclude
  the scanner. Reverting to the previous behavior means accepting a report that
  states coverage it does not have.

- **`ash merge` treats the configuration each shard recorded as a repository's
  config.** A shard's `ash_aggregated_results.json` carries the configuration its
  scan resolved, and `ash merge` builds its reporters from the lowest-indexed
  shard's copy. Every setting a config file inside the scanned tree cannot choose
  now comes from the operator at merge time instead: which plugin modules are
  imported, whether ASH's off-host reporters run, where the reporters send
  findings and the credentials they use, the sandbox grants and the scanners' own
  config files. The operator's values are ASH's defaults, the new `--config`
  option (or `ASH_CONFIG`), and the new `--config-overrides` option. A recorded
  value the operator's configuration does not set is replaced, and a warning names
  the setting and the shard's results file. The merged `ash_aggregated_results.json`
  records the configuration as the merge applied it.

  `ash_plugin_modules` is stricter than in a scan: `ash merge` imports ASH's
  built-in plugins and the modules the operator names in `--config` or
  `--config-overrides`, whether or not a shard recorded them, so an installed
  plugin module a shard recorded is dropped, with one warning naming it, unless
  the operator names it too. `enabled` of a
  reporter that sends findings off the host comes from the operator's
  configuration, or the reporter's default where that is silent, as in a scan:
  `ash merge` ignores a shard's `enabled: false` with a warning, as it ignores a
  shard's `enabled: true`.

  The settings the verdict reads (`fail_on_findings`, `fail_on_incomplete_scanners`,
  `global_settings.severity_threshold`, `global_settings.suppressions`,
  `global_settings.ignore_paths`, each scanner's `options.severity_threshold`,
  `content_db_staleness` and `content_db_staleness_overrides`) still come from the
  shards. Shards whose values for any of them differ, after `--config-overrides`
  are applied, are now refused with exit code 3 instead of merged under the
  lowest-indexed shard's values, and the completion gate reads the same shard's
  value whatever order `--results` lists the shards in. A value `--config` sets
  for one of these settings is named in a warning, with the `--config-overrides`
  key that would apply it. A suggested override whose value needs quoting, such
  as a list of suppressions, is quoted for a POSIX shell, and the warning says
  so; in PowerShell or cmd.exe, quote it for that shell instead.

  A merge that relied on a shard's recorded reporter settings (an S3 bucket, a
  Security Hub region, an `ash_plugin_modules` entry that loads the AWS reporters)
  no longer sends findings there. To keep it, pass the same values to `ash merge`,
  with `--config-overrides` or in a config file named with `--config`. As for
  `ash report`, a `--config` file inside the working directory's tree (the
  outermost git checkout around it, or the working directory itself outside a
  checkout) is not the operator's, so keep that file elsewhere. `--config`
  supplies the operator's values for the settings the recorded configuration
  names; a reporter or plugin module the shards did not configure is added with
  `--config-overrides`, for example
  `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_aws_plugins"]'`.
  Loading that package makes all four AWS reporters available, each on unless the
  operator's configuration turns it off, so turn off the ones you do not want; the
  [`ash merge` reference](docs/content/docs/cli-reference.md#settings-a-shards-recorded-configuration-cannot-choose)
  has an S3-only example. Shards that disagree on a verdict setting merge once
  `--config-overrides` sets it for all of them, or, for `fail_on_findings` and
  `fail_on_incomplete_scanners`, once the matching `ash merge` flag is given.

- **An MCP profile's `runtime_overrides` and a workspace policy are read more
  strictly.**
  - A profile's own `denied_paths` adds to the default list. Before, it replaced
    it, so a profile that listed a copy of the defaults with an entry removed let
    a client change that field; now the entry still applies, and a warning names
    each default entry the list leaves out. Set
    `replace_default_denied_paths: true` to use the list as written.
  - A `denied_paths` entry or a `denied_value_patterns` key that does not start
    with `/` matched nothing before. A config file that holds one, used by any
    command, is now refused when it is read, with the entry named. Write it as a
    JSON pointer, such as `/fail_on_findings`.
  - The MCP workspace tools refuse a workspace policy file that is not in a
    directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names, where before they used it.
    Move the file into such a directory, or name its directory there.

- **A repository's config can no longer turn an AWS reporter on or off.** The
  Security Hub, Bedrock summary, CloudWatch Logs and S3 reporters send findings off
  the host, so whether they run is the operator's choice in both directions, as
  their destinations already are. A config file inside the scanned tree, or one an
  MCP client delivered or named, neither turns one of them on nor turns one off:
  where its `enabled: true` or `enabled: false` differs from the defaults,
  `--config-overrides` or a config file outside the tree, it is ignored with a
  warning, and a config that leaves the section out, which would return the
  reporter to its own default, leaves it as the operator has it. The same holds for
  a reporter from a plugin module that declares `destination_options`, once the
  scan or `ash report` has imported it. A repository that turned one of these
  reporters on or off from its own config sets it with `--config-overrides`, such
  as `--config-overrides reporters.s3.enabled=true` or `reporters.s3.enabled=false`,
  or with a config file outside the tree.
  - Under the MCP server, `/reporters/aws-security-hub/**`,
    `/reporters/bedrock-summary-reporter/**` and `/reporters/s3/**` join the
    default `denied_paths` (`/reporters/cloudwatch-logs/**` already covers that
    reporter), in place of Security Hub's and S3's per-option entries. A delivered
    config, or a client's runtime override, that turns one of these reporters on or
    sets any other setting of its section, S3's `file_format` included, is refused
    with `error_type: config_field_denied`. A value equal to the server's is
    accepted, and so is `enabled: false`, which then takes no effect (see Behavior
    changes). A profile that relied on a client turning one of these reporters on
    or off sets it in the profile instead.
  - The Bedrock reporter's `include_code_snippets` and `custom_prompt`, which choose
    what is sent to the model with the findings, are the operator's too: a config
    file inside the scanned tree that sets one is ignored with a warning, and a
    repository that set them in its own config sets them with `--config-overrides`
    or in a config file outside the tree instead.
  - So are the rest of what the Bedrock reporter sends to the model:
    `industry_context`, `compliance_frameworks` and `custom_context`, the text
    added to its prompts; `exclude_scanner_types`, which keeps secret findings out
    by default, `actionable_only`, `max_findings_to_analyze`,
    `max_findings_per_severity`, `summarize_findings` and `batch_processing`, which
    choose which findings are sent and how many; `enable_fallback_models`,
    which lets a model other than `model_id` receive them; and
    `add_section_headers`, `output_markdown`, `include_sections`,
    `exclude_sections` and `group_by_severity`, which choose which of the
    reporter's calls are made, each sending findings. A repository that set
    one of these in its own config sets it with `--config-overrides` or in a config
    file outside the tree instead. A repository config that repeats the operator's
    value is unchanged and not warned about. An operator-only option of any AWS
    reporter is now matched whether its name is written with `-` or `_`.
  - The retry options of the Bedrock summary, CloudWatch Logs and S3 reporters,
    `max_retries`, `base_delay` and `max_delay`, are the operator's too: a config
    file inside the scanned tree that sets one is ignored with a warning, so a
    repository that tuned retries in its own config sets them with
    `--config-overrides` or in a config file outside the tree instead. From every
    source they are now capped: `max_retries` at most 10, `max_delay` at most 60
    seconds, and `base_delay` at most `max_delay`; a larger value is a validation
    error naming the option and its limit.
  - A reporter's section is validated by that reporter's own config model when the
    scan, `ash report` or a workspace report builds the reporter. A section the
    model refuses, such as a retry option over its cap or an S3 `file_format`
    other than `json` or `yaml`, is logged as an error naming the option and the
    limit, and that reporter does not run; the others do. Before, the reporter was
    built from the generic reporter config instead, with the refused value in it
    and nothing logged.
  - The same holds for scanners and converters. A plugin scanner's section, such
    as `snyk-code`'s, is checked when the scanner is built rather than when the
    config is read, and a section its model refuses, such as
    `honor_tree_exclusions: "flase"`, now records that scanner as ERROR under its
    own name, with the error naming the option; the other scanners run. Before,
    the scanner ran with the refused value, or failed on an unrelated attribute
    error recorded under its lowercased class name (`snykcodescanner`). Built-in
    scanner and converter sections are still refused when the config is read.
  - The Bedrock summary reporter now retries a throttled Bedrock call `max_retries`
    times, waiting `base_delay` seconds and doubling up to `max_delay`, as the
    CloudWatch Logs and S3 reporters do. Before, it read none of the three options
    and reported a rate-limit error at the first refusal.
  - `enabled: false` for one of these reporters is accepted the same way through
    `select_profile`'s `patch_ops` and `override_yaml` and the MCP workspace tools'
    `config_overrides`, under the entries that cover it, and takes no effect there
    either; `enabled: true`, and removing `enabled`, are still refused there.

### Fixes

- **An MCP client's runtime override can't set the reporters section of a reporter
  that isn't one of ASH's built-in reporters, whatever the profile's
  `allowed_paths` permits.** That covers `select_profile` with `patch_ops` or
  `override_yaml`, and a workspace scan's `config_overrides`. A reporter a plugin
  module brings may send the findings wherever its options say, with the server's
  credentials. Under an allowlist of `/reporters/**`, a client could enable one
  that declares no `destination_options` and give it a URL of its own. The AWS
  reporters' sections were already always-denied entries, and they count too.
  Every spelling the config lookup reads counts, and so does every op type. An
  `add` or `replace` of all of `/reporters`, or of the whole document, counts when
  its value holds such a section, and a `test` or `remove` of `/reporters` counts
  outright. The refusal names the section. A client's `enabled: false` of an AWS
  reporter is still accepted, has no effect and is named in a warning, but not
  when it's sent with a destination option. Built-in reporters' sections can
  still be changed where the allowlist permits. An operator who wants such a
  reporter configured puts it in the trusted config (the registered profile)
  instead.
- **A config file's path is quoted with its control characters escaped.** When
  `ash merge --config`, `ash scan --config` or another command refuses a config
  file it cannot use, the error and the log line name the file. A path holding a
  newline or a terminal escape sequence was printed as it was, so it could start a
  line of its own in a CI log or restyle the console. It is now written as `\n`,
  `\x1b` and the like, wherever ASH names a config file, including the YAML
  parser's own message. `ash merge --config` was checked for a missing file, an
  unreadable one, a directory, a dangling link, a file that is not YAML and one
  that does not validate: each still exits 3, before anything is written, and
  the file is read at most once.
- **A scanner that refuses a target before starting its tool says so, without an
  exit code.** A refusal while the command was being assembled, such as bandit's
  for a link it cannot leave out, was reported with "(exit code 0: an accepted
  exit code for this scanner)" and a note that the tool had written no stderr log,
  describing a run that never happened. It now ends "(bandit was not started)".
  A tool that ran and failed is still described with its exit code, whether that
  code is accepted, and its stderr.
- **bandit reads no file in `global_settings.ignore_paths`.** bandit's `--exclude`
  value was built once, when the scanner was constructed, so the scan's ignore
  paths never reached it: bandit read the ignored files, and its own results under
  `scanners/bandit/` held their findings, which the reports then dropped. The
  value is now built for each scan. Each ignore path is matched as ASH matches it
  when it drops findings, and passed as the ignored files themselves, or as a
  directory whose every file is ignored. An entry that bandit would also apply to
  a file nobody ignored (bandit leaves out every path an entry is a substring of)
  is not passed, and bandit then reads that file and ASH drops its findings as
  before. An option changed after the scanner was built, such as
  `scanners.bandit.options.excluded_paths`, now reaches bandit too.
- **No scanner reads a file in `global_settings.ignore_paths` where its options
  can leave it out.** Only detect-secrets and ferret-scan were given the ignore
  paths. The other scanners read the ignored files, and their own results under
  `scanners/<tool>/` held their findings (grype's and trivy's vulnerabilities, the
  packages in syft's SBOM, which also reached the reports' SBOMs). Each is now
  told, matching each pattern as ASH does when it drops findings: grype and syft
  with `--exclude ./<path>` (a fully ignored directory `./<dir>/**`), trivy-repo
  with `--skip-files` and `--skip-dirs`, checkov with an anchored `--skip-path`,
  and semgrep and opengrep with `--exclude=<name>` for a name nothing else has.
  cfn-nag, cdk-nag and npm-audit leave the ignored files out of the scan set they
  read. A semgrep or opengrep scan whose every file is ignored is `SKIPPED`, not
  `ERROR`. snyk-code, which has no such option and uploads what it reads, refuses
  a directory holding an ignored file, the source directory and ASH's directory of
  converted files alike, wherever that is: `snyk code test` is not started,
  snyk-code is `ERROR`, and the error names the first such file and the pattern
  that matched it, with the number of files, the patterns, and the remedy (narrow
  `ignore_paths`, or `--exclude-scanners snyk-code`). Each file is matched by the
  same function that decides whether ASH drops a finding at the location snyk
  reports for it, its path below the directory snyk tests, so a converted file is
  refused exactly when ASH would drop its findings, by its path below the
  directory of converted files. This applies to the operator's ignore paths:
  those in a config an MCP client delivered drop their findings but do not stop
  the upload, and a client that does not want its files sent leaves snyk-code out
  with the `excluded_scanners` argument of `run_ash_workspace_scan`.
  `run_ash_scan` has no argument that selects scanners, so a client using it does
  not deliver the files it does not want sent.
- **A plugin module that failed to import in any shard or workspace project fails
  the combined results too.** `metadata.plugin_load_errors` lists the plugin modules
  a scan could not import, and the completeness gate
  (`.github/scripts/assert_scanners_completed.py`) fails a results file that lists
  any. `ash merge` took the field from the lowest-indexed shard only, and the
  workspace results file wrote none, so a module lost in shard 1, or in a
  workspace's second project, left a combined file the gate passed. Both now list
  every shard's or project's modules: once when they agree on the error, and with
  each distinct error, joined by `; `, when they don't.
- **A scanner the run does not select is not resolved against the package index.**
  The scan phase builds every registered scanner to learn its name, and bandit,
  checkov and semgrep ran `uv tool run --from <spec> <tool> --version` while being
  built, so `ash scan --scanners detect-secrets` online had uv resolve three scanners
  it never ran, and an excluded scanner was resolved too. Those version probes now
  wait until a scanner is selected and run just before its dependency check, so a
  selected scanner's version still reaches its report. A scanner built outside a scan
  (`ash dependencies`, the MCP server) probes as before.
- **Two offline scans overlapping in one process both stay offline, and the process
  is online again after them.** An offline scan set `ASH_OFFLINE=YES` and put back the
  value it had seen when it ended. With two overlapping (two MCP sessions, or two
  `run_ash_scan(offline=True)` threads), the first to end put back "unset" while the
  other was still running, so the rest of that scan ran online: secret verification
  permitted, none of the offline tool variables on its spawns, trivy's Terraform checks
  on, npm-audit auditing against the registry. The last to end put back "YES", so every
  later scan in the process ran offline. Offline scans now hold the variable, and the
  last one to end restores what the process started with.

- **A profile's own `runtime_overrides.denied_paths` no longer drops the shipped
  denials that trust depends on.** A list set in a profile replaced the default list
  whole, so an operator who added one entry let MCP clients turn on detect-secrets
  verification (the client's override is then replayed as the operator's setting, and
  a candidate secret found in the project was sent to its issuer), import a plugin or
  filter from a file, switch off the scanner sandbox, or load `ash_plugin_modules`.
  Those entries (`ALWAYS_DENIED_PATHS` in `config/ash_config.py`) are now added to any
  list, so a profile can add denials but not remove them. A root-pointer replace is
  now always refused, even with an empty list, since it writes every one of them.
  The reporters that send results off the host are in that set as whole sections
  (`/reporters/s3/**`, `/reporters/aws-security-hub/**`, `/reporters/cloudwatch-logs/**`
  and `/reporters/bedrock-summary-reporter/**`), so a client's config overrides
  cannot turn one on or choose where it sends, whatever a profile's list says; the
  default list now holds all four whole. So are the scanners that send data off the
  host: `/scanners/snyk-code/**` (uploads the source), `/scanners/npm-audit/**` and
  `/scanners/trivy-repo/**` (dependency lists), `/scanners/detect-secrets/**`
  (candidate secrets, when verifying) and `/scanners/semgrep/**` and
  `/scanners/opengrep/**` (usage metrics). A client can no longer configure, enable
  or disable any of them through config overrides. The workspace scan tools'
  `scanners` and `excluded_scanners` arguments can still leave a scanner out of a
  run, though not add one the configuration leaves off. An operator's own
  configuration and scans are unchanged.

- **snyk-code on a tree with no file Snyk supports is SKIPPED, not ERROR.**
  `snyk code test` exits 3 when the target holds no file it reads ("no supported
  projects detected"), for example a Terraform-only tree. scan() raised on every
  exit code but 0, so snyk-code was recorded ERROR and the default completeness gate
  failed the scan. Exit 3 now records that nothing was evaluated, which is SKIPPED;
  exit 2 is still ERROR. The plugin README and `snyk-plugin.md` also say what offline
  mode does: snyk-code is MISSING, the scan exits 1, and `--exclude-scanners
  snyk-code` leaves it out.

- **Every built-in plugin group registers, whichever ASH module a process imports
  first.** Importing the results model loads the built-in plugins, and those import
  core modules back. When one of those core modules was the first ASH module
  imported, it was still empty when its plugins imported it, and the whole group was
  dropped for the rest of the process. Measured over the package's 211 modules, seven
  orders lost a group: `from automated_security_helper.interactions.run_ash_scan
  import run_ash_scan` as a script's first import ran scans with no reporters (0 of
  15), and `utils.suppression_matcher` first lost every group. `load_internal_plugins`
  now imports a failed group again once that first import has finished; a group that
  fails for another reason, such as a missing optional dependency, still fails and is
  still reported MISSING.

- **A scanner that turns out MISSING while it runs stays MISSING.** A scanner whose
  scan finds a dependency unavailable (its `scan()` returns False, or its sandbox
  cannot be set up) is recorded MISSING per target. Consolidating the results then
  rebuilt its `scanner_results` row with `dependencies_satisfied: true`, and every
  later reader, the exit-code gate included, takes that row first. So when another
  of its targets evaluated nothing, the scanner was reported SKIPPED, which the
  completeness gate lets through. The consolidated row now says
  `dependencies_satisfied: false` for a MISSING scanner, in
  `ash_aggregated_results.json` and the S3 and CloudWatch payloads, and `ash.flat.json`
  says `dependencies_missing: true`.

- **An excluded scanner's results row says it was excluded.** Consolidating the
  results rebuilt each `scanner_results` row from the unified metrics alone, so every
  field they do not compute was dropped: a scanner left out by `--exclude-scanners`,
  `--scanners` or a disabled config was reported `excluded: false`, the same as a
  scanner that ran with nothing to scan, and `exit_code` and any extra field were
  lost. The row is now built from the existing one with only the status, counts and
  duration replaced, so an excluded scanner says `excluded: true` in
  `ash_aggregated_results.json` and the S3 and CloudWatch payloads.

- **Offline mode turns off the scanner tools' own update, version and telemetry
  checks.** Measured with a refusing proxy and empty tool caches, an `--offline` scan
  still contacted check.trivy.dev (trivy's version check; `--skip-check-update` only
  skips the checks bundle), semgrep.dev (semgrep's version check, in `semgrep scan` and
  in the `semgrep --version` probe), pypi.org (checkov's update check, which runs on
  every checkov command) and registry.npmjs.org (npm's update notifier, with
  `--offline`). Offline, every process ASH starts now gets the variables that turn
  those checks off, and the syft and grype settings that look things up over the
  network, trivy's version check and telemetry included whatever `disable_telemetry`
  says (offline npm-audit now starts no npm at all; see Behavior changes). On a Go
  module,
  offline syft no longer runs the Go toolchain on PATH (`golang.use-packages-lib`
  was on by default), and the toolchain grype runs gets `GOPROXY=off` and
  `GOTOOLCHAIN=local`, so neither can download modules or a toolchain. See
  [What offline mode turns off](docs/content/docs/advanced-usage.md#what-offline-mode-turns-off).

- **detect-secrets finds its baseline in the source directory.** A relative
  `scanners.detect-secrets.options.baseline_file`, and the default
  `.ash/.secrets.baseline` and `.secrets.baseline`, were looked up from ASH's working
  directory, although the option's description says the source directory. So
  `ash --source-dir repo` run from elsewhere missed the repository's baseline, and
  used one in the working directory if there was one. They are now taken from the
  source directory. A baseline that is not a regular file is skipped with a
  warning.

- Scanners and the other tools ASH starts get an empty standard input. They used to
  inherit ASH's own: under `ash mcp` over stdio that is the client's message stream,
  and in a terminal a tool that asked a question stopped the scan. Every spawn route
  now passes `subprocess.DEVNULL`, so a tool that reads standard input gets
  end-of-file at once: the spawn helpers and the scanner runner, git for
  `--changed-files-only` and MCP source delivery, the Jupyter converter, nix mode,
  the scanner sandbox's probes, and the image build's checks. A call that passes
  `input=` still writes it to the tool, and that now also holds when the tool runs
  under the scanner sandbox.

- **A setting spelled two ways merges as the one setting ASH reads**, in `extends`
  and in the workspace operator layer. Keys that differ only in `-` versus `_` were
  merged under the base's spelling, whatever ASH reads, so a base could keep a
  child's value from applying (and a project an operator's), by writing an
  unread spelling (`global-settings: {}`, `ash-plugin-modules: []`,
  `nag-packs: {}`) or both spellings of an aliased section (`cdk-nag` beside
  `cdk_nag`, where the alias wins). Now each setting is merged under the
  spellings ASH reads and written once; a base's unread spelling is left alone,
  and a child's still reaches the base's spelling of the setting unless the
  child also uses a spelling ASH reads. Two spellings of a plugin's section that
  ASH reads for the same plugin (`BedrockSummary` and
  `bedrock-summary-reporter`) are one section, under the child's spelling.

- `ash mcp --profile NAME=path/to/ash.yaml` works. The server registered profiles
  given with `--profile`, but `ash mcp` did not accept the option and exited 2 with
  `No such option: --profile`, so `list_profiles` always returned an empty list.

- `ash mcp --profile` registers a profile that uses tagged `!ENV` or is a TOML file.
  The check for unknown top-level fields read the profile with a plain YAML parser,
  which refused the `!ENV` tag and misread TOML; it now reads the file as the
  profile itself is loaded.

- **The nix shell's database downloads run from an empty temporary directory.**
  grype's and trivy's databases are downloaded with an empty config file from a
  fresh temporary directory, so a grype or trivy config in the directory the
  shell is entered in no longer applies to the download.

- **An `OFFLINE=YES` image build fails when an offline ruleset cannot be downloaded.**
  With more than one ruleset in `OFFLINE_SEMGREP_RULESETS`, a ruleset other than the
  last that failed to download was skipped and the build passed without it.

- `ash dependencies install --tool ArchiveConverter` works again. Building each plugin
  from its own config section renamed the archive converter's selector to `archive`,
  so the old spelling exited 2 as an unknown tool. It is now accepted as a deprecated
  alias for `archive` and prints a deprecation warning to stderr. An unknown name
  still exits 2.

- npm-audit no longer reads a failed audit as a clean one. npm exits 1 both for
  "vulnerabilities found" and for "audit endpoint returned an error", and the scanner
  accepted exit 1, found no `vulnerabilities` key in npm's error document and converted it
  to zero findings. A document carrying npm's `error` object, or a non-zero npm or pnpm
  exit without that tool's report, is now an audit failure reported as ERROR. A clean
  audit (exit 0, empty `vulnerabilities`) still passes, and findings on exit 1 are still
  findings.

- npm-audit now parses yarn's audit output. yarn 1 writes `yarn audit --json` as one JSON
  object per line, which the scanner handed to `json.loads` whole, so every report failed
  to parse and was dropped. yarn 2 and later have no `yarn audit`; the scanner ran it
  anyway and took the usage error for a clean audit. The scanner now asks `yarn --version`
  in the project, runs `yarn audit --json` for yarn 1 and `yarn npm audit --json
  --recursive` for yarn 2+, and reads all three output formats (yarn 1 NDJSON, the npm v1
  document yarn 2 and 3 print, and yarn 4's NDJSON). Each advisory becomes one result per
  installed version, with the npm path's severity levels, rule ids and properties.
  yarn 4's deprecation notices are not findings. A yarn audit with no report (yarn 1
  without its closing `auditSummary`, yarn 2+ exiting non-zero without advisories, or an
  error event or crash) goes through the same failure path as npm and pnpm.

- npm-audit now reports pnpm findings. `pnpm audit --json` writes npm's v1 report, with
  `advisories` and `metadata`, and the scanner read only npm 7's `vulnerabilities` key, so
  a project with a `pnpm-lock.yaml` came out PASSED with 0 findings and exit 0 whatever
  its dependencies held. Each pnpm advisory now becomes one result per installed version
  it lists, with the npm path's severity levels, rule ids, URI and properties, so a
  vulnerable pnpm project fails the scan (exit 2). A GHSA that pnpm, or yarn 2 and 3,
  return as several advisories, one per vulnerable range, keeps each range on its own
  results instead of reporting every version under the first range. A failed pnpm audit
  is still ERROR.

- **A scanner whose constructor raises is recorded under its scanner name.** The
  ERROR row for a scanner that could not be constructed was keyed by its class
  name (`banditscanner`) because the configured name was read off a dict with
  `getattr`. It is now keyed by the scanner name (`bandit`), which is the name
  the expected-scanner roster, the shard partition and `--exclude-scanners` use.
- MCP config tools now confine config paths, including `extends` chains, to the allowed roots.
  The `get_config`, `validate_config`, `explain_finding`, `suggest_suppression` and
  `diff_scan_results` functions in `cli/mcp_server.py` now take the MCP `Context` as
  their first argument, as the other tools already did. The MCP tool schemas are
  unchanged; only direct Python callers need to pass it.
- **A scanner whose tool could not be started is reported as ERROR.** When the
  exec itself failed (an `OSError` such as a missing binary or `[Errno 14] Bad address`),
  the subprocess helpers returned exit code 1. Semgrep and bandit accept 1, so the scan
  went on and the only error shown was a missing SARIF file. The helpers now return 127
  with a `Could not start <cmd>: <error>` message, 127 is never an accepted exit code,
  and the scanner is recorded as ERROR. The spawn is not retried.
- **Scanner spawns no longer fail intermittently with `[Errno 14] Bad address`.** On
  Linux, Python 3.10+ starts children with vfork, and a spawn with `env=None` hands the
  child the parent's live `environ` array until `execve`. Scanners run in parallel
  threads and cdk-nag sets and removes three JSII variables around every template, so
  another scanner's child could exec against freed memory. In CI this showed up as
  cfn-nag recording "returned no stdout" and "1 of 9 targets unevaluated", with a rerun
  passing. ASH's spawn helpers and the other spawns that run alongside scanners now pass
  an explicit copy of the environment, and runtime changes to `os.environ` go through
  one process-wide lock in `utils/process_env.py`. Scanners see the same variables as
  before. An offline scan also now restores a pre-existing `ASH_OFFLINE` value when it
  finishes rather than clearing it.
- **`ash scan --offline` in local mode runs every scanner offline.** checkov, grype,
  npm-audit, opengrep, semgrep, syft and the trivy-repo plugin defaulted their
  `offline` option to `ASH_OFFLINE` as read when their config was built, and ASH builds
  the default scanner configs at import, before `--offline` sets `ASH_OFFLINE`. Those
  scanners kept `offline: false` and used the network: checkov ran without
  `--skip-download` and opened three HTTPS connections, grype and syft kept their
  database and update checks, and semgrep ran `--config p/ci --metrics auto` against the
  registry instead of the offline rule cache. Offline mode is now resolved when each
  scanner runs. The precedence change and the new exit code for a missing rule cache
  are under Behavior changes. The option's schema default is now a plain `false`
  instead of the import-time environment value.

- **Plugin discovery no longer crashes on Windows with Python 3.13+.**
  `discover_plugins` enumerated every `sys.path` entry with `pkgutil.iter_modules()`.
  On CPython 3.13 and later that raises `KeyError` for a zip archive on `sys.path`
  after any `importlib.invalidate_caches()` call, because `pkgutil` reads a zipimport
  cache entry that invalidation now removes. On Windows the console-script launcher
  (`ash.exe`, `pytest.exe`) is a zip archive and is `sys.path[0]`, so loading
  `ash_plugin_modules` in a scan or workspace run could fail there. Discovery now looks
  up each requested top-level package name directly and never reads unrelated
  `sys.path` entries. It matches the same packages as before, with one addition: a
  plugin package installed in editable mode through an import hook is now found.

- **`ash dependencies install` no longer installs a second copy of a pinned tool
  that is already present.** The container image installs syft, grype and trivy into
  `/usr/local/bin` from their pinned release assets, and then ran
  `ash dependencies install` twice (once per image stage), each writing grype and
  syft into `ASH_BIN_PATH` again; trivy would have followed once a builtin scanner
  installs it. The installer now checks the executable a scan would resolve: if its bytes
  hash to the pinned SHA256 of that release's executable, the install is skipped and
  the row reads `VERIFIED PRESENT`. A same-named binary with any other bytes,
  whatever version it reports, does not count, and the pinned build is installed
  exactly as before. The image is 334.6 MB smaller (5,598.7 MB to 5,264.1 MB
  uncompressed). To make the check possible, `tool_downloads.py` now pins the SHA256
  of the executable inside each release archive as well as the archive's, and every
  install, including the image's `install-pinned-tool`, refuses an extracted
  executable that does not match it.

- **The container image ships the license and notice files of the programs it
  bundles.** grype, syft, trivy, opengrep and uv were copied into the image without
  the license texts and notices their licenses require to travel with them; trivy's
  NOTICE was missing everywhere, because its release archive leaves it out. Each now
  has `/usr/share/doc/ash/third-party/<tool>/`, holding the files from the exact
  release the image carries (read from the release archive the binary already comes
  from where it has them, otherwise fetched at the upstream commit and checked
  against a pinned SHA256), and a `SOURCE` file with the repository, tag and commit.
  For opengrep, which is LGPL-2.1, that file also says where the corresponding source
  is. `index.json` in the same directory lists everything bundled. The list is
  `THIRD_PARTY_LICENSES` in `utils/tool_downloads.py`: a pinned tool with no entry
  there fails the unit tests and the image build, the build checks each tool's
  `--version` against its entry, and the container CI legs fail on any executable on
  the image's PATH that neither a Debian package nor an entry accounts for.
  The Python scanners bandit, checkov and semgrep, which `ash dependencies install`
  puts in the image with `uv tool install`, are covered too. semgrep is LGPL-2.1 and
  its wheel ships no license file at all, only a `License-Expression` line in its
  metadata, so its LICENSE and COPYRIGHT are fetched at the release commit and checked
  against pinned SHA256s, and its `SOURCE` says where the corresponding source is.
  bandit's and checkov's licenses are copied from their installed wheels' dist-info,
  checked against the wheel's RECORD; a wheel that ships a file is always read before
  anything is fetched. So that these files describe the release in the image, the
  image now installs each of the three at exactly its entry's version (bandit 1.9.4,
  checkov 3.3.26, semgrep 1.180.0) instead of the newest release its scanner's default
  range allowed on the day of the build. Outside the image the defaults are unchanged.

- **The ferret-scan plugin supports ferret-scan 2.5.x** (#684). The window moves from
  `>=2.4.5,<2.5.0` to `>=2.4.5,<2.6.0`, and the recommended version from 2.4.5 to 2.5.2.
  Two 2.5.x changes needed handling. Its SARIF locations are now relative to the scan
  target with `uriBaseId: %SRCROOT%`, a base ASH's aggregated report never defined; the
  plugin resolves them back to absolute URIs, so 2.4.5 and 2.5.2 produce the same paths
  in every report. Its `--exclude` no longer matches raw substrings, so ASH's `.git`
  ignore path stops skipping `.github/` and patterns like `test-results/**` now take
  effect. Separately, the plugin now passes `FERRET_PRECOMMIT=0`: under ASH's own
  pre-commit hook, ferret-scan detected pre-commit mode from `PRE_COMMIT=1`, exited 1
  on findings (reported as a scanner failure) and narrowed its results.

- **SARIF upload can hold `security-events: write`.** `run-ash-security-scan.yml`
  declares only contents, checks and pull-requests, and a called workflow can only
  narrow its caller's token, so its "Upload ASH SARIF file" step never had
  `security-events: write` even when the caller granted it. Same-repo pull requests
  uploaded anyway; `workflow_dispatch` failed with "Resource not accessible by
  integration".

  The new reusable workflow `upload-ash-sarif.yml` declares the permission and
  uploads the report from the `ash_output` artifact. To use it, set
  `collect-sarif-report: false` on the scan and call it from a second job that
  `needs` the scan job, granting `security-events: write` to that job only.
  `run-ash-security-scan.yml` is unchanged for existing callers.

  The permission was not added to the scan workflow, not even on a job gated by
  `collect-sarif-report`. GitHub validates every permission a called workflow
  declares when the run starts, including on a job whose `if:` is false, and fails
  a caller that does not grant it before any job runs. That would have broken
  every caller that never granted `security-events`.

- **cdk-nag now evaluates CDK-synthesized CloudFormation templates.** A template
  produced by `cdk synth` carries a `BootstrapVersion` parameter and a
  `CheckBootstrapVersion` rule of its own. ASH re-includes a template under
  `CfnInclude` into a fresh stack, and `DefaultStackSynthesizer` adds the same
  parameter and rule to that stack, so the two collided with
  `SectionAlreadyContains: section 'Parameters' already contains 'BootstrapVersion'`.

  The collision was invisible. It raised inside `app.synth()`, which the wrapper
  catches and logs at DEBUG — correctly, because cdk-nag reports violations *by*
  raising there — so no `validation-report.json` was ever written and the only trace
  left was `cdk-nag produced no validation report`. No rule ran against the template
  and nothing above DEBUG said which rule, or that there had been a collision at all.

  `WrapperStack` now synthesizes with `generate_bootstrap_version_rule=False`. The
  bootstrap check is deploy-time machinery that refuses a deployment against a stale
  CDK bootstrap stack; this wrapper synthesizes only so that the policy validation
  plugins run and never deploys anything, so the parameter and rule were inert
  scaffolding either way and no nag rule reads them.

  Measured on this repository: the two affected templates went from unevaluated to 30
  violations each across five packs. Measured as a control on a template that already
  worked, the validation report is identical with the flag and without it — same
  packs, same rules, same construct paths — so the change adds coverage without
  moving any existing verdict. `BootstraplessSynthesizer` was the alternative and was
  rejected: it also refuses file and Docker image assets, which would make an
  asset-bearing template fail for a second, unrelated reason.

- **A file cdk-nag cannot parse is an announced skip, not an unevaluated target.**
  cdk-nag's scan set is every `*.json`, `*.yaml` and `*.yml` file in the tree, most of
  which were never CloudFormation. A file that no YAML or JSON parser can load cannot
  carry a `Resources` mapping, so it is not a candidate template — but the parse error
  fell through to `CdkNagScanner.scan()`'s broad `except Exception`, which counts a
  **failed target**.

  It is uncounted **and still reported**, which is two changes rather than one. A
  parse failure is not confidently a non-template the way a document that parses with
  no `Resources` key is — a truncated or malformed real template produces the same
  symptom, and ASH cannot tell which from here. So the notice goes through
  `_plugin_log(append_to_stream="stderr")`, which appends to the scanner's error list
  and therefore reaches SARIF `exitCodeDescription`: the same channel the "target
  directory is empty" notice uses, at INFO rather than ERROR because it is a fact
  rather than a failure. Dropping it to a DEBUG log was tried first and rejected —
  `tests/integration/scanners/test_cdk_nag_real_pack.py` pins that an unparseable
  target must appear in that channel, on the grounds that "not a finding" would
  otherwise also be satisfied by the failure vanishing entirely.

  With `fail_on_incomplete_scanners` on by default, that made any repository holding
  a JSON-with-comments file or a YAML with application-specific tags report
  incomplete coverage for cdk-nag while containing nothing unscanned. In ASH's own
  tree it was `deploy/cdk/tsconfig.json` (a `//` comment) and `mkdocs.yml`
  (`!!python/name:` tags).

  The sibling `cfn_nag_scanner` already classified this case as a skip over the same
  scan set, calling the same `get_model_from_template`, and that function's docstring
  already recorded the contract — "Exceptions from `load_yaml` propagate unchanged
  ... and the two callers already classify that case for themselves." cdk-nag was the
  caller that did not. This is convergence on a decision the codebase had already
  made, not a new leniency.

  **Narrow on purpose.** Only `YAMLError` and `UnicodeDecodeError` are reclassified,
  in the scanner's per-target loop immediately above the broad handler it carves out
  of. `OSError` is not: an unreadable file is a target ASH was asked to scan and could
  not, which is an incompleteness the gate should see. A document that *does* carry a
  `Resources` mapping and cannot be modeled is not either — that stays a failed
  target, with a test pinning it so the arm cannot be widened into a bare
  `except Exception`.

- **An unavailable converter with nothing to convert no longer fails the scan.** The
  converter arm of `fail_on_incomplete_scanners` fired whenever a converter's tool was
  absent, regardless of whether that converter had any inputs. In `--mode nix` the dev
  shell supplies scanner binaries and exports `ASH_OFFLINE=YES`, which correctly refuses
  `uv tool install nbconvert`, so the jupyter converter is unavailable on every Nix-mode
  run — and both Nix CI legs exited 1 on a fixture holding one CloudFormation template,
  one Python file and one `package.json`, and **no notebooks at all**. Nothing had gone
  unscanned.

  `ConverterPluginBase.candidate_input_count()` answers how many files a converter *would*
  have converted, established **without** its external tool — which is what makes it
  available for a converter already dropped for a missing tool. `ConverterStatusInfo`
  carries it as `candidate_inputs`, and the gate exempts a row only on an explicit `0`.

  **This is not a carve-out, and the carve-out was the rejected alternative.** Exempting
  converters from the gate would let ASH report success on a tree whose notebooks were
  never scanned, which is the defect the gate exists to catch — reintroduced one file type
  at a time. So the exemption is "nothing to convert", never "converters", and it turns on
  a positive claim rather than on missing information: `None` means the converter reports
  no count and is treated exactly as strictly as every row was before the field existed,
  which covers a converter that has not opted in, one whose count raised, and a results
  file written by a version predating the field.

- **An incomplete-conversion exit says so, instead of claiming an exception.** The message
  selector behind exit 1 handled the scanner arm and fell through to `ERROR (1) Exiting
  due to exception during ASH scan` for everything else. Nothing raises on the converter
  path — `_compute_exit_code` returns 1 after a `logger.error` — so both Nix legs exited
  claiming an exception that did not exist, and the only record of the real cause was a log
  line seventy lines earlier. The converter arm now names the converter and what to do
  about it. The arm selection moved into `print_incompleteness_message`, because inline in
  a function that runs a whole scan it could not be unit tested, which is how wording that
  wrong survived.

- **The Nix install-method CI job installs the `cdk` extra.** cdk-nag is the one
  scanner Nix cannot supply — it runs in-process through jsii rather than as an
  external binary, which is why `flake.nix` omits it — but "Nix does not supply it"
  is not "it need not be installed". The job's `pip install .` left cdk-nag's three
  distributions absent, so the scan selected it and recorded `MISSING`. Tolerable
  while the completeness gate was opt-in; with the new default the scan exits 1 for a
  reason that has nothing to do with Nix. `node` comes from `pkgs.nodejs` in the
  flake's dev shell, already there for `npm audit`, and ASH re-execs itself inside
  `nix develop`, so the in-process scanner finds it.

- **`ash report --format spdx` works, and the SPDX reporter writes SPDX.** The
  reporter was a stub that wrote the whole results model as YAML into
  `ash.spdx.json`, and `ash report` exited 1 trying to print that as JSON. It now
  emits an SPDX 2.3 JSON document built from the scan's CycloneDX SBOM, validated
  against the SPDX 2.3 schema; see [Output formats](docs/content/docs/output-formats.md#spdx).
  The reporter is still disabled by default.

- **`ash report` passes a reporter its configured options.** The command assigned the
  reporter's config section as a plain dict, so on any scan with a finding
  `ash report --format junitxml` exited 1 with `'dict' object has no attribute
  'options'`, and `github-ghas` failed the same way. Options such as junitxml's
  `respect_severity_threshold` now take effect there as they do in a scan. The list
  of formats `ash report` prints as JSON named reporters that do not exist (`asff`,
  `security-hub`, `security-lake`, `opensearch`) and missed `github-ghas`,
  `gitlab-sast` and `gitlab-cyclonedx`, whose stdout came out soft-wrapped with
  newlines inside JSON strings; `bedrock-summary-reporter` was spelled
  `bedrock-summary` and so was not rendered as Markdown.

- **The text and html reports show each scanner's real duration.** The scanner rows
  they render had no `duration`, so every scanner read `<1ms`. The rows, and the
  `scanner_metrics` rows in `ash.flat.json`, now carry it. The markdown report's
  legend no longer describes a Duration column its table has never had.

- **S3 uploads are keyed by the scan's timestamp, and `ash.s3.json` is JSON.** The
  key was `ash-reports/ash-report-None.json` for every scan, because it was read from
  a field the engine sets only after reporting, so each run overwrote the last. It
  now uses `metadata.generated_at`, which is the same during the scan and in a later
  `ash report --format s3`. `reports/ash.s3.json` held the bare `s3://` URL (or, on a
  failed upload, the error message); it is now a JSON receipt with the URL, bucket,
  key, format and local copy path, and a failed upload writes no receipt.

- **The MCP `get_scan_summary` tool reports real severity counts.** It read the
  counts from the top level of `summary_stats`, where a real scan has none, so every
  severity read 0. The `actionable_only` and severity filters on scan results had the
  same mistake and left the real counts unfiltered.

- **`ash scan --mode nix` refuses with a message instead of a traceback.** With no
  `nix` on PATH, and when the recursion guard found it already inside a Nix-mode
  run, the scan ended in an uncaught `RuntimeError`. It now prints the same message
  on stderr and exits 1, like the other refused invocations.

- **A container-mode refusal is no longer followed by "Results file not found".**
  When `ash scan --mode container` refused before any container ran (no OCI
  runner, a non-numeric `--container-uid` or `--container-gid`, an unsafe
  `--ash-revision-to-install`, a missing Dockerfile, a failed image build), it went
  on to log "Container execution failed" and then looked for a results file that
  nothing could have written, ending in `Results file not found at
  .../ash_aggregated_results.json`. It now stops after the refusal's own message,
  with its exit code: 1, or the runner's status for a failed build.

- **`ash scan --mode container --no-build` no longer needs a Dockerfile.** The
  Dockerfile was looked up before ASH decided whether to build, so outside an ASH
  checkout, with ASH installed from one, `--no-build` refused with `Dockerfile not
  found` although nothing was going to be built. The lookup now happens only for a
  build, and `--no-build` runs the image that is already present.

- **The PowerShell `Invoke-ASH` finds an OCI runner when you do not name one.**
  Without `-OCIRunner` and with `ASH_OCI_RUNNER` unset, PowerShell bound the
  parameter to an empty string rather than `$null`, so `Invoke-ASH` tried to run a
  runner named `""` and always failed. It now falls back to the first of `docker`,
  `finch`, `nerdctl` and `podman` on PATH, as `./ash` falls back when `OCI_RUNNER`
  is empty.

- **The container image installs cfn-nag's gems from the committed `Gemfile.lock`.**
  The Dockerfile copied only `automated_security_helper/assets/Gemfile`, so every build
  resolved cfn-nag's dependencies again and could install gem versions the lockfile does
  not list. It now copies the lockfile beside the Gemfile and runs Bundler with
  `BUNDLE_FROZEN=true`, so a build installs exactly the locked gems and fails when the
  Gemfile and the lockfile disagree.

### Reporting changes

- **Reports now carry the age of every content database a scan used.** Additive:
  `ash.flat.json` gains a top-level `content_databases` list (an empty list when no
  scanner read one), each entry with `built`, `age`, `max_age`, `stale`, `policy` and
  `enforced`; each such scanner's SARIF invocation gains an `ash_content_databases`
  property and, when stale, a `toolConfigurationNotifications` entry; and the markdown
  and text summaries and the console gain a stale-database section, emitted only when
  there is one. See the breaking change above.

- **Reports now say how much of its input each scanner evaluated.** Additive, but
  it does change bytes, so it is listed rather than left to be discovered:

  - `ScannerMetrics` gained `targets_attempted` and `targets_failed`, and
    `ash.flat.json` carries both. `targets_attempted` is `null` — not `0` — for a
    scanner that does not track per-target outcomes, so a consumer can tell "made
    no claim" from "attempted none".
  - The console table and the markdown report gained an "Incomplete coverage"
    section, emitted only when there is something to report. Measured on this
    repository it named cdk-nag's 7 of 11 when the section was added; with both
    cdk-nag fixes under Fixes below in place the tree has nothing to report and the
    section is absent again. It is the *conditional* emission that is the change
    here, not a number.
  - cdk-nag's SARIF gained `runs[].invocations[].toolExecutionNotifications`, one
    per rule that raised instead of returning a verdict, at `level: error`.
    Measured on this repository: 11 notifications where there were previously
    none. These do **not** reach GitHub Advanced Security — the `github-ghas`
    reporter assembles a fresh run carrying only `tool.driver` and `results`, so
    `ash.ghas.sarif` has no `invocations` key at all. A pipeline that uploads
    `ash.sarif` itself rather than `ash.ghas.sarif` will surface them.
  - A cdk-nag rule that could not be evaluated is now `kind: notApplicable` at
    `level: none`, which ASH maps to INFO. It was previously reported as a finding
    at the rule's declared severity. Measured on this repository, the aggregated
    SARIF holds the same 453 results before and after, of which 15 move to
    `notApplicable`/`none` — 10 that were `error`/`fail` and 5 that were
    `warning`/`informational`. The actionable counts do not move here because those
    15 were already suppressed; on a tree where they are not, the scanner's
    high-severity count drops by however many of its rules raised.

- **No secret value a finding exposes reaches a report.** Masking used to cover
  one field: the message of a bandit B105, B106 or B107 finding. The same values
  were written in plain text to the SARIF snippets (`region.snippet`,
  `contextRegion.snippet`), the flat JSON and CSV `code_snippet` and `raw_data`,
  GitLab SAST `details`, YAML, the markdown summary, the Bedrock summary and
  `ash_aggregated_results.json`, and a non-secret finding's context could hold a
  secret from a neighboring line. The results are now masked once, after the
  scanners' results are merged and before any reporter runs, by location (every
  snippet line at a line a secret finding reports) and by value (each value a
  secret finding's message quotes, wherever it recurs). Snippets without a secret
  are unchanged. The B105-B107 message is now masked in every output, not only the
  flat model's `description`. Secret findings include semgrep's and opengrep's
  `generic.secrets.*` rules, recognized by the CWE-798, CWE-259 or CWE-321 tag their
  rules carry or by the `secrets` segment in their id. See "Secret values in reports" in
  docs/content/docs/output-formats.md.

- **Stored results are masked when they are read back.** `ash report`,
  `ash scan --use-existing`, `ash merge`, the MCP tools that read an existing
  `ash_aggregated_results.json`, the findings browser and a workspace's unified
  reports now mask secret values as the file is loaded, so a results file written
  without masking (by an earlier ASH or another producer) no longer passes its
  values on to the reports and responses rendered from it. `ash merge` masks the
  merged results against every shard's secret findings before it writes them.

- **Secret masking misses fixed.**
  - A form feed, vertical tab, NEL, U+2028 or U+2029 in a snippet shifted every
    later line number, so the secret line was written in clear while a
    neighboring line was masked. Lines are now counted at `\n`, `\r\n` and `\r`
    only, and a snippet holding one of the other characters, or a lone `\r`, in a
    file with a secret finding is masked whole.
  - A private key reported on its BEGIN line (detect-secrets) is masked through
    its END line in every snippet.
  - A value holding its own quote character (`'ab'cd...'`) is masked to the last
    quote of the message, not the first.
  - A secret finding's own snippets are masked whole, whatever line numbers the
    tool's context carries.
  - A raw value holding a `*` is no longer mistaken for one the scanner already
    masked.
  - A percent-encoded URI (`my%20app/settings.py`) matches the same file written
    plainly.
  - A line with an unterminated quote and many backslashes no longer stalls the
    masking (and an MCP server with it), and a secret region ending at line
    3,000,000 no longer allocates one entry per line.

- **The findings browser masks the source lines it reads from disk.** For a
  finding with no snippet, `ash inspect findings` shows the five lines either side
  of it from the file, which were not masked: a secret on a neighboring line was
  shown in clear. Those lines are now masked as the results' snippets are.

- **checkov's and cfn-nag's hard-coded credential rules are secret findings.**
  checkov's `CKV_AWS_41`, `CKV_AWS_45`, `CKV_AWS_46` and the other "hard-coded"
  checks, and cfn-nag's "... must not be a plaintext string" password rules, were
  not recognized, so the credentials checkov puts in every snippet of the
  resource (a Lambda's environment, say) stayed in clear in every finding about
  it. They are now recognized by what their message or rule description says.

- **Ordinary words a password check quotes are no longer masked everywhere.**
  A B105 on `FIELD = "password"` masked every `password` in the results: rule
  descriptions, tags, other findings' messages (which changed their IDs) and SBOM
  entries. A value is now masked beyond its own finding only when it looks like a
  secret (eight characters or more, not letters alone, not a template
  placeholder, not repetitive), and only in what findings report, never in rule
  metadata, tags or identifiers. A secret finding that quotes no value (semgrep's
  and opengrep's `generic.secrets.*`) gives the value its own region matched.
  Any value, whatever it looks like, is also masked in every finding whose region
  or context covers a line the secret finding reports, so a second scanner's
  finding on that line no longer quotes it. A short or all-letter secret is still
  left as it is in findings on other lines and in other files.

- **A value one project or shard exposes is masked in the others' findings.**
  Each workspace project and each `ash merge` shard was masked against its own
  secret findings only, so a value project A's B105 reported stayed in clear where
  project B's finding showed it, in B's files and in the unified results and
  reports. A workspace scan now masks every project's `projects/<key>/` results
  and reports, and the unified results, again with the values every project
  exposed. Results files now record, under `secret_value_shapes`, the visible
  prefix, visible suffix and length of each value they masked, never the value,
  and `ash merge` masks every token of those shapes in every shard. Masking by
  shape can also mask a different token with the same visible characters and
  length.

- **ferret-scan's bundled profiles no longer turn on `show_match`.** The
  `comprehensive`, `json-api`, `debug`, `person-name`, `enhanced-metadata` and
  `social-media` profiles in the bundled `ferret-config.yaml` set it to `true`, so
  choosing one of them wrote every matched value into ferret-scan's own results
  file. All of them now set it to `false`. With `show_match` turned on explicitly,
  the matched values are still masked in ASH's reports (see above); they remain in
  ferret-scan's own output under `scanners/ferret-scan/`.

- **The Bedrock summary reporter recognizes secrets-scanner findings.** Its
  `exclude_scanner_types` compared a `scanner_type` property that no scanner
  writes, and its default `SECRET` did not match the `SECRETS` tool type, so
  detect-secrets and ferret-scan findings were sent to the model as ordinary
  findings. A finding's type is now its scanner's tool type, looked up from the
  scanner's name, or a `tool_type::` tag in either spelling, and `SECRET` and
  `SECRETS` both match. With the secrets type excluded, findings from rules that
  detect a credential or key are counted too, such as semgrep's and opengrep's
  `generic.secrets.*` (CWE-798). A finding whose scanner type cannot be determined
  is sent without its snippets. With `include_code_snippets` off (the default),
  `reports/ash.bedrock.summary.md` no longer carries snippets in its "Raw JSON"
  blocks.

### Configuration sources

- **`pyproject.toml [tool.ash]` and `ashrc` files are config sources (#313).**
  Without `--config`, ASH uses the first of: the existing `.ash.*` / `ash.*` names
  (root, then `.ash/`, in their existing order), then `.ashrc.{toml,yaml,yml,json}`
  and `ashrc.{toml,yaml,yml,json}` at the root, then a `pyproject.toml` that has a
  `[tool.ash]` table. Sources are never merged: the one used is logged, and every
  other source found is logged as ignored. The older names still win, so a
  repository with `.ash/.ash.yaml` keeps its settings; when one of them shadows a
  newer source the warning says those names are deprecated. Results still go to
  `.ash/`.

- **A config can `extends` other configs and `patch` the result (#289).**
  `extends` names one or more base files (relative to the extending file);
  mappings merge key by key, lists and scalars from the extending file replace the
  base's, and `patch` applies RFC 6902 `add`/`remove`/`replace`/`test` operations
  afterwards. Bases must resolve inside the scanned repository, symlinks included,
  and URLs are refused. A missing base, a cycle, or a chain past 10 levels or 50
  files fails the load instead of falling back to the default config.
  `ash config validate` and `ash config lint` follow the chain and print it.
  `ash config validate` and `ash config lint` without `--config` now check the
  config a scan of the current directory would use, instead of always
  `.ash/.ash.yaml`.

## v3.7.0 (2026-08-27)

### Feat

- severity ladder, path containment, and workspace path conversion (workspace mode phase 0) (#456)
- **mcp**: confine MCP scan targets to configured roots (#477)

### Fix

- **config**: describe what a suppression without line_end actually matches (#457)
- **ci**: let a release PR trigger the checks that gate it (#458)
- **scanners**: bound the tool invocation so a scanner cannot run forever (#453)
- **scanner**: name the cause when a scan fails, instead of the symptom (#476)
- **config**: stop discarding a --config-overrides value that cannot be applied (#475)
- **bedrock**: drop inference parameters a model reports as deprecated (#454)
- **container**: keep the C toolchain out of the runtime image (#455)
- **core**: let callers hand the orchestrator an already-resolved config (#474)
- **validation**: restore the two reporters scan_phase calls, and the guard that discarded one (#473)
- **ci**: make the schema freshness gate see a newly added schema (#466)
- **reporters**: make yaml and spdx output loadable by a safe parser (#464)
- **tests**: stop the integration conftest marking the whole repo slow (#463)
- **config**: find plugin config when the config key contains the plugin type (#459)
- **mcp**: report scanners that never ran instead of hiding them (#452)
- **sarif**: relativize absolute URIs whose path crosses a symlink (#450)
- **container**: stop pnpm audit hanging on a corepack prompt, and move to Node 22 (#451)
- **config**: lint and auto-fix suppression reasons that span multiple lines (#449)
- **homebrew**: bump the tap to v3.6.0 and keep it bumped (#448)
- **mcp**: write command output to stderr so stdio JSON-RPC stays parseable (#447)
- **config**: honor an explicit --config when source_dir is not supplied (#446)

## v3.6.0 (2026-08-21)

### Feat

- agentic-coding transpiler — single-source-of-truth across 15 AI agent platforms (#331)
- add 19 model methods (TDD) + fix to_flat_vulnerabilities bug + docs overhaul (#312)
- **config**: lint detects + fixes legacy snake/kebab plugin name variants (#332)

### Fix

- make piped install retries actually retry, and stop the bash entrypoint continuing past a failed build (#427)
- **ci**: stop the fork-PR comment failure from failing the required ASH scan check (#429)
- enforce plugin-declared tool version constraints when installing scanner tools (#426)
- **ci**: stop installing ASH from the ephemeral merge-queue ref, and gate all three upgrade paths (#424)
- **logging**: restore UTF-8 console reconfiguration on Windows (#412)

### Refactor

- scan-phase decomposition + offline mode + lint sweep (#95) (#334)

### Perf

- **tests**: run the unit suite on all cores instead of pinning -n 1 (#417)

## v3.5.9 (2026-08-10)

### Fix

- **deps**: patch grype CVEs in gitpython, cryptography, pymdown-extensions (#407)

## v3.5.8 (2026-07-24)

### Fix

- **deps**: patch GitPython argument-injection vulnerabilities (#397)
- **deps**: patch vulnerable mcp, setuptools, and soupsieve (#394)

## v3.5.7 (2026-07-06)

### Fix

- **scanners**: do not embed literal quotes in checkov/bandit exclusion args (#350)

## v3.5.6 (2026-06-30)

### Fix

- **deps**: trigger patch release for dependency updates (v3.5.5 -> v3.5.6)

## v3.5.5 (2026-06-30)

### Fix

- **windows**: document Git prerequisite, persist alias, shorten long paths (#375)
- install CDK dependencies in container mode (#373) (#374)
- update vulnerable dependencies and switch to slim base image (#368)

## v3.5.4 (2026-06-12)

### Fix

- prevent source_dir basename stripping when it collides with real project dirs (#361)
- update vulnerable dependencies in uv.lock (#362)

## v3.5.3 (2026-05-13)

### Fix

- **gitlab-cyclonedx**: emit minimal empty SBOM when no components found (#343)

## v3.5.2 (2026-05-12)

### Fix

- MCP Server, config validation and cli (#339)

## v3.5.1 (2026-05-11)

### Fix

- respect severity_threshold in SARIF file actionable count (#329)

## v3.5.0 (2026-05-11)

### Feat

- **#242**: support inline code suppressions (#297)
- **#158**: support scanning only changed files in PRs (#296)
- **#201**: add suppression creation from inspect UI (#298)
- **reporters**: add gitlab-cyclonedx reporter for GitLab Dependency List (#284)
- **#200**: add interactive configuration wizard (#299)
- **#230**: add compact mode for markdown reporter (#293)
- config lint command (#286)
- add GitHub Advanced Security (GHAS) SARIF reporter (#291)
- **#96**: CDK-based offline test infrastructure (#295)
- 80%+ test coverage gate, OCI_RUNNER_WRAPPER, Finch CI, inline nosec (#285)

### Fix

- **docs**: sync version templates with current documentation (#327)
- **ci**: disable coverage gate in release smoke test (#325)
- handle None output_dir in inspect findings command (#321)
- changed-files-only filter and YAML append indentation
- **ci**: skip SARIF upload in merge_group events (#303)
- **ci**: migrate PR title check to commitizen and skip in merge queue (#302)
- Dockerfile retry hardening, offline parity, suppression & CI fixes (#292)

### Refactor

- codebase cleanup, bug fixes, and issue resolution (#283)

## v3.4.0 (2026-04-29)

### Feat

- adopt commitizen for unified release management (#280)

### Fix

- configure git identity before cz bump in release workflow (#281)
- config file discovery broken since v3.2.7 (#279)
- **detect-secrets**: apply global_ignore_paths to scanner (#239)
- SAST scan fails on fork PRs due to hardcoded repo URL (#278)
- version bump workflows create PRs instead of pushing to main (#277)
- replace label-gated version bump with required check and dispatch workflows (#276)
- replace label-gated version bump with required check and dispatch workflows (#275)
- resolve ~187 bugs across 119 files with 276 TDD regression tests (#274)

## v3.3.0 (2026-04-24)

### Fix

- resolve 14 bugs with TDD regression tests (#273)

## v3.2.7

### Fixes

- Fix Pydantic 2.13 compatibility — resolve `AshConfig` forward reference in `AshAggregatedResults` via deferred `model_rebuild()`, and guard against `ValidationInfo.data` being `None` in the `line_end` field validator
- Fix suppression glob pattern `tests/**/*.py` not matching `tests/test_example.py` — `fnmatch` treats `**` as a single `*` (one path segment). Replaced with a custom recursive glob matcher that handles `**` as zero-or-more directories (#265)
- Fix GitLab SAST reporter including suppressed findings as active vulnerabilities — suppressed findings are now downgraded to `Info` severity with the suppression reason in the `solution` field (#266)
- Fix dependency vulnerabilities: upgrade `python-multipart` 0.0.24 → 0.0.26 (GHSA-mj87-hwqh-73pj), `pytest` 8.4.2 → 9.0.3 (GHSA-6w46-j5rx-g56g)
- Fix 4 ruff F841 unused variable warnings and formatting drift across the codebase
- Fix `pytest.ini` `asyncio_default_fixture_loop_scope` value — remove quotes that broke `pytest-asyncio` 1.3.0 parsing
- Update B108 suppression line numbers in `.ash.yaml` after ruff reformatting

### Features

- Add `exclude_suppressed` option to GitLab SAST reporter config — when `true`, suppressed findings are omitted entirely from the report instead of being downgraded to Info severity

### Maintenance

- Lift Pydantic pin from `<2.13` to `<2.14` now that forward ref issues are resolved
- Upgrade `pytest-asyncio` 0.26.0 → 1.3.0 (required for pytest 9.x)
- Run `ruff format` on all files to resolve pre-commit formatting drift

## v3.2.6

### Fixes

- Fix `ash config init` generating invalid config files — internal-only fields (`build`, `mcp-resource-management`, `name`, `extension`, `tool_version`, `install_timeout`) were leaking into the generated YAML, causing `ash config validate` to reject the output with 38 errors
- Fix config validator false positive on duplicate top-level fields — nested fields like `scanners` inside trivy-repo options were incorrectly flagged as duplicates
- Fix `ash report` and container result parsing crash (`'NoneType' object has no attribute 'get'`) caused by Pydantic 2.13.0 tightening forward reference validation — `AshConfig` forward ref in `AshAggregatedResults` was not resolved before `model_validate_json`
- Remove internal `build` field from `.ash/.ash_no_ignore.yaml`
- Fix Docker base image compatibility — upgrade from `python:3.12-bullseye` (glibc 2.31) to `python:3.12-bookworm` (glibc 2.36) to support semgrep 1.158.0+ which requires `manylinux_2_35` wheels
- Fix dependency vulnerabilities — upgrade `cryptography` 46.0.6 → 46.0.7 (GHSA-p423-j2cm-9vmq) and `uv` 0.11.3 → 0.11.6 (GHSA-pjjw-68hj-v9mw)

### Maintenance

- Pin Pydantic to `<2.13` in `pyproject.toml` to prevent forward ref breakage in uvx environments until forward refs are properly resolved
- Tighten upper bounds on high-risk dependencies (`uv`, `mcp`, `python-multipart`, `aws-cdk-lib`, `boto3`) to prevent surprise breaking changes from fresh `uvx` resolution
- Pin external tool versions in Dockerfile: Grype v0.111.0, Syft v1.42.4, Trivy v0.69.3, cfn-nag 0.8.10, npm 11.12.1
- Upgrade GitHub Actions to Node.js 24 compatible versions: `actions/checkout` v6, `actions/setup-python` v6, `actions/upload-artifact` v7, `docker/setup-buildx-action` v4, `mikepenz/action-junit-report` v6, `github/codeql-action` v4, `mshick/add-pr-comment` v3
- Add ASH scan artifact upload (7-day retention) to CI validation workflow for debugging scan failures
- Add config validation step to CI validation workflow before scan execution

## v3.2.5

### Fixes

- Fix detect-secrets scanner — propagate baseline exclude filters and fix multiprocessing issue

## v3.2.4

### Maintenance

- Upgrade all dependencies to latest compatible versions via `uv lock --upgrade`, including:
  - `aws-cdk-lib` 2.238.0 → 2.243.0
  - `boto3`/`botocore` 1.42.47 → 1.42.68
  - `constructs` 10.4.5 → 10.5.1
  - `pydantic-settings` 2.12.0 → 2.13.1
  - `pyjwt` 2.11.0 → 2.12.1
  - `ruff` 0.15.0 → 0.15.6
  - `uvicorn` 0.40.0 → 0.41.0
  - `certifi` 2026.1.4 → 2026.2.25
  - `mkdocs-material` 9.7.1 → 9.7.5
  - `platformdirs` 4.5.1 → 4.9.4
  - `sse-starlette` 3.2.0 → 3.3.2
  - And various other transitive/type-stub dependency bumps

## v3.2.3

### Fixes

- Fix Dockerfile `COPY` glob patterns that fail on Podman/buildah when source directories don't exist in the build context. Replaced targeted `COPY` globs with `COPY . .` which works across all OCI runtimes (Docker, Finch, Podman, nerdctl)
- Fix `BUILD_DATE` build arg mismatch in container mode — the Python code passed `BUILD_DATE` but the Dockerfile expected `BUILD_DATE_EPOCH`
- Fix Bandit scanner crash when SARIF output is empty — the fallback `SarifReport` was constructed with an invalid `schema_uri` parameter, causing a Pydantic validation error that lost all Bandit findings
- Fix Bandit B110 (Try, Except, Pass) finding in `get-genai-guide` command by replacing bare `pass` with an explicit assignment in the local file read fallback
- Fix reusable workflow `run-ash-security-scan.yml` failing for external consumers — `ASH_UVX_SOURCE` was resolving to the caller's repository instead of the ASH repo, causing `uvx` to fail with "does not appear to be a Python project". Now correctly uses `inputs.ash-version` to reference the ASH repo.
- Update example workflow to use floating `v3` tag for both the workflow ref and `ash-version` input.

## v2.0.1

### What's Changed

- Fix handling of Bandit config files in util script

## v2.0.0

### Breaking Changes

- Building ASH images for use in CI platforms (or other orchestration platforms that may require elevated access within the container) now requires targeting the `ci` stage of the `Dockerfile`:

_via `ash` CLI_

```sh
ash --no-run --build-target ci
```

_via `docker` or other OCI CLI_

```sh
docker build --tag automated-security-helper:ci --target ci .
```

### Features

- Run ASH as non-root user to align with security best practices.
- Create a CI version of the docker file that still runs as root to comply with the different requirements from building platforms where UID/GID cannot be modified and there are additional agents installed at runtime that requires elevated privileges.

### Fixes

- Offline mode now skips NPM/PNPM/Yarn Audit checks (requires connection to registry to pull package information)
- NPM install during image build now restricts available memory to prevent segmentation fault

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.5.1...v2.0.0

## v1.5.1

### What's Changed

- Fix SHELL directive in Dockerfile
- Fix small items in Mkdocs config

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.5.0...v1.5.1

## v1.5.0

### What's Changed

- Introduced support for offline execution via `--offline`

### New Contributors
* @awsmadi made their first contribution in https://github.com/awslabs/automated-security-helper/pull/104

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.4.1...v1.5.0

## v1.4.1

### What's Changed

- Fixed line endings on relevant files from CRLF to LF to resolve Windows build issues

## v1.4.0

### What's Changed

- Adds `--format` parameter to `ash`/`ash-multi` scripts to enable additional output integrations, beginning with ASHARP (Automated Security Helper Aggregated Report Parser) as the intermediary data model to enable subsequent conversion from there.
- Adds `automated_security_helper` Python code as a module of the same name from within new `src` directory, including poetry.lock and pyproject.toml files to support. This module includes the `asharp` script (CLI tool) that enabled programmatic parsing of the aggregated_results content in conjunction with the JSON output changes.
- Adds pre-stage build of `automated_security_helper` module to Dockerfile
- Adds support to handle when `--format` is a value other than the current default of `text` so scanners switch output to programmatically parseable output formats and `asharp` is called to parse the `aggregated_results.txt` file into `aggregated_results.txt.json`.
- Moved source of version string truth into `pyproject.toml` for all projects, removed `__version__` file to coincide with this.

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.3.3...v1.4.0

## v1.3.3

### What's Changed
* fix(ash): adjust where/when output-dir is created, if necessary by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/74
* fix(ash): set execute permission on ash script in the container by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/81
* fix: update __version__ file to match release tag format in github.com by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/84


**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/v1.3.2...v1.3.3

## v1.3.2

### What's Changed
* added get-scan-set.py to utils scripts to return a list of non-ignored files for processing by @scrthq in https://github.com/awslabs/automated-security-helper/pull/47
* fix/codebuild shared bindmount issue by @scrthq in https://github.com/awslabs/automated-security-helper/pull/49
* fix error in reflecting return code in ash script by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/51
* Issue 58: missing double quotes by @awsntheule in https://github.com/awslabs/automated-security-helper/pull/64
* fixed cdk nag scanner, added unique stack names based on input filenames. corrected guards on git clone calls within the scanner scripts to ensure those happen in the container image by @scrthq in https://github.com/awslabs/automated-security-helper/pull/54
* Add support for pnpm audit by @awsntheule in https://github.com/awslabs/automated-security-helper/pull/66
* fix(cdk-nag-scan): copy output files to separate folders by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/69
* fix(ash): use /tmp rather than tmpfs for scratch area by @climbertjh2 in https://github.com/awslabs/automated-security-helper/pull/73
* Fix CTRL-C cancelling by @awsntheule in https://github.com/awslabs/automated-security-helper/pull/71

### New Contributors
* @awsntheule made their first contribution in https://github.com/awslabs/automated-security-helper/pull/64

**Full Changelog**: https://github.com/awslabs/automated-security-helper/compare/1.2.0-e-06Mar2024...v1.3.2

## 1.3.0 - 2024-04-17

### Features

* New version scheme introduced, moving ASH to SemVer alignment for versioning releases
* Moved version number to standalone `__version__` file for easier version maintainability
* Added [ripgrep](https://github.com/BurntSushi/ripgrep) to replace `grep` on the `cdk-docker-execute.sh` script for speed as well as to respect `.gitignore`/`.ignore` file specifications automatically. Implemented `ripgrep` for the intended purposes.
* Updated `cdk-docker-execute.sh` script to create a unique internal stack name per imported-and-scanned CloudFormation template.

### Fixes

* Removed extraneous `git clone` calls into the temporary `${_ASH_RUN_DIR}` now that single container is the primary use case to prevent collisions and spending time on repeat tasks during scans.

### Maintenance / Internal

* Added better support for debug logging via `--debug` flag.
* Added new `debug_show_tree` function to `utils/common.sh` for easy debugging insertion of a tree call at any point in the scan to see repository contents
* Improved functionality of `utils/get-scan-set.py` script to generate the ignore spec and initial scan set to file in the output directory

## 1.2.0-e-06Mar2024

* Changes default base image in the root Dockerfile from `public.ecr.aws/bitnami/python:3.10` to `public.ecr.aws/docker/library/python:3.10-bullseye` to allow builds for linux/arm64 platforms to work
* `ash` script has been renamed to `ash-multi` if multi-container architecture is needed from local. When running in the single-container, this is copied in as `ash` itself and becomes the entrypoint of the in-container run to prevent API changes for CI invocations.
* New `ash` script for local invocation entrypoint is now defaulting to building the single-container image and running the scan within as normal
* Printed output path of the `aggregated_results.txt` now shows the correct, local output path when using the single container instead of `/out/aggregated_results.txt`
* Updated GitHub Actions workflow for the repo to invoke ASH using the `ash` script as well to validate the entire experience end-to-end
* Deprecated `--finch|-f` option with warning indicating to use `--oci-runner finch|-o finch` if needing to use Finch explicitly

## 1.1.0-e-01Dec2023

* Introduced single-container architecture via single Dockerfile in the repo root
    * Updated `utils/*.sh` and `ash` shell scripts to support running within a single container
    * Added new `ash_helpers.{sh,ps1}` scripts to support building and running the new container image
* Changed CDK Nag scanning to use TypeScript instead of Python in order to reduce the number of dependencies
* Changed identification of files to scan from `find` to `git ls-files` for Git repositories in order to reduce the number of files scanned and to avoid scanning files that are not tracked by Git
* Updated the multi-container Dockerfiles to be compatible with the script updates and retain backwards compatibility
* Updated ASH documentation and README content to reflect the changes and improve the user experience
* Added simple image build workflow configured as a required status check for PRs

## 1.0.9-e-16May2023

* Changed YAML scanning (presumed CloudFormation templates) to look for CloudFormation template files explicitly, and excluding some well known folders
added additional files that checkov knows how to scan to the list of CloudFormation templates (Dockerfiles, .gitlab-ci.yml)
* Re-factored CDK scanning in several ways:
    * Moved Python package install to the Dockerfile (container image build) so it's done once
    * Removed code that doesn't do anything
    * Added diagnostic information to report regarding the CDK version, Node version, and NPM packages installed.
* Fixed Semgrep exit code

## 1.0.8-e-03May2023

* Cloud9 Quickstart
* Remove cdk virtual env
* README reformat
* Pre-commit hook guidance
* Fix Grype error code
* Minor bug fixes

<!-- CHANGELOG SPLIT MARKER -->

## 1.0.5-e-06Mar2023

* hardcoded Checkov config
* Fix return code for the different Docker containers
* Fix image for ARM based machines
* Added Finch support

<!-- CHANGELOG SPLIT MARKER -->

## 1.0.1-e-10Jan2023

ASH version 1.0.1-e-10Jan2023 is out!

* Speed - running time is shorter by 40-50%
* Frameworks support - we support Bash, Java, Go and C## code
* New tool - ASH is running [Semgrep](https://github.com/returntocorp/semgrep) for supported frameworks
* Force scans for specific frameworks - You can use the `--ext` flag to enforce scan for specific framework
For example: `ash --source-dir . --ext py` (Python)
* Versioning - use `ash --version` to check your current version
* Bug fixes and improvements

<!-- CHANGELOG SPLIT MARKER -->
