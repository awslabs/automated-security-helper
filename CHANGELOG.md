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
  the sandbox settings it writes itself, `mode` included (a `mode` its own `patch`
  sets counts as written), and loses what it inherits from any base and the grants
  it adds with `patch`. A setting its own `patch` removes or rewrites is read as
  patched, so the scan is granted no more than the file wrote and its patch left. A
  grant list the patch rewrites keeps the entries that both the list the file wrote
  and the list the patch leaves name. It still replaces the list of a trusted config
  such as the one `ASH_CONFIG` names, so a path that neither list names is not
  granted even when that config grants it; a list the file wrote and the patch
  removes is left to that config. A patch that rewrites the `sandbox` section or the whole document leaves
  only the `mode` and the lists the rewrite still names. A `network_scanners` list is
  cut down the same way (none, when the patch removes it). A list the patch writes
  where the file wrote none, a null or no key, limits the scan to the entries that it
  and the list already in force both name, for a grant list as for
  `network_scanners`, so the patch can only narrow that list: a path or scanner it
  names that the list in force lacks adds nothing, and a path that list holds and the
  patched list leaves out is no longer granted. A patch that leaves no grant list
  there (it removes the list, rewrites the section or the document without it, or
  edits one of its entries) limits it to nothing, because the operator's own config
  ends with the empty list; a missing `network_scanners` is the widest, so that list
  keeps the trusted one. The operator's file is named in one warning when such a
  limit leaves trusted entries out or names entries the trusted list lacks as
  spelled, such as a relative path for an entry the list holds as an absolute one.
  A list the file wrote as a null and
  its patch replaces counts as a list the file did not write, and the file keeps its
  `mode` and its other lists.
  An `extends` base is judged by the
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

  If a sandbox was requested and cannot be provided, ASH never falls back to
  running the scanner unsandboxed, and the scan exits 1. A backend named
  explicitly (`--sandbox bwrap`) that is unavailable records the scanner as an
  ERROR that could not start its tool, naming the backend; `auto` with no working
  backend records it `MISSING` with the reason; a sandbox refused for any other
  reason is an ERROR with that reason.
  `auto` picks bubblewrap, then firejail, then Landlock on Linux, and
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
  now fails with an error naming the scanner and the limit, as every other
  scanner's does, where the in-process scan kept whatever it had found before the
  cutoff: a killed worker's partial results are not recoverable, and a report
  built from the baseline alone would read as a clean scan. See
  `docs/content/docs/scanner-sandbox.md` for the threat model and per-scanner
  policy. Two scanners that ran inside the ASH process now run as worker
  subprocesses so the sandbox can cover them: detect-secrets and cdk-nag. Their
  findings are unchanged. detect-secrets reads back at most
  `scanners.detect-secrets.options.max_worker_output_mib` of its worker's output,
  256 MiB by default (a finding is about 300 bytes of it, and reading it costs about
  three times its size in memory); a scan whose output is larger fails, and records
  no findings, with an error that names the option. The option is at most 4096,
  and only the operator sets it, from `--config-overrides` or a config file outside
  the scanned tree: whatever a config file inside the tree writes for it, a value
  the option would refuse included, is ignored with a warning, as for the
  operator-only reporter options, so the file still loads; `ash config validate`
  says so, and MCP `get_config` shows it ignored for a file in a checkout. A scan
  whose configuration includes such a file uses the operator's limit whether or
  not that file names it, so a lower limit the operator set (in the file
  `ASH_CONFIG` names, say) holds there too.
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
  [Built-in Scanners](docs/content/reference/scanners.md).
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
    sets `options.online_audits` (a repository-written config cannot). A workflow
    or action that resolves outside the scan root, or is a broken symlink, is
    skipped with a warning.
  - trivy: `trivy fs` (0.75.0), `vuln` only by default, held to
    the trivy database's 24h bound; offline with no database it is MISSING with the
    reason. A scanner-level `severity_threshold` gates the verdict as for every
    scanner, and lower findings are still reported; it is not passed to trivy as
    `--severity`, and neither is trivy-repo's any longer. `scanners.trivy.options.scanners`
    is honored only from the operator; set by a repository-written config, any set
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
    `TRIVY_CONFIG` for a file outside the scanned tree, else the empty config. The
    container image keeps trivy's cache in `/deps/.trivy`, owned like grype's
    database cache (see "The container image no longer has directories every user
    can write" under Behavior changes). An image built with `OFFLINE=YES`
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

  Options that name something a tool executes or loads are not taken from a
  repository-written config (defined under "A repository-written config file can
  no longer choose what ASH installs" in Behavior changes): a config file inside any
  git checkout or the scanned directory, or one with an `extends` base there.
  actionlint's `shellcheck` and
  `pyflakes` accept only their own names there, and cfn-lint's and trivy's
  `config_file` (a `.cfnlintrc` can import Python rules, a `trivy.yaml` can load
  WASM modules) are honored only from `--config-overrides` or a config file outside
  every checkout and the scanned directory, for a file outside the scanned tree.
  cfn-lint's and zizmor's `tool_version` must be a version constraint.
  zizmor's and cfn-lint's `tool_version`, which pick the release that is installed
  and accepted, cfn-lint's `ignore_checks` and cfn-guard's `rule_sets`, which narrow
  what is reported, are honored only from the operator; from a repository-written
  config each is ignored with a warning and the default applies. An MCP client's
  `config_overrides` are the client's, not the operator's, for every one of these.

  None of the six reads its tool's own config from the scanned repository: see
  "The scanned repository's own scanner configs are not read" under Behavior
  changes.

  actionlint, zizmor, cfn-lint and cfn-guard take their files from ASH's scan set,
  so the scanned tree's `.gitignore` and `.ignore` files leave files out of them
  only while `honor_ignore_files` is on (the default); `--no-honor-ignore-files`
  scans those files with them too.

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

- **The reusable scan workflow hands its artifact over by ID.**
  `run-ash-security-scan.yml` has a new `artifact-id` output: the ID
  actions/upload-artifact gave the scan's artifact. `upload-ash-sarif.yml` has a new
  optional `artifact-id` input. When it is set, it must be a number, and the report is
  downloaded by that ID, which names exactly the artifact the scan job uploaded in
  whichever attempt it ran. When it is empty, the default, the report is downloaded by
  name, as before, so existing callers need no change. Pass it the scan job's
  `artifact-id` output, as the usage comment in `upload-ash-sarif.yml` shows.

### Breaking changes

- **`set_source_git` clones only from the hosts `ASH_MCP_GIT_ALLOWED_HOSTS` names.**
  The variable is unset by default, so a server whose operator has not set it clones
  from no host and answers every `set_source_git` call with `error_type`
  `clone_host_not_permitted`. An operator whose clients clone with the tool sets it to
  the hosts they clone from: comma- or whitespace-separated `[scheme://]host[:port]`
  entries, matched without regard to case, where a bare host stands for its scheme's
  default port (https 443, ssh 22) on either scheme, `host:port` names the port, and
  `https://` or `ssh://` the scheme. The tool also refuses every `ssh_key_id` with
  `error_type` `ssh_key_not_registered`: the server registers no SSH keys and never
  accepts a private key over MCP, so a repository that needs one cannot be delivered
  this way.
- **A configured plugin module that fails to import refuses the run with
  exit 3.** `ash scan`, `ash report`, `ash merge`, `ash dependencies install`
  and `ash plugin list` used to log a WARNING and continue without the module's
  plugins, so a scan whose configuration named a module with a missing
  dependency ran without the scanners the operator asked for and reported
  itself complete. Each command now refuses with exit 3 (invalid
  configuration), naming the module and its import error, whatever the scanner
  selection; `ash config validate`, `lint`, `get`,
  `validate-plugin-dependencies` and the MCP `validate_config` and
  `get_config` agree, refusing a configured module no installed package
  provides without importing it. A
  CI job that relied on the old warn-and-continue behavior must install the
  module's dependencies or remove the entry. The vendored inventory's tolerant
  load is unchanged.
- **Only the operator's configuration turns on a reporter that sends findings
  off the host, and chooses where it sends.** That is the four AWS reporters and
  any plugin reporter that declares `sends_off_host`. A repository's own
  `.ash/.ash.yaml` (or any config file inside the scanned tree, or one an MCP
  client uploaded) could name `ash_aws_plugins`, enable S3 with its own bucket,
  and have the scan upload the findings there with the host's credentials. Now
  such a reporter's whole section, `enabled` and every option, comes only from
  the operator: the defaults, `ASH_CONFIG`'s file or a config file outside the
  tree, with `--config-overrides` applied. A value that configuration reads from
  the environment for such a reporter is masked in the scan's messages, as the
  scan's own configuration's are. What a repository's file sets for it
  is ignored with a WARNING. A repository that enables S3, CloudWatch Logs,
  the Bedrock summary or Security Hub in its own config must move that section
  to a `--config` file outside the tree, or to
  `--config-overrides reporters.<name>.<key>=<value>`. For `ash merge`, a
  `--config` inside the working directory's checkout counts as the repository's.
- **`validate_bedrock_model` takes `values` and `label` by name only.** The function
  in `ash_aws_plugins.aws_utils` took `values` as its third positional argument and
  `label` by name. `values` is keyword-only now too, so a call such as
  `validate_bedrock_model(client, model_id, values_list)` raises `TypeError` instead
  of reading the third argument as the environment values. Write
  `values=values_list`. The Bedrock reporter's calls pass `values` by name.
- **`ash mcp` checks an auth header value in the bytes the header will carry.**
  A value with a character outside latin-1 can't be a header value, so `ash mcp` now
  refuses to start on one, and `build_streamable_http_app` and `build_sse_app` raise
  `ASHValidationError` for it before they build anything. A value that starts or
  ends with a space or tab is refused the same way, in all three forms and by both
  app builders, because a header value never keeps that whitespace; a space or tab
  between other characters is kept. A value given with `--auth-header-value` has to
  be visible ASCII (letters, digits and punctuation, with spaces or tabs between
  them) and at most 16 KiB, the limit the file and descriptor forms already had: any
  other character, a line break, a NUL or another control character is refused with
  the usage-error exit code, and the message does not repeat the value. A file or a
  descriptor is refused too when the value holds a control character, meaning any
  byte below 0x20 except a tab, or DEL, where only a line break and NUL were refused
  before; a conforming client never sends one, so a server configured with it
  answered 401 to every request. The two app builders refuse a control character
  too, and refuse an `auth_header_name` given without an `auth_header_value`, or the
  reverse, as the command line does; before, a name with an empty value built an app
  that let every request through. The bytes 0x80 to 0xFF are kept. Before, an
  accented letter passed the check as the one byte latin-1 gives it, which a client
  that sends UTF-8 never sends, a line break passed where `--auth-header-value-file`
  and `--auth-header-value-fd` refuse it, and a value with a space or tab at an end
  started the server, as did a file or descriptor line that ended in a space before
  its newline. To migrate, remove the space or tab at the end of the value, in the
  server's configuration and in the client's. Give a byte from 0x80 to 0xFF through
  `--auth-header-value-file` or `--auth-header-value-fd`, which carry it exactly,
  and replace a character outside latin-1 with an ASCII value such as hex or
  base64. The container entrypoints hand the value to `ash mcp` on a descriptor when
  its `--help` lists `--auth-header-value-fd`, and on the command line for an older
  release, which has none of the checks above. The Terraform `ash-mcp-serve` reads
  `ASH_MCP_AUTH_HEADER_VALUE`, drops whitespace at both ends and passes the rest as
  UTF-8 bytes, so a newline at the end of the value and a non-ASCII character in it
  do not stop the container, while a line break inside it does. The CDK entrypoint
  reads the secret named by `ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN` and drops only
  newlines at its end, so a secret that starts or ends with a space or tab now stops
  the container at startup with the refusal above, where it used to start a server
  that answered 401 to every request; remove the space or tab from the secret.
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
  [Relative paths in the operator's settings](docs/content/how-to/configure.md#relative-paths).

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
- **Usage errors exit 5, a code of their own.** A command-line usage error (an
  unknown option or a bad option value) now exits 5 instead of 2. Every command's
  usage errors used to exit 2, click's code for them, which is also ASH's code for
  actionable findings, so
  a CI gate read a mistyped flag as a scan that found problems. ASH's own refusals of
  a mistyped command line exited 1 (a missing `--source-dir`, an unusable
  `--shard-index`/`--shard-count` pair, a `--scanners` list that names no scanner,
  in a workspace only after every project had started, an `ash merge --results`
  path that does not exist, an `ash report --format` naming no reporter) or 3
  (`ash mcp` option checks such as an unknown `--transport`). All of them now exit
  5; the CLI reference's "Usage errors" section lists every case. An
  `ash dependencies install --tool` that it cannot select, and a `--plugin-type` that
  is none of `converter`, `scanner` and `reporter`, exit 2, the command's own
  bad-selection code, which the `ash://exit-codes` resource names under `commands`.
  Problems with state rather than with
  the command line, such as `--use-existing` or `ash report` with no results yet,
  still exit 1. `ASH_EXIT_CODES` and the
  `ash://exit-codes` MCP resource list it. Container mode passes an inner scan's 5
  through to the host as it already did 3 and 4, and `--mode nix`, which reported 1
  whenever the inner scan wrote no results, now exits with the inner 3, 4 or 5.
  Workspace-mode refusals keep exit 4. A pipeline that branched on 1 or 2 for these
  cases should branch on 5. `ash config validate`, `lint`, `get`, `update` and
  `validate-plugin-dependencies` exited 1 for a `--config` (or `ASH_CONFIG`, or path
  argument) naming a file that does not exist, the code they also give when a
  directory has no config file; they now exit 3, the code for a configuration ASH
  cannot use, for a named file that does not exist, is a directory or cannot be
  read, and print "Config file not found: <path>" for a missing one.
- **`ash scan` and `ash build-image` refuse arguments they do not declare.** Both
  ignored unknown options and extra arguments, so `ash scan --fail-on-finding` ran
  without the gate it misspelled and exited as if the flag had not been given.
  `build-image` said it forwarded such arguments to the scan in the image, and it
  dropped them. Both now exit 5 for them; for scan options in a container, use
  `ash scan --mode container`. Check `ash-args`, `ASH_SCAN_EXTRA_ARGS` and similar
  pass-through settings for arguments `ash scan` does not take.
- **Options given to `ash` before a subcommand now reach it.** They were parsed and
  then dropped, so `ash --source-dir src scan` scanned the working directory and
  `ash --output-dir out report` read the default output directory. An option the
  subcommand also takes is now passed to it, as if it had been written after the
  subcommand name; one it does not take, such as `--source-dir` before `report`, is a
  usage error, exit 5.
- **`--min-severity` accepts only `critical`, `high`, `medium`, `low` and `none`**, in
  any case, on `ash scan` and `ash merge`. Any other value used to count as `low`, so
  a typo such as `--min-severity hihg` gated on every low finding. It is now a usage
  error, exit 5, and the Python API's `run_ash_scan(min_severity=...)` raises for it.
- **`run_ash_scan()` raises `TypeError` for a keyword argument it does not take.** The
  Python entry point accepted any keyword and ignored the ones it did not declare, so
  `run_ash_scan(fail_on_finding=False)` ran with the findings gate on, the library
  counterpart of `ash scan` ignoring unknown options. Check calls for misspelled
  parameter names. The documented example in the advanced usage and migration
  guides also failed: it imported a `Strategy` enum that does not exist (it is
  `ExecutionStrategy`), read `results.summary_stats` instead of
  `results.metadata.summary_stats`, and did not say that a scan with actionable
  findings ends the call with `SystemExit(2)` unless `fail_on_findings=False`.
- **Every report grades a finding the way the summary and the exit code do.** A
  finding at SARIF `error` with no declared `properties.issue_severity` is
  CRITICAL in every report; it was HIGH in `ash.flat.json`, CSV, the HTML,
  Markdown and text finding lists and `ash inspect`, `High` in GitLab SAST,
  `severity_id` 4 in OCSF and security-severity 8.0 in the GitHub GHAS report,
  while the summary counts and the exit code already read it as CRITICAL. A
  declared `issue_severity` now wins in GitLab SAST and `ash inspect`, which
  graded from the level alone. The documented "error is HIGH in reports" fork is
  gone. Dashboards, filters and triage rules keyed on these severities see the
  changed values. Reports follow the gate; the alternative
  is to grade `error` as HIGH in the gate too, which loosens exit codes under a
  `CRITICAL` threshold.

- **A finding that states no SARIF level is graded `warning` (MEDIUM)
  everywhere.** It was HIGH in the finding lists, `ash.flat.json` and CSV and
  CRITICAL in the summary counts (the results model defaulted to `error`), and
  LOW at the exit code (it read the level missing from the written SARIF as
  `note`). One constant now applies, SARIF 2.1.0's own
  default (3.27.10), after the rule's
  `defaultConfiguration.level` when it declares one and `none` for a `kind` other
  than `fail`; `ash.sarif` writes every finding's level. Under the default MEDIUM
  threshold such a finding now fails the scan. `note` (LOW)
  is the alternative, one constant, and would keep the gate as lax as it was for
  them.
- **`--sandbox` with a mode other than `off` is refused when ASH runs in a container.**
  `ash scan --mode container --sandbox <mode>`, `./ash --sandbox <mode>` and
  `invoke-ash` with it exit 5, a usage error, before the image is built or run;
  `Invoke-ASH` throws with `$LASTEXITCODE` set to 5. In the wrappers every `--sandbox`
  counts, and so does one with no mode or a value that is not a mode, whose message
  lists the modes. Container mode never sandboxes the scanners inside the image (the
  container is the boundary), so the scan went ahead without the sandbox that was asked
  for: the Python CLI dropped the flag with no message, and `./ash` and `Invoke-ASH`
  passed it to the scan inside the image, which ships no bubblewrap or firejail, so with
  those modes every scanner was recorded MISSING after a full build. Use
  `ash scan --mode local --sandbox <mode>` to sandbox each scanner, or drop the flag.
  `--sandbox off` is still accepted.
- **`--changed-files-only` is refused with `--mode container`.** `ash scan --mode
  container --changed-files-only`, and the same with `ASH_CHANGED_FILES_ONLY` set, exit
  5, a usage error, before the image is built or run. Container mode did not pass the
  flag to the scan in the container, so that scan reported the findings in every file,
  with only a log line, which `--quiet` hides, to say so. Run with `--mode local`, or
  drop the flag. `./ash` and `Invoke-ASH` pass the flag to the scan in the container,
  which applies it as a local scan does, and are unchanged.

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
  scanner statistics guide.

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
- **`ash config validate` and `ash config lint` give the verdict a scan gives.** They
  ran only structural checks, so a config a scan refuses with exit 3
  (`fail_on_findings: banana`, a suppression without a `reason`, an unquoted date in
  `expiration`) was reported valid with exit 0, while files a scan accepts (an
  unknown top-level key, a missing `project_name`, internal fields, any `!ENV`
  reference) failed with exit 1. Both now load the file with the loader and the
  `AshConfig` model a scan uses and exit 3, naming each field, when a scan would
  refuse it. `validate` reports the structural findings as warnings and exits 0 when a
  scan accepts the file; it gains `--config-overrides`. `lint` marks the issues that
  block a scan, and reports everything a scan accepts as a warning: internal plugin
  fields, the `build` section, a duplicated key, or a plugin or top-level key written
  in two spellings no longer make it exit 1. With `--fix` it takes its exit code from
  the fixed file. The MCP `validate_config` tool also gives the scan's verdict:
  `valid` is true for a config whose only entries are warnings, which stay in its
  `errors` list with their types. `mcp_resource_management`, which a scan reads as
  `mcp-resource-management`, is no longer called an unknown key. A pipeline that
  treated `validate`'s exit 1 as "invalid" should treat 3 that way. The checks
  load every file, one without `extends` too, with the one function a scan loads
  a config file with (its `extends` chain, then the model), so each refusal is
  the scan's, in the scan's words: an empty file, or one that is not a mapping,
  gets `Invalid value at '(top level)': Input should be a valid dictionary or
  instance of AshConfig` instead of a message of their own. The chain is confined
  to the scan's source directory (the current directory, or the new
  `--source-dir`), so a `--config configs/ash.yaml` that extends
  `../shared/base.yaml` is accepted as a scan accepts it. A file that does not parse exits 3 too, and the message says
  that a scan refuses it as well. A JSON
  `$schema` key is no longer a warning.
- **The messages of `ash config validate`, `lint`, `get`,
  `validate-plugin-dependencies`, `ash scan` and the MCP `validate_config` tool no
  longer print values read from the environment.** A validator message such as
  "Invalid expiration date format" ended with the value, and an `extends` error
  named the base it could not read, after `!ENV` and `${VAR:default}` references
  were resolved, so the output carried whatever the variable held; through
  `validate_config` that sent server environment values to an MCP client. A model
  error now names the field without quoting its value. A value a reference resolved
  to, and a key one resolved to, is shown as `<value>` wherever these commands
  would print it: in a message, quoted with escapes (`repr`, JSON or
  `unicode_escape`), without its trailing `/` (as a directory warning prints it), in
  the "Resolved source chain" list (where a base named by a reference is printed
  normalized, so the part the reference resolved to is redacted too) and in the
  `--fix-unused` list; `validate-plugin-dependencies` names the file it checked
  instead of the project. A scan's refusal and the error it logs are redacted the
  same way, for the file the scan found or was given, for the file `ASH_CONFIG`
  names (which was described with pydantic's own text, input values and all), for
  the operator's config, and for each project of a `--workspace` scan. When `get`
  or `validate-plugin-dependencies` refuses a configuration because of the
  `ASH_CONFIG` file, it prints that refusal under "Invalid configuration:", not as
  pydantic's error (with the keys the file read) under the named file's name.
  `ash scan --debug` no longer logs the resolved configuration with the plugin
  context. `ash config get` still prints the configuration with its
  references resolved: only its messages changed. An `extends` chain that fails,
  the `ASH_CONFIG` file's included, is described from a second resolution that
  reads nothing from the environment, the same reason in the scan and in the
  checks; when that would name the reference itself, or the chain resolves without
  the environment, the reason only says that a file reached through a base named by
  an environment variable (that base, or one it extends) is missing, unreadable or
  outside the allowed directory. In free text a value is redacted in any case, by the
  length of the form the message prints it in (`build/` is printed as `build`):
  - one of eight characters or more, or of four or more holding a character other
    than a letter, a digit or `_` (`/src`), wherever a message prints it, inside a
    longer word too (`ash<value>logs`);
  - a piece of such a value, eight characters or more, where it touches the `...`
    or `…` a message cuts the value at, when the piece is a whole word on its other
    side. A piece run into another value's match, or into another such piece, is
    hidden with it, as two values run together are, and so is a part of eight
    characters or more from the middle of a value, cut at both ends between two
    markers (`...1234secretvaluelong5...`). A piece of four to seven characters
    is hidden only in such a run, eight characters or more, as a message that cuts
    two values printed back to back can leave four characters of one beside the
    other; alone it is shown. A word that only starts or ends
    like a long value is shown, unless it is a whole word touching the marker,
    which reads the same as a message that cut the value there and is hidden; a
    piece at the end of a message with no marker is shown;
  - one of four to seven word characters (letters, digits and `_`) as a whole
    word, so the `true` in
    `untrue` stays. `_` bounds a word like any other character that is not a
    letter or a digit, so a value glued into a longer name by `_`
    (`<value>_findings`, `ASH_<value>_logs`) is hidden -- and so are a piece
    between runs of underscores (`__<value>__`, a dunder whose stem equals the
    value) and a path piece after a lone `_` (`/_<value>/`, a CI working
    directory): the band fails closed. The edge of another value's match
    bounds a word too, so two values run together, or one beside a hidden longer
    value, are hidden together; a four- to seven-character value whose far side runs into
    an uncovered letter or digit (in test reports, one `_` before an uncovered
    word character, or a run of two or more `_` that reaches neither the text's
    edge nor a covered character) is shown even beside a hidden one. Run into
    letters or digits (`qz4b1`, `xqz4b`) such a value is shown;
  - one shorter than four characters only where the message quotes it whole (`'x'`,
    `"x"`, `` `x` ``, or `\"x\"` in JSON), since replacing every whole-word "a" or
    "on" made the messages unreadable.
- **In test reports only, a short value glued to a word by `_` is shown.** The
  product's own messages hide a four- to seven-character value glued into a
  longer name by `_` (the band rule above). The test-report backstop, which
  sweeps the whole environment over report text, instead treats `_` as a word
  character, so a CI path or module name holding a common host value
  (`test_uv_tool_<word>` under `USER`) stays readable there instead of being
  mangled into markers that hide no secret. In that report rule the value
  still hides where what lies past the `_` is another hidden value, the
  text's edge, or a character that itself bounds a word -- a path piece after
  a lone `_` (`/_<value>/`) therefore hides under this rule too; a run of two
  or more `_` bounds only against the text's edge or a covered character, so
  values joined by `__` hide together while `__main__` stays whole; and a
  value standing alone or quoted, or matched by the longer bands above, hides
  everywhere.
- **A validator's message is matched against its input in any case, and is not
  shown when it repeats the input in another form.** A model error replaces its
  input by `<value>` in the message a validator wrote also when the validator
  changed its case, and a message that still holds the input once both are
  compared as letters and digits alone (the input with its separators taken out,
  say) reads "the value is not valid (the check's message is not shown: it
  repeats the value in another form)". This is checked for inputs of eight such
  characters or more, and for the whole input only: a message that quotes part of
  the input (its first characters, say) or the input reversed is shown as the
  validator wrote it. pydantic's own messages, which never quote the input and
  can list the values a field accepts, are matched as written. An error raised
  from a validation error, or while handling one (`from None` included), whose
  message quotes that error's entries (its `errors()` or `json()`) has each
  refused input replaced the same way, in the error's text, its traceback and its
  log line. An error that quotes them with no such link, one raised after the
  `except` block that caught the validation error, say, is shown as it is: the
  validation error cannot be reached from it.
- **`ash config update` writes nothing for a `--set` it cannot apply, and exits 3.** A
  `--set` without `=` used to be skipped with exit 0 and the file rewritten anyway;
  `--set` now goes through the same code as `--config-overrides`. `update` no longer
  writes the internal `build`, `name` and `extension` fields, writes JSON back into a
  `.json` file (it, `config init --config x.json` and `lint --fix` wrote YAML into
  it, which a scan then could not parse), and, like `config wizard`, refuses a file
  that reads values from the environment (`!ENV` or `${VAR:default}`), because
  rewriting it would store their current values. `lint --fix` refuses such a file
  only when it has something to fix. MCP profiles are saved with the same writer.
  `config wizard` exits 3 instead of overwriting a config it cannot load.
- **`ash config get`, `update` and `validate-plugin-dependencies` take `--config`/`-c`**
  and `ASH_CONFIG`, as the other `config` subcommands and `ash scan` do; the
  positional path still works. All of them have `-v`/`-d`/`--color`.
  `validate-plugin-dependencies` exits 3 instead of 1 for an invalid config. `get`,
  `lint`, `validate` and `validate-plugin-dependencies` take
  `--source-dir`/`ASH_SOURCE_DIR`, as `ash scan` does.
- **New config files are named `.ashrc.yaml`.** Discovery calls the older `.ash.*` and
  `ash.*` names deprecated, yet `ash config init` and `ash config wizard` created
  `.ash/.ash.yaml` and `ash inspect findings` saved suppressions to `.ash.yaml`. They
  now create `.ashrc.yaml` at the project root, and `config init` refuses to add it
  next to an existing config source, since sources are never merged. `--force`
  overwrites only the file at the target path: `ash config init --force` used to
  reset `.ash/.ash.yaml` to the defaults, and in a project with that file it now
  exits 1; `ash config init --config .ash/.ash.yaml --force` resets it. Existing
  files under the older names keep loading and keep taking precedence.

- **`ignore_paths[].expiration` is now enforced, the same way as a suppression's,
  and a malformed date refuses the configuration.** The field was accepted and never
  read, so an ignore path kept excluding its files after its date. From the
  expiration date the entry no longer applies anywhere ignore-path entries are
  applied: `global_settings.ignore_paths` (the list handed to the scanners, the
  archive and Jupyter converters, and the step that drops findings after the scan),
  workspace policy ignore paths, and the scanner options of the same type, bandit
  `excluded_paths`, checkov `skip_path` and syft `exclude`. **Files under an expired
  entry are scanned again, so a scan can report more findings and change its exit
  code.** The date is read on the local clock of the host running the scan, which in
  container mode is UTC because the image sets `TZ=UTC`. **A date that is not
  `YYYY-MM-DD`, in any of those lists, now refuses the configuration with exit code
  3** (a workspace policy with one is refused with exit code 4), as it already did for
  a suppression; such a configuration loaded before. Results files written before
  this change still load: a stored date the check now refuses is kept as written,
  with a warning that names where it is (`global_settings.ignore_paths[0].expiration`)
  but not what it says, since the value is the file's data. Each scan warns about entries that expire within 30 days, and one
  warning at the start of the scan lists the ignore paths and suppressions that have
  already expired, for the scanner option lists as well as the global ones. Those
  warnings print a path or reason as written: a bracket in one, as in `see
  [/docs/policy]`, was read as console markup, and a suppression's raised an error
  that failed the scan. `ash config lint` reports expired and malformed ignore-path
  entries, and now calls a suppression expired on its expiration date, as the scan
  does, rather than the day after. An expired entry stays in the configuration and in
  the aggregated results.

- **An unknown key in a suppression or ignore-path entry refuses the configuration.**
  Unknown keys were dropped, so a misspelled `rule_id` (`ruleId`, `rule-id`) left the
  entry with no rule, and a suppression with no rule suppresses every rule in its
  path; a misspelled `expiration` made an entry permanent. Such a key now stops the
  scan with exit code 3 (exit code 4 in a workspace policy), and the error names the
  entry, the key and, when one is close, the key that was meant: `Unknown key 'ruleId'
  (did you mean 'rule_id'?)`. The same holds for the scanner options of the same kind,
  bandit `excluded_paths`, checkov `skip_path` and syft `exclude`. A results file
  written by another ASH version with such a key still loads: the key is kept, a
  warning names the entry that holds it (`an unknown key <key> in
  'global_settings.suppressions[0]'`) but not the key, which is the file's data,
  and the entry is never applied.

- **An option a plugin does not declare refuses the configuration.** Plugin options
  kept unknown keys without reading them, so `severity_level: HIGH` under bandit (the
  option is `severity_threshold`) silently did nothing. Such a key now stops the scan
  with exit code 3, naming the plugin by where the key sits
  (`scanners.bandit.options`) and the key, with a suggestion when one is close. A
  built-in plugin's options are checked when the configuration loads; a plugin loaded
  from `ash_plugin_modules` is checked once the plugins are loaded, before anything
  is converted or scanned, and a value its options model rejects is refused there
  too, with the plugin's own message (ferret-scan's "Use 'ferret_debug: true'
  instead"). `ash config validate` and `ash config lint` do not import those
  plugins, so they do not check their options; both name those sections, `lint` in
  an INFO issue and `validate` in a note after its verdict. A section for a plugin the run does not load cannot be checked and
  is left as it is. `offline` is now an option of every scanner, because
  ASH already read it for every scanner; `ash config init` writes `offline: false`
  for each. Results files written with an option that is not declared still load, with
  a warning.

- **`ignore_paths` and `suppressions` paths are matched case-sensitively on every
  platform.** `tests/**` no longer covers `Tests/x.py` or `TESTS/x.py`: on a
  case-sensitive filesystem those are other directories. Both sides used to be
  lower-cased, so a pattern also covered every spelling of its names in another
  case. A workspace policy pattern is rebased onto a project case-sensitively too,
  so `Project-A/src/x.py` does not apply to project `project-a`. Rule IDs and the
  package name and version fields stay case-insensitive. **A pattern that relied on
  another case no longer matches, so a scan can report more findings and change
  its exit code.**

- **`ash config validate` and `ash config lint` warn about an ignore or
  suppression path that matches nothing, and say what to write instead.** ASH
  matches these paths case-sensitively against paths below the scan root, which
  never start with `./`. So a path starting with `./` gets "Use 'src/'" for
  `./src` (a directory spelled as for a path naming one without the slash), and
  "Use 'app.py'" for `./app.py`. A bare `.`, `./`, `.\` or an empty path gets
  advice to name the paths to ignore, or whose findings to suppress. A path whose
  leading names match the tree only in another case is named with the tree's
  spelling: "'tests/**' matches 'Tests/' only by case; patterns match
  case-sensitively". A path read from the environment is named as `<value>`, and
  the advice then quotes neither it nor the tree's spelling. Each is a warning,
  so validate exits 0 when the scan accepts the config. Lint reports each piece
  of advice once, as a warning at the path's place in the file, so a config with
  only these warnings lints with exit 0. Advice for a path an `extends` base adds
  is a warning too.

- **A trailing `/` in an `ignore_paths` path now names the directory's files.**
  `vendor/` matched nothing in the step that drops findings after the scan, because
  no file path ends in a slash; the scanners that receive ignore paths read
  `vendor/` as the directory, so a finding a scanner reported there anyway
  (snyk-code receives no ignore paths) stayed actionable. `vendor/`, `vendor/**` and
  `**/vendor/` now all cover the files under `vendor`, wherever ASH applies an
  ignore path: the step that drops findings after the scan, the detect-secrets
  pre-filter, snyk-code's refusal and the converters. A `suppressions` path keeps
  its literal meaning, so `vendor/` there matches no file; `vendor/**/*` suppresses
  the findings in every file inside `vendor`. In either, a backslash is a separator
  in the pattern only (a `\` in a file's own path is part of its name, as on Linux
  and macOS), a leading `./` is not dropped from the pattern, and `./`, `.\`, `.`
  and an empty path match no file. A finding's location is read as the file it
  names, so `./vendor/v.py`, `vendor/./v.py` and `vendor//v.py` from a scanner
  are `vendor/v.py`, and `vendor/**` covers them; a `..` in it is kept. A
  finding located with a `.` or empty path component therefore gets a new id and
  `file_path`, those of the file it names. A `file://` location is read as its
  path; one with another scheme and an authority (`https://host/...`) is
  compared as written, so a pattern for a file in the tree does not cover it. A
  trailing slash never covers a file of
  that name: `vendor/` does not
  match a file called `vendor`, and `**/.*/` covers the files in dot-directories
  such as `.git/`, not dotfiles such as `.env`; `vendor/**` still matches a file
  named `vendor`, since a trailing `**` can match nothing, but `vendor/**/` and
  `tests/**/`, which used to, no longer do. **Patterns written that
  way now take effect, so a scan they apply to can report fewer findings and change
  its exit code.** That includes the findings of dependency scanners located in the
  directory: an ignore path `node_modules/` now drops grype's findings at
  `node_modules/<package>/package.json`. A workspace policy's ignore paths keep the
  slash when they are rebased onto a project, so `api/vendor/` in the policy is
  `vendor/` in project `api`, and `api/` covers the whole project; a policy
  suppression path ending in `/` keeps its literal slash, so it covers no file in
  any project, and one that reaches a project's root is not given to that project
  (pushed down as `**`, `api/` suppressed every finding of project `api`).
  `**/vendor/` and `**/vendor/**` in a policy, which were refused with exit code 4,
  now reach every project, as `**` in a project whose own path has a `vendor`
  component. A policy pattern holding `**` is rebased component by component, as
  the matcher reads it, so `???/**` covers nothing in project `a/b`, and one
  component after a leading `*` (`*/a*`) is refused unless it is a literal, `*` or
  `*` followed by a literal: under the matcher `a*` there can span `/`, and
  rebased as `**/a*` it covered less. A policy path of `./`, or one with a `.` or
  empty component (`api/./x.py`, `api//vendor/`), names no file to the matcher and
  is refused with exit code 4 rather than pushed down as one that does; a trailing
  run of slashes reads as one (`api/vendor//` is `vendor/` in project `api`). A
  policy path that starts with `./` (`./api/x.py`) is now refused with exit code 4
  the same way, because the matcher no longer drops the `./`: write `api/x.py`. A
  run of three or more stars (`***`, `***/x.py`), which the matcher reads as one
  `*` in one component, is rebased as that: `***` covers no file of any project,
  and `***/x.py` is `x.py` in project `api`. It was pushed down as `**` and
  suppressed every finding in every project. A bare `vendor` still names only the
  path `vendor`, and `ash config lint` and `ash config validate` no longer flag a
  trailing-slash pattern. For a path that names an existing directory and no file
  in it, both now suggest `<dir>/` for an ignore path and `<dir>/**/*` for a
  suppression path, where they suggested `<dir>/**` for either, which also matches
  a file named `<dir>`. ASH's own list of directories the code scanners skip
  (`.venv/`, `venv/`, `node_modules/`) is no longer applied to findings after the
  scan, where it never matched anything; it still keeps bandit and checkov out of
  those directories.

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
  [`ash merge` reference](docs/content/reference/cli.md#merge--config)
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
- **`set_source_git` takes a depth from 1 to 1000; `depth=0` is no longer a full
  clone.** The tool reference and the tool's docstring offered `depth=0` as a full
  clone, the delivery accepted it, and no depth was too large: `depth=2**31` cloned
  the whole history. The tool description and the page on the streamable HTTP
  transport said any other depth is refused, and the delivery coerced a `bool`, a
  float or a numeric string to an integer. The depth is now a whole number of commits
  from 1 to 1000 (`MAX_CLONE_DEPTH`), a limit on how much history is fetched and not a
  bound on disk or time. `0`, a negative number and a number above 1000 are answered
  `invalid_clone_depth`, naming the range, with `success`, `error` and the session id,
  before the session's workspace is made and before git runs. A value that is not a
  whole number is refused by the tool's argument validation before the tool runs, with
  a framework error and no `error_type`; a caller of the delivery function gets
  `invalid_clone_depth` for it as well. A client that passed `depth=0` for the whole
  history must name the depth it needs, or deliver the tree with `set_source_zip_chunk`
  and `set_source_zip_finalize`. The description, the parameter note and the reference
  give that one rule. The input schema of the tool shows the range, as a `minimum` of 1
  and a `maximum` of 1000 on `depth`, so a client that validates its arguments against
  the schema sees it; the schema does not enforce it, so a depth outside the range
  reaches the tool and gets its own answer.

- **A detect-secrets baseline entry audited as a real secret (`is_secret: true`)
  is reported as an ordinary finding, whichever baseline lists it.** A
  `baseline_file` the operator's own settings name used to remove every
  candidate it listed from the report, audited real or not, so a confirmed
  secret still in its file was cleared by the record of it. A gate that passed
  on such a baseline can now fail: remove the secret, or audit the entry as a
  false positive if it is one. An entry audited as a false positive, or not
  audited, is still removed by an operator-named baseline.

- **`./ash` and `Invoke-ASH` place the default output directory inside the scanned
  directory (`<source>/.ash/ash_output`), as `ash scan` does, rather than under the
  working directory.** Two consequences for a caller that relied on the old place: a
  CI step that runs `./ash --source-dir app` (or `Invoke-ASH -SourceDir app`) from
  the repository root and then uploads `./.ash/ash_output` still passes the scan but
  uploads an empty directory, because the reports are now in `app/.ash/ash_output`;
  and a scanned directory that cannot be written (a read-only checkout) is refused
  with exit 5 unless `--output-dir` (`-OutputDir`) names a writable place.
  `Invoke-ASH` works the default out once `-SourceDir` has passed its checks (a
  default worked out while the parameters bound failed on an empty `-SourceDir`
  ahead of the refusal) and takes a `-SourceDir` that is itself a link under the
  working directory as `./ash` does. A refusal of the default output directory (a
  file at the path, a directory that cannot be created, entered or written, or one
  reached through a link the repository commits) gives the reason and names
  `--output-dir`, or `-OutputDir`, as the way to write elsewhere; a refusal of an
  output directory the operator gave does not.

### Behavior changes

- `run_ash_scan()` raises `ValueError` for `severity_threshold_restriction` and
  `keep_previous_results` in container and nix mode, as it does for the other
  options only the local orchestrator applies (`untrusted_config`,
  `client_config_policy`, `remote_client`). A caller that set one of them there
  was scanning with it silently dropped; the MCP server, the two options' only
  caller, sets them in local and workspace mode only.
- In nix mode an exit code of ASH's own that no results file decides (3 for a
  refused input or config, 4 for a workspace error, 5 for a usage error) is
  carried out of the shell before any read-back, as container mode carries the
  container's. A `--use-existing` run kept the earlier results file, read it back
  and reported such a refusal as exit 1, "did not complete".
- The scan summary's actionable count and the exit-code legend name the number the
  exit code gates on: the persisted SARIF report this run wrote, each result under
  its own scanner's threshold, with `--min-severity` applied. They printed the
  in-memory metrics total, which can differ from it. One consequence: with
  `--min-severity` above every finding the summary omits its "Actionable findings
  detected" block, as the exit code is 0 for them, while every report still lists
  them.
- `./ash scan -v` and `./ash report -v` now reach the subcommand as its `--verbose`,
  as the CLI defines `-v`; the wrapper read `-v` anywhere on the line as its own
  `--version` and exited without scanning. `./ash -v` with no subcommand before it
  still prints the version and exits, so a habit or a health check never builds an
  image; `./ash -v`, `./ash --version` and `./ash --help` exit with the host CLI's
  own status, so a health check sees a host CLI that cannot run. The wrapper also
  takes its own value options in both spellings (`--source-dir=DIR` as well as
  `--source-dir DIR`, and `-oRUNNER`, `-uUID`, `-gGID` as well as the spaced short
  forms), accepts the CLI's `--oci` and `--runner` aliases for `--oci-runner`, and
  writes its own status lines and the image build's output to stderr so that
  `./ash report ... > file` holds the report alone. `./ash get-genai-guide -o
  guide.md` and `./ash config -o DIR` now reach those subcommands' own `-o`
  (`--output`, `--output-dir`) instead of naming the container runtime; `-o` with
  no subcommand, after `scan` (whose `-o` is the CLI's own alias of
  `--oci-runner`) and after `build-image` is still the wrapper's runner, so
  `./ash scan -o podman` picks podman as it always did.
- `./ash` exits 5, the usage-error code, for a value option given no value, where
  it exited 3; `Invoke-ASH` exits 5 for a parameter given an empty or blank value,
  as `./ash` does.
- `./ash` keeps the container's stdin open only for the subcommands that read it
  (`mcp`, `inspect`, `config`) and for a run given `--cli-json-input -`; a scan no
  longer consumes the caller's stdin, so `while read` loops and job scripts fed to
  bash on stdin run every line.
- Redaction matches a value's JSON spelling with non-ASCII kept raw as well: a
  message that embeds a value as a JSON body written with `ensure_ascii=False`
  (an HTTP client quoting the body it could not send) escapes the value's
  double quotes and backslashes while keeping a non-ASCII character as it is, a
  combination none of the other printed forms spells, so such a quote printed
  in clear. The form joins the set every sink matches (`error_text`,
  `traceback_text`, `text_without_values` and the read-edge trim all share it),
  so the spelling is hidden whichever printer shows the text.
- The MCP `get_config` tool and every `extends` base of a config load judge the
  file that is opened. The file is opened first, the session's grant (and, for a
  base, the confinement root) is asked about the path the open file leads to, and
  the read is held to that file and to its inode, which stays in use until the
  answer is made. A name that leads to another file by the time it is read is
  refused instead of read, and a raw `get_config` takes its bytes from the file
  the grant was asked about. A file that the `ASH_CONFIG` chain also names is read
  again, held to the checked file, when `get_config` asks for it by name, and a
  read that differs from the cached one is refused. A cached read that holds no
  text for its file has nothing to compare, so it is refused for the missing
  text, as a reader that did not fill its text cache is, and not as a changed
  file.
- A config that cannot be loaded because the file changed after it was checked is
  reported as such, with `error_category` `invalid_path`, whether the refusal is
  the error itself, its cause, or the mark of a reworded error.
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
- **Only the operator turns trivy's and trivy-repo's telemetry on.** A config file
  inside a git checkout or the scanned directory could set
  `scanners.trivy-repo.options.disable_telemetry: false`, or the same option of the
  builtin `trivy` scanner, and trivy then sent
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

- **`ash report` and `ash merge` take an off-host plugin reporter's settings from
  the overrides.** A plugin reporter that sends findings off the host and declares
  no destination options was left out of the rule that holds a `--config` file's
  `enabled` flag and destinations to the overrides, so a `--config` file outside
  every git checkout and the scanned directory could enable it and aim it. Its
  whole section, `enabled` included, now comes from the defaults and
  `--config-overrides` in both commands. `ash merge` also holds its `--config` file
  to the rule for a plugin reporter that declares destination options: the file no
  longer turns it on or changes its destination options, and its other options
  still apply. That holds for a reporter that is on by default too: its own default
  used to match a file's `enabled: true`, so the file's value was kept and the
  reporter ran to its default endpoint. In both commands the file's `enabled` is
  now dropped for such a reporter unless `--config-overrides` sets it, and the
  reporter is refused until an override enables it. The notice `ash merge` prints
  for a shard's setting of such a reporter names `--config-overrides` as what
  decides. In `ash report`, a
  `--config` file that extends a file inside a tree is part of the operator's view
  that such a reporter is built from; the same rule now applies to that view, an
  `options` value that is not a mapping is replaced like a destination, and the
  section is read once. A config file `ash report` finds on its own in the working
  directory is in the tree, and such a reporter is built from the operator's view,
  not from that file. The warning `ash report` prints for a plugin reporter names
  the reason the file is held: a file in the working directory or a git checkout
  keeps the reason for a file in the tree, a file the command cannot place in any
  tree gets its own reason, and both end with the remedy of passing the settings
  with `--config-overrides`, since moving the file out of the tree does not change
  how `ash report` treats it. For a plugin reporter that lists no destination
  options, whose whole section `ash report` replaces, that warning is printed once:
  building the reporter no longer repeats it with the remedy for a scan. A scan
  keeps its operator view and the sections of its reporters as before. Only a
  reporter that sends findings off the host is held to the opt-in for `enabled`: a
  plugin reporter that declares destination options but writes only local files
  is not named in the warning for an `enabled: true` the file sets, since it still
  runs. For one that does send findings off the host, the file's `enabled` is
  replaced by `false` instead of being left out, so `ash merge` no longer adds a
  warning that the section sets options but not `enabled`, and a `false` the file
  wrote is not reported as ignored. When a named `--config` file in the working
  directory sets a destination for a built-in reporter and for a plugin reporter,
  both warnings end with the remedy of passing the settings with
  `--config-overrides`, and so does the warning for a built-in reporter when the
  named file is outside every tree and extends a file inside one. In `ash report`
  and `ash merge`, a setting that the file spells differently from the operator's
  config is named once, under the file's spelling, for the built-in reporters as
  well as for plugin reporters. In a scan, an `options` value that is not a
  mapping is left as written in the resolved config, so a reporter built from
  that section is refused by its model; a reporter that sends findings off the
  host is built from the operator's config instead.

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
  fixed choice cannot hold one, so those commands exit 3, naming the field and
  the reference, unless `--config-overrides` or the file that `--config` (or
  `ASH_CONFIG`) names supplies the field. An override that appends with `+=`
  adds to a value and does not supply the field. A config file in the working
  directory supplies nothing. `ash merge --output-formats` supplies
  `output_formats`. Any other reader of the results takes that
  field's default, with a warning. A true/false or a number field refuses the
  results file. Also changed:
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
  not accept is refused the same way. When the image is built with another ASH revision,
  whose schema may accept a value this tree's model refuses, only an override that does
  not parse or cannot be applied is refused on the host, as for the config file; the
  scan inside judges the value. The same read gives the host its
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
- The MCP `set_source_git` tool follows no HTTP redirect and clones with LFS
  smudging disabled: every git command it builds (the clone, the fetch and the
  checkout) carries `http.followRedirects=false` and runs with
  `GIT_LFS_SKIP_SMUDGE=1`. A failed `https://` clone now says that redirects
  are not followed and to give the URL the host redirects to (for example with
  the `.git` suffix); the streamable-HTTP docs say the same.
- A configured path under the scan's own output or work directory is a
  repository-derived file and is refused unless the operator wrote the
  value, whether or not the caller passes the directories: `honored_path`
  reads the directories every plugin context records on the configuration,
  and its `operator_written` argument now defaults to the stricter judgment
  (not the operator's) where it defaulted open. A caller that omits the
  argument under an output or work directory outside the scanned tree now
  takes the derived-directory refusal; ASH's own callers pass it
  explicitly. The workspace output directory is recorded as derived too,
  so one workspace project's configuration cannot hand a tool a file
  derived from another project's repository.
- In container mode, the config the scan inside the container is given
  follows the mounts. A `--config` or `ASH_CONFIG` file inside the scanned
  source directory is handed on by its mounted place, `/src/<its relative
  path>`, so the scan inside can open it where a host path meant nothing
  there. An existing config file outside the source directory is mounted
  read-only outside the scan's own tree inside the container, its `extends`
  chain with it, and the host tells the scan inside which mounted files
  count as repository-written, so a pipeline that points `ASH_CONFIG` at a
  file outside the scanned tree keeps that file's settings in container
  mode. A path that names no existing file -- or an empty value, or a
  directory -- is refused on the host with exit code 3 before any image is
  built ("Config file not found"), the code a local scan gives an unusable
  config, rather than mounted as nothing and scanned with the defaults; a
  relative path is read from the host's working directory. A file the host
  itself cannot read is refused the same way, since ASH does not hand the
  container runner a file it cannot read itself.
- In container mode, a workspace policy file that the scanned repository wrote
  is now refused with exit code 3 before the container starts. A mounted
  config chain tells the scan inside which files the repository wrote, and the
  workspace policy has no such mark, so it is no longer mounted and applied
  without one. Keep the policy outside the repository being scanned.
- In container mode, the scan report streamed to the terminal hides a carried
  environment value shorter than the match-anywhere length only where a line
  quotes it, so a short common word that equals such a value (a severity or a
  region name) prints as the scan wrote it. A value read from a variable whose
  name ends with a secret word (`KEY`, `TOKEN`, `SECRET`, `PASSWORD`,
  `CREDENTIAL`, `PASS`, `PASSWD`, `PWD`, `PAT`, `AUTH`, `PASSPHRASE`, and
  their plural forms), or holds one as a whole `_`- or `-`-separated segment
  followed only by trailing qualifiers (a digit run, a version mark, or
  `PROD`, `STAGING`, `DEV`, `TEST`, separated or glued: `ASH_API_KEY_PROD`,
  `ASH_API_KEY2`, `ASH_TOKENPROD`, `GITHUBTOKEN`), is hidden where a line
  quotes it, as a whole `_`/`-`-bounded word from 4 characters, and anywhere
  only from 8 characters (the match-anywhere length) or when it holds a
  character besides letters, digits and underscore; a shorter value glued
  inside a longer alphanumeric token still prints. A name whose later
  segments are not such qualifiers (a flag or a limit named after the word)
  is not treated as secret. Four names measured as false positives of the
  ends-with rule (`COMPAT`, `BYPASS`, `COMPASS`, `OLDPWD`), and their plural
  or digit-qualified spellings, are not treated as secret. The image build
  and the runtime's own stderr keep the stricter matching for every value.
- An operator configuration chain that used to load is now refused with exit
  code 3 when one of the operator's own files writes a `sandbox.mode` outside
  the known modes. The refusal names the file and never the value written,
  and the configuration is no longer resolved without the mode the file wrote.
  The check runs on every load, over the operator's files in both the
  selected config's chain and the `ASH_CONFIG` chain, so a bad mode that a
  later file in the chain would have overridden is refused too.
- bandit's `config_file` option, when relative, is now read from the scanned
  source directory instead of the process's working directory. A scan run from
  another directory than its source used to look for the file in the wrong
  place.
- The MCP `get_config` answer with no config file is now the resolution a
  scan of the same directory applies, so a sandbox grant or plugin-module
  entry written by a file inside the scanned tree (in the `ASH_CONFIG` chain)
  is dropped from it, as the scan drops it, instead of being shown as if it
  applied.
- Leftover scan copies of a session's profile (files named
  `.ash-scan-<scan id>.<profile name>`, left behind when a scan process was
  killed before it could remove its copy) are removed when a profile is next
  bound. A copy whose scan is still running, a symbolic link, and any file
  whose name does not match the scan copy form are left alone.
- Error text and recorded tool output no longer carry terminal escape
  sequences: complete CSI sequences (color included) and complete OSC
  sequences (such as terminal hyperlinks) are removed from error messages,
  tracebacks and the tool stderr that reaches reports.
- With `--no-build`, the container image's own ASH validates the
  configuration. The host still refuses, before anything is built or run, a
  config file that does not parse or whose `extends` chain leaves its root,
  because those hold for every ASH revision; a value this revision's schema
  refuses may be one the image's revision declares, so it is the scan inside
  that refuses it, with exit code 3.
- A container run passes into the container only the environment variables
  the operator's configuration reads, each by name, and refuses a
  configuration that reads one of a fixed list of names ASH itself owns (the
  run command's own settings, ASH's `ASH_CONFIG`, scanner, plugin-module,
  workspace and path settings, the MCP, mode, image and download settings,
  and the reporter and model settings such as `ASH_BEDROCK_MODEL_ID`) or a name the container image defines for the tools
  inside it (`HOME`, `PATH`, `PYTHONPATH`, `TMPDIR` and their family), since a
  host value for one of those is wrong inside the container by construction.
  Other `ASH_` names are not on the list. The host's own ASH
  reporter and model environment variables are not passed; a value the scan
  inside needs comes from the operator-written configuration, which is the
  supported route. Adding `-e` flags to the wrapper's runner invocation by
  hand is not a supported way to hand environment to the scan.
- **A config file that reads a value from the environment (`${VAR}`) at a typed
  field is now refused with exit 3 unless the field can hold the text.** The
  fields it refuses are those typed as a number (`int | float`, `List[int]`),
  `Decimal` or `date`, where the substituted text used to reach validation as a
  string and failed there, or was coerced. The fields that admit a reference
  now include `SecretStr` and `Enum` ones. `Path` and URL fields stay refused,
  and the refusal's hint names the `Path | str` annotation a plugin author can
  use to take a reference.
- **The reason an MCP scan gives for a scanner that lost some of its targets is
  now `partial_coverage`, where it used to read `error`.** A current scan
  grades such a scanner ERROR (or FAILED, when the surviving findings fail the
  severity gate), and the token now follows the recorded counts instead of the
  status, so a client can tell a tool that never ran from one that ran and left
  targets unevaluated. A row's `status` is `MISSING`, `ERROR`, `FAILED` for a
  partial loss whose surviving findings fail the gate, `FAILED` for findings
  that outrank a tree that went unevaluated (its `detail` reads `FAILED
  (MISSING on some files)`), or a status an older results file kept despite
  lost targets.
- **The `enabled` field of the scanner inventory for an external plugin whose
  config reads it from the environment is now the literal `"${VAR}"`.** It was
  the resolver's marker, which a tool answer could not carry. The text the
  variable holds is not reported, only the reference.
- **A workspace project's outcome gains `incomplete_scanner_details` and
  `partial_coverage_scanners`.** `incomplete_scanner_details` maps each name in
  `incomplete_scanners` to the status the completeness gate shows for it, with
  the unevaluated-target counts when the audit was partial.
  `partial_coverage_scanners` lists the incomplete scanners whose counts show
  a partial audit, whatever status was recorded. Results files written before these fields existed read
  as empty for both, and a reader falls back to the status.
- **A scanner that lost SOME of its targets but found gate-failing problems on
  the rest now reports FAILED instead of ERROR.** The per-target guard used to
  grade ERROR before the severity gate ran, so one unevaluable target (one
  cdk-nag template whose value cannot be built, say) relabeled a run full of
  gate-failing findings as ERROR, and consumers that gate or waive on FAILED
  never saw them. On a partial loss the severity gate now runs first: FAILED
  when the findings from the evaluated targets fail it, ERROR otherwise. A
  scanner whose every attempted target failed, or whose counters are
  inconsistent, still grades ERROR unconditionally, and the incomplete-scan
  gate still lists the partial loss and exits 1 either way. The scanner-level
  status follows the same rule across the source and converted trees: a tree
  that lost some of its targets reads FAILED beside gate-failing findings on
  either tree, and only a tree that lost every target it attempted outranks
  them. The partial loss stays visible in `incomplete_scanners`, with its
  counts. The rule reads the rows a scan writes, including the ERROR row the
  completeness check records for a scanner with an ERROR tree, and it applies
  only to the ERROR a partial loss earns: a tree whose ERROR was written for
  another cause (a killed tool whose own findings fail the gate, a scan that
  returned nothing, a tool ASH could not stop) keeps ERROR beside a finding.
- **`no_scanner_ran` is now `false` when the only scanner that ran lost some of its
  targets.** A scanner that evaluated part of its input and lost the rest grades
  `ERROR` when the targets it did read are clean. Counting it as "no scanner reached
  a verdict" contradicted the `ERROR (4 of 10 targets unevaluated)` row listed beside
  it. The field now reads `false` in that case, in `get_scan_progress`,
  `get_scan_results`, the workspace coverage payload and a workspace project's
  `no_scanner_ran`; a scanner that lost every target, or that recorded no target
  counts, still reads `true`. The exit code is unchanged: the `ERROR` row still fails
  the incomplete-scanner check and the scan exits 1. A client that treated
  `no_scanner_ran: true` as "restore the tool" advice should read `incomplete_scanners`
  and its `partial_coverage` reason instead. The CI script
  `.github/scripts/assert_scanners_completed.py` reads statuses only and keeps
  reporting that nothing executed for such a file; it exits 1 either way.
- A `.git` entry in a directory above the scan root now marks a repository
  only when it is shaped like a marker git's own discovery reads: a gitfile
  (a regular file starting `gitdir:`), a symlink or junction (counted even
  dangling), or a directory holding `HEAD` (counted even without objects or
  refs); the near misses err toward "nested".
  A stray `.git` above the root that git would not open -- an empty
  directory such as a transient mount point leaves, a non-gitfile regular
  file, a `HEAD`-less directory, a FIFO -- no longer makes the repository
  below it count as nested: such a scan records its scan source (`.` at the
  repository root) instead of none, so the aws-security-hub reporter starts
  archiving its stored findings again. An entry that cannot be read still
  counts, whoever left it: the nesting walk fails closed.
- **A configuration read with the working directory deleted loads fail-closed
  instead of raising.** A load that used to end in `FileNotFoundError` out of
  the missing working directory now answers, with every checkout's file read
  as the repository's: its operator-only options, off-host reporter sections
  and sandbox grants are left out, and places-only warnings say so. A
  client-supplied config with no root at all may name only the trusted
  list's plugin modules and ASH's own (the load refuses others, naming the
  gone working directory); a caller that still gives a root has modules
  judged against that root, as a scan of it would, and a client path that
  vanished before the read falls back to the operator's rules.
- A patch pointer that spells a plugin section in a different case or with
  different separators between its words now lands on the section the
  document holds, instead of refusing the load or writing a twin section the
  plugin never reads. A separator spelled inside the plugin-type word
  (`bedrock-summary-repo_rter`) does not fold; one inside another word
  (`bed_rock-summary-reporter`) does, since the config lookup reads it as
  the same plugin. A spelling that matches no held section, or more than
  one, stays as typed. When the operator's own files wrote a spelling of
  the section, an operator file's pointer resolves only against the keys
  those files wrote: a repository twin neither blocks the fold nor
  captures the operator's patch, even when the twin's spelling is a
  dash-for-underscore swap of the operator's own key standing apart in
  the document. A pointer at a section only the repository's files wrote
  resolves as it does without the ownership, so such a chain keeps
  loading whatever spelling the pointer uses.
- With no config file selected and ASH_CONFIG set, the settings the
  operator's chain files write for an off-host reporter now reach the
  section that reporter runs with, as they do under a selected config.
- A `remove` patch operation that indexes into a scalar value now loads,
  with the operation dropped where only one view refuses it; the full
  document still refuses an operation that misfits both views, naming the
  patch entry.
- The settle warnings that name a dropped operator-only option now mask
  section keys the configuration chain read from the environment, the way
  the fail-closed warning masks its places, so a value spelled into a key
  no longer prints in clear.
- The fail-closed warning for the ASH_CONFIG chain's left-out places no
  longer repeats what the settle warnings already said when the chain IS
  the configuration: each place is warned about exactly once.
- The confinement warnings now say the membership that put each dropped
  file under the rule: client-supplied content is named as the session
  client's, read as the repository's; a checkout file under a truly
  rootless no-tree load is named as "in a checkout", read as the scanned
  tree, and under a no-tree load whose trees are known (a root given, or
  trees the caller named) as "in a checkout", read as the repository's; a
  file inside such a load's known trees is named as inside the given
  root's trees, in every voice -- the sandbox, settle and module lines
  alike, since the scanned-tree wording would claim a tree the load
  declared it does not have; and files inside a real scan's tree keep the
  scanned-tree wording. A drop no longer claims a membership the file
  does not have. The module-drop warning's location half is the same
  shared clause; its judgment tail stays the module rule's own: with a
  root given, modules are judged against that root -- in the per-entry
  reason too, wherever the config file sits -- and a load whose trees
  were named without a root keeps the any-checkout judgment, named as
  such. The scanned-tree wording is a real scan's alone. A line that
  would cover files of both memberships carries a mixed sentence naming
  each file's own, though no production load produces one: a chain's
  bases stay inside one confinement root, and everything inside a root
  that is its own tree is the tree's. The mixed sentence speaks the given
  root's trees only when the load's trees are known -- a root given, or
  trees the caller named; a mixed line without known trees speaks the
  host's mark and the checkout reading instead, so no caller gets a root
  claim, or a scanned-tree claim, the load does not have.
- The MCP get_config answer keeps the operator-only ignored marker for a
  checkout base that both the selected config and the ASH_CONFIG chain
  extend; telling the two chains apart by set membership dropped the
  shared file from the selected view and the marker with it.
- **The MCP get_config answer judges the configuration's plugin-module list
  as a scan of the same inputs would.** A config whose `ash_plugin_modules`
  list every such scan refuses now answers `success` false with its own
  `error_type` and `error_category`, both `plugin_module_refused`, exit
  code 3, suggestions that name what an MCP client can change, and this
  surface's closing words; clients used to get a load-failure frame
  ("Configuration file ... cannot be loaded") under the `invalid_format`
  category with file-format suggestions for a file that loads fine. Only the config's own entries are judged: the server-side
  `ASH_PLUGIN_MODULES` variable is a CLI scan option that no scan started
  through the MCP server reads, so it never refuses an answer and its
  content never reaches one. `raw` requests are never judged, on either
  answer path: they ask for a document (the file as written, or with no
  file the default configuration), not a run. The no-file answer's entries
  are the operator configuration's, so its refusal names the ASH_CONFIG
  variable, never that file's path or the client's remedies, and carries no
  `config_path`.
- The MCP get_config tool's `search_dir` -- the directory the caller's scan
  will target -- now crosses the scan tool's own gates before anything reads
  it. With no `config_path` it is still where the config is discovered; with
  a named `config_path` it is the target the file is judged for, so the
  answer refuses exactly what a scan of that target refuses, and an entry
  such a scan drops with a warning never refuses the answer. What changed
  for a caller that passes one: a `search_dir` that does not exist or is not
  a directory is refused (`source_dir_not_usable`, exit code 5) where it
  used to get the default configuration's answer; a remote caller's
  `search_dir` outside the session's delivered source is refused as a scan
  of it is (`scan_target_not_permitted`, exit code 4), where the refusal's
  `error_type` was `config_input_not_permitted`; and a local caller's
  discovery runs only in a directory a scan could target. Without
  `search_dir`, a named file is judged for the session's delivered source,
  or else the server's working directory, as before. A `search_dir` outside
  the scan roots is refused before the named `config_path` is opened, so
  nothing under a refused directory is opened, a named file inside it
  included.

- **A stop the kernel refuses leaves the run reported as one ASH could not stop,
  with no exit code.** A kill refused at the MCP server's stop (EPERM on a setuid
  child, say) ended the spawn as "the server is stopping, so <tool> was stopped"
  while the tool still ran; it now ends as a cancel saying ASH could not stop the
  tool, naming its pid, and the spawn's record says the same. A refused group
  stop counts even when the group's leader already exited: a surviving member
  can still write into the output directory, so the leader's exit alone no
  longer clears it, and such a run reports no exit code, where the leader's own
  code read as a run that finished. The same holds when the kernel reported the
  group kill as a success: it reports success when it signalled any member, so
  a member ASH may not signal survived with nothing raised, and the run read as
  a plain timeout; a group that still exists once the leader is reaped and a
  short settle has passed is now recorded the same way.
- A failed wait writes both stream logs: a run whose wait on a started child
  broke, in the wait itself or in that failure's own handling, now writes
  `<class>.stderr.log` beside the stdout log, under the same stream
  preferences. The file scanners read to explain a failure exists on those
  paths too.
- A completed run whose stdout log cannot be written still writes its stderr
  log, through the same per-stream writer the failed-wait and timeout paths
  use, and every failed write is named in the run's reason and its error-log
  record after both writes were attempted; the response's returned streams
  are set before the writes, so the preference's "return" half never fails
  with the disk.
- Tool stderr entering the reports (a scanner's `errors`, and through them
  the SARIF exit description and raw results) is redacted with escape codes
  removed first — every complete CSI sequence (color included) and every
  complete OSC sequence, such as a terminal hyperlink — so an escape code
  inside a value no longer splits the match. Escape forms outside those two
  sets (DCS, APC, C1 bytes) are not stripped.
  A uv run's stderr additionally hides every printable spelling of an
  env-read value and the run's plugin-built inputs, through the same hiding
  layers the install debug record applies to its own input set (each record
  hides the inputs of the command it is about, so the sets themselves
  differ), so a resolver line that respells or glues the value
  no longer sits in the reports in clear beside the redacted message — a
  glued value inside a hidden requirement's own name is hidden even where
  that name appears inside a file name. The
  scan-failure message's stderr-log excerpt — the only route uv's resolver
  text reaches that message under the default `stderr_preference="write"` —
  applies the same rules for a uv scanner's log, and the neutral layer for
  any other tool's.
- Every bounded excerpt of a tool's output is redacted before it is cut, so
  a cut can no longer split an env-read value and leave a fragment the
  whole-spelling redaction misses: the scan-failure stderr-log excerpt, the
  npm and yarn audit failure details, the yarn version probe's output, a
  pre-installed tool's version-probe excerpt, and a content database
  update's or status probe's error text. The scan-failure excerpt's bounded
  log read is additionally trimmed at its read edge before the redaction:
  bytes past the bound were never read, so a value split at the edge leaves
  a piece whole-spelling redaction cannot match, and when the log is mostly
  color codes the shown text falls under the excerpt bound and that piece
  would print at its end.
- Records about a `uv tool install` — the installation-attempt record and
  uv's stderr debug line — build their hidden input set with one shared
  builder (the spec, the base spec, the bare constraint, and each `--with`
  entry), pass the same public tool name, and the spec uv installs is the
  builder's own string, so the installed spec, the two records' hidden sets
  and their placeholder numbering cannot drift apart. The attempt record's
  "Package extras:" and the start record's `retry_config=` lines are
  redacted like the lines beside them.
- The `<argument N not shown>` placeholders that hide a uv install's or run's
  plugin-built arguments keep the number they were given: a later hidden token
  made of digits or a short word, such as the bare pin `1` of `pk01==1`, no
  longer matches inside an earlier placeholder and rewrites it. A tool's own
  `--version` answer keeps its version when the version is also the spec's
  pin, because the version is the answer there; the spec the tool echoes back
  is still hidden, and a record that checked nothing still hides a pinned
  version inside a wheel or sdist file name.
- The sandbox's spawn debug line, the uv pre-dispatch record and the
  process runner's own command-line records hide the scope's env-read
  values and, for a uv run, the run's plugin-built inputs — whatever the
  sandbox mode: with the sandbox off the dispatch sets a record-only
  context carrying the same input set — so a spec that pins or glues a
  value is hidden in ash.log by the same rules as the report lines.
- The results-directory sweep's removal-failure warning and a sandbox
  cleanup-failure record are redacted with the scanner's env-read values:
  either can name a path or an entry a tool chose, and a tool can name
  files after options it was given.
- A cancelled parallel scan records what it has, drains its pool, then records
  the rest: results already in hand at the cancel are recorded before the drain
  rather than behind a scanner that cannot see the cancel event, so an
  interrupt during the drain no longer throws them away; scanners queued but
  not started are cancelled instead of started by the pool's exit; and a
  scanner that finishes while the running ones are waited for -- a wait the
  pool's exit performed either way -- is recorded like one that finished before
  the cancel, where its returned results were thrown away.
- In a cancelled parallel scan, SCAN_COMPLETE's completed_count counts only
  scanners that completed (returned, or failed and were recorded): the cancel's
  own future no longer inflates it, so a run of three scanners where one
  finished and one carried the cancel reports 1 of 3, not 2 of 3.
  completed_scanners was already right; only the event payload changes.
- Every exit-1 cause that holds is logged before the exit, in arm order: a run
  with several causes (a tool ASH could not stop beside an incomplete scanner,
  say) named only the first, and an operator working from ash.log met the next
  cause only after fixing the first and re-running.
- **A scanner whose dependencies were unavailable on the converted files only is
  `MISSING`.** A scanner's `scan()` can find its dependencies unavailable on one of
  the two trees ASH gives it, the source files and the converted files, and that
  tree's report says `MISSING`. The scanner's row read only the source report, so a
  scanner that evaluated the source files and nothing in the converted ones was
  `PASSED`, with no reason, in the summary table, `ash.flat.json` and the
  completeness gate. Its row is `MISSING`, its `missing_reason` starts with the
  files it missed (`on the converted files: <reason>`), and `exit_code` is the code
  its tool returned on the files it did scan. With `fail_on_incomplete_scanners` on,
  the default, such a scan exits 1. A scanner that missed the source files and
  scanned the converted ones was already `MISSING`; its reason names the source
  files the same way. A scanner with findings on the files it scanned stays
  `FAILED`, since findings outrank `MISSING`, and its row carries the same
  `missing_reason`; the completeness gate lists it as
  `FAILED (MISSING on some files)` with that reason, and with
  `fail_on_incomplete_scanners` on such a scan exits 1, as one with any other
  `MISSING` scanner beside findings does, where it exited 2 for its findings, or 0
  with `fail_on_findings` off. A tree whose report says
  `dependencies_satisfied: false` counts as missing whatever status it reached,
  which is a scanner whose `scan()` recorded its tool absent and still returned a
  report; ash.log gets the same WARNING with the scanner's reason.
- **A selection naming only a scanner whose constructor raised runs, with that
  scanner `ERROR`, and exits 1.** It was refused as "None of the requested scanners
  exist ... Check the spelling", with exit 5 from the CLI and a failed project over
  MCP, and the constructor's error never reached an MCP client. The scanner's row is
  `ERROR` under the name the scanner is selected by, where a scanner with no config
  of its own was recorded under its lowercased class name (`banditscanner`), and a
  workspace project's `scanner_reasons` carries the constructor's error. A name no
  registered scanner has is still refused.
- A notebook the jupyter converter cannot convert fails the scan with exit 1
  under the default completeness gate (fail_on_incomplete_scanners), with the
  notebook named and why. A file that is not a notebook (not JSON, or JSON with
  no cells, such as a Git LFS pointer) is an input error. To accept one, add a
  suppression with rule_id ash-unconverted-input and its path, which keeps it in
  the results. To skip it entirely, add it to ignore_paths. A converter that
  could not run nbconvert, or that nbconvert failed on, is not accepted this
  way. The record of an accepted input names the entry that accepted it: its
  `accepted_by` field holds that suppression's id in the written form, the form
  `used_suppressions` records (absent in results files written before the field
  existed and where the id could not be recorded). Only the entry that granted
  an acceptance counts as used by it, so a broader entry that also matches the
  path but granted nothing shows in the unused-suppressions report and is
  commented out by `ash config lint --fix-unused` instead of reading used for
  good.
- A scanner selection naming no registered scanner exits 5, usage error, in
  every mode: the workspace scan, its `--dry-run` (which exited 0 printing the
  plan), and the MCP workspace tool, which now refuses it before any project is
  registered, any output directory is created or any previous results are set
  aside. The workspace pre-check judges the selection against this workspace's
  own plugins rather than the whole process-wide registry, so its refusal
  message no longer lists scanner names other sessions loaded, and a name only
  another session's plugins provide is refused instead of selecting nothing in
  every project. The no-match and self-cancelling refusal texts are the same in
  a single scan and a workspace, named for the selection's origin. To make the
  pre-check, `--dry-run` now imports the workspace's plugin modules (from
  `--ash-plugin-modules` and every project's config), as the scan does, so
  their top-level code runs; a module outside ASH's plugin namespace is
  refused with exit 3, as in the scan, before anything is imported.
- **`ash inspect findings` filters combine, and the table and suppress dialog
  changed.** The user-visible changes to the findings explorer:
  - The severity, scanner, and suppression filters intersect: picking a scanner
    narrows the current severity view instead of replacing it, and `Only
    suppressed` applies together with both.
  - The table shows Severity and Finding columns, with Location added at 70
    columns of terminal width and Scanner at 110, in place of the old ID,
    Rule ID, Severity, Scanner, File, Line, and Message columns. The Finding
    column holds the rule id with the message under it, and Location the file
    with the line under it.
  - The scanner column and the scanner filter read a result's
    `properties.scanner_name` first, falling back to
    `properties.scanner_details.tool_name` as before. A script that reads the
    explorer's scanner names, or a saved filter habit, sees `scanner_name`
    values where results record both.
  - The suppress dialog stays open on a failed save, with the typed input kept
    and the failure shown in the dialog; it used to close and discard the
    input. The expiration date is checked in the dialog: a date that is not
    YYYY-MM-DD, or one already reached, is refused with the rule named, before
    anything is written.
  - A new `r` binding resets the filters and the search.
- Saving a suppression into a config the save cannot write is refused with the
  file unchanged and the reason in the save's own words, ending
  `<path> is unchanged`: a read-only config (the save previously replaced it
  through its writable directory, ignoring the file's own mode), a config in
  a directory the process may not write, and a directory that refuses the
  replace (named as a sticky directory only when the sticky bit can be the
  cause: the directory's mode carries it, the config existed, and the process
  owns neither the config nor the directory and is not root - otherwise the
  refusal reads "the system refused to replace the file" with the system's
  own reason) or a config mounted as a single file. No refusal names
  ASH's internal staging file.
- A saved suppression's reason reloads as the operator's literal text. The
  loader reads a plain `${ASH_...}` scalar from the environment, so a reason
  with that shape, saved unquoted, came back from the next load as the
  variable's value. Every suppression save path now writes a reference-shaped
  string quoted, which the loader reads as the text itself.
- A suppression save that rewrites the config whole (a shape the text edits
  cannot touch, such as an inline `global_settings: {...}` mapping, or a save
  with no config file yet) quotes reference-shaped strings the same way: a
  deliberately quoted `'${ASH_X}'` already in the file stays quoted instead
  of becoming a resolving reference, and a `$` without the reference shape
  stays a plain scalar.
- Saving a suppression edits the config as text: every line and comment the
  file held (top-of-file, trailing and in-block comments alike) is still
  there byte for byte, with only the new entry's lines added. The save
  previously rewrote the file from its parsed values, which dropped every
  comment and reindented the document.
- A JSON config whose `global_settings` or `suppressions` is an explicit
  `null` takes the entry as though the key were empty, as the YAML save and
  the in-memory comparison already read it, instead of being refused as "is
  not an object"/"is not a list".
- Two saves that previously succeeded by rewriting the file are refused with
  the file unchanged and advice in the save's own words: a flow-style
  `suppressions` value (on the key's line, or starting on the line under it),
  where a block item cannot follow and the old rewrite dropped every comment,
  and a config that reads values from the environment (`${VAR}` or `!ENV`)
  whose shape would force a full rewrite, which would drop the `!ENV` tags.
- A named config file whose status cannot be read (a directory with no search
  permission, for example) is refused instead of silently running the scan
  with the default configuration; only a missing path keeps that fallback.
  The refusal names the errno's code and the path as the caller wrote it.
  ASH_CONFIG naming a symbolic link loop or an unreadable path is refused by
  that reason, not as "does not exist", and before Python 3.14, where
  `exists()` propagates a denied stat, that check classifies it instead of
  crashing.
- A local scan whose `--config` names a path that exists and is not a regular
  file (a directory, a FIFO, a device) is refused as "<path> is not a regular
  file, so it is not read as a config". It was reported as "Configuration file
  not found: <path>", which named the wrong problem.
- Nix mode refuses a `--config` it cannot read in the local scan's words: a
  missing path, a symbolic link loop, and a path that is not a regular file are
  named as they are in a local scan, and a path whose status is denied is
  refused as "cannot be read (EACCES)". The old "Config file not found: <path>.
  --config (or ASH_CONFIG) has to name an existing file" text no longer appears
  in nix mode; container mode keeps it. On Python 3.10 through 3.13 a denied
  status for the named path raised an uncaught `PermissionError` out of the nix
  refusal check; the path is now classified from one status call and refused.
- `--config-overrides fail_on_findings=...` and `fail_on_incomplete_scanners=...`
  decide the exit code in container and nix mode as they do in a local scan.
  The host used the config file's value, so the same command could pass with
  `--mode local` and exit 2 with `--mode container`, or the reverse. When the
  image's ASH may declare another config schema (no image is built, a custom
  Containerfile, or another revision), the overrides still decide as long as
  this tree's model loads the config file. The file's values decide only when
  this tree's model refuses the file, or an override names a key only another
  schema declares, so the scan inside judges the overrides.
- The `ValueError` that `run_ash_scan` raises for a `config_base_gate` it cannot
  honor now names the case: a workspace scan, or container or nix mode, where
  the gate would be dropped. Callers that match on the text should match on
  `config_base_gate`, which both forms contain.
- A `--config-overrides` key whose first segment respells one of the
  configuration's own top-level fields (`Reporters.`, `REPORTERS.`) is refused
  naming the real key; before, it landed as a new top-level key the model
  ignores, so the command exited 0 with nothing changed. A first segment that
  is no spelling of a declared field is still tolerated.
- The respelled-override refusal redacts a section key the config read from
  the environment, naming it `<value>` instead of the variable's value in the
  exception's text, the MCP error response, and the log.
- A `--config-overrides` key that respells an existing section is refused on
  the scan path too, with the same keys-only message `config get` gives. The
  scan's resolution previously caught that refusal while replaying `reporters`
  overrides onto the operator's own configuration and went on with one
  warning, so disabling an off-host reporter under a respelling left it
  enabled while the run reported success.
- When the repository's config and the operator's own file spell one reporter
  section differently, the spelling the scan's apply demands (the
  repository's) now also passes the replay onto the operator's configuration,
  folded onto that file's own section. Before, each application refused the
  other file's spelling, so no spelling worked, and the repository controls
  its half of that. The fold is bounded to exactly that case: the section must
  be one the repository's file spelled before the overrides were applied (a
  respelling of a section only the operator's file holds stays refused), the
  two keys must name one plugin as the off-host classification reads names
  (an override typed for a built-in reporter never lands on an operator-only
  section it merely folds with), and only `reporters` segments fold. The
  replay's own log lines print a section key the operator's file read from
  the environment redacted, as the refusals already did.
- `ash config update --set` refuses a value shaped like an environment
  reference (`${VAR}` or `!ENV`), naming the key only: the command refuses to
  rewrite a file that reads the environment, so it does not create one either,
  and it never silently writes a typed reference as literal text. Edit the
  config file to add a reference. The check matches the value as the model
  reads it (whitespace stripped), walks a nested value iteratively so a
  reference at any depth is refused rather than crashing, and refuses a
  reference-shaped key segment the same way.
- Describing a validation refusal walks the refused input iteratively when it
  redacts the input's strings from the message, so a value nested deeper than
  the interpreter's recursion limit is answered by the one-line refusal
  instead of a RecursionError traceback.
- `ash config update` and `ash config lint --fix` keep a quoted
  reference-shaped literal (such as `project_name: '${VAR} ...'`) quoted when
  they rewrite the file, as a suppression save already did; before, the
  rewritten value was written plain and the next load read it as an
  environment reference.
- When the handler for a failure after a tool started raises itself, the
  fallback answer honors the caller's stdout preference (under the scanners'
  default the body the wait had read is written to the results file instead
  of riding the response) and its reason leads with the original failure the
  handler was answering, with the handler's own error after it.
- MCP error messages now show control characters as escapes.
- ASH replaces or removes only the logging handlers it added, so a handler an
  application put on the `ash` logger stays when a scan or a command sets up
  ASH's logging. Such a handler gets ASH's records as written, text from the
  scanned repository in them included. Give it
  `automated_security_helper.utils.log.CommandSafeFormatter` to have it write
  them as ASH's console and log file do, with control characters as escapes
  and CI command lines broken.
- A cancelled scan, such as one an MCP client cancels, ends as an interrupted
  one: event handlers get no `EXECUTION_COMPLETE` event for it, as for a scan
  stopped with Ctrl-C, and ASH logs no "ASH Security Scan Completed" line for
  it. The event was sent as for a scan that had finished, with an empty
  `completed_scanners`. A handler that relies on `EXECUTION_COMPLETE` to learn
  that a scan ended gets no such event for a cancelled one.
- `ScanPhase`'s per-scanner methods (`_safe_execute_scanner`, `_execute_scanner`,
  `_execute_scanners_sequential` and `_execute_scanners_parallel`) are not
  extension points. A scan runs `ScannerExecutor`'s own per-scanner path, as it
  did in the last release, so a `ScanPhase` subclass that overrides one of them
  changes no scan, and `_safe_execute_scanner`'s docstring no longer says to
  override `_execute_scanner` to wrap a scanner's run. A direct call to
  `_safe_execute_scanner` or to the run-loop methods now runs that same path:
  they called an override of `_safe_execute_scanner` or `_execute_scanner`, so
  a direct call and a scan of one phase could run different code. A direct call
  to `_safe_execute_scanner` or `_execute_scanner` records no completed scanner,
  as in the last release; the run-loop methods record each scanner that
  completes. To change how a scanner runs, change its plugin; a test that stands
  in for a scanner's run patches `ScannerExecutor._execute_scanner`.
- A streamable-HTTP or SSE `ash mcp` server that is stopping waits at most 5
  seconds for the requests clients still hold open. It waited for as long as a
  client kept one open, with the scans and their scanners' tools running, so a
  service manager's SIGKILL ended it and left the tools running. After the 5
  seconds it cancels those requests, stops the scans, ends their tools, and exits
  with the status the signal gives it otherwise (130 for Ctrl-C, 0 for SIGHUP, by
  SIGTERM for SIGTERM).
- An `ash mcp` server that stops while a scanner's tool is starting ends that tool
  too. The server kills the process groups of the tools it has recorded and then
  exits, and a tool started just before the stop was recorded only just after it,
  so it kept running after the server had gone. The stop now waits up to 2
  seconds for the tools already starting to be recorded, and starts no new one; a
  tool recorded after that is killed as it is recorded. nbconvert, which the Jupyter
  converter runs for each notebook, and the `git clone`, `fetch` and `checkout` that
  `set_source_git` runs are ended the same way: they ran unrecorded in the server's
  own process group, so a stopping server left them running. Each now runs in a
  session of its own, with no controlling terminal: an ssh remote whose key needs
  a passphrase fails the clone rather than prompting on the server's terminal.
- **The MCP workspace tools report a workspace file they may not read as
  `config_input_not_permitted`, with exit code 3.** `resolve_ash_workspace` and
  `run_ash_workspace_scan` refused a `workspace_file` or `workspace_config` outside
  the directories the session may read config from with `error_type`
  `MCPResourceError` and exit code 4. They now answer `config_input_not_permitted`
  and 3, as they answer for a policy file they find there themselves and as
  `run_ash_scan` answers for a `config_path` outside them. A client that matched on
  `MCPResourceError` or exit code 4 for this refusal should match on
  `config_input_not_permitted`. Exit code 4 stays for a scan target outside the
  roots and for a workspace definition or policy that is wrong.
- **A config file an MCP client delivers is refused when it reads the
  environment, and a value a `patch` reads from the environment is shown by its
  place.** A delivered file that uses an `!ENV` tag or a `${VAR}` reference is
  refused before anything is read from the environment: `run_ash_scan`,
  `get_config` and `validate_config` answer `config_env_not_resolved` (exit code 3
  for the scan tools and `get_config`), and so does `validate_config` for content
  a remote client sends. In the operator's file, `get_config` shows such a value
  as `<from ${VAR}>` at the entry the patch puts it in, after the operations that
  follow it, where it used to mark the entry at index 0.
- **The lines that give an exit code of 1 its reason are ASH log messages.**
  "Scan incomplete: ...", "Scan ran no scanners: ...", "Conversion incomplete,
  ...", the unevaluated-rules and stale-database lines, "ASH scan produced no
  results" and a workspace scan's warnings about its config file were written by
  Python's last-resort handler to stderr, and nowhere else. They now go through
  ASH's log, as every other message does: to `ash.log`, and to the console log on
  stdout with a level column (`ERROR    Scan incomplete: ...`). Under the live
  progress panel on a terminal they are written to `ash.log` only, as any message
  logged after the panel closes is; the exit-1 summary on the console still names
  each scanner and its reason. A script that read the line from stderr reads it
  from `ash.log` now.
- **A reference written with the shell's `${VAR:-default}` form logs a warning.** A
  configuration reads `${VAR:default}`, everything after the colon, so `:-x` gives
  the default `-x`. The value is unchanged; the warning names the variable and says
  to write the default right after the colon. It does not quote the default.
- **The MCP server writes a bound profile with its references as the profile wrote
  them.** `select_profile` writes the session's configuration into the session's
  sandbox for the scan to load. A value the profile read from the environment is
  written there as its reference (`${VAR}`, `!ENV ${VAR}`), not its value, also
  after `patch_ops` or `override_yaml`, so the scan reads it from the environment
  at load and its messages and logs redact it. Only those places are written as
  references: a string that only reads like one, a profile's quoted `'${VAR}'` or
  `'!ENV ${VAR}'` or the same text in a patch, is written quoted, and the scan
  reads it as that text. A string a patch writes over such a value is the
  client's, whatever it holds, and is written as the client wrote it, so neither
  the session config nor `get_config` tells the client whether its string is the
  value. A patch that adds or removes a list entry before one the profile read
  from the environment keeps the reference with its entry; a patch that would move
  such a value where its reference does not follow is refused, and a
  configuration that would hold one as text where its file wrote the reference is
  not written: `select_profile` reports either. Only those places are checked, so
  a value that is also a default string, such as `markdown`, is written.
- **`select_profile` refuses a patch op it cannot apply without quoting the
  configuration.** The refusal quoted jsonpatch's own text, which holds the current
  value for a `test` op that does not match and the whole mapping for a path that
  names a missing member. It now names the op and the kind of failure
  (`JsonPatchTestFailed`, `JsonPatchConflict`), so a `test` op tells the client
  only whether it matched. Where a profile reads a key from the environment (a
  `reporters`, `scanners` or `converters` section, or an option of a plugin ASH
  does not ship, named `${VAR}`), an op through a key of that mapping applied only
  when the key existed; it is now refused with one text, before any other rule,
  unless the key is one the profile writes as text, and a `test` op at, above or
  through that mapping is refused too. Where that mapping has built-in keys, as a
  plugin section, a built-in plugin's options or a list entry such as a
  suppression does, a section named for a built-in merges with the built-in's, so
  the answer told whether the variable names one: every patch, override and
  `test` op on such a profile is refused with one text, whatever the variable
  holds and whether or not it is set (`${VAR:default}`), decided from the file as
  written, and so is a workspace scan's `config_overrides`
  against it. A profile that writes the section's name as text is patched as
  before. An op that is not a JSON-Patch op (not a mapping, an `op` that is none
  of RFC 6902's `add`, `remove`, `replace`, `move`, `copy` and `test` as spelled
  there or no `op` at all, or a `path` that is not a string, null included) is
  refused as `InvalidJsonPatch` before any rule reads it, where a number, list or
  mapping path raised an error out of the tool and a null path was read as the
  root. An op whose
  path goes on into a text setting's characters (`.../path/0`) is refused, the
  same way whatever its value, where a `test` op there compared one character. And
  a `test` op at a setting the profile read from the environment compares with the
  reference its file wrote (`${VAR}`), not the value.
- **The results file records a value read from the environment as its reference.**
  Where a configuration reads a value or a key from the environment (`${VAR}`,
  `${VAR:default}` or `!ENV ${VAR}`), the configuration recorded in
  `ash_aggregated_results.json`, the merged results of `ash merge`, the project name
  and scanner names the results carry, and the results the CloudWatch Logs and S3
  reporters send keep the reference exactly as the file wrote it. A variable that was
  not set records the default it gave, and one set to nothing records null. The scan
  itself uses the values. Its own reports (`ash.flat.json`, `ash.html`,
  `ash.summary.md`, `ash.summary.txt` and the SPDX document) name a project whose
  name the configuration read from the environment by that reference, and
  `ash config get` prints each such value and key as its reference. `ash report` and
  `ash merge` read the record as it is, without reading the environment again, so a
  report rendered from a results file shows the reference text. Results that record no
  configuration send `null` to those reporters, not ASH's defaults as the sending
  process loads them.

  A field with fixed choices, such as `global_settings.severity_threshold`, cannot hold
  a reference, so a results file that records one there is read with the field's
  default and a warning naming the field and the reference. A list of such choices
  (`output_formats`, a scanner's `additional_formats`) is read as its default as a
  whole. A reference in any other field (a true/false or a number) refuses the
  results file, as does a reference beside any other refusal. `ash merge` and
  `ash report` then exit 3 unless the invocation supplies the field, with
  `--config-overrides` or in the file that `--config` (or `ASH_CONFIG`) names;
  a config file found in the working directory supplies nothing. With it, they
  use that value. `ash merge` over several shards refuses once, naming each
  field with its reference and every shard and results file that recorded it,
  and both commands word a refusal over several fields the same way. A
  container or Nix scan, and
  `ash scan --use-existing`, use the value from their own configuration, so the exit
  code is the one a local scan gives; where that configuration read the value from
  the environment, the results they write record its reference. A results file that still does not load is
  reported by field and problem, without quoting the value, by `ash inspect findings`,
  the MCP results tools and their log, and a container or Nix scan reading back the
  inner scan's results.
- **`used_suppressions` names a suppression as its configuration wrote it.** The
  ids in `used_suppressions` (`ash_aggregated_results.json`) are
  `path|rule_id|line_start|line_end` over the fields as the file wrote them, so a
  field read from the environment appears as its reference (`${VAR}|RULE|*|*`),
  never the value. A script that compared these ids with resolved values needs the
  written form. The unused-suppressions report's `summary.used_suppressions` now
  counts the configured entries matched, not the ids recorded, so `total =
  used + unused` always holds: two identical entries count as two, and an id that
  matches no configured entry counts as none. A results file written before this
  change, which recorded resolved ids, still counts its entries as used, except where
  a configured entry has that resolved id as its written id, so `ash report` on such
  a file followed by `ash config lint --fix-unused` does not comment out an entry the
  scan applied.
- **An ignore path or suppression whose expiration is not a YYYY-MM-DD date is named
  by its location.** A configuration kept from a results file keeps such a date as
  written, and the entry does not apply. The warning for it, from a scan or from
  `ash merge`, and the debug line for an expired entry, name the entry by where it
  is, such as `global_settings.ignore_paths[0]` or
  `scanners.bandit.options.excluded_paths[0]`, and not by its date or path. The
  scan-start notice of expired entries says that such a date is not YYYY-MM-DD,
  without the date.
- **`ash dependencies install` and `ash plugin list` refuse a configuration with an
  unknown plugin option, exit 3, as `ash scan` and `ash report` do.** Install
  refuses it only for a plugin it builds: one of the kinds `--plugin-type` names
  and, with `--tool`, one requested. Another plugin's bad option is logged at info.
- **`ash report --help` lists only the formats `--format` accepts.** `aggregated`,
  `dict`, `asff` and `custom`, which no reporter writes and which `--format`
  refuses with exit 5, are not among them, and the AWS plugin module's reporters
  are named apart, as accepted once `ash_plugin_modules` loads
  `automated_security_helper.plugin_modules.ash_aws_plugins`.
- **Every usage error is one line, with each value and path whole.** It is printed
  after the usage line and the help hint as one `Error:` line, unwrapped, not in a
  panel that folds at the console's width. That includes `ash config get`,
  `update` and `validate-plugin-dependencies` given two different config files, an
  extra argument, click's own checks of a path option, and each refusal of a
  `--cli-json-input` document, which names the document's file and prints it whole.
- **`ash dependencies install --plugin-type` takes only `converter`, `scanner` or
  `reporter`.** Any other value meant `scanner`, so a mistyped type (`scanners`,
  `Scanner`, `bogus`) installed the scanners' dependencies and exited 0. It is now
  refused with exit 2, the code of an unknown `--tool`, naming the value and the
  three types, before the bin path is made or anything is installed.
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
    the collector host's credentials. The modules the `--config` names in
    `ash_plugin_modules` are the plugin modules the merge loads; a module only
    the shards recorded is not imported, and a warning names it. A `--config`
    that does not parse or validate refuses the merge with exit 3 before
    anything is written, as `ash report` refuses it.
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
  [Secret verification](docs/content/concepts/scanning-untrusted-code.md).

- **A finding in a file whose name holds a backslash gets a new `id` and Security Hub
  `Id`, once.** The identity key wrote every backslash in a path as `/`, so on Linux
  and macOS, where `a\b.py` and `a/b.py` are two files, their findings shared one key:
  the next import of either took the other's Security Hub finding. A backslash is now
  part of the name, except in a drive-letter or UNC path, whose separators still
  become `/`. A path a Windows scan wrote already had `/` for its separators, so its
  findings keep their `id`s. See the identity section of the Security Hub reporter's
  page.

- **A scan, `ash config validate` and `ash config lint` print one message for a
  refused `expiration` or `symbol`.** An unquoted date such as `2099-01-31` was
  refused with pydantic's "Input should be a valid string", and lint printed
  messages of its own for both fields. Each now reads, wherever it is printed,
  `expiration must be a quoted YYYY-MM-DD string: an unquoted 2099-01-31 is read as
  a date, not text, so put it in quotes`, `Invalid expiration date format. Use
  YYYY-MM-DD`, or `symbol must be a dotted qualified name such as
  'MyClass.my_method' (identifiers joined by '.', no spaces, wildcards or call
  syntax)`. A content database override's `expiration` reads the same. A string
  that is not a date and a symbol that is not a qualified name are not quoted: the
  string may have been read from the environment.

- **Other refusals state the rule without the refused value.** An undeclared
  content database lists the declared ones, two overrides for one database are
  named by their positions in `content_db_staleness_overrides`, a `generated_at`
  that is not a date and time says it must be ISO 8601, and an `output_formats`
  entry that is not a format lists the formats. A detect-secrets `plugins_used` or
  `filters_used` entry that is dropped, because it names a module other than one of
  detect-secrets' own or a relative `file://` path, is warned about by its key and
  the reason, not the value.

- **`ASH_DEBUG_SHOW_LOCALS` is ignored on a CI runner.** It makes a traceback show
  every frame's local variables, which hold values from the config and the
  environment, and a CI log is read by everyone who can see the build. When
  `GITHUB_ACTIONS`, `TF_BUILD`, `AZURE_PIPELINES`, `TEAMCITY_VERSION`,
  `JENKINS_URL`, `CODEBUILD_BUILD_ID`, `GITLAB_CI`, `BUILDKITE`, `CIRCLECI`,
  `TRAVIS`, `APPVEYOR`, `BITBUCKET_BUILD_NUMBER` or `bamboo_buildKey` is set, to
  any value, an empty one included, or `CI` is set to anything but `0` or `false`
  (Vercel's `CI=1` included), no
  traceback shows locals, in the log or for an uncaught error, and the scan logs one
  warning saying the variable was ignored and why. Elsewhere it works as before.

- **The reusable scan workflow installs the ASH of the commit it is called at.**
  `ash-version` and `ash-repo` in `run-ash-security-scan.yml` default to empty
  instead of `main` and `awslabs/automated-security-helper`. Empty means the commit
  and repository the workflow file was called at (`job.workflow_sha` and
  `job.workflow_repository`), so a caller of `@v3.8.0` gets ASH v3.8.0 and a caller of
  `@main` gets that commit of main, instead of whatever main was on the day of the run.
  Setting either input still overrides it. GitHub Enterprise Server provides no
  `job.workflow_*`, so there both inputs are required and the job fails naming the one
  that is missing. An `ash-repo` other than the workflow's own repository needs an
  `ash-version` too; a caller that passed only a fork used to get the fork's `main`
  and is now asked for the ref. `ash-version` accepts any name `git check-ref-format`
  accepts, including `@`, `#`, `,` and non-ASCII letters. When ASH v3.7.0 or v3.7.1 is
  pinned with any of `install-grype`, `install-syft` or `install-opengrep` on (the
  default), the job now fails early with a message naming those inputs, since those
  releases have no `ash dependencies install --tool`, instead of failing at "Install
  Grype" with "No such option: --tool".

- **The agent plugins' install scripts add ASH to an MCP config instead of replacing
  it.** The Windsurf and Cline scripts wrote their user-level MCP config with
  `cat >`, deleting every other server and setting in it, and the Gemini CLI script
  refused to touch an existing file. All three now add or update only the `ash`
  entry, keep everything else, and save the previous file beside it as
  `<file>.ash-backup-<UTC time>` with the file's own permissions; a symlinked config
  is backed up beside the link and its target is updated. They now need `python3`,
  and when it is missing, or the file is not plain JSON or cannot be written, they
  change nothing, print the entry to add by hand and exit 1. The Goose script appends
  the extension only to a `config.yaml` with no `extensions:` block. With a block
  that already runs this ASH it changes nothing and exits 0; with one that runs
  another ASH version it names that version and exits 1; with any other block it
  prints the entry to add by hand and exits 1. Commented-out lines do not count.

- **The reusable scan workflow uploads SARIF only from pull_request runs, and says so
  elsewhere.** With `collect-sarif-report: true`, the default, the upload ran on every
  event but merge_group and failed the job on push, workflow_dispatch and schedule,
  because the workflow cannot hold `security-events: write` and code scanning accepts
  an upload without it only from a pull_request run. The upload now runs on every
  pull_request event, from forks too, and on every other event the step is skipped
  with a notice: merge_group runs are on the merge queue's temporary branch, which
  the pull request's own run already covers, and the other events are pointed at
  `upload-ash-sarif.yml`, which uploads on every event from a job that grants the
  permission.

- **`changed-files-only` in the reusable scan workflow reports only the findings in
  the changed files, or fails.** Every file is still scanned; findings in other files
  are dropped from the reports, the summary and the exit code. The input passed
  `--changed-files-only` to ASH from a depth-1 checkout. On most events that checkout
  had no base ref, so ASH could not compute a diff and reported the findings in every
  file; on an event on the default branch (push, schedule, workflow_dispatch) it had
  `origin/main`, which there is the commit being scanned, so the diff was empty, and
  ASH's exit code and `ash.sarif` dropped every finding (exit 0) while the summary,
  the pull request comment and the code-scanning upload still listed them. With the
  input on, the workflow now checks out the whole history and diffs against the pull
  request's base commit, the merge group's base commit, or `base-ref` on other
  events. When that ref is not in the checkout, shares no history with the commit
  being scanned, or holds characters ASH refuses in `--base-ref`, the job fails
  instead of reporting the findings in every file. When the base already contains
  the commit being scanned, the diff would be empty: a push then diffs against the
  commit the branch was at before it, and the job fails on any other event and on a
  push whose previous commit cannot be used, which is one that created a branch or
  tag (every release tag, so a caller that scans tag pushes with changed-files-only
  should turn it off for them), one whose previous commit is no longer in the
  checkout, one that rewound the branch, and one whose previous commit shares no
  history with it. The error says which. It also fails before the scan in container
  mode (`ash-mode: container`, or `--mode container` in `ash-args`), where ASH
  ignores `--changed-files-only` and reports the findings in every file.
- **The reusable scan workflow's `ash-args` takes options only.** It is passed after
  the workflow's own options, and click reads a bare word there as an `ash`
  subcommand: `ash-args: scan` ran `ash scan` with the caller's words alone, without
  `--output-dir`, `--fail-on-findings` or `--changed-files-only`, so the job reported
  every finding and could not fail. The job now fails before the scan when a word of
  `ash-args` is neither an option nor an option's value, or is `--`. The word after an
  option that takes a value is read as that value, as click reads it, so
  `--phases scan --phases report`, `--output-dir report` and `--config config` still
  pass.
- **The `aws-security-hub` reporter now imports findings into AWS Security Hub.**
  It used to send nothing and write a placeholder to
  `reports/ash.aws-security-hub.asff.json`. It now converts every SARIF finding to
  ASFF and imports them with `BatchImportFindings`, and that file is the import
  receipt. Any import failure fails the reporter with a message saying what to fix,
  and `ash report --format aws-security-hub` exits 1.
  - It ships disabled: set `reporters.aws-security-hub.enabled: true`. Loading
    `ash_aws_plugins` for another AWS reporter no longer sends findings to Security
    Hub.
  - It needs `reporters.aws-security-hub.options.findings_scope`, a name unique
    among the repositories that import into the same account and Region, because
    finding Ids and archiving follow it. It does not use `project_name`, which the
    scanned repository's own config can set. Set `enabled`, `aws_region`,
    `aws_profile`, `account_id`, `findings_scope` and `archive_resolved_findings`
    only in the operator's configuration (`--config-overrides`, `ASH_CONFIG`'s
    file, or another config file outside the scanned tree).
  - `findings_scope` and `archive_resolved_findings` set by a config file inside
    the scanned tree are ignored with a warning, unless `--config-overrides` or
    a file of the operator's outside the tree sets them (`ASH_CONFIG`'s, a
    workspace's default config, or a `--config` file that `extends` the
    repository's): a pull request could otherwise turn archiving on in
    `.ash/.ash.yaml` and archive its scope's findings in the operator's account.
    The record of the configuration (a results file's `ash_config`, `ash config
    get`) writes either option, and detect-secrets' `max_worker_output_mib`, as
    the `${VAR}` a file wrote only when that file's value is the one kept.
    `ash merge` ignores both in the configuration the shards recorded; it imports
    into Security Hub only as the operator's own `--config` sets the reporter up.
    `ash report` judges its `--config` against the repository that holds the
    results as well as the working directory. The MCP `get_config` tool shows both
    options from a file in a checkout as
    `<operator only; ignored from this file: VALUE>`, as a scan of that checkout
    treats them.
  - A `--config-overrides` key with a dot-separated part that is empty, holds
    whitespace, or holds a character that does not print (a zero-width space, a
    byte order mark) is refused (exit 3). It was applied to a key nothing reads,
    so ` reporters.aws-security-hub.options.archive_resolved_findings=false` and
    `reporters..aws-security-hub.options.archive_resolved_findings=false` left a
    repository's `archive_resolved_findings: true` in place.
  - A finding's Id hashes the same identity as its `id` in `ash.flat.json`, with
    the file relative to the source directory. A finding in a converted file (a
    notebook, a file inside an archive) is identified by the file's path under the
    converted files, so its Id does not depend on where the output directory is.
  - Archiving findings a later scan no longer reports is opt-in
    (`archive_resolved_findings: true`, which needs `securityhub:GetFindings`).
  - Scans record `changed_files_only` in the results metadata, true when results
    were filtered to changed files, and `scan_source`, the scanned directory
    relative to its git repository's root. Archiving compares the recorded
    directory, so `ash report` on another host, or on a merge's output, archives
    what the scan would have. No directory is recorded, and nothing is archived, for a
    repository below another one (a submodule, a nested clone, a repository
    under an enclosing one), locally and in container mode; for a container-mode
    scan of a directory outside a git repository; for a scan the legacy `./ash`
    or `Invoke-ASH` wrapper starts; or for `ash merge` over shards that recorded
    different ones. A linked worktree inside its own checkout keeps its label.
    `GIT_CEILING_DIRECTORIES` changes this only for a repository whose enclosing
    one neither tracks it nor lists it as untracked, such as a checkout in a home
    directory kept in git that ignores it; a submodule or a nested clone below a
    ceiling still records no directory.
    With archiving on, such results print a notice to stderr, once, at any log
    level, saying nothing is archived and why.
  See docs/content/docs/plugins/aws/security-hub-reporter.md.

- **A converter whose `convert()` requires an argument is refused before it runs.**
  ASH calls `convert()` with no argument. A converter written to
  `convert(self, target)`, the signature `ConverterPluginBase` declared before,
  failed with "missing 1 required positional argument"; it now fails before the
  call, and its row names the converter and says to declare `convert(self)` and
  read its inputs from `self.context.source_dir`.

- **A key at a plugin's section level, beside `enabled`, now refuses the
  configuration with exit code 3.** A section declares `enabled`, `options`, `name`
  and, for a reporter, `extension`; any other key there was kept and never read, so
  `scanners.bandit.severity_threshold: HIGH` beside `enabled: true` loaded and bandit
  gated at the global threshold. **Configs written from the old docs, which showed
  options at the section level, stop loading until the key moves under `options`.**
  The error says so: `scanners.bandit.severity_threshold is not a section-level key;
  move severity_threshold under options`; a key that is not an option is named as
  unknown. `tool_version`, `install_timeout` and a scanner's `extension` at that
  level are refused as internal-only fields rather than options to move, since
  moving a leaked `tool_version` under `options` would pin the tool's version:
  `Scanner 'bandit' contains internal-only field 'tool_version' - this should not
  be in user configs`. Where the plugin declares an option of that name (bandit,
  checkov, semgrep, jupyter, ferret-scan), the message adds `if you meant a version
  constraint, put it under options`. The scan and `ash config validate` print the
  same message, and `ash config lint --fix` removes them, except a `tool_version`
  or `install_timeout` that is neither null nor equal to the plugin option's
  default, which may be a pin and is left for a hand edit. A field an `extends`
  base sets stays an issue that blocks the scan, since --fix edits only the linted
  file. `ash config validate` says `lint --fix` removes them only when it does: not
  for a pin it keeps, a section whose plugin is not loaded, or a TOML file or one
  that reads the environment, which --fix does not rewrite. A scan, a workspace project's config, the MCP config tools and
  `ash config validate` refuse it the same way; for a plugin loaded from
  `ash_plugin_modules`, the scan checks the section once the plugins are loaded. A
  results file written with such a key still loads, with a warning.

- **snyk-code tests a copy of the scan set, not the source directory.**
  `snyk code test` has no option that leaves a path out, so ASH now runs it on a
  temporary copy without the files under `global_settings.ignore_paths`, the files
  the scan set excludes, ASH's output directory apart from the files git tracks
  there, symlinks, files with more than one hard link, and paths outside the
  scanned tree. The copy has no `.git` directory, so ignores managed in the Snyk app
  may stop applying and a finding ignored there can be reported again; suppress it
  in ASH's configuration instead. When none of the files it would send could be
  copied (each was a link, a hard link, outside the tree or unreadable), when the
  copy cannot be written, or when `TMPDIR` is inside the scanned or the output
  directory (a CI job that points `TMPDIR` into its workspace hits this on
  upgrade), snyk-code reports ERROR and the scan exits 1 as incomplete. See
  [What ASH sends to Snyk](docs/content/docs/plugins/community/snyk-plugin.md#what-ash-sends-to-snyk).

- **An ignore path names an archive member in the scanned tree's terms.** A
  member was extracted to `archive/<the archive's folded name>/<member>`, and
  only that path matched an ignore path, so `bundle.zip/vendor/m.js` let a member
  of `bundle.zip` through, and the folded name followed the directory ASH ran
  from (`archive/src__bundle__zip/...` from the parent, `archive/bundle__zip/...`
  from the tree), so a pattern written for one missed the other. The archive
  converter now leaves out a member an ignore path names by the archive's path
  and then the member's, as if the archive were a directory
  (`lib/bundle.zip/vendor/m.js`, `lib/bundle.zip/vendor/**`): no scanner reads
  it, and snyk-code's copy cannot upload it. A pattern that matches at any
  depth, such as `**/vendor/**`, now also leaves out the members under a
  `vendor/` in an archive. A path in the tree names no member, so `vendor/**`, or
  an ignore path for the file `lib/vendor/m.js`, keeps `lib/bundle.zip`'s
  `vendor/m.js` in the scan.

- **A relative `ASH_BIN_PATH` is no longer searched for tools.** It was read
  against the working directory, usually the repository being scanned, so with
  `ASH_BIN_PATH=bin` a repository that committed `bin/grype` had that file run as
  grype. Tool lookup, the scanner sandbox's tool paths and the check that skips an
  already-installed pinned tool now leave it out, and the run's `ash.log` gets one
  warning naming the value. A scan whose tools were only there reports them
  MISSING and exits 1, and the incomplete-scan message names the relative value;
  set `ASH_BIN_PATH` to an absolute path. Related changes:
  - A blank value, meaning empty or whitespace in every part (` `, ` /`), is no
    value. A blank `ASH_BIN_PATH` means `~/.ash/bin`, and a blank `--bin-path` is
    the same as none, so the install uses `ASH_BIN_PATH` when that is set. Either
    used to name the working directory, or a directory called ` ` in it.
  - `ash dependencies install` creates the bin directory and exports `ASH_BIN_PATH`
    to its own commands as an absolute path, and prints each command it runs on one
    line. Building opengrep's download command no longer creates the directory.
  - An install command a plugin declares that runs uv (`uv`, `uv.exe`, `uv.cmd`,
    `uv.bat`, or `python -m uv` in any spelling), other than `uv tool` and `uvx`,
    runs with `UV_NO_CONFIG=1`, so the scanned repository's `uv.toml` and
    `[tool.uv]` cannot choose what it installs.
  - ASH runs the uv installed with it, the one its install pins
    (`uv>=0.13.4,<0.14`): beside the interpreter that runs ASH, in that
    interpreter's scripts directory, or where the `uv` package keeps its
    executable. Only when none came with ASH does it use a uv on `PATH`, then one
    in the ASH bin directory or, except on Windows, `/usr/local/bin`. That holds
    for every uv ASH starts: a scanner's `uv tool run`, the uv commands of
    `ash dependencies install` and the check for a pre-installed tool. A pipx or
    `uv tool` install, or a virtual environment that is not activated, keeps its
    uv off `PATH`; ASH finds it beside the interpreter.
  - `uv cache dir`, which ASH runs to report the cache, runs from the filesystem
    root (the system drive's root on Windows) without `UV_PROJECT` or
    `UV_WORKING_DIR`, so a `uv.toml` in the repository or in a shared temporary
    directory cannot name the cache. The documented cache recipes do the same.

- **An empty or relative `HOME` gives ASH no `~/.ash/bin`.** An empty `HOME`
  names the filesystem root, and a relative one a directory under the working
  directory, usually the repository being scanned. With `ASH_BIN_PATH` unset as
  well, ASH has no bin directory: tool lookup searches none, `ash dependencies
  install` without `--bin-path` exits 3 before it installs or creates anything and
  says why, and a plugin's install command (a pinned tool, an opengrep download,
  cfn-nag's gem install) only refuses, naming `--bin-path`. A sandbox probe is given
  `HOME` only when it is absolute, and the install's hint about `ASH_BIN_PATH` is
  shown when there is no `~/.ash/bin` a scan would search. One warning per value
  names the variable to set. The cfn-guard rules directory is kept beside the bin
  directory unless `ASH_CFN_GUARD_RULES_DIR` names one, so with neither there is
  nowhere to look for the rules: cfn-guard is reported as missing with that reason
  instead of failing on an `AttributeError`, and its sandbox is given no rules
  directory, with a warning.

- **Offline, a tool install downloads nothing.** With `ASH_OFFLINE` set (as
  `--offline` sets it), a pinned binary (grype, syft, opengrep and the others) or a
  configured-version opengrep that is not installed is refused, with the reason,
  instead of fetched from its release URL. An installed copy or a verified copy
  already present is used as at any other time, and a verified copy in the
  release-asset cache (`ASH_TOOL_DOWNLOAD_CACHE`) is installed from there.

- The MCP `get_config` tool shows a value its config files read from the server's
  environment as `<from ${VAR:default}>`, the reference as the file writes it,
  instead of the value, in the resolved config and in the `ASH_CONFIG` defaults:
  at the place the file wrote the reference, a short value too, and in a list at
  that one entry, so a string elsewhere that equals a value, one a client wrote
  say, is shown as written. With
  `raw`, it returns the file as written, references unresolved, and each value
  the loader would read from the environment comes back as `!ENV ` followed by the
  reference, so it can be told from a string that only looks like one: a TOML
  file was returned with its references resolved, and any other file was read as
  YAML, so `ash.TOML` came back as one string and a file with an `!ENV` tag or a
  tab-indented JSON file failed.

- `AshConfig.from_file` raises `ASHConfigValidationError` for a file the model
  refuses, where it raised pydantic's `ValidationError`; `ASHConfigValidationError`
  is now a `ValueError`, as `ValidationError` is, so `except ValueError` still
  catches it. Its message is the redacted description `ash config validate` prints,
  and the pydantic error is on its `validation_error` attribute rather than chained:
  every error that describes one is raised `from None`, because a traceback, and
  the MCP server's `logger.exception`, printed the chained error's `input_value`.
  An `ASH_CONFIG` file that does not parse makes `ash scan` exit 3, as one the
  model refuses does, where it exited 1 with "Unexpected error in resolve_config".
  `ash report --config <file>` likewise exits 3 for a named file that does not
  parse, where it rendered the reports with the default configuration (exit 0).
  With `--config` naming another file, `ash config validate`, `lint`, `get`,
  `validate-plugin-dependencies`, `ash report --config` and the MCP
  `validate_config` tool also refuse, exit 3 or an invalid result, when the
  `ASH_CONFIG` file is one a scan refuses, and name that file; they called the
  named file valid, or blamed it. `ASH_CONFIG` naming a directory is refused the
  same way, exit 3, by the scan (which exited 1 with an `IsADirectoryError`
  traceback) and by `get` and `validate-plugin-dependencies` wherever the named
  file is (they called it valid when that file was outside the source directory).
  A config path that is not a regular file, as `--config` or `ASH_CONFIG`, is
  refused before it is opened, exit 3: a FIFO left `ash config validate`, `lint`
  and `get`, and a container-mode scan, waiting for ever, and `/dev/null` read as
  an empty config. So is one a command edits: `ash config update`, the wizard,
  `init --force` (which opened a FIFO for writing), the inspect app's added
  suppression, and the MCP `get_config` tool with `raw`, which also reported a
  directory as an internal error. The lines that name the config's path print it
  on one line, a newline in it written as `\x0a`: that refusal, the
  "Validating/Linting configuration file" header, each error `ash config
  validate`, `get` and `validate-plugin-dependencies` list, lint's issues and
  its refusals to rewrite a TOML or
  JSON file, `validate-plugin-dependencies`' verdict, the log line naming the
  file `ASH_CONFIG` names, and `ash report`'s warning for a `--config` that does
  not exist. The TOML refusal now says that `--fix-unused` rewrites YAML only,
  and `--fix-unused`'s help names the TOML and JSON files it leaves alone.
  An `ASH_CONFIG` that names a file that does not exist is refused, exit 3, with
  "ASH_CONFIG names <path>, which does not exist". Where it was read as the
  configuration a run starts from, not as a `--config`, the run used the
  built-in defaults and reported success: `ash config validate`, `lint` and
  `get` checking another file, and a scan that names no config, such as the MCP
  server's. `ash report` exited 1 for it, and now refuses a `--config` that does
  not exist too; a scan, which already refused it, now says why in those words.
  An empty `ASH_CONFIG` still counts as unset; one of only whitespace is refused.
  The commands that check another config file read `ASH_CONFIG` wherever that
  file is: `ash config get`, `validate-plugin-dependencies` and `ash report
  --config` refused a missing, whitespace or dangling `ASH_CONFIG` only for a
  file inside the working directory.
  `ash plugin list` and `ash dependencies install` exit 3 with the scan's
  refusal for a configuration a scan refuses, the `ASH_CONFIG` file included,
  before loading any plugin: `plugin list` exited 1 and `dependencies install`
  raised the error. The MCP `get_config` tool returns an error result for it,
  where the error escaped the tool.

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
  - A directory install whose directory has since been deleted, or no longer holds
    ASH's source, is no longer `LOCAL`: the image installs the commit the package
    build recorded, or the release tag of the installed version, with a warning that
    this is a guess.
  - A commit id, given with `--ash-revision-to-install` or recorded by the package
    build, is built only if a branch or a tag of the ASH repository reaches it,
    because GitHub serves a commit that only a fork or a pull request holds under
    the ASH repository's URL too. Otherwise the Dockerfile's clone step stops with
    exit status 3, the image build fails, and `ash` exits with the build's status
    (1 for a failed `docker build`).
  - A Homebrew install builds its image from the commit the formula built (or the
    release tag of its version, with a warning, when Homebrew built it from a source
    tarball). The formula now deletes the `direct_url.json` that named its build
    directory, which another local account could recreate.
  - **Rebuild any image ASH v3.0.1 to v3.7.1 built in or under a project with its
    own Dockerfile.** For a `LOCAL` revision (an editable or directory install, any
    `file://` install record, and Homebrew before this release), v3.0.1 to v3.7.1
    built the Dockerfile of the directory they ran in, or else the nearest one above
    it with a `pyproject.toml` beside it. For a pinned revision, v3.2.3 to v3.7.1
    built the Dockerfile of the directory they ran in when a `pyproject.toml` was
    beside it, and never one above it. The image carries ASH's tag
    (`automated-security-helper:<target>`, or your `ASH_IMAGE_NAME`), and
    `--no-build` runs it. Remove it, run `ash build-image --force`, and push again
    any copy you host in a registry.
  See [Which ASH goes into the image](docs/content/how-to/run-in-a-container.md#revision).
- **Container mode always mounts the source directory read-only.** `ash --mode
  container`, `./ash` and `Invoke-ASH` used to mount `/src` read-write whenever the
  output directory was inside the source directory, which the default
  `.ash/ash_output` is, and the test was a string prefix, so a sibling such as
  `<src>-out` counted as inside too (`Invoke-ASH` matched a substring anywhere in the
  path). The output directory has its own mount at `/out`, so `/src` is now read-only
  in every case. See [Running a scan in a container](docs/content/how-to/run-in-a-container.md#scan-in-container-mode).
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
  A one-directory container scan marks a config from outside `--source-dir` that the
  scanned tree holds, or that a link there leads to (`--config-from-scanned-repository`),
  and the scan inside limits it as repository-written. A workspace scan inside the
  container refused that mark, so in workspace mode the host passed such a config
  unmarked, and the scan inside gave it the operator's grants (`sandbox.extra_read_paths`
  and the other sandbox settings). `ash --mode container --workspace` now marks each file
  of a config chain that is in another git checkout, such as an ops repository beside the
  workspace, with `--config-file-from-another-checkout`, and the workspace scan inside
  limits those files for every project and for the plan, as a local workspace scan does:
  the same five confinements and the same warnings. A file there cannot grant, and it is
  not a member of the workspace's tree. No file's `sandbox.mode` applies inside:
  container mode runs the scan there with `sandbox.mode=off` as the last override,
  because the container is the boundary. In a one-directory scan and a workspace scan
  alike, the scan inside holds that verdict as a mark on the mounted files, so its
  warnings give the reason the host's do. A config
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
  that is in the scanned tree on its own (`--config-file-from-scanned-repository`, by
  its path inside the container), and each base in another checkout with
  `--config-file-from-another-checkout`, in one-directory and workspace scans, and the
  scan inside applies the same split the host does. A config that is itself in the
  scanned tree is still marked with every file it extends, one in another checkout is
  marked file by file as in another checkout, and one outside every checkout with no
  base in one is not marked. The scan inside refuses a mark for a file that is not in
  the config's chain, without `--config`, or outside local mode, with exit 3. It reads
  each chain once for both file marks, and when both name files outside the chains, one
  message names both options.
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
- **A config file in another git checkout is limited inside a container as it is on the
  host, and an image built before this change refuses the new option.** Container mode
  marked a config file in any git checkout, the scanned one or another, as written by the
  scanned repository. A file in a checkout other than the scanned one, an ops or dotfiles
  repository say, is not the repository's, and on the host it cannot grant but still sets
  what only restricts: a lowered archive extraction limit, a scanner option that sends no
  usage data, and a `network_scanners` list as a limit. The scan inside dropped those from
  an `ASH_CONFIG` file in such a checkout. The host now marks each file of the `--config`
  chain and of `ASH_CONFIG`'s chain that is in another checkout, or that only a link in
  one leads to, with the hidden `--config-file-from-another-checkout`, by its path inside
  the container, and the scan inside limits it as the host does. A file already marked as
  the scanned tree's keeps that mark alone, and the mark carries no value, so it cannot
  carry a grant. The reason the scan inside gives for such a file says the host found it
  in, or reached it through a link in, a git checkout other than the scanned directory.
  The option is new to the image, so `ash --mode container --no-build`, or
  a run with an `ASH_IMAGE_NAME` image built before this change, with a `--config` or
  `ASH_CONFIG` chain that touches another checkout now exits 3 with the message to rebuild
  the image from this ASH; the same run used to start with the older mark. A config
  outside every checkout and one in the scanned checkout are marked as before. In a
  one-directory scan, a `--config` or `ASH_CONFIG` name whose link walk cannot finish
  is refused, not marked: `./ash` exits 3, `Invoke-ASH` refuses the `ASH_CONFIG` file,
  and `ash --mode container` refuses the name, each saying what could not be resolved,
  because none of them hands the container runner a name it cannot resolve. A file
  reached further down a chain, an `extends` base, whose name walk cannot finish is
  read as the scanned tree's, as on the host, and marked that way, so it has no mark
  of its own.
- **`./ash` and `Invoke-ASH` mark a config file in another git checkout, as
  `ash --mode container` does.** The two wrappers marked a config only when the scanned
  repository wrote it. A `--config` or an `ASH_CONFIG` file in a checkout other than the
  scanned one, an ops or dotfiles repository say, went to the scan inside as the
  operator's and kept its sandbox grants there, while a local scan and
  `ash --mode container` confine it. Both wrappers now judge the file as the launcher
  does: by its real path, by the name as written with each `..` applied the way the
  kernel applies it, and by the directory each link on the way sits in, looking at every
  directory up to the root for a `.git` that is a link, a file or a directory holding
  `HEAD` and, in a directory others can write, that root, the directory's owner or the
  user running the scan left. A file they find in another checkout is passed with
  `--config-file-from-another-checkout`. When `ls` or `id` cannot say who left an entry,
  or who can write its directory, and no checkout is found, the run is refused with exit
  3 and nothing starts, and the refusal names the entry or directory it could not read;
  a `.git` directory that cannot be searched counts, with a warning, as it does for a
  local scan. With `--no-build`, or with an `ASH_IMAGE_NAME` image built before this
  change, the scan inside rejects the option it does not know with its own usage error
  (exit 2) after the container has started, where `ash --mode container` stops earlier
  with exit 3 and the message to rebuild the image.
- **`./ash` and `Invoke-ASH` mark a `--config` reached through a link in a checkout.**
  A local scan, and `ash --mode container`, limit a config when a symlink its path
  follows sits in the scanned tree or in any git checkout, even though neither the
  path given nor the file it resolves to is in one: whoever wrote the link chose the
  file. A link in the scanned tree makes the config the scanned repository's, and a
  link in another checkout makes it a file in another checkout, which cannot grant
  either. The two wrappers checked only the path given and
  the resolved file, so a config named `ops/cfg.yaml`, linked to a link in the
  scanned checkout that leads to a file outside it, went to the scan inside unmarked
  and kept its sandbox grants there. Both wrappers now follow the path one component
  at a time, at most 40 links, once for both marks. They mark the file as the scanned
  repository's when a link on the way sits in the scanned tree, and with
  `--config-file-from-another-checkout` when none does and a link sits in another git
  checkout. A walk that stops (more than 40 links, a link that cannot be
  read, a directory that cannot be searched) with no checkout found in the links it
  did reach is refused with exit 3. A chain of links outside every checkout is used
  as before.
- **`Invoke-ASH` judges a config file beside a `.git` entry on PowerShell 7.0 to 7.2.**
  Those versions run on a .NET without `File.GetUnixFileMode`, and their items may
  carry neither `UnixMode` nor `User`, so `Invoke-ASH` refused every `ASH_CONFIG` file
  it mounted from a directory with a `.git` entry beside or above it as one it could
  not judge. It now reads the mode of the directory and the owners from `ls -ldn` and
  `id -u`, as `./ash` does, and still refuses, with exit 3, when neither the runtime
  nor those programs say.
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
  [Running a scan in a container](docs/content/how-to/run-in-a-container.md#scan-in-container-mode).
- **Container mode refuses a mounted path that `--mount` cannot carry.** A comma, a
  double quote, a carriage return or a line feed in the source or output directory, the
  config file or a file it extends, or the workspace policy now refuses the run with
  exit 3 before anything is built. `--mount` reads its value as comma-separated
  fields, so such a character was read as part of the mount options.
  A path holding a NUL byte, which only a caller of the API can pass, is refused
  the same way instead of raising `ValueError`, and `--no-run`, which mounts
  nothing, is not refused.
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
  cache, and the trivy cache the new trivy scanner adds (`/deps/.trivy`), are owned by
  the user the image runs as (root in `ci`, the unprivileged user in `non-root`),
  because their updates write them at scan time; in an offline image, which never
  updates them, they stay root's. A `non-root` image started under another UID than it
  was built with can therefore no longer update grype's database, and grype reports
  ERROR, failing the scan, where it used to write the shared cache; trivy's update
  fails the same way. `/src` and `/out` stay
  writable by every user in the `ci` stage, now with the sticky bit. Files an
  installer left writable by every user elsewhere in the image (uv's lock files at 666,
  some gems' files under `/var/lib/gems` at 777) lose group and other write too. See
  [Who can write to the image's directories](docs/content/how-to/run-in-a-container.md#mounts).
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
  [Config files in delivered source](docs/content/how-to/mcp-server.md#what-a-delivered-config-cannot-set).

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
  [A patched value is the client's](docs/content/how-to/mcp-server.md#what-a-delivered-config-cannot-set).

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

- **An MCP client cannot configure trivy or zizmor.** `/scanners/trivy/**` and
  `/scanners/zizmor/**` join the denials every profile keeps, beside
  `/scanners/trivy-repo/**`: trivy sends usage data to Aqua when `disable_telemetry`
  is false, and zizmor's online audits send the workflows' action references to the
  GitHub API with the token in ASH's environment. A client can no longer turn either
  on or off or change its options; the operator's own configuration is unchanged.
  actionlint, cfn-lint, cfn-guard and gitleaks send nothing off the host and stay
  tunable, within the profile's `denied_paths`.

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
  `--config-overrides` or an ASH config file outside every git checkout and the
  scanned directory:
  - actionlint runs with an empty config ASH writes, not `.github/actionlint.yaml`;
  - cfn-lint runs with an empty config ASH writes, not a `.cfnlintrc` in the
    repository or the home directory, and in a new, empty, private directory
    outside the scanned tree, so a relative path in an operator's `.cfnlintrc`
    names nothing;
  - gitleaks runs with its default rules, not `.gitleaks.toml` or
    `.ash/.gitleaks.toml`, and ASH re-scans each file a root `.gitleaksignore`
    names (gitleaks always reads that file), from copies it makes outside the
    scanned tree and removes when the run ends, and reports what it dropped;
    `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` from the environment still apply
    outside `--sandbox`;
  - zizmor runs with `--no-config`, not `zizmor.yml` or `.github/zizmor.yml`;
  - trivy runs with empty config, ignore and secret-config files, not
    `trivy.yaml`, `.trivyignore` or `trivy-secret.yaml`, and with an empty
    `--module-dir`, so it loads no WASM module from `~/.trivy/modules`.

  Each of those scanners' `config_file` options and gitleaks' `baseline_path`, set
  by a repository-written ASH config, are ignored with a warning (a config an MCP
  client delivered that sets one is refused, as a default `denied_paths` entry),
  and so are trivy's and trivy-repo's `ignore_file` and
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
  is given copies of the files ASH read, written outside the scanned tree in the
  same per-run directory as the config files ASH writes for a tool. gitleaks runs with
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
  or a config file outside every git checkout and the scanned directory, for paths
  outside the scanned tree, and are ignored with a warning otherwise.

- **A repository-written config file can no longer choose where ASH installs a
  tool from, what it imports, or what it hands a scanner as its own
  configuration.** It applies to a discovered `.ash/.ash.yaml`, a `--config` path,
  an `extends` base, or `ASH_CONFIG`, when the file is repository-written (defined
  below):
  - `tool_version` (bandit, checkov, semgrep, ferret-scan, the jupyter converter)
    must be a PEP 440 version specifier set such as `>=1.2,<2`, from any source.
    Any other value is replaced by the default, with a warning naming the key and
    not the value, which `ash merge` prints for a shard's config.
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

  Each value that is not honored is logged once as a warning naming the key. See
  [Settings a repository's config cannot choose](https://awslabs.github.io/automated-security-helper/concepts/trust-model/#denied-settings).

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
  [Failing on a stale content database](docs/content/how-to/troubleshoot.md#a-content-database-is-stale).

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
  Guard Rules Registry bundle in `RULES_BUNDLES`, the license files, the cfn-nag gem
  and the Bundler the image installs it with) with its upstream's latest release and
  fails when one is behind, listing every
  value the bump has to change: the module's entries, the Dockerfile ARG, and each
  tracked file that repeats one of the pin's digests. A gem is compared with the newest
  release whose required Ruby version admits the Ruby the image installs (the
  Dockerfile's `ruby=` apt pin); a newer release that needs a newer Ruby is named in
  the report and does not fail it. A license entry that no download pin names is
  refused rather than reported with part of its steps. It sends the job's
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
  Other lockfiles are still audited. Offline, npm-audit does not run at all; see
  "npm-audit does not run offline" below. Pass `--no-fail-on-incomplete-scanners` to
  accept the partial scan.

- **npm-audit now reports yarn findings, and a failed yarn audit is ERROR.** A project
  with a `yarn.lock` always came out of npm-audit PASSED with 0 findings and exit 0,
  whatever its dependencies held. It now reports yarn's advisories as findings, so a
  vulnerable yarn project fails the scan (exit 2) the way an npm one does, and a yarn
  audit that could not get advisories reports ERROR and the scan exits 1 as incomplete.
  Under yarn 2 and later, npm-audit now runs `yarn npm audit --recursive`. Offline,
  npm-audit does not run at all; see "npm-audit does not run offline" below.

- **npm-audit does not run offline, and a scan with a lockfile to audit exits 1.** npm,
  yarn and pnpm audit a lockfile by asking the registry for its advisories; offline,
  `npm audit --json --offline` reads none, prints `"vulnerabilities": {}` and exits 0
  (npm 10.9.4, on a lockfile pinning lodash 4.17.15), and ASH graded that `PASSED`
  with exit 0. yarn and pnpm failures offline were logged as warnings and passed the
  same way. Offline, npm-audit is now `MISSING`, with the reason, for a project with a
  lockfile beside a `package.json`, and the scan exits 1; for a project with none it is
  `SKIPPED`. Pass `--exclude-scanners npm-audit` to scan such a project offline. The
  offline strategy the MCP `list_scanners` tool reports for it is now `skip_offline`
  (it was `cache_flags`), as snyk-code's is. Online, a `yarn.lock` or `pnpm-lock.yaml`
  whose package manager is not installed was skipped with a warning and the scan
  passed. It is now a failed target named in the scanner's errors: the other
  lockfiles' findings are kept, the scan exits 1 with npm-audit listed as incomplete
  ("1 of 2 targets unevaluated"), and npm-audit is `ERROR` when no lockfile could be
  audited.

- **`--python-only` leaves the non-Python scanners out before ASH looks for their
  tools, and only the Python-only scanners run or count.** `--python-only`
  (`--python-based-plugins-only`) used to be applied after the tool check, so on a
  host without cfn_nag, grype, npm, opengrep or syft those scanners were reported
  `MISSING` and the scan exited 1, although the option had left them out. They are now
  `SKIPPED`, and only bandit, checkov, detect-secrets and semgrep run or count toward
  the completeness gate. snyk-code, ferret-scan and cdk-nag used to count as
  Python-only because they declare no dependencies, although they run the Snyk CLI, a
  Go binary and Node.js; they no longer do. A third-party scanner counts only when it
  declares `python_only: ClassVar[bool | None] = True` or runs its tool through uv, so
  an in-process third-party scanner that declares nothing is now left out (see
  "Declaring whether a scanner is Python-only" in the scanner plugin guide). A
  Python-only scanner whose tool is absent is still `MISSING`. `ash merge` of a sharded
  `--python-only` scan no longer warns that no shard intended to run each non-Python
  scanner and advises checking `--scanners` and `--exclude-scanners`; it names the
  scanners `--python-only` left out at INFO, and still warns about a scanner no shard
  selected for another reason. Each shard records whether it ran with `--python-only`
  (`metadata.shard.python_only`), and when the shards disagree the merge still warns,
  naming the scanners that ran nowhere because only some jobs passed the flag.

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
  [Which scanners run offline](https://awslabs.github.io/automated-security-helper/how-to/run-offline/#scanners).
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
  installed from its pinned release asset (0.13.4), verified against its SHA256,
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
  - a scanner that ran but could not evaluate part of its input fails it, reported
    with `(n of m targets unevaluated)` beside its status — the partial-coverage arm
    of the same function, and the arm most likely to be new to an existing scan;
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
  [A Scanner Is ERROR With an Exit Code It Does Not Accept](docs/content/how-to/troubleshoot.md#a-scanner-is-error-with-an-exit-code-it-does-not-accept).

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
  some of its targets used to keep whatever status the severity gate gave it —
  `PASSED` or `FAILED`, decided only by what the targets it *did* read contained —
  because `determine_status` returned `ERROR` only once
  `targets_failed >= targets_attempted`. Neither value said anything about the
  targets that went unread, so the flag reported total coverage loss and stayed
  silent on partial loss, which is the more common case and the one operators turn
  it on to catch. A scanner that lost some targets now grades ERROR, or FAILED when
  the surviving findings fail the gate (see the gate-first entry under Behavior
  changes), and the incomplete-scan gate lists it either way.

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

  This flag does not itself change a scanner's status; the gate-first change under
  Behavior changes does, with no flag to opt into. Read the two together.

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

- **ASH no longer scans its own output.** The scan's output directory, and
  `.ash/ash_output` under the scanned directory and under the directory ASH runs
  from, are left out whether or not an ignore file lists them; a second scan used to
  report the first one's reports and results as findings. In a git checkout, regular
  files committed to one of those directories are still scanned, the scan's own
  output directory included, and ASH warns that its output directory holds committed
  files; a committed link there is not taken, wherever it points. Outside a git
  checkout, or when git cannot list the repository, only the scan's own output
  directory is left out: an earlier run's `.ash/ash_output` is scanned like the rest
  of the tree, since leaving it out hid every file in it from every scanner. While the
  scan set still holds files in it, each scan warns once, naming it and saying how to
  leave it out: delete it, or list it in an ignore file such as `.gitignore`. Adding it
  to `global_settings.ignore_paths` leaves its findings out, but the warning repeats
  until the directory is deleted or an ignore file lists it. The output directory is
  recognized when it or the scanned directory is given through a link above the
  tree, as `/var` is on macOS; compared as spelled, it was not, and ASH's own
  `ash.log` went to the scanners. A directory that only holds files like ASH's
  output, such as another shard's results, is scanned, with a warning. Each scanner
  told to skip one of those directories gets its path escaped in the tool's
  own pattern syntax, so an output directory named `out[1]` is skipped and a source
  directory `out1` beside it is not. An output directory holding a committed file
  still has `analysis/`, `reports/`, `scanners/` and `converted/` skipped, each that
  holds no committed file: one committed README turned off every exclusion for the
  whole directory, and syft, whose SBOM nothing filters afterwards, cataloged ASH's
  own files there. On macOS and Windows a scan-set entry is matched with an output
  directory without regard to case. In a workspace scan, the workspace's output
  directory is left out of each project's scan like the project's own: a project at
  the workspace root scanned the unified results and the other projects' reports of
  the same run.

- **A scan no longer deletes files committed to git in its output directory.** When it
  started, a scan deleted `ash_aggregated_results.json`, `ash-ignore-report.txt` and
  `ash-scan-set-files-list.txt` from its output directory, cleared `analysis/`,
  `reports/`, `scanners/` and `converted/` there and truncated `ash.log`, whatever git
  said, so with the default `.ash/ash_output` a file a repository committed to one of
  those paths was deleted or emptied in the working tree. A scan now exits 3 before it
  deletes or writes anything when git tracks a file at one of those paths, at
  `ash-scan-set-run.json` or `ash.log.jsonl`, or where an MCP scan sets the previous
  results aside (`.ash_previous_results/`, `.ash_previous_results.partial/` and the
  `.ash_previous_results_restored` marker), and names it; move it, or pass
  `--output-dir`. The same holds when git tracks the output directory itself as a
  link: `.ash/ash_output` committed as a link to the repository's `src` had a scan
  clear `src/reports`. The check runs before the logger opens `ash.log`, before container
  and Nix mode clear the output directory on the host, and before the MCP tools set
  the previous results aside, and the refusal is printed as `ERROR (3) Scan refused`.
  When git cannot list the repository the output directory is in (git is not
  installed, it times out, or it fails on the repository, as for a `.git` file naming
  a directory that is not there), nothing tells a committed file from a previous
  run's, so any file at one of those paths stops the scan the same way; the message
  names git's error and says to let git read the repository or remove the old
  results. On macOS and Windows a name is matched without regard to case, as their
  filesystems match it, so a committed `Reports/x.md`, which clearing `reports/`
  removed, stops the scan too. A workspace scan checks the unified results file and `reports/` at the root of its
  output directory and every project's `projects/<key>/`, before any project starts: a
  file committed in one project's output refuses the whole workspace with exit 3, so no
  project runs, where before only that project failed. A
  report over existing results (`--use-existing`) is stopped only where it writes: the
  results file, the logs, `reports/`, and `analysis/` with `--inspect` or `converted/`
  with `--cleanup`. ASH does not write this run's results under another name instead,
  because `ash report`, `--use-existing`, container mode and the MCP server all read
  `ash_aggregated_results.json` where it is; `ash report` writes nothing and still reads
  that file. Committed files elsewhere in the output directory were never touched and
  stop nothing. A workspace scan's unified results file and reports replace a link at
  their names instead of writing through it.

- **A scan reads back only the scan-set list it wrote.** The scan set is written to
  `ash-scan-set-files-list.txt` and `ash-ignore-report.txt` in the output directory, and
  the scanners and converters read it back from there. They read whatever pair they
  found, so one an earlier run left, or one a repository committed to
  `.ash/ash_output`, decided which files they were given: a committed list naming one
  file made detect-secrets scan that file alone. Each scan now has a run ID, written
  with the SHA-256 of both files to `ash-scan-set-run.json` beside them, and the pair is
  read back only by the scan that wrote it, while both files are as written. Anything
  else walks the tree again.

- **`ash merge` warns about a scanner that ran on no shard only when some job's
  selection asked for it.** Each shard now records, as `intended_scanners` in its
  shard provenance, every scanner its `--scanners`, `--exclude-scanners`,
  `--python-only` and each scanner's `enabled` setting ask for. A scanner no job
  asks for, such as one left out of the same `--scanners` list on every job, is
  logged at verbose level instead. If any shard was written without the field, the
  previous warning, which names every scanner no shard ran, still applies. These
  lines, and the one naming the scanners `--python-only` left out, keep a shard's
  scanner names on one line, with a newline or a terminal control in one written
  once as its escape, and read no markup in them. **An
  earlier release cannot read the results of a sharded scan by this one:** its
  results model rejects the new field, so its `ash merge` stops with `Could not
  read shard results from <file>` and `metadata.shard.intended_scanners: Extra
  inputs are not permitted`. Merge with the release that ran the shards, or a later
  one.

- **A `--source-dir` that names no directory to scan is refused the same way
  everywhere.** A missing path, from `--source-dir` or `ASH_SOURCE_DIR`, used to be
  scanned anyway: every scanner found no files and the run could exit 0, the same
  answer as a clean scan of the directory you meant. `ash scan`, `./ash`, `Invoke-ASH`
  and the `ash config` commands that take `--source-dir` (`get`, `validate`, `lint`,
  `validate-plugin-dependencies`) now refuse it before anything runs with exit 5, the
  usage-error code, and one text per case: `Source directory does not exist: <path>`,
  `Source directory is not a directory: <path>` or `Source directory cannot be
  entered: <path>`. `./ash` and `Invoke-ASH` exited 3 for these, with texts of their
  own, and the `ash config` commands did not check the directory at all: they reported
  "No config file found in" a directory that did not exist. An `--output-dir` that is
  a file, that cannot be created, or that is there but cannot be entered or written
  is refused the same way, with `Output directory is not a directory: <path>`,
  `Output directory cannot be created: <path> (<reason>)`, where the reason is the
  system's own text such as `Not a directory` for a file on the way to it, `Output
  directory cannot be entered: <path>`, or `Output directory cannot be written:
  <path> (<reason>)`, found by making a file there and deleting it, so a read-only
  mount reads as `Read-only file system`: `ash scan` ended in a traceback for each,
  and `./ash` and `Invoke-ASH` exited 3 with texts of their own, or for one that
  cannot be written, mounted it and let the scan fail inside the container. A missing `--output-dir` is still
  created. The MCP scan tools, `scan_directory` and
  `run_ash_scan`, refuse a source directory with the same three texts, `error_type`
  `source_dir_not_usable` and exit code 5. They reported a missing directory or a
  file as `Directory not found or not a directory: <path>`, and a directory that
  cannot be entered as an unexpected error, exit 1, once its `.ash/ash_output` could
  not be created. Both tools refuse an `.ash/ash_output` that is a file with `Output
  directory is not a directory: <path>`, `error_type` `output_dir_not_usable` and
  exit code 5, before the scan is registered; the registry refused it as `Not a
  directory: <path>`, exit 1. `run_ash_workspace_scan` refuses a file at its output
  directory or at a project's `projects/<key>` the same way, before any project is
  registered; it reported the `NotADirectoryError` of creating the projects'
  directories, or the registry's refusal, exit 1. An output directory that cannot
  be created, such as one under a `.ash` or a `projects` that is a file, is refused
  by all three tools with `Output directory cannot be created: <path> (<reason>)`,
  `error_type` `output_dir_not_usable` and exit code 5, before anything is
  registered when a file on the way shows it, and when the directory is made
  otherwise, with the scan's claim given back. They reported it as an unexpected
  error, exit 1.

- **`ash scan --use-existing` with no existing results exits 1 with a message.** It
  raised an uncaught `ValueError` and printed a traceback. It now names the
  `ash_aggregated_results.json` it looked for, on stderr, and exits 1, like the other
  refused invocations above.

- **`ash config get` exits 3 on a configuration file that does not parse.** A file
  with a YAML or JSON syntax error used to be logged and replaced by the default
  configuration, so the command exited 0 and printed the defaults as though they
  were the file's contents. It now prints `Invalid configuration: <path> could
  not be parsed (<error type> at line L, column C)` and exits 3, the code for an
  invalid configuration and the one it
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
- **`ash get-genai-guide` writes the guide of the installed version, without the
  network.** The wheel and the sdist now carry the guide, and so do the container
  images built from a checkout (`.dockerignore` keeps the guide in the build context).
  An install made from a wheel had no copy, so the command downloaded the `main`
  branch's guide from GitHub, which describes whatever `main` says, and failed on a
  host without network access. An installation with no copy now exits 1 and names
  `--from-github`, which still downloads the guide from `main` or from the branch or
  tag `--branch` names.
- **The first image build of each UTC day rebuilds the `core` stage from its
  `apt-get upgrade` step down, so `./ash` and `Invoke-ASH`, offline included, need
  network access then.** Every entrypoint passes the day on every build, online or
  offline, and that first build of a new day re-runs the OS package upgrade and every
  step after it in `core`: the scanner tool installs, the ASH package and, for an
  offline image, the download of a current grype database and current rulesets.
  Rebuilds later the same day stay cached. With `--force` every build re-runs all of
  it. So OS packages and offline databases are at most a day old when built. `./ash`
  and `Invoke-ASH` build the image before every scan unless told not to, and used to
  reuse the OS packages and offline databases of whichever build filled the cache,
  however old. `ash build-image` and `ash scan --mode container` used to re-run the
  whole stage on every build; they now rebuild it once a day like the others. On a
  host without network access, pass `--no-build` (`-NoBuild` to `Invoke-ASH`) to scan
  with the image already there.
- **Container mode warns when a config asks for a sandbox it does not apply.** The scan
  inside the container still runs its scanners unsandboxed, with the container as the
  boundary, but `sandbox.mode` in a config file or a `--config-overrides` value now gets
  a warning that says so, and the scan runs; it used to be dropped with no message. The
  warning is printed on stderr, not logged, so `--quiet` and `--log-level ERROR` do not
  hide it.
- **`./ash` and `Invoke-ASH` turn a configured sandbox off inside the container.** As
  `ash scan --mode container` does, they run the scan in the container with the sandbox
  off: they give it `--sandbox off`, which the scan applies after every
  `--config-overrides` value, so a `sandbox.mode` from a config file, a
  `--config-overrides` value or a `--cli-json-input` document's `sandbox` no longer
  reaches it. A document's own `config_overrides` still apply. The flag goes right
  after the command, ahead of the caller's words, so a `--` or a value-taking option
  left last cannot turn it into an argument. They used to pass the
  mode on, and the scan tried to sandbox its scanners inside the image. Only `scan`
  (also when no command is named) takes `--sandbox`; other commands, such as
  `build-image` and `report`, are given nothing. The command is the first word that
  names one, not counting a root option's value, so `--phases inspect` or
  `--config config` still scans with the sandbox off.
- **`./ash` passes the image name and the build target as one argument each.**
  `ASH_IMAGE_NAME` and the `--build-target` value, which names the default image, were
  expanded unquoted into the build and the run. A value with spaces gave the container
  runtime options of its own, or gave the scan in the image words the `--sandbox`
  refusal never checked. An image name that starts with `-` is an option to the runtime
  even as one argument, so both wrappers refuse one, and an image name may now hold
  only A-Z, a-z, 0-9 and `. _ : / @ -`: `./ash` refuses any other `ASH_IMAGE_NAME`
  and `Invoke-ASH` any other `-AshImageName`, with the same message. `./ash` also
  refuses a `--build-target` that starts with `-` or holds a character other than
  A-Z, a-z, 0-9 and `. _ -`, which is not a Dockerfile stage, and both wrappers hold
  `ASH_BASE_IMAGE_OVERRIDE` to the image-name characters (`./ash` when it builds,
  `Invoke-ASH` when it starts): `python:3.12 --network=host` gave `./ash`'s build an
  option of its own. Each is refused with exit 3 before anything is built. The
  characters are spelled out, so the match is the same in every locale: whitespace
  of every kind (U+00A0, U+0085 and U+2028, which bash's `[[:space:]]` and .NET's
  `\s` had disagreed on), any non-ASCII letter, and the Kelvin sign that a
  case-insensitive `[A-Za-z]` would take for `K` are all refused by both.
- **`ash scan --mode container` holds `ASH_IMAGE_NAME` to the same characters.** It
  passed the variable to the build and the run as it was. A name that starts with `-`
  or holds a character other than A-Z, a-z, 0-9 and `. _ : / @ -` is now refused with
  the wrappers' message and exit 3, before anything is built or run, so the three
  entrypoints take and refuse the same names. An empty `ASH_IMAGE_NAME` names the
  default image, as it does in both wrappers. When it builds, it holds
  `ASH_BASE_IMAGE_OVERRIDE` to the same characters, with the wrappers' message and
  exit 3, before the build starts. A value of only whitespace is refused too, as both
  wrappers refuse it; only an empty one is unset and redirects nothing. Both refusals
  write a tab, a newline or a carriage return in the value as `\x09`, `\x0a` or
  `\x0d`, as ASH's other one-line messages do, so each stays one line and a space
  and a tab are shown apart.
- **`./ash` and `Invoke-ASH` carry `ASH_CONFIG` into the container for a scan, and
  warn when they do not.** The scan in the container sees the host only through its
  mounts, so a host path in `ASH_CONFIG` named nothing there and the scan ignored the
  file with no message. For a scan (no subcommand, or `scan`) both wrappers now mount
  the file read-only, or read it through the source directory's mount when it is
  inside the source directory, and give the scan its container path. A missing or
  unreadable file, an outside file with an `extends` entry, and a file named inside
  the scanned tree that a link leads out of are refused with exit 3 before the build.
  For any other subcommand they print one warning naming the variable and do not pass
  it. None of this applies under `--no-run` (`-NoRun` to `Invoke-ASH`), when no
  command will run. `Invoke-ASH` passes `-Config` as the path given. Like `./ash`, it
  also carries a set `ASH_CONFIG` beside `-Config`: the file is mounted and named to
  the scan as the host's config, and it is the scan's `--config` only when `-Config`
  is not given. `Invoke-ASH` resolves the `ASH_CONFIG` string as written, so a `..`
  after a link steps out of the link's target as the kernel steps, and refuses a path
  that is not a regular file (a FIFO or a device) before opening it, with the message
  for a missing file. A mounted file the scanned repository wrote is passed with the
  marks that tell the scan so.

- **`ash scan`'s end-of-run messages and help describe what the scan does.** The
  incomplete-scan message said to "drop --fail-on-incomplete-scanners", a flag that
  is on by default, so dropping it changed nothing; it now names
  `--no-fail-on-incomplete-scanners`. That flag's help on `ash scan` and `ash merge`
  said both that it defaults to on and what happens "without this"; it now says it
  is on by default and what turning it off does. The exit-code legend printed after
  a scan that exits 2 listed codes 0, 1 and 2; it lists all six, 0 to 5, from
  `ASH_EXIT_CODES`. Code 2's meaning there, in the `ash://exit-codes` MCP resource
  and in the MCP tools' `exit_code_meaning` now reads "actionable findings at or
  above threshold", which is what the gate checks; it said "above". The `--mode`
  help said precommit runs Python-based plugins only;
  it now names the five scanners precommit runs (bandit, detect-secrets, checkov,
  cdk-nag and npm-audit) and describes `nix` mode. The guides no longer say that
  local mode runs only Python scanners or that precommit scans only staged files,
  and the CLI reference no longer says that `--mode precommit` limits a workspace
  scan to changed files.
- **Report paths in the scan summary use one rule.** The "Next steps" paths were
  relative to the source directory while the metrics table printed just above them
  was relative to the working directory, so the two named the same directory
  differently whenever you scanned another directory. Both are now relative to the
  working directory, or absolute when the path is outside it, and so are the paths in
  the workspace scan summary, which were always absolute. The metrics legend no
  longer offers a `(s)canner` threshold source, which no row ever showed, and the
  `--config-overrides` help links the configuration guide on the documentation site
  instead of naming `docs/config-overrides.md`, a path that is in neither the
  repository root nor an installed ASH.
- **`./ash` passes `--format` on to `ash`.** The bash entrypoint consumed `--format`
  into an `ASH_OUTPUT_FORMAT` variable that nothing reads, so `./ash report --format
  text` printed report's default markdown and `./ash --format sarif` scanned with
  every default output format. `--format` now reaches `ash` where it was typed:
  report's report format, or scan's output formats. `Invoke-ASH -OutputFormat` set
  the same variable in the container; it no longer does, and the parameter is
  accepted and ignored (choose formats with `-AshArgs '--output-formats ...'`).

- **The PowerShell `Invoke-ASH` (`utils/ash_helpers.ps1`) now starts the container
  the way `./ash` does.**
  - It reads `OCI_RUNNER`, the variable `./ash` and the CLI read. `ASH_OCI_RUNNER`,
    which only `Invoke-ASH` read, is deprecated: it still applies when `OCI_RUNNER`
    is unset and `-OCIRunner` is not given, with a warning.
  - With no runner named it tries `finch`, `docker`, `nerdctl`, and `podman`, in that
    order. It used to try `docker` first.
  - It no longer passes `--fail-on-findings`, `--no-progress`, and `--no-show-summary`
    unless asked. **A configuration with `fail_on_findings: false` now exits 0 on
    findings**, the summary is printed, and progress is shown. `-NoFailOnFindings`,
    `-Progress`, and `-ShowSummary` pass their flag when given, and the opposite flag
    when given as `:$false`. With both wrappers, then, a configuration file in the
    scanned repository can set its own verdict, `fail_on_findings: false` included. A
    gate that must fail on findings pins the verdict itself: `--fail-on-findings` for
    `./ash` or `-NoFailOnFindings:$false` for `Invoke-ASH`, since a flag given directly
    takes precedence over any configuration, or an operator configuration named with
    `--config` (`-Config`) that sets `fail_on_findings: true`, which is used in place of
    the repository's own file. Both wrappers hand that path to ASH in the container, so
    the file has to be reachable there.
  - On Linux and macOS the image is built for your UID and GID (`id -u`, `id -g`)
    unless `-ContainerUID` or `-ContainerGID` is given. It was built for the image's
    default, 500:100, which cannot write an output directory you own with mode 0755.
    For a caller running as root the default is kept, since the non-root stage
    cannot create a user with UID 0, with a warning for the non-root target.
  - `-AshArgs` is read with PowerShell's tokenizer, so a quoted value is one argument,
    spacing included, and pieces written with no space between them, such as
    `sarif,html` or `k=[a,b]`, are one argument. It used to be split on whitespace.
    Variables are not expanded, and `-AshArgs` is refused if it holds `;`, `|`, `&`,
    `>`, or any other operator except `,`, a `$variable`, `$( )`, `@( )`, or a
    comment. It is also refused, with exit 3, if it holds a word or a double-quoted
    string that PowerShell would expand, such as `x$env:HOME`, `a$(y)`, `$a/b` or
    `"dq$a"`: the tokenizer took their text, so ASH got the characters typed where
    PowerShell would have put a variable's value or a command's output. A value
    single-quoted inside `-AshArgs`, such as `--config-overrides 'a.b=$x'`, is still
    passed as typed. Arguments written after `Invoke-ASH`'s own parameters are
    passed one each, and a comma list there is passed with its commas; the first of
    them is `-SourceDir` unless `-SourceDir` is given, since it is that parameter's
    position.
  - `--force`, `-q`/`--quiet`, and `-c`/`--no-color` in `-AshArgs` are matched as whole,
    case-sensitive words and consumed as `./ash` consumes them, so `--config` or
    `--cleanup` no longer turns color off and `-q` no longer reaches ASH, which has
    no `-q`.
  - The source and output directories reach ASH as `ASH_SOURCE_DIR` and
    `ASH_OUTPUT_DIR` instead of `--source-dir` and `--output-dir`, so
    `-AshArgs 'report'` runs `ash report`.
  - With a subcommand in the arguments (the first argument that names one and is
    not the value of a root option such as `--phases report`), the options
    `Invoke-ASH` adds from its parameters go right after it, and only those the
    subcommand takes. It does not pass the rest, and warns about each except
    `--quiet` and `--no-color`, which have already quieted the build and kept the
    container off a terminal. They used to come first, where ash dropped them:
    `-Config c.yaml -AshArgs 'scan'` scanned without the config.
  - `-Verbose:$false` and `-Debug:$false` no longer pass `--verbose` or `--debug`.
  - A runner named by a path (`OCI_RUNNER=/opt/bin/podman`) is run by that path,
    never by whichever program `PATH` holds under the same name.
  - An output directory that is a link, or is reached through a link below the
    working directory or inside `-SourceDir`, is refused before anything is created
    or mounted. In CI the working directory is the scanned checkout, so a link
    anywhere under it counts, a linked directory passed as `-SourceDir` included.
    The refusal names the link; pass the resolved path instead. On macOS, as on
    Windows, the paths are compared without regard to case, so an `-OutputDir` typed
    in another case is still checked.
  - With no runner found it throws instead of calling `exit 1`, which closed the
    PowerShell session it was dot-sourced into. This and every other refusal sets
    `$LASTEXITCODE` to 3, the code ASH uses for input it refuses (it was 1 for a
    missing runner), before it throws, so a script that catches or continues past the
    error and ends with `exit $LASTEXITCODE` exits 3, and the error is reported once.
    A script that leaves the error uncaught ends with 1, as PowerShell ends any script
    on an uncaught error. A failed build is not a refusal and keeps the build's exit
    code. To end a script with Invoke-ASH's own code, wrap the call as its help shows:
    `try { Invoke-ASH ... } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue; exit $(if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }) }`.
    The `Write-Error` reports the error the catch would otherwise hide, and the 1
    covers an error PowerShell raises before Invoke-ASH runs (a parameter given with
    no value, say), which leaves `$LASTEXITCODE` unset, so that a bare
    `exit $LASTEXITCODE` would exit 0. Start such a script with `pwsh -File`;
    `pwsh -Command`, which GitHub's stock `shell: pwsh` uses, reports any exit code a
    script sets, other than 0, as 1. The PowerShell leg of the CI scan test now wraps
    its call this way and runs with `shell: pwsh -File {0}`, so a refusal there fails
    the step with 3, and the scan's own exit code is no longer reported as 1.
  - Under PowerShell 7.3 and later each value reaches the runner as one argument
    even when `$PSNativeCommandArgumentPassing` is `Legacy`. PowerShell before 7.3
    has only the legacy rules, so there a value they would break is refused: one
    holding a double quote, an empty one (dropped), and one holding a space that
    ends with a backslash (which escapes the closing quote). A runner or
    `OCI_RUNNER_WRAPPER` that is a batch file gets the legacy rules under every
    version and has its arguments read again by cmd.exe, so for one the same values
    are refused, and so is a value holding `&`, `|`, `<`, `>`, `^`, or `%`.
  - On Windows PowerShell 5.1 a call without `-OutputDir` failed to bind: the
    default was built with a three-path `Join-Path`, which needs PowerShell 6.
  - Every refusal now exits 3 (with the catch form above), and only an explicit
    `--sandbox` other than `off` exits 5. Input PowerShell used to check while binding
    the parameters, which left `$LASTEXITCODE` unset (exit 1 with the catch form), is
    now checked by Invoke-ASH itself: a `-SourceDir` that is not a directory, now read
    as a literal path (`[r]` was read as a wildcard, so a directory named `s[r]c` was
    refused, and next to a directory named `src` the scan read `src`), and a
    `-BuildTarget` other than `ci` or `non-root`, which tab completion still offers.
    A parameter given an empty or blank value is refused, as `./ash` refuses an option
    given one: `-OCIRunner ''` used to discover a runner, while an `-OCIRunner` left
    to default from an empty `OCI_RUNNER` still does. An `-OutputDir` where a
    directory cannot be created (a file at the path, which was mounted at `/out` in
    place of a directory, or a file on the way to it) is refused before anything is
    built. So is a
    `--workspace` or `--workspace-config` among ASH's arguments: Invoke-ASH scans one
    directory, and the scan inside refused the workspace with exit 4 after the image
    was built. Run `ash --mode container --workspace <file>` for a workspace scan.
  - A refusal shows the value it refuses with each control character written as
    `\xHH` and each format character, line or paragraph separator, surrogate,
    private-use or unassigned code point as `\uXXXX` (`\UXXXXXXXX` above U+FFFF),
    the classes `./ash` writes out. A control character was shown as `?`, and a
    format character such as U+202E was printed as it was, reversing the text after
    it in the terminal. A run of backslashes before text that reads as an escape, or
    before a character written as one, is doubled, so the display reads back to the
    value one to one; any other backslash, as in a Windows path, is kept as typed.
    `./ash` writes the same characters as bash's `printf %q` does, so the two
    refusals use different notations for the same value. The `-Verbose` lines that
    print the source and output directories, the runner, and the build and run
    commands write their values the same way. Spaces other than ASCII's,
    combining marks and fillers such as U+3164 are outside that set. `Invoke-ASH`
    shows them as typed, and so does `./ash` in a UTF-8 locale; in the C locale
    `./ash` writes their bytes in octal.
  - `ISCI` set now makes the default `-BuildTarget` `ci`, as it does for
    `ash --mode container`. `Invoke-ASH` already read `CI`, `IsCI`, and
    `CODEBUILD_BUILD_ID`, and off Windows the names are case-sensitive.
- **`./ash` refusals exit 3.** When the bash entrypoint declines its own arguments or
  environment, before anything is built or run, it prints `ERROR: ...` on stderr
  and exits 3, the code ASH uses for input it refuses. That covers no OCI runner on
  PATH (it exited 1, on stdout) and a malformed `ASH_BASE_OCI_LAYOUT` (exit 1), and
  cases that were not refused at all: an option that takes a value given last with
  none, or given an empty one (a trailing or empty `--oci-runner` fell back to
  whichever runner was on PATH, and an empty `--source-dir` scanned the working
  directory), a `--source-dir` that does not exist (the working directory was
  scanned instead), and an `--output-dir` that is a file or cannot be created (the
  results went to the working directory; it is now refused as a usage error, exit
  5, and one that cannot be created with the reason `mkdir` gave, such as
  `(Not a directory)`). An `OCI_RUNNER` of only whitespace is
  refused too: unquoted, it would run a command named `build`. So is a
  `--workspace` or `--workspace-config`, anywhere among ASH's words: `./ash` scans one
  directory, and the scan inside refused the workspace with exit 4 after the image
  was built, so run `ash --mode container --workspace <file>` instead. The one
  exception to exit 3 is an explicit `--sandbox` other than `off`, which exits 5,
  next to a `--workspace` too, in either order and in `Invoke-ASH` as well: in one
  quoted argument, a `--workspace` ahead of it gave 3, and `Invoke-ASH` always gave 3. A
  failed image build still exits with the build's own status. The refusals print a path as
  typed when every character in it is one a terminal shows and it holds no backslash
  and no `$'`, and otherwise as bash's `printf %q` quotes it, so a control character
  is written out rather than sent to the terminal, and the text `$'a\E[2Jb'` is shown
  apart from a value holding a real ESC: every quoted form holds a backslash and no
  value printed as typed does, so each display reads back to one value. A value
  holding a Unicode format character, such as the bidirectional override U+202E or a
  zero-width space, or a private-use character, is quoted in the C locale, which
  writes its bytes as octal, because a UTF-8 locale's `%q` leaves those characters
  raw. Spaces other than ASCII's, combining marks and fillers such as U+3164 are not
  written out in a UTF-8 locale, here or in `Invoke-ASH`. In the C locale their bytes
  are not printable, so `./ash` quotes the value with them in octal, as in
  `$'img\302\240name'`.
- **`./ash` reads `--source-dir` and `--output-dir` as paths only.** A value that
  starts with a dash names that directory (`--source-dir -dashdir` was refused),
  and `--`, `-L`, `-P` and `-` are no longer read as `cd`'s options or as the
  previous directory: `--source-dir --` mounted and scanned `$HOME`. An exported
  `CDPATH` no longer chooses another directory of the same name. With `--no-run`,
  which only builds the image, neither directory is checked, and the output
  directory is no longer created (it was, even though nothing was written to it). A
  value of only whitespace is refused like an empty one: `--oci-runner " "` ran a
  command named `build`. The source directory is mounted read-only unless the output
  directory is inside it; an output directory next to it whose name starts with the
  same characters (`src-out` beside `src`) was taken for one inside it, and the
  source was mounted read-write, while a `--source-dir` of `/` was mounted read-only
  over an output directory inside it. A `--source-dir` or `--output-dir` whose path
  holds a newline, a carriage return, a comma or a double quote is refused, naming
  the option, because a runtime reads `--mount` as CSV: a source directory named
  `src` plus a newline was mounted as `./src`, and an output directory named
  `o,src=/etc` mounted the host's `/etc` read-write at `/out`. An output directory is
  refused before it is created, also when only the working directory's path, which a
  relative one resolves under, holds one of those characters. A path with bytes that are not UTF-8 is refused the same
  way, with exit 3 and the path shown escaped, because a runtime reads `--mount` as
  UTF-8 text: docker took such a byte as U+FFFD, then refused the mount or mounted a
  directory of that other name. `./ash` judges UTF-8 in bash, as Python decodes it
  (no overlong form, no encoded surrogate, nothing above U+10FFFF), and needs no
  other tool for it. The default source directory, the
  working directory, is resolved the same way: one whose name ended in a newline
  mounted its sibling without it. The lines that name the runner, the image and a base image override
  show their values the same way as the refusals.
- **Paths with square brackets print as given.** `ash merge` and the end-of-scan
  summaries print paths, project names and error text through Rich markup, so a
  name such as `out[/x]` raised a markup error, and `ash merge` exited 1 with a
  traceback instead of refusing the path; one such as `out[bold]x` printed as
  `outx`. These values are now escaped in `ash merge`'s refusals and summary, the
  scan's "Next steps" and configuration warnings, the workspace summary, and
  `ash config wizard`'s panels naming the file and its list of plugin modules.
- **A file an error names prints once.** An error such as "Is a directory" quotes
  its file by repr, which writes a control or a backslash as an escape, and the
  console and `ash.log` then showed that text again: a report that could not be
  written under an output directory holding an ESC was logged with two backslashes
  before `x1b` where the scan's other lines showed one, and each backslash of a
  Windows path printed twice. Error text, and the tracebacks ASH formats itself for
  results files and debug lines, now name the file as given, so each sink shows it
  once.
- **Log messages print as text.** The console log and the live progress panel read
  every message as Rich markup, and messages quote repository paths, exception text
  and tool output, so a scan of a directory named `[/x]` died with a markup error in
  the first log call that named it, and `ash merge --output-dir 'out[/x]'` exited 1
  instead of writing its reports. Messages are now text unless the call asks for
  markup, and the progress bar's descriptions and `ash report`'s refusals escape what
  they quote. A `--scanners` list that names no registered scanner is refused with
  exit 5, naming each requested scanner as given, one holding brackets such as
  `x[/y]` included, with no markup error; a list that names at least one registered
  scanner scans those and warns about the rest.
  - The console log and the live panel show the terminal controls a message carries
    as `\xNN` (an escape sequence, a carriage return, DEL, C1), and the
    bidirectional controls and other format characters (the zero-width space and
    joiners, the byte order mark, the tag block), the line and paragraph
    separators, which end a line in some log viewers, lone surrogates and the
    private-use and unassigned code points as `\uNNNN`, or `\UNNNNNNNN` beyond
    U+FFFF. One definition, by Unicode category, decides which, for every sink:
    the console, `ash.log`, `ash report` on a terminal and `ash merge`'s refusals.
    Text that already reads as such an
    escape has its backslash doubled, so `C:\x1b\out` prints as `C:\\x1b\out` and
    each escape shown stands for one character. A Windows path segment that reads
    as one is doubled the same way: a traceback frame under
    `...\Python\3.12.0\x64\Lib\` shows `\\x64`. Other backslashes are left alone. A logged traceback's error text,
    notes and file names are shown the same way. `ash report` on a terminal uses
    the same set, so it now shows a report's format and separator characters as
    escapes too (in JSON, as JSON's own escapes).
  - Outside a terminal (a pipe, a file, a CI log), text ASH prints is no longer
    wrapped at 80 columns: each line stays one line, so a long path or scanner name
    is shown whole, and `ash merge`'s refusal no longer split a name before a `::`
    in it. Tables, panels, tracebacks and the log's columns keep their layout, and
    a terminal still wraps at its width.
  - Outside a terminal, no line ASH's consoles write is a CI command, however Rich
    wraps or folds it: a line that would start with `::` (a GitHub Actions workflow
    command such as `::error` or `::add-mask::`) has its first colon written as
    `\x3a`, and `##[` or `##vso[` (the runner's legacy form and Azure Pipelines')
    has its first `#` written as `\x23`. Each console ASH builds comes from one
    factory that does this; on a terminal, text passes through unchanged, except
    under GitHub Actions, Azure Pipelines or TeamCity (`GITHUB_ACTIONS`, `TF_BUILD`
    or `TEAMCITY_VERSION` set), whose job log reads a terminal's lines too.
    Container mode and `./ash` pass each of those variables that is set into the
    container, so the scan there checks its lines under `-t` as well: by name, or,
    with `OCI_RUNNER_WRAPPER` set (a wrapper such as `sudo` need not pass the
    environment on), with its value, as one argument. No other variable of the
    caller's environment goes on the runner's command line with its value: the
    others there, such as the mount paths, `ASH_DEBUG`, `ASH_OFFLINE` and the
    terminal size, are ASH's own. Through a wrapper, a value holding a newline is
    refused with exit 3, before anything is built. What the
    CLI prints without a console (its refusals, `ash config`'s messages and
    questions, the workspace `--dry-run` plan, container mode's notices) goes
    through the same text rule, so a workspace file or folder name with an escape
    sequence or a `::add-mask::` line in it is shown, not obeyed. That includes
    the default a question shows: `ash config wizard` offers the file's project
    name as its first answer, and names each plugin module it asks about. So are
    a usage error, whose
    message quotes the arguments (an unknown option's name included, which click
    prints as typed), and the traceback of an exception that escapes a command:
    both now print through ASH's console instead of typer's, set up as typer's
    is, so they keep typer's option highlighting, its color under
    `GITHUB_ACTIONS`, and its widths. A refused value click or typer names by its
    repr (a choice such as `--mode`, a number, a path, an unknown command) or a
    `--cli-json-input` key is shown as typed, once: a real U+202E prints as its
    escape with one backslash, and the same six characters typed literally with
    two, where both printed alike before.
    `ash report`'s stdout is still the report as rendered, and the CLI reference
    now says to write it to a file in CI.
  - `ash.log` shows a message's and a traceback's controls and breaks its CI
    commands the same way, each escaped once, since it's read in terminals and
    printed in CI logs too; the JSONL log keeps the text, in JSON's own escapes.
    A message that asks for markup is written as its text, without the tags.
    That includes one the cdk-nag scanner logs in its worker process, a
    template's own suppression reason, which the worker handed back as text: in
    `ash.log` it kept its `[yellow]` tags and Rich's `\[`, and each escape in
    the rule id had its backslash doubled.
  - A warning no log handler takes, which Python's own last resort wrote to
    stderr as given, is shown the same way: one logged before ASH sets up its
    logging (the `ash` command clears its log handlers before each command, and
    the MCP server's tools read a repository's configuration before any are set
    up), and one from a logger under `ash` that does not pass its records up. A
    base file name with an escape sequence or a `::add-mask::` line in it
    reached the client's stderr as written. A workspace scan's warning that it
    could not find the workspace root's config, which quotes the file's path,
    went through a logger outside ASH's and reached stderr the same way; it now
    goes through ASH's, on one line, and a root config that cannot be read or
    parsed refuses the run (see Fixes). So do the lines that
    give an exit code of 1 its reason ("Scan incomplete", "Scan ran no
    scanners", "Conversion incomplete", rules that could not be evaluated,
    stale content databases, a scan with no results), which `ash merge` fills
    with names the shards chose: they are now in `ash.log` and the console log,
    where they were written to stderr only.
  - A record the console log cannot print (an argument whose text raises, a
    message logged with markup that does not parse) is reported as a
    "--- Logging error ---" on stderr, shown like the other handlers' reports,
    and the log call returns. Rich's handler formats and renders outside the
    part it guards, so the error escaped the log call, ended the command, and
    was printed by Python's exception hook as given.
  - A failure the `ash` command reports as it exits (an error that escapes a
    command, or one that stops the CLI from loading) is shown like the rest.
    Python's own hook, still in place when the CLI fails to load, printed the
    error's text as given; it now prints through ASH's traceback, as typer's
    does, and so does `rich.traceback.install()`'s, which only prints. Any
    other hook a library, a plugin or the user installs over it still runs,
    with stdout and stderr showing each line it writes; if it raises, ASH's
    traceback reports, and if it exits, the process ends with its code. A
    Ctrl-C while the failure is reported ends it with 130 and prints nothing
    more, and so does one while the CLI loads, before the command runs. A hook
    that writes to a file descriptor itself, or to a stream it
    saved before the failure, is not covered.
  - On a Windows CI runner or a console that cannot encode Unicode, a log line
    that quotes a repository's text is shown once, as on any other host. The
    filter that puts emoji in ASCII there rebuilt the shown line as plain text,
    so the console and `ash.log` showed it again: an escape sequence printed as
    `\\x1b` and a Windows path's `\x64` with its backslashes doubled twice. Its
    other characters outside ASCII are written as escapes (`caf\xe9`), not
    dropped, since a character dropped from shown text could join a `::` that
    starts a CI command.
  - Text the markup used to swallow now prints: `[tool.ash]` in the log messages
    that name a `pyproject.toml` configuration, and `--<letter>[alphanumeric_-]*`
    in the warning that skips a scanner's extra argument. A plugin's log line that
    gives no target type no longer appends `None` to the plugin's name
    (`(npm-audit)`, was `(npm-auditNone)`). The live
    panel colors numbers, strings and paths in a message (Rich's ReprHighlighter)
    where it showed them plain.
  - These are printed as given, with their controls shown: the caption of the
    results table, which names the scanned directories; the notice that an output
    directory was adjusted (`ash scan --source-dir 'src-[/x]' --output-dir
    'src-[/x]'` ended in a markup error and exit 1); the container mode's `--debug`
    command line; `ash report`'s refusals; a failed scan's summary row in the
    progress display; and the scan's "Next steps" and configuration warnings and
    the workspace summary, whose paths, project names and error text set the
    reader's clipboard through an OSC 52 in a directory's name, and stopped the
    summary on a strict stdout when a name was not UTF-8.
  - A results file that does not load is described by field, without its content:
    `ash report` and the container and Nix modes no longer print pydantic's quoted
    input, the file's own keys, or the byte a decode error stopped at.
  - `ash report --config` naming an invalid file whose path holds `[/x]` exits 3, as
    any invalid configuration does, instead of 1 with a traceback. So does `ash scan
    --debug --config` with such a path, whose log line naming the file raised a
    markup error.
  - What ASH printed with Python's print now follows the same text rule: the scan
    set that `python -m automated_security_helper.utils.get_scan_set` lists (the
    repository's file names), the content-database helper's refusals (a database
    name, and a `--built` time read from grype's report of its database), a tool's
    output that `run_command_stream_output` streams, Nix mode's `--debug` command
    line, and the error fallbacks that quote an exception: the traceback the live
    display prints when it cannot start, and logging's report of a record a log
    handler could not write (the console, `ash.log`, the JSONL log and the live
    panel), which now gives the traceback and the line that logged the record, and
    leaves out the message and its arguments. So do the lines the sandbox's
    exec wrapper writes to stderr when it refuses (the policy paths it quotes,
    the scanner's path and the error of a failed exec), each on one line, and the
    cdk-nag worker's refusal of a request whose protocol it does not speak. A
    `--built` value that
    does not parse now exits 2 with a message, as an unknown database name does,
    instead of a traceback, and `check-age`'s help names 2 as the usage-error
    code beside 0 and 1. The output container mode streams from the
    containerized scan is already shown by that scan, so it gets only the line
    check: none of its lines is a CI command, and its colors survive on a
    terminal. Nix mode's `--debug` header no longer prints `[bold blue]` as text.
  - `ash inspect findings` shows a finding as text in every view. Its rule id,
    file, message, suppression reason, code snippet and scanner name were Textual
    markup there, so `[@click=app.quit]` in a rule id was an action a click ran,
    `[link=...]` a hyperlink, and a scanner name or error holding a URL in a
    bracket ended the app with a markup error. The detail view was a Markdown
    document, where a message's markdown link opened a browser and a "```" in the
    snippet ended its code fence. It's now built from text widgets, with the
    metadata in a table and the snippet highlighted as code, and terminal
    controls in any of it show as `\xNN`. Suppressed rows are drawn struck
    through, as the stylesheet meant; the markup tag they used named no style.
  - `ash inspect findings` reads a finding's source only from a regular file in
    the scanned directory. For a finding whose results hold no snippet, it opened
    the file the results named, relative to the working directory, with no check:
    a FIFO there froze the app, `/dev/zero` grew its memory until it failed, and a
    symlink or a `../` path showed a file from outside the scanned tree. A
    finding's code is still the snippet its results hold, wherever the results
    file is. For a finding with none, its lines are now read only when the
    results file sits in `<root>/.ash/ash_output`, and only from a regular file
    inside `<root>` (a symlink only while it stays inside; a hard link counts as
    a file in the tree, as it does for the scanners), at most 64 MiB of it;
    otherwise the detail view says "(source not shown)". The results record no
    absolute path for the scanned directory, so results anywhere else read no
    file.
  - `ash inspect findings` shows at most 200 lines of 500 characters of a
    snippet, then "(truncated)", and highlights it once. Minified code reaches a
    snippet whole, and the detail view lexed and wrapped all of it again on every
    resize: a 1 MB line took 36.5 s per resize, with no input taken.

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

- **The candidates a repository's own detect-secrets baseline lists stay in the
  report as suppressed findings.** A `.secrets.baseline` or
  `.ash/.secrets.baseline` found in the scanned tree, or a `baseline_file` named
  by a config the operator did not write, is the repository's record: its known
  candidates are reported suppressed, with the baseline named as the reason, so
  the count stays visible and a repository cannot hide a secret still in its
  files by listing the hash in a file it commits. They used to be removed from
  the report. Only a `baseline_file` the operator's own settings name
  (`--config-overrides` included) removes its known candidates. A baseline read
  through an in-tree link into the enclosing checkout (a monorepo's
  `service/.secrets.baseline` pointing at the checkout's own baseline) has its
  result keys and `should_exclude_file` patterns read relative to the directory
  the baseline sits in, as detect-secrets wrote them; a link that leaves the
  nearest checkout is not read. The worker is never seeded with the baseline,
  so an entry whose secret has left its file is not reported at the baseline's
  stale line, and a `--slim` baseline's entries no longer fail the scan.

### Fixes

- **A `--cli-json-input` number where the parameter takes true/false or a whole
  number is refused with a usage error that names the key.** A JSON number for a
  true/false parameter (`"verbose": 1`) ended in an AttributeError traceback, 0 and
  1 included: the click that typer bundles reads a boolean from a JSON boolean or
  from text only. A number with a fraction or an exponent for a whole-number
  parameter (`"shard_index": 1.9`) was truncated by `int()` without a word, so
  shard 1 ran. Both are usage errors now (exit 5) that name the key; `true`,
  `false`, whole numbers and the text forms click already read are unchanged.

- **`--cli-json-input` reads a document as tools write it.** A UTF-8 byte order
  mark on a file or on stdin is accepted; stdin is read as UTF-8 whatever the
  process locale, and a read that fails is the usage refusal a file gets, not a
  traceback. The text after `file://` is a path, relative or absolute,
  percent-decoded, as the AWS CLI reads the prefix: it used to be parsed as a URI,
  so `file://params.json` was refused as a remote host and a `#` in a file's name
  cut the name. A document nested too deeply to parse, a number too large for a
  whole-number parameter and a file name with a null byte (`file://a%00b`) are
  usage refusals, not tracebacks. `--help` and
  `--generate-cli-skeleton` run before the document is read, so a bad document
  blocks neither. The document's values rank above environment variables, as
  documented: an environment value the parameter's type refused used to fail the
  run even when the document set that parameter. The skeleton writes `null` for a
  parameter that is required or that an environment variable backs, so an
  unedited skeleton no longer overrides the variable with the default; its
  `--generate-cli-skeleton` help says so.

- **`ash plugin list` lists what a scan with the configuration loads, on or off,
  built as the scan builds it.** It listed every class registered in the process, so
  plugins no scan of the configuration would run (a module the configuration does
  not name, an off-host reporter a trusted module does not load) were listed and
  had their options checked; the listing now follows the scan's selection. Each
  plugin is built from its own section, so the Enabled column follows the
  plugin's model default where the section leaves the key out (an opt-in plugin
  whose section sets options only is listed off, as a scan runs it), a section
  without `name` shows the plugin's declared name, and an off-host reporter's row
  shows the section the report phase reads, with Enabled true only for an
  `enabled: true` there. `--show-versions` matches each scanner to its inventory
  entry by position, so a scanner whose config name differs from its class name
  no longer reads Unknown; its help no longer calls the default listing fast, since
  the default listing builds every plugin too.

- **`ash build-image` stops its container scan on SIGTERM and exits as terminated.**
  The scan that follows the build ran outside the SIGTERM shutdown scope `ash scan`
  uses, so a SIGTERM killed the process at once with no word; the scan now runs
  inside that scope, the runner is stopped through the launcher's interrupt path,
  and the command exits with the terminated code and one line saying so. Ctrl-C
  cancels the scope before the command exits, and a SIGTERM that lands where
  nothing in the run polls the event still ends the command as terminated. The
  command also applies `--quiet`, `--verbose` and `--debug` to records logged
  before the scan attaches its handlers, and shows the scan's summary and
  exit-code legend when a scan runs, which the host used to suppress along with
  the container's copy.

- **What an archive does to itself is an input error; what the run does is a tool
  error, and only the first can be accepted.** The archive converter graded every
  failure as a tool error, so no `ash-unconverted-input` suppression on an archive's
  path took effect. A damaged, truncated or misnamed archive, an encrypted zip
  member, a member compressed with a method zipfile does not read, a damaged
  compressed stream inside a tar, a member name the filesystem refuses, and a member
  under a path an earlier member made a file are input errors now: a reviewed
  suppression on the archive's path accepts the record, which keeps the record in the
  results with the reason it was accepted for (`accepted_reason`, beside
  `accepted_by`), and the completeness gate leaves it out. A failure of the run (a
  full, over-quota, read-only or forbidden work directory, or a defect) stays a tool
  error that no suppression accepts. A suppression a client delivered with its own
  tree accepts nothing. An empty tar (end-of-archive blocks only, with or without
  gzip) is a valid archive with no members, extracted to nothing and recorded whole,
  instead of a failed input. A scan-set path not lexically under the source tree no
  longer raises when ignore paths are set.

- **Two archive members bound for one path are both extracted and scanned.** A later
  member written to the same path as an earlier one (`vendor//m.js` after
  `vendor/m.js`, a tar's repeated name, or two spellings of one name on a
  case-insensitive filesystem) used to be refused, so the bytes one unpacker produces
  were never scanned. It is written beside the earlier member under a numbered name
  (`vendor/m~2.js`) that no member of the archive is named by, with a warning naming
  both; past the first 20 in one archive, one line counts the rest. An environment
  file with a stage suffix (`.env.local`, `.env.production`) is extracted as `.env`
  is. A notebook member whose name is written in another case, or that cannot be
  encoded by the filesystem, keeps a distinct converted output.

- **ASH now requires uv 0.13.4 or later, and the container image pins uv
  0.13.4.** uv before 0.13.4 is affected by GHSA-hq85-5cpj-mr62 (critical). The
  requirement is `uv>=0.13.4,<0.14`, and the image installs the 0.13.4 release
  asset, verified against its SHA256. uv 0.13 changes some behavior: Python 3.15
  is the default stable version when uv has to download an interpreter, tar
  archives are read more strictly, and the constraints and requirements options
  parse differently. See https://github.com/astral-sh/uv/releases/tag/0.13.0.

- **A masked plugin module name is hidden wherever a message prints it, and the
  lines that print a registered module's path hide it too.** A module a config read
  from the environment is shown as `<value>` in the scan's messages. The name itself,
  and the name of every other masked module of the run, is hidden wherever it occurs,
  inside a longer name (`<name>_extras`) too, in the recorded failure text, the
  warning line and the refusal, whether the modules load in one call or one at a
  time. A module that failed on a longer name holding the masked name used to print
  that name in clear when it loaded in the same call as the masked module, and a
  module that failed on the parent package of a masked dotted name printed the
  parent in clear when the two loaded in separate calls. The path spellings of a
  dotted name (`<parent>/<child>` and `<parent>\<child>`) are hidden the same way,
  so the file line of a traceback for a longer name that holds it
  (`<parent>/<child>_extras.py`) hides it too; before, that line printed the masked
  leaf beside a source line that hid it. An inner segment is hidden in the import
  statement and the errors that name a longer sibling of it too
  (`from <parent> import <child>_extras`, `cannot import name '<child>_extras'
  from '<parent>'` and `has no attribute '<child>_extras'`) when a letter, a digit
  or `_` goes on after it and it stands after `import` and its blanks, after the
  error's quoted name, after a `,` or `(` (a later name of an import list, also
  over several lines) or after the leading dots of a relative import. The other
  spellings of the name (its
  dotted parents and inner segments, its file names, and the separator variants of
  its distribution name) are hidden only as a whole component: no ASCII letter,
  digit or
  `_` beside either end, with `.`, `/`, `\` and quotes ending a component, so a
  longer module name that merely holds a dotted parent keeps its text. A character
  that only folds onto an ASCII letter in a case-insensitive match (the Kelvin sign,
  for one) is not part of a name. The forms include the entry point the interpreter
  names when a compiled extension lacks it (`dynamic module does not define module
  export function (PyInit_<leaf>)`) and the file names of a compiled extension:
  `leaf.so`, `leaf.abi3.so`, `leaf.cp312-win_amd64.pyd`, the names PyPy and GraalPy
  give an extension (`leaf.pypy310-pp73-x86_64-linux-gnu.so`) and the Windows debug
  names (`leaf_d.pyd`, `leaf_d.cp312-win_amd64.pyd`; the `_d` is taken only before
  `.pyd`, so `leaf_d.so` stays readable). In those names the leaf is hidden and a
  dotted tag that is not a version stays readable. Another environment value that
  equals a derived form (a dotted parent, an inner segment) keeps hiding a longer
  word that holds it. The auto-registration debug line, the
  already-registered warning, the protected-name error, the failed-import warnings
  and the debug list of registered plugins the scan does not use printed the module
  path of a plugin class or registration as it was recorded. While a load, a scan's
  engine or a workspace run reads the registry, they now hide a masked module, a
  module inside it, a longer module name that holds it (`<name>_extras`) and a
  dotted parent of it, as the load's own lines do; a namespace root such as
  `ash_plugins` stays readable. Other callers that read the
  registry (`ash plugin list`, `ash dependencies install`, `ash report`) set no
  masked modules and print as before. A registration made while a masked module was
  in scope hides that module in its own failed-import warning, whoever resolves the
  registry later, and the two registry reads a workspace run makes outside its
  pre-warm (the report step's reporter list and the check of a `--scanners`
  selection) hide the run's masked modules too. The "not selected" line of the
  registry and the debug list of registered plugins the scan does not use hide the
  modules their registrations were made under a mask for as well, so a module that
  another run masked prints by its mask there. The import that plugin discovery
  makes of a plugin package runs under the same masked modules, so a package that
  registers a plugin and then fails to import hides its name in the failed-import
  warnings that follow. The next reader of the registry imports such a package
  again, because the loader dropped it from `sys.modules`, and its decorators run
  again; that import runs under the names its registration was made under, so the
  auto-registration debug line and the already-registered warning they write hide
  the package too, whichever scope the reader sets. The names a registration
  recorded are also found for a module below its path (a subclass defined in a
  submodule of the registered package). A masked-module block that nests
  inside another keeps the inner block's plain names and holds each form once,
  and two forms that differ only in the exemption inside a traceback frame line are
  two forms; the forms a load builds for the masked names of a run are kept apart
  by the same identity, so the form of an inner segment keeps its import-line
  pattern beside the form of another entry's parent that has the same text. The
  auto-registration debug line and the debug list of registered plugins the scan
  does not use are built and masked only when DEBUG is enabled.
- **The cfn-nag rules ASH ships report a public principal and a star action in each form
  a policy can write them.** `StarResourceAccessPolicyRule` read a principal as a Hash
  whose `AWS` value is the String `*`. A principal written as the String `"*"` made the
  rule raise, and under `--isolate-custom-rule-exceptions`, which ASH passes, that
  dropped the rule's result for every resource in the template. A Hash such as
  `AWS: ["*"]`, where the `*` sits in a list, was not reported. The rule now reports a
  principal that is `*`, a list holding `*`, or a Hash holding either as a value under
  any key, with or without an `AWS` key. An `Allow` statement written with
  `NotPrincipal` is reported too.
  `ResourcePolicyStarAccessVerbPolicyRule` reported an action only when it ended in
  `:*`, so `Action: "*"` was not reported. It is now, and so is an `Allow` statement
  written with `NotAction`. An action that reaches the rule as a mapping, which
  `Fn::ImportValue`, `Fn::GetAtt`, `Fn::Transform`, `Fn::Cidr` and a `Ref` to a
  parameter all do, made the rule raise, and that dropped its result for every resource
  in the template.
  Both rules now read a parameter the same way, in an action and in a principal. A `Ref`
  to a parameter is read through the parameter's `Default`, split at commas, and through
  every entry of its `AllowedValues` when it lists any, so `Action: !Ref P` and
  `Principal: {AWS: !Ref P}` with a `Default` or an allowed value of `*` are reported,
  and so is a principal that is itself `!Ref P`. An `Fn::Sub` that names parameters is
  read with each `${Name}` filled from the same texts, so `!Sub "es:${Verb}"` with a
  `Verb` whose `Default` is `*` is reported.
  Both rules also check every branch of an `Fn::If`: in an action, a principal or a
  statement's `Effect`, as a statement in the list, or around the whole
  `AccessPolicies`. cfn-model reads only the first branch. The rules do not evaluate the
  condition, so a statement is reported when any combination of its branches is public,
  including a combination that no value of the condition produces. A branch that is
  `Ref: AWS::NoValue` is an absent value. A statement with more than 32 combinations of
  branches is read the way cfn-model reads it, and the rule writes one line to stderr
  naming the resource.
  An action or a principal that a rule cannot read is not checked. The rule writes one
  line to stderr naming the resource and the shape, and says the action or the principal
  was not checked. For an action that covers an import, a `Ref` to a parameter with no
  `Default`, a `Ref` to a parameter of an SSM type (its `Default` is the name of an SSM
  parameter, not the action), a `Ref` to a parameter whose `Default` is empty or holds
  only commas, and an `Fn::Sub` with a name that is not a parameter with text to read;
  the rule still reads the other actions in the list. For a principal it covers an
  import, a `Ref` to a parameter with no text to read, and an `Fn::Sub` with such a name
  when the text around the names could still be `*`. It writes no line for an
  `Fn::GetAtt`, or for an `Fn::Sub` whose text around its names cannot be `*`, such as
  an ARN built with the account id. The line is not a finding. ASH keeps cfn-nag's
  stderr for each template, as cfn-nag wrote it, in `CfnNagScanner.stderr.log` in that
  template's own directory under the scanner's results, and adds its lines to the
  scanner's error lines. The line names the resource and not the template, so the log
  it is in says which template it is about. Both rules list a resource once however many
  statements or actions matched. Everything either rule reported before is still
  reported.
- **A refused Bedrock model listing is reported with its error code.** A listing that
  the control plane refused with an access-denied or credential error
  (`AccessDeniedException`, `ExpiredTokenException`, `UnrecognizedClientException`)
  was reported as a model that was "not checked", as if a later try could pass, and its
  reason said that no models were found in the region. The failed listing now carries
  the error code, and the reason reads "the model listing failed: `<code>`". A failure
  that botocore raised without a service code (`NoCredentialsError`, `NoRegionError`,
  `ParamValidationError`, an expired SSO token, a lost connection) is named by its
  class, as in "the model listing failed: `NoCredentialsError`"; "unexpected error" is
  left for an error that did not come from botocore. When a refused listing leaves the
  fallback models unchecked, the "no suitable fallback model" text names them in a
  group of their own, "not checked, listing refused (`<code>`)" ("listing failed
  (`<class>`)" when botocore failed the listing before any service answered it, and
  "listing failed (unexpected error)" for an error outside botocore), and no longer
  calls them "unavailable", the word for a region that does not list the model. When the shim
  that checks the configured model first (`_call_bedrock`) finds that model unchecked
  by the same refusal, the text names it in that group too, and the refused listing is
  requested once for the call, not twice. Only throttling, service faults
  (`InternalServerException` among them) and connection failures count as transient.
  Any other code, and a failure that is not a connection failure, is reported as the
  listing's failure, not as a model that a later check may pass. A fallback walk keeps
  one answer per listing call and makes one call for it: its retries are set on the
  control-plane client, not made by the walk, and follow the reporter's `max_retries`
  (that many retries after the first call, at most 10), so `max_retries: 0` sends one
  attempt. Left unset, `max_retries` gives the client three attempts, the call and two
  retries, where the option's old default of 3 gave it four. A failure kept for the rest of the walk is a `ClientError`, with the
  original response where there was one, and the walk logs the listing's failure as one
  warning; a copy or pickle of it is a kept failure again, with the same original
  error.
  `retry_with_backoff` decides a retry with the same check when it is given no list of
  its own, so botocore's connection failures (`EndpointConnectionError`,
  `ConnectTimeoutError`, `ReadTimeoutError`, `ConnectionClosedError`), which carry no
  code and derive from the `ConnectionError` and `HTTPClientError` that the list names,
  are retried; before, none of them was. That covers the retries of the Bedrock summary,
  CloudWatch Logs and S3 reporters. The runtime, Logs and S3 clients they wrap in those
  retries are now built with a botocore config that makes one attempt per call, so
  botocore does not retry a call inside the reporter's own retries: a failed call costs
  `max_retries + 1` requests, and one when `max_retries` is 0. The check also reads two
  more things. An error that
  carries a `transient` flag of its own is told by it, so the kept failure of a listing
  that lost its connection is transient to the plain check and to the retry, as the
  first caller's error was. A service answer sent with an HTTP status of 500 or more
  is transient whatever its code, so `ServiceUnavailableException`, which Bedrock sends
  with 503, is retried, and so is a 5xx answer with a code nobody listed; an answer
  without a status is still told by its code. The Bedrock reporter's retries of a model
  call therefore repeat a call that fails with `InternalServerException`, another
  answer with a 5xx status, or a connection failure on the same model, up to
  `max_retries` times (three by default), as a throttled call already was. A retry is
  not a reason to try another model: the failure comes back as it is, or walks on to
  the next model when it is one another model could answer, once the retries are used
  up. The Security Hub reporter passes a list of its own and keeps matching by class
  name and code.
- **A plugin's config named for another plugin does not turn the plugin on.** A
  subclass of a plugin's own config class that declared another plugin's name as its
  default was accepted as the plugin's config, with the `enabled` it set. The name is
  now compared before the class is, and a plugin that declares no name of its own no
  longer takes the name of a config of another class.
- **MCP source delivery deletes the read-only files a clone leaves.** git makes its
  pack files read-only, and Windows does not delete a read-only file, so a failed
  `set_source_git` clone, a leftover zip staging directory, the previous tree of a
  re-delivery, and a workspace that `clear_source` or the end of a session removes
  were left half-deleted. The next clone then failed on the leftovers, or a zip's
  stale files landed in `source/`. The delete now clears the read-only bit of what it
  cannot remove and retries once, and walks the tree again for each level of
  directories it could not open (up to 64 passes, and only while a pass changed a
  mode: a chmod that a file system accepts and changes nothing is not counted). An
  entry it still cannot remove (a file another account owns) stays on disk, and the
  delete goes on with the rest instead of stopping there. Delivery reads that answer:
  a failed clone is made in a staging directory beside `source/`, and one that cannot be
  fully deleted stays there under its own name, logged, while the tool reports git's own
  `error_type` with git's message in `error` (a timeout is reported as
  `clone_timed_out`), and a previous clone and a zip re-delivery's previous tree are
  renamed aside once the new tree is complete, so the delivered path never names a
  half-deleted tree. What cannot be deleted of either stays under a hidden name, which
  the next delivery deletes.
  The tool reference (`skills/ash-mcp/references/tool-reference.md` and its copies under
  `ash-agent-plugins/`) now names the `error_type` values these tools return.
- **A re-run of the reusable scan workflow no longer fails on its own artifact.**
  Artifact names are unique within a run across its attempts, so a "Re-run failed
  jobs" that ran the scan job again failed at "Collect ASH output artifact" on the name
  `ash_output` its first attempt had taken. A re-run (`github.run_attempt` other than
  1) now replaces that artifact. In the first attempt a second upload under the same
  name still fails, so a matrix or a caller that calls the workflow twice is not left
  with one scan's results in place of another's. The `artifact-name` input,
  default `ash_output`, gives each such call its own artifact, and
  `upload-ash-sarif.yml` takes the same input. One case is left: a re-run of a matrix
  whose legs share a name replaces one leg's artifact with another's; distinct names
  avoid it.
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
- **A scan with a converted tree keeps the components of both its SBOMs.** syft runs
  on the source tree and, when a converter wrote files, on the converted tree too.
  The second SBOM replaced the first, so `ash.cdx.json` (and the SPDX and GitLab
  reports built from it) listed only the converted tree's components, and a
  converted tree with nothing to catalog left it empty. The SBOMs are now combined.
  The `version` and `metadata` are the first SBOM's, which is the source tree's.
  Components are kept from both. A component the second SBOM repeats is listed
  once, wherever its first copy sits (a top-level component of the first SBOM,
  one nested inside a component, or an earlier component of the second SBOM), and
  the first copy is kept. It is matched on `bom-ref` and `purl` together or, for a
  component without a `bom-ref`, on `purl`; a component with neither is never
  matched. A `bom-ref` is only unique within one SBOM, so a `bom-ref` that two
  SBOMs give to different packages keeps both packages: the second one gets a new
  `bom-ref`, and its references in the second SBOM's `dependencies` follow it.
  When either component has no `purl`, as with the files, operating systems and
  vendored code that generators numbering their references describe, two
  components with the same `bom-ref` are one package only if their `type`,
  `group`, `name` and `version` all match. A component nested inside another gets
  the same check. When the merge drops a component as a repeat, the components
  nested in it are checked in its place, and the ones the first SBOM lacks are
  kept. A merge that gives components new `bom-ref` values logs one warning with
  their number and the first three shared `bom-ref` values, and a debug line for
  each. `dependencies` are united by `ref`, with `dependsOn` and `provides` united
  too. A merge that adds a component, a dependency or a reference gives the SBOM a
  new `serialNumber`; one that adds nothing keeps the first SBOM's.
  Four limits. A package that syft gives different `bom-ref` values in the two
  runs is listed twice, because matching `purl` across `bom-ref` values would need
  every reference to the dropped one rewritten. The same holds for a package the
  second SBOM lists under a `bom-ref` that the first SBOM gives to a different
  package: the first SBOM holds it under one `bom-ref`, the merge adds the second
  copy under the new one, and each further SBOM that does the same adds another
  copy. Only `components` and `dependencies` are combined: the second SBOM's
  `vulnerabilities`, `services`, `annotations`, `compositions` and the other lists
  are not carried. The SBOM syft writes holds none of them. And the second SBOM's
  components keep the locations syft wrote for the converted tree, under the
  source tree's header, and its `metadata.tools` entry is not added to the first
  one's.
- **`ash merge` keeps the components of every shard's SBOM.** The merge took the SBOM
  of the first shard that listed any component and dropped the SBOMs of the rest, so
  a scan whose shards each wrote one (two SBOM-producing scanners on two shards)
  left `ash.cdx.json`, and the SPDX and GitLab reports built from it, with one
  shard's packages only. The shards' SBOMs are now united in shard order by the rule a
  single scan uses for its own. The `version` and `metadata` are the first SBOM's,
  which is the lowest-indexed shard's that has one. A merge that adds a component, a
  dependency or a reference gives the merged SBOM a new `serialNumber`; one that adds
  nothing keeps the first SBOM's. Components are kept from every shard. A component a
  later shard repeats is listed once and the first copy is kept. It is matched on
  `bom-ref` and `purl` together or, for a component without a `bom-ref`, on `purl`; a
  component with neither is never matched, and a `bom-ref` that two shards give to
  different packages keeps both packages, the later one under a new `bom-ref`. When
  either component has no `purl`, the `type`, `group`, `name` and `version` decide
  whether they are one package, and a component nested inside another gets the same
  check. `dependencies` are united by `ref`, with `dependsOn` and `provides` united
  too. The same limits apply as for a single scan. A package that two shards name
  with different `bom-ref` values, or that a later shard lists under a `bom-ref`
  another shard gives to a different package, is listed twice. And only
  `components` and `dependencies` are combined: a later shard's `vulnerabilities`,
  `services`, `annotations`, `compositions` and the other lists are not carried.
  With the default scanner set only syft writes an SBOM, so those shards merge as
  they did.
- **No scanner reads a file in `global_settings.ignore_paths` where its options
  can leave it out.** Only detect-secrets and ferret-scan were given the ignore
  paths. The other scanners read the ignored files, and their own results under
  `scanners/<tool>/` held their findings (grype's and trivy's vulnerabilities, the
  packages in syft's SBOM, which also reached the reports' SBOMs). Each is now
  told, matching each pattern as ASH does when it drops findings: grype and syft
  with `--exclude ./<path>` (a fully ignored directory `./<dir>/**`), trivy and
  trivy-repo with `--skip-files` and `--skip-dirs`, checkov with an anchored
  `--skip-path`, and semgrep and opengrep with `--exclude=<name>` for a name
  nothing else has. cfn-nag, cdk-nag, npm-audit, cfn-lint and cfn-guard leave the
  ignored files out of the scan set they read, as actionlint and zizmor already
  did; those two now also read an ignore path ending in `/` as the files inside
  that directory, as every other scanner does. A semgrep or opengrep scan whose every file is ignored is `SKIPPED`, not
  `ERROR`. gitleaks has no option that leaves out a path, so it still reads the
  ignored files, and ASH drops what it finds there. snyk-code, which has no such
  option either and uploads what it reads, refuses
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
- A bandit, grype or syft run whose configured config file is refused or does not
  exist gets an empty config file that ASH writes in the scanner's results directory
  (`--ini` for bandit, `--config` for grype and syft), so the tool does not look for
  `.bandit`, `.grype.yaml` or `.syft.yaml` itself. A run with nothing configured
  still uses the checkout's own file.

- Error text and tracebacks that ASH saves into results, reports and MCP payloads
  have every complete escape sequence removed, with or without environment values to
  hide, as do the lines `redact_then_split` returns. Text the container run streams
  to a terminal keeps its colors and progress redraws.

- A work product under a derived directory (the output or work directory) is refused
  as a tool config when it sits in no scanned tree that the directory contains. In
  workspace mode both questions are now asked of the same tree.

- On PowerShell, an `ASH_CONFIG` file that is mounted into the container is marked as
  written by the scanned repository when its real path is inside the scanned tree or
  its name follows a link that sits in the tree, as `./ash` marks it.

- The refusal for a config name whose walk cannot be decided now says which it is:
  a directory that cannot be searched, a link that cannot be read, or a link loop
  or a place a link lands on that cannot be examined.

- A SIGTERM to a running `ash scan` now stops the scan instead of killing the
  process mid-flight. The console-script entry point installs a SIGTERM handler
  that only sets the scan's cancel event -- the same cooperative cancellation a
  server-side timeout uses -- so the running scanner's tool is stopped (SIGTERM,
  a short grace, then its whole process group), queued scanners do not start,
  the report phase's cleanup runs, and the command exits 143 (128 + SIGTERM, the
  code the default kill produced) with one line saying the scan was stopped.
  Before this, the process died at the signal: no stop ran, and a scanner's tool
  could be left running, orphaned. The kill semantics are kept where cooperation
  has no object: with no scan running, and on a second SIGTERM while the first
  is being honored, the signal falls back to the default disposition, so a hung
  process stays killable. A process started with SIGTERM ignored keeps it
  ignored; the MCP server paths install their own handling over this one when
  they start; on Windows nothing is installed, deliberately, because
  TerminateProcess does not run signal handlers. Library imports of ASH never
  install the handler.
- Container mode and Nix mode now honor that SIGTERM stop while their child
  runs. Both launchers sat in a wait that never read the cancel event, so the
  handler set it, nothing looked, and the scan ran to completion as though no
  signal had arrived. Each wait now reads the event and stops its child -- the
  OCI runner, or the `nix develop` shell -- through the same interrupt stop
  path a Ctrl-C takes (the interrupt, a short grace, then a kill), and the
  command exits 143 with the same stop line as local mode. The stop always
  passes the interrupt on, even at a terminal: the SIGTERM was delivered to
  the ASH process alone, so unlike a typed Ctrl-C the child has not received
  anything yet.
- A cancel set on a workspace scan's run-wide event reaches the checks that run
  under a project's own cancel scope. Cancel events chain through a parent,
  given at construction or recorded when a scope opens inside another;
  `is_set` and `stop_promptly` answer for the event or any ancestor, and `set`
  stays local, so cancelling one project never stops its siblings or the run.
  A stop already waiting out its grace sees an ancestor's prompt within one
  poll tick.
- The trim that shortens a bound-cut read of a tool's log never opens its
  search window inside an escape code: a code longer than the window, a code
  the read bound cut short, and a long ST-terminated hyperlink each hid the
  value fragment right behind them. The trim also computes each value's
  printable spellings once per read and slices the text once, so a read full
  of color codes costs one pass instead of one per stripped token.
- The carried stderr of a tool whose response could not be read is trimmed
  with the run's uv inputs as well as the environment's values, so a cut
  inside an input's spelling -- the wheel name included -- no longer leaves a
  fragment whole-spelling redaction cannot match. A uv spec's glued extras
  join the hidden spellings in the spec's own written order as well as
  sorted, and a tool whose module spelling uses underscores keeps its own
  name readable in shown uv output.
- yarn's error events are read from the raw endpoint text before redaction
  can rewrite them, so an environment value that collides with a JSON keyword
  no longer hides the error's own words.
- A shown sandbox text hides the union of the active scope's and the recorded
  command's values and inputs, and composing it never raises, since its
  callers sit in cleanup paths where a raise would end the sweep half done.
- The uv setup debug line builds its install command through the same
  spec-hiding record the install itself writes, so a value-holding spec shows
  as a hidden argument there too.
- The offline resolver's cause-first explanation is found even when the
  resolver's error sits past the shown excerpt's read bound, through a
  verdict-only reader that answers whether the phrase occurs and returns no
  text.
- The overridable redaction-values hook is read under one rule: record and
  best-effort paths read it once, guarded, and degrade to a value-free note
  rather than an empty value set, while the run's own paths let it raise. The
  two "Command stderr" debug records are built only when DEBUG is enabled.
- The MCP error context's non-string pieces are redacted like its strings:
  dict keys, and leaves such as a Path, are shown as their redacted text.
- A config file that does not parse, or cannot be read, refuses the run with exit 3
  before anything is scanned, as one that does not validate does. That holds for a
  file discovered in the scanned directory or named with `--config`, a workspace
  project's file, the `--config` given to a workspace scan, and the workspace
  root's file, in `ash scan` (with `--dry-run` and `--use-existing` too),
  `ash dependencies install`, `ash plugin list`, `run_ash_scan` and the MCP
  `scan_directory` and `resolve_workspace` tools. The message names the file,
  the parser error's type and where the parser stopped (`<path> could not be
  parsed (ParserError at line 2, column 1)`; a file that is not UTF-8 reads
  `(not UTF-8 at byte offset N)`, the offset and never the byte's value),
  never the parser's own words:
  those can quote the file's text (a load from a str quotes a snippet of the
  malformed line, and the messages for an undefined alias or an unknown tag
  quote the token itself), and a config file can hold a secret on that line.
  The same words refuse the file in `ash config validate`, `lint`, `get` and
  the MCP `get_config` and `validate_config` tools, in ash.log, and when a
  suppression is saved into a file that does not parse or an `extends` base
  does not parse. The defaults apply only when there is no config file. A
  file that did not parse was replaced by them with a warning, so none of its
  suppressions or ignore paths applied and the run could exit 0.
- `ash mcp` writes the log lines of the MCP SDK and of uvicorn through the same CI
  command check as ASH's own output, on every transport, however it is started.
  The SDK logs the name of a tool a client called and that failed, and its
  handler wrote that name as it was, so a `##vso[` in it reached the server's
  stderr as a command.
- `ash report` to a pipe or a terminal breaks CI command lines in the report, as
  the rest of ASH's console output does; written to a regular file, the report is
  as the reporter wrote it.
- `ash report` with no `--output-dir` and no `ASH_OUTPUT_DIR` reads only `.ash/ash_output/ash_aggregated_results.json` under the current directory, and names that path when it isn't there.
- No line of a YAML report starts with a CI command. A refused input's name is
  kept as it was read, so it can hold a line break followed by `::add-mask::`,
  `##[group]`, `##vso[` or `##teamcity[`, and PyYAML wrote such a value as a
  block of lines, or folded a long one at a space, putting the command at the
  start of a line of `ash.yaml`, the S3 reporter's YAML and
  `ash report --format yaml`. A string in which `::` or `##` starts the text or
  follows whitespace is now written double-quoted, with its line breaks as `\n`,
  and a double-quoted value holding either is written on one line, since PyYAML
  folds a long one right after an escape such as `\n` or `\t`, which would start
  the next line with the command. Every value reads back unchanged; other values are written as
  before.
- No line of a config file ASH writes, or of the config `ash config get` prints,
  starts with a CI command. A value can come from the repository, such as the
  project name `ash config init` takes from the directory, and the config writer
  wrote one holding a line break as a block of lines. The files `ash config
  update`, `init`, `wizard` and `lint --fix` write, `AshConfig.save`,
  `ash config get` and a suppression saved into a config file, whose path comes
  from a finding, now follow the YAML report's rule.
- A refused-input record keeps only its own fields (`path`, `member`, `reason`).
  A results file read by `ash report`, `ash merge`, `ash scan --use-existing` or
  the MCP `get_scan_results` tool could add any other key to a record, and every
  record and report written from it carried that key. Such a key is now dropped,
  and the reader logs one warning giving how many keys it dropped and from which
  file. No ASH version
  writes another key, so results ASH wrote load as before.
- A file whose name is not valid UTF-8 is reported like any other. Python reads
  such a byte as a lone surrogate, which a result could not hold: one such name
  stopped a scanner's SARIF from being written, so detect-secrets reported ERROR
  and lost its findings for every file in the run, and one in a scanner's
  arguments stopped the aggregated results from being written at all. The result
  models now hold the name with each such byte written as `\udcNN`
  (`secr\udce9t.py` for a latin-1 `secr\xe9t.py`), in `ash.sarif`, the aggregated
  results and every report, which read back as written. A name spelled with those
  same characters gives the same text.
- The suppression `suggest_suppression` writes matches the finding's own file. Its
  `path` is a pattern, and it held the file's path as it is: for `x[1].py` it
  matched `x1.py` and not the file, and for a file named `src\app.py` it matched
  `src/app.py`. `[`, `*` and `?` in the path are now written as one-character
  classes. A pattern reads every backslash as a separator and has no way to spell
  a literal one, so a finding whose path holds one gets no suggestion: the tool
  answers `success: false` with `error_type` `path_not_expressible`.
- **The scan set leaves out a link to a file whose target leaves the scanned
  tree.** A link is in the scan set only when its target, with every link on the
  way resolved, is inside the source directory, so the scanners and converters
  that read the scan set are not given one that leaves it. Each one left out is
  not scanned, and a warning names the link and not where it points, as
  `Not scanning 'vendor/config.py': link leaves the scanned tree`. A link to a file
  inside the tree stays, and a source directory reached through a link is scanned
  as given.
- **The scanners that walk the directory they scan skip a link to a file whose
  target leaves it.** bandit and checkov 3.3.26 follow a link to a file (measured),
  and none of these scanners reads the scan set. Each is now told to
  skip every such link in its own exclusion option: bandit's `--exclude`, one
  anchored checkov `--skip-path` per link, ferret-scan's `--exclude` (the link's full
  path, escaped), `--exclude ./<path>` for grype and syft, and `--skip-files` for
  trivy-repo. A link that option cannot name alone (for bandit a path with a comma,
  `*`, `?`, `[` or a line break, or one another path contains; for checkov values
  checkov's terraform module finder cannot compile into the one regex it joins them
  into, as an unmatched parenthesis after a dotted link does; for ferret-scan a path
  with a comma, or one another path contains, since ferret-scan 2.4.x also matches a
  pattern as a substring) stops that scanner on the directory, and the scan fails
  naming the link. grype and syft are also given the files the global ignore paths
  ignore, as `./<path>`, or `./<dir>/**` for a directory whose every file is
  ignored. The syft `exclude` option is now described as the glob syft takes.
- **ferret-scan is given the files the global ignore paths ignore, not the ignore
  paths as written.** Each was passed to `--exclude` as it was, and ferret-scan
  2.4.x also matches a pattern as a substring of the full path, so an ignore path of
  `.` or `api` left nearly every file unscanned, and one holding a comma became two
  patterns. The paths are now the ones ASH ignores when it drops findings: each file
  as its full path with glob characters escaped, and a directory whose every file
  is ignored as that path followed by `/*`. An ignore path ASH matches to no file,
  such as a bare `api` (write `api/` for the directory), leaves nothing out. A path
  with a comma, one whose pattern another file that nothing ignores holds, and
  patterns that would take the `--exclude` value past 100,000 bytes are not given;
  ferret-scan reads those files, and ASH drops their findings.
- The MCP scan tools report exit code 3, with its meaning in `exit_code_meaning`,
  when they refuse a tree the CLI exits 3 for. `run_ash_scan` and `scan_directory`
  do so for committed files in `.ash/ash_output` (or files there git cannot account
  for), where they reported no exit code, and for `.ash` or `.ash/ash_output` being
  a link. `run_ash_workspace_scan` does so for a link in its output tree, which it
  reported as 4, the code for a workspace definition, policy or confinement
  refusal.
- `ash config lint` and `ash config validate` warn about an ignore path or
  suppression whose `path` starts with `/` or a drive (`/vendor/**`,
  `C:\repo\vendor\**`), which matches nothing because paths are matched relative to
  the scan root, so its files were scanned. The warning names the spelling that
  matches when there is one: the rest of a path under the scan root (a root on a
  UNC share included), or `vendor/**` for `/vendor/**` when the scan root has a
  `vendor`; a directory, `/vendor` or `/vendor/`, is `vendor/`, and for a
  suppression `vendor/**/*`. A drive or UNC share outside the root, a `/x` that
  names nothing there, a path with a `.` or `..` component, or a path the config
  reads from the environment (whose spelling would print part of the value) is
  told to write it relative. In an
  `extends` chain the warning names the base that holds the path. Matching is
  unchanged. The directory
  check no longer advises adding `/**` to an absolute directory path. Lint's issues
  and validate's warnings each print on one line, with a newline in the file's text
  shown as an escape.
- Every other refusal from the MCP scan tools carries an `exit_code` and its
  `exit_code_meaning` too, where most carried none: 3 for a refused or unusable
  config, 5 for the request itself (an unusable session header or severity
  threshold, a directory that is missing or not a directory, or `run_ash_scan`
  with no `source_dir` and nothing delivered), 4 for a target the server will not
  scan (outside the permitted roots, or a delivered tree no longer on disk), and 1
  for anything else. Where the CLI refuses
  the same thing, it exits with the same code. `run_ash_scan` passes a refusal from
  `scan_directory` on as it was given; it relabeled each one `scan_start_failure`,
  dropping its `error_type`, category, suggestions and code, so a client that
  matched on `scan_start_failure` should match on the refusal's own `error_type`.
  `get_config` carries the same codes when it refuses: 3 for a config outside the
  directories the session may read config from (`config_input_not_permitted`) or
  one that cannot be loaded, 5 for an unusable session header, 1 for anything else.
  As for `ash config get`, a named file that does not exist (a link to nothing
  included) and a named or discovered file that does not parse are configs that
  cannot be loaded: `get_config` answered the first two with the default
  configuration, as a success, and `raw=True` on a file that does not parse with
  exit 1.
- An MCP scan that ASH refuses or gives up once it has started tells the client why.
  `get_scan_progress` reported only "ASH exited with code N" for a config that does
  not validate, files git tracks where the scan writes, or an error during the scan.
  Its `error_message` now carries the text the CLI shows for it, on one line with
  terminal controls written as escapes, and new `exit_code` and `exit_code_meaning`
  fields carry the code; both are null for any other ending. The exit `run_ash_scan`
  raises for these refusals is `ScanRefusedExit`, a `SystemExit` with the same code
  whose `message` is that text, so an in-process caller can read it too.
- The MCP scan tools' refusal of an unknown `severity_threshold` suggests `ALL` among
  the valid thresholds, as its error and the config's own
  `global_settings.severity_threshold` accept it, and no longer suggests checking the
  value's case, which is not matched.
- For a remote MCP caller, a config file that `scan_directory` (and `run_ash_scan`)
  discovers in the scan target is checked against the permitted roots, as a named
  `config_path` is. Only its `extends` bases were, so a discovered `.ash/.ash.yaml`,
  `.ashrc.toml` or `pyproject.toml` linked out of the roots was read by the scan: one
  that parsed configured it, and one that did not failed the scan on the outside
  file. It is now refused with `error_type:
  "config_input_not_permitted"`, carrying neither its resolved path nor its contents.
  `pyproject.toml` is checked whether or not it configures ASH, because discovery
  reads it to find out. `get_config` checks the config it discovers the same way,
  before discovery reads it: a `pyproject.toml` linked out of the roots was read,
  and one that did not parse was reported with the outside file's line and column.
  The same check covers each project's own config in a
  workspace that `resolve_workspace` or `run_ash_workspace_scan` resolves: one
  linked out of the roots was read, and the plan returned what it set
  (`display_label`, `severity_threshold`) and the outside path as `config_source`.
  It is refused before any project starts. The workspace policy file the workspace
  root holds is checked the same way: a discovered `.ash-workspace.yaml` (or another
  policy name, at the root or in its `.ash/`) whose entry resolves outside the
  roots, a link to a missing file included, is refused before it is read, and the
  refusal names neither the outside path nor anything in the file. Both carry
  `config_input_not_permitted` with exit code 3, the code `run_ash_scan` gives the
  same refusal and the CLI exits with for a config whose `extends` chain leaves its
  root. A `.ash` that is a link out of the roots is refused by itself, in config
  and in policy discovery, before any name in it is looked at, so no answer says
  whether the directory the link leads to holds the name.
  On Windows a junction at `.ash`, which is no symbolic link to `Path.is_symlink`,
  is refused the same way. So is a workspace project directory that is a junction,
  as one that is a symlink is, and a junction a config path passes through counts
  as a link to the check that decides whether the config is a repository's. A
  reparse point that names no other path, such as a OneDrive placeholder, is the
  directory it appears to be to both checks, and on Windows a `..` in a config path
  is applied before any link in front of it, as Windows opens the path.
- **A scan run on the host refuses a directory whose path is not UTF-8 at the
  start.** The scan writes the directory's absolute path into the results file and
  the SARIF, which hold UTF-8 only, so a local scan of a directory named `caf\xe9`
  ran its scanners, then exited 1 with "Error serializing to JSON" and wrote no
  results and no reports. Local, precommit and nix mode now exit 1 before they
  write anything or clear the previous results. The message names the directory,
  with its bytes that are not UTF-8 written as escapes, and says to rename it. A
  report over existing results (`--use-existing`) on the host is not refused.
  Container mode does not get around it: it bind-mounts the directory at `/src` and
  the output directory at `/out`, and docker took the byte that is not UTF-8 as
  U+FFFD, then refused the mount (the scan exited 125) or, where a directory of that
  other name existed, mounted that one. Container mode now exits 3, as for any
  path the runtime cannot take, before any runtime call when either path is not
  UTF-8, with `--use-existing` too; `--no-run` mounts nothing and is not refused.
- **A workspace with a path that is not UTF-8 is refused with exit 4, not a
  traceback.** The workspace plan and the results hold the workspace file's path,
  its root's and every project's, and both are UTF-8 only. A workspace whose root
  or a folder had such a path got as far as building the plan, where pydantic
  refused it: `ash scan --workspace` exited 1 with a traceback, with `--dry-run`, in
  local and container mode and with `--workspace auto`, and both MCP workspace
  tools answered exit code 1, the code for an ASH bug. Resolution now refuses the
  workspace file, its root or the folders first, before reading any project's
  config, with exit 4 like every other workspace definition refusal. The message
  names each path, with its bytes that are not UTF-8 written as escapes, and says
  to rename it; container mode does not help, since the workspace is planned on
  the host. The same holds for a workspace policy file (`--workspace-config`) and
  a default config (`--config`, or the profile an MCP session bound) whose path is
  not UTF-8, following links: the plan holds their paths too, and both MCP
  workspace tools answered with a plan their client could not be sent.
- The MCP results readers (`get_scan_results`, `explain_finding`,
  `suggest_suppression` and `diff_scan_results`) read a results file only when it
  resolves to a file inside the directory it is named in. A results file that is a
  link elsewhere, or a link to a file that is not there, is refused with one
  message, which names the file as given and nothing the link leads to.
  `get_scan_progress` checks the same way, before it reads any of them, the
  scan's aggregated results and each scanner's `ASH.ScanResults.json` under
  `scanners/<scanner>/<target>/`, which it reads and returns, and it follows
  `scanners/`, a scanner's directory or a target directory only when it resolves
  to a directory inside the output directory: one linked to another tree's was
  read, and that tree's results were counted as the scan's. A results file that
  `suggest_suppression` or `diff_scan_results` is named directly, and that is a
  link out of the roots, gets the same refusal: it got the roots' refusal of the
  path, which carried the path the link resolves to. `get_scan_result_paths` lists
  such a file as not there, with no size and the reason in `error`, without
  following the link, and lists nothing a linked `scanners/` or scanner directory
  leads to; it reported the existence and size of whatever a link led to.
- **A config file inside another git checkout is held to one rule for the settings
  only the operator chooses.** A file inside any git checkout other than the scanned
  one, and a file an MCP client delivered, already made no sandbox grant and was
  capped at the default archive limits. The options only the operator sets
  (detect-secrets' `max_worker_output_mib`, the Security Hub scope options) and the
  reporters that send findings off the host now follow the same rule: such an option
  takes the value from the defaults or `--config-overrides`, a reporter section the
  file writes is not used, and one warning names each option or section, the file and
  the remedy. A value and the environment reference the file wrote for it are left
  out together. `honor_ignore_files: false` in such a file is ignored, as it is in a
  file inside the scanned tree, because it widens the scan to the files the ignore
  files leave out; `--no-honor-ignore-files` or `--config-overrides` sets it. One
  warning names only the files that write the key, whether the file is the selected
  config, the file `ASH_CONFIG` names (also when the project's own config replaces
  it, as it still supplies the trusted base), or a workspace's trusted config. A file
  outside every git checkout keeps the `false` it writes itself when it is the
  selected config, or the file `ASH_CONFIG` names while the project has no config,
  even if it extends a base inside a checkout; the base's own `false` is replaced and
  named. A client's `config_overrides` are named as a writer only when they set the
  key. Container mode, the workspace loader, the container's sandbox-mode floor, the
  trusted base, `ash config validate` and the MCP `get_config` tool read such a file
  as a scan reads it: before, they treated it as the operator's, so a value the scan
  ignored was refused with exit 3. With the working directory gone, `get_config`'s
  `ASH_CONFIG` check and the load take the same trees, so a file inside the named
  config's project directory is left out by both, and the warning for a value left
  out because the given root holds it does not call the file a checkout's. A config
  kept in an ops or dotfiles repository counts as inside a checkout: to keep a
  setting, move the file outside every git checkout, or pass the setting with
  `--config-overrides`. The trusted-config route names every reporter section its
  chain writes when a file of the chain is in a checkout, the operator's own file
  included, and that warning, like the one for `honor_ignore_files`, says of an
  operator's own file that it extends a base in a checkout instead of calling it a
  checkout's. Neither it nor the reporter's own warning claims a scanned tree on a
  load that has none or says the scanned repository wrote the file. The plugin-module warning says
  a module installed in any other checkout is refused as well.
- **`get_config` answers a named file when `ASH_CONFIG` writes a value the load
  leaves out.** A config file the MCP client names is checked against rules built
  from the session's bound profile or, with none bound, from the configuration
  `ASH_CONFIG` names. That file was read without the trees the load reads it with,
  so an option only the operator sets, written there with a value it refuses by a
  file in another git checkout or inside the named config's project directory,
  made the rules unreadable and the named config was refused, although the load
  leaves that value out. The rules are now read with the same trees as the load.
- **A config file whose directory walk did not finish grants nothing, and every
  warning for it says the walk stopped.** When resolving a config file's name stops
  before the end, because a directory on the way cannot be searched, a link cannot be
  read, or there are more links than ASH follows, ASH reads the file as the
  repository's. In a scan with a source directory, the sandbox settings such a file
  wrote itself were still merged into the operator's, so a grant in it was kept and
  no warning named it. They are no longer merged, and a warning names the file and
  says the walk stopped, whether the file is the selected config, the file
  `ASH_CONFIG` names or the operator's trusted config. A root's sandbox settings
  are judged by the answer the load reached about its walk, not by a second walk of
  the file, which could read it differently. The warnings for a reporter's
  destinations, a scanner's own configuration, `tool_version`, the content database
  staleness policy, detect-secrets' scan settings, `honor_ignore_files`, the archive
  extraction limits and the destinations a plugin module's reporter declares claimed
  that the file is inside a git checkout or the scanned tree or directory, or who
  wrote it, which the walk never established. They now say the walk stopped, as the
  sandbox and settle warnings do, and a value an MCP client's overrides set is
  attributed to the client, not to the walk. Each also ends with how to keep the
  setting from such a file, which is to make each directory on its path searchable
  and each link on it readable; moving out of every checkout a file that is not
  known to be in one changes nothing. In `ash report`, the warning for a plugin
  reporter's destinations speaks as the command's other reporter warnings do. The
  text for a file whose location was decided is unchanged. A line that holds a
  located file and one whose walk stopped gives each its own reason and remedy. The
  warning for an operator-only option such a file wrote gives that remedy when only
  the search for any checkout could not place the file and no located file is on the
  line with it, as the other warnings do. The warnings for the off-host reporters and
  `honor_ignore_files` that a trusted config wrote and the load dropped whole say
  the walk stopped and give the same remedy for such a file, instead of stating
  where it is. A root whose walk stopped only in the search for any checkout, and
  not in the walk over the scanned trees, keeps none of its own sandbox settings
  either, as its other settings are already confined. A root whose path, or a name
  it was given, the checkout judgment could not place is named in the same warning
  as the other roots that are left out. Before, the file `ASH_CONFIG` names and the
  operator's trusted config were left out without a warning. A config file that is left
  out because it is not the operator's, or because its walk stopped, is named also
  when the only sandbox setting it writes is a list its `patch` sets, as when it
  writes a `sandbox` section of its own. A `network_scanners` list in such a file
  still narrows the network as a limit. The selected config and the file `ASH_CONFIG`
  names when no config is selected are named once, by the warning for the files the
  scan confines, which says the walk could not be decided and which settings the file
  loses; the root's own warning is given for the roots that warning does not name. A
  root found in a git checkout by one of its names is named by that checkout, not by
  the walk of another of its names, and the remedy for a file whose walk stopped now
  also says to name the file through fewer links when it goes through a long chain of
  them, the only cure for a name that passes the bound on the links ASH follows.
  A walk that stops at a directory it could
  not examine now says where, once per name, as the stops at the link bound and at
  a link it cannot read already did.
- **A name whose directory walk did not finish is read as the repository's by the rule
  that judges paths, not only by the checks that confine a config file.** The rule that
  decides whether the scanned repository could have written a path, which config
  files, the tool paths a config file names, and the record of the paths the operator
  named all read, followed the links of a name but dropped whether the walk reached its
  end. A name whose walk had not finished therefore read as outside every tree there:
  a root whose walk had not finished was recorded as the operator's, its tool paths
  were judged as the operator's and not as a repository-written file's, and a tool path
  whose own name walk could not finish was passed to the tool. The rule now gives such
  a name a reason of its own that says the walk stopped, after judging the links the
  walk did find, so a link in a tree is still named as the reason when there is one.
  The reason the scan inside gives for a file marked as in another checkout keeps the
  link clause (the host found it in, or reached it through a link in, a git checkout
  other than the scanned directory) and no longer says the host could not rule a
  checkout out, a state no mark is sent for.

  The rule for a path the operator named, in an environment variable, in a
  `--config-overrides` value or in a config file outside every checkout, had the same
  gap. A path whose own name walk could not finish was handed to the tool, while the
  walk's warning said the name is treated as inside the scanned tree. Such a path is
  now refused with the same reason, after judging the links the walk did find. The
  refusal for an unfinished walk tells the operator to make each directory on the path
  searchable and each link on it readable, or to name the file through fewer links,
  instead of to move the file out of a checkout or to name one outside the tree, which
  cannot help when no place was found.

  The sandbox warning for the files the scan confines ends the same way when every file
  on it is there only because its walk did not finish: it says to pass the settings with
  `--config-overrides` or to make each directory and link on the path readable so the
  walk can finish, and no longer to move the file outside the tree, which cannot help a
  file no tree was found to hold. A warning that also names files whose place was found
  keeps its present ending. A file an MCP client delivered, or a session profile a
  client's patch changed, is named as that and not as an unfinished walk, since those
  refusals hold once the walk finishes too.

  Those two checks resolve the name themselves, and a symlink loop made one of them
  raise on Python 3.12 and older, out of the check on a path the operator named. A
  check that cannot answer now leaves the walk's reason. The warning for a sandbox
  section left out because the file sits in a tree or was delivered logs the file's
  path and the tree as data, as the warning for an unfinished walk does.
- **A patch that only appends an entry to a sandbox grant list a root config does not
  write keeps the trusted list.** The patch's entry is never adopted, so an append, or
  an insert at an index, can only add to the list in force. It was read as an edit of an
  entry the file's list does not hold, and the list was limited to nothing: the scan
  got less than the same file with no patch. It is no limit now. A patch that removes
  or replaces an entry of such a list still limits it to nothing, and its warning says
  that the patch edits entries of a list the file does not write, so none of the
  trusted list's entries is kept. The warning for a limit by a list the patch names
  speaks of scanners for the scanner-name lists and of spelling only for the path list,
  says that an entry the patch adds is never adopted, agrees in number, and is given
  only once the file's own section validates; before, a section that did not validate
  had already been reported as limiting the list.
- **The warning for an `honor_ignore_files` that a trusted chain in another checkout
  wrote names the value the scan uses.** The warning is given once the value in
  force is settled. When the operator's own file outside every checkout, selected
  with `--config`, writes the key itself, that file's value is kept, and a trusted
  chain's file that writes the same value is no longer reported as replaced. A
  trusted chain's file that writes the other value is reported only when the
  trusted base gives the value in force too, and the warning then names the
  operator's file as the one that decides it; when the trusted base gives the
  dropped file's own value, nothing is said, because the dropped chain changed
  nothing.
- **Ctrl-C exits 130 in every mode, and says the scan was interrupted.** In container
  mode it exited 241: the container runtime was stopped with SIGTERM, which killed it
  before it could pass the interrupt to the container, and its -15 status became 241.
  The interrupt is now passed on to the runtime, which has 5 seconds to stop before it
  is killed, also when it comes while the runtime or the Nix shell is being started
  or ASH is setting up reading the runtime's output. On Windows the runtime shares
  ASH's console, which passes it the Ctrl-C
  itself, and it gets the same 5 seconds; it was terminated at once, which can leave
  a `docker run --rm` container running after ASH exits. An ASH attached to no
  console still ends the runtime at once. A second Ctrl-C during the 5 seconds kills
  the runtime at once, Windows included. Nix mode gives the shell the same interrupt
  and grace; it was killed after 0.25 seconds, and was passed nothing when the
  interrupt reached ASH alone. A local scan exited 130 already, but first logged
  "ASH Security Scan Completed in 0s" and printed the results table for a scan that
  never finished; it now prints neither, and every mode ends with "ASH scan
  interrupted before it finished".
  `ash build-image` exited 130 without a word; it now says "ASH build-image
  interrupted before it finished".
- **A scan names its config file only once the file has loaded, and refuses a
  `--config` that does not exist.** "Using config file found at" and "specified at"
  came from a second discovery made before the configuration was resolved, so the
  line was printed for a file that then failed to validate, and for a `--config` that
  did not exist, which the scan replaced with the defaults and exited 0. A missing
  `--config` now exits 3. The resolution that loads the file prints "Using ASH
  configuration from <file>" once it has loaded; anything that reads a config
  through it announces a discovered file the same way, after loading it.
- Path sanitizing keeps a backslash that is part of a POSIX file name. It rewrote
  every backslash to `/`, so the SARIF location for the file `a\b.py` became `a/b.py`,
  a path that names no file. A backslash now separates segments only where the scan
  root's paths use it: always on Windows; on POSIX only in a drive-letter or UNC
  path, or where the backslash spelling names no file under the source directory
  and the slash spelling does (SARIF written on Windows for the same tree). When
  both spellings name a file, the name as written wins.
- After sanitizing, the steps that read a location URI keep a backslash that is part
  of a POSIX file name: suppression matching and inline suppressions (in a scan and
  in `ash merge`), workspace aggregation (the location and `workspace_uri`), and
  `SarifReport.filter_results_by_files`. Each rewrote every backslash to `/`, so an
  `ash-ignore` comment in `a\b.py` was read from `a/b.py` and never applied. A
  backslash is still a separator in a drive-letter or UNC path, and in every URI
  under a Windows source or project directory.
- Ignore files are read with git's whitespace rules. A pattern's leading space, a
  trailing space escaped as `\ `, and a trailing tab are part of the pattern, and a
  line is a comment only when `#` is its first character. ASH stripped every line
  first and its ignore-file parser strips leading whitespace, so ` dir/` ignored
  `dir/` (and the walk never entered it) and `name\ ` ignored `name`. Only
  unescaped trailing spaces are dropped now, as git drops them. A line also ends
  only at a line feed, losing one carriage return before it, as in git: a lone
  carriage return split the pattern `a<CR>b.py` into `a` and `b.py`. A UTF-8 byte
  order mark at the start of an ignore file is skipped, as git skips it; kept, it
  was part of the first pattern, which then matched nothing. That holds on Windows
  too, where the file is read with the ANSI code page and the mark decodes as
  `ï»¿`. As in git, only that one mark is skipped. A line the locale's encoding
  cannot decode is read as its bytes, as git reads it, and matches the file whose
  name holds them; it stopped the scan set with a UnicodeDecodeError.
- A scanner that cannot read the run's scan set stops, naming the error, and the
  scan exits 1 with that scanner incomplete. It was handed an empty scan set, so
  it ran as though nothing were in scope.
- A `!` pattern in the root `.gitignore` brings back a file below a directory whose
  children alone are excluded, as git does: under `vendor/*` and `!vendor/keep.js`,
  `vendor/keep.js` is scanned. The scan-set walk skipped `vendor` because a file
  inside it was ignored, so the negation never saw `keep.js`. A directory the
  rules exclude itself (`lib/`) is still skipped, and a `!` below it brings nothing
  back, also as in git.
- The scan set keeps every file name exactly. It stripped whitespace from each entry,
  so a file whose name ends in a space, a tab or (on POSIX) a carriage return, and
  every file under a relative `--source-dir` whose name starts with a space, was
  handed to scanners as a path that does not exist. Only the list's newline
  separator is removed, and on Windows a carriage return before it.
- checkov findings in a file whose POSIX name holds a backslash name that file.
  checkov writes every backslash in a path as `/`, so its result for `a\b.tf` named
  `a/b.tf`, which does not exist. When the path checkov wrote names nothing, ASH now
  finds the one scanned file checkov spells that way and reports it (as `a%5Cb.tf`
  in the SARIF URI). A limit that comes from checkov remains: when `a\b.tf` and
  `a/b.tf` both exist, checkov's output cannot tell them apart, and its path is kept.
- `ash merge` keeps a finding in a committed file under the merge's output directory
  when the shards kept it. Each shard already dropped the results in its own output
  directories that are not files the repository committed, with its own git answer
  and run ID; the merge decided again, and outside git, where nothing counts as
  committed, it dropped them. The merge no longer applies that exclusion. The
  suppressions and ignore paths of the configuration the shards recorded still apply.
- `output_formats` in a config file chooses the reports. The report phase read it,
  but the config model did not declare it and ignores unknown keys, so the value was
  dropped when the file loaded: a config asking for `[sarif]` got every enabled
  report, and `ash config validate` called the key unknown. It takes a list, one
  name, or names separated by commas, as `--output-formats` does, and narrows the
  enabled reporters without enabling a disabled one; empty or null writes every
  enabled reporter, and an `--output-formats` list on the command line replaces it.
  `ash merge` uses the list the shards' configuration recorded. A misspelled name is
  an invalid configuration (exit 3), refused at the entry that holds it.
- `ash report` refuses an option that a plugin loaded from `ash_plugin_modules` does not
  accept, as a scan does: one message naming the option, exit 3. It loaded the plugins and
  built the reporter without checking, so `reporters.aws-security-hub.options.max_retries:
  three` printed pydantic's raw two-branch validation error and exited 1.
- `ash inspect findings` saves a second suppression for a rule and path that already
  has one. It skipped every suppression whose `rule_id` and `path` matched an
  existing entry, so a second line range of the same file, or a renewed expiration,
  was dropped while the status bar said "Suppression saved". Only an identical entry
  is skipped now, and the status bar then says the finding is already suppressed and
  nothing was written.
- `ash config lint --fix-unused` leaves a config a scan loads when it comments out
  every suppression. The key was left with only comments under it, which YAML reads
  as `suppressions: null`, and the next scan refused the file (exit 3). It is now
  `suppressions: []`, also for a list written at the key's own indent
  (`suppressions:` then `- path: ...` under it) with another list after it, and
  for entries that start with a `-` alone on its line. A `-` or `- text` line
  inside an entry, such as a line of a block `reason: |`, is no longer taken for
  the next entry, which left the unused entry after it in place.
- A refused configuration names the file in the command it suggests, which it
  prints last and unquoted: "Run: ash config lint --config <file>", with
  `--source-dir <dir>` when the scan's source directory is not the working
  directory (lint confines an `extends` chain to it, as the scan does). A path is
  printed only when it holds nothing but ASCII letters, digits and `_ . / : -`;
  otherwise (a space, `&`, `~`, a non-ASCII letter) the command says `<the file
  named above>`, followed by `--source-dir <the directory the scan scanned>` when
  it names a source directory, whichever of the two paths needed it. The line then
  ends in `>`, and a shell refuses it rather than run a different command. A bare
  `ash config lint` lints the current directory's config, which for
  `--config other.yaml`, `--source-dir`, or `ash plugin list --config` is a
  different file, and could report it clean.
- A discovered config that is a symlink to a file outside the source directory
  has its `extends` bases confined to that file's directory, as the same path
  named with `--config` always had. They were confined to the source directory,
  so such a config could extend files in the repository but not next to itself.
- `ash config init --config x.toml` and `ash config wizard --config x.toml` exit 1
  and write nothing. They wrote YAML into the file, which the TOML reader then
  refused, and `init --config pyproject.toml --force` would have replaced
  `pyproject.toml` with YAML. A config's format follows its suffix in upper or
  lower case: the checks matched lower case only, so on a file system that ignores
  case (the default on macOS and Windows) `init --config PYPROJECT.TOML --force`
  replaced the project's `pyproject.toml` with YAML, and a scan read it as YAML.
  `ash.TOML` and `PYPROJECT.TOML` are now read as TOML and refused by every command
  that writes YAML, and `ash.JSON` is read and written as JSON.
- A TOML config reads the same on Python 3.10 as on later versions. 3.10 has no
  `tomllib`, and the fallback was `toml` 0.10, which implements TOML 0.5 and refuses
  valid TOML 1.0 such as an array of mixed types; it is now `tomli`, the parser
  `tomllib` was taken from, declared for Python below 3.11.
- An MCP `--profile` in TOML (`p.toml`, or a `pyproject.toml` with `[tool.ash]`)
  registers. The check of its top-level keys read every profile as YAML, so a TOML
  profile was refused for "unknown top-level field(s)" made of its own text. The
  check now covers each base the profile `extends` too, whose unknown fields were
  ignored.
- `ash config validate-plugin-dependencies` exits 1, "does not name a project",
  for a config whose `project_name` is empty, which a scan and `ash config validate`
  accept; it exited 3 as for an invalid configuration. `ash config update` and
  `ash config wizard` describe an invalid file by field, without pydantic's text
  and the input values it quotes.
- `ash config update --set` and `--config-overrides` read a JSON list or object
  with whitespace after it (a trailing space, or the CR that `$(cat file)` keeps
  from a CRLF file) as JSON; it was taken as a string. The entries `config update`
  and `config init` write into lists (suppressions, ignore paths) hold only the
  fields that are set, not a `null` line for every other field.
- A scanner whose result is clean and whose content database is past its bound is
  `ERROR` under `content_db_staleness: fail`, not `PASSED`. The scan already failed
  on that database ("a clean result from a stale database is not evidence of a clean
  target"), while the scanner's per-target report, its row, `ash.flat.json` and the
  summary table said `PASSED` with 0 findings; with grype's database download
  refused, the summary showed grype `PASSED` and the scan exited 1. The scanner's
  errors name the database. A scanner that found something stays `FAILED`, and under
  `warn` nothing changes. The exit-1 message and the MCP payload still report it once,
  as the stale database with its refresh advice, and not also as an incomplete
  scanner; the scanner counts as having run, and `ash merge` merges a shard whose
  scanners are all in this state and then exits 1 on the stale database. A workspace
  project reports it the same way: its outcome gains `stale_content_databases`,
  leaves a scanner listed only for its database out of `incomplete_scanners`, and
  still fails; the MCP coverage view and the workspace report name the database.

- A scan that exits 1 because no scanner ran (every scanner `SKIPPED`, for example
  `--exclude-scanners` naming them all) or because a rule could not be evaluated now
  says so, listing the scanners or the rules. Both used to end with "ERROR (1)
  Exiting due to exception during ASH scan", although nothing had raised; that line
  is now printed only when a scan produced no results. A scan in which every scanner
  ran and found something no longer logs "Metrics consistency check failed"
  warnings: the check ran at the end of the scan phase, before the scanner rows it
  compares exist, and now runs after they are written.
  When the scan exits 1 for a `MISSING` scanner, the message prints the reason the
  scanner recorded under its name, and when every `MISSING` scanner has one it points
  at them instead of saying "Install the missing tools", which was wrong for
  npm-audit offline with npm installed.

- A scanner's own results file, `scanners/<name>/<target>/ASH.ScanResults.json`, is
  graded against the threshold the summary uses. It was graded against the scanner's
  own `options.severity_threshold` alone, which is unset unless the config sets one,
  and an unset threshold turns the gate off; the summary, the scanner row and the exit
  code fall back to `global_settings.severity_threshold`. So a scanner with findings
  at or above the global threshold and none of its own was `FAILED` in the summary and
  `PASSED` in its own file (the documentation's ruff-security sample: two HIGH
  findings, "FAILED MEDIUM (global)" against a `PASSED` file). Both now come from
  one helper and agree.

- A scanner with nothing to scan in the project is `SKIPPED` whether or not its tool
  is installed. cdk-nag and cfn-nag pick CloudFormation templates out of the scan set
  and npm-audit picks `package.json` files with a lockfile beside them; with the tool
  installed and no such file they ended `SKIPPED` (npm-audit `PASSED`), and without
  it `MISSING`, so on a machine without Node.js the scan of a Python project exited 1.
  ASH now asks the scanner's own file selection when the tool is absent, and a
  scanner that has a template or a lockfile to scan and no tool is still `MISSING` and
  still fails the completeness gate. A JSON or YAML file that cannot be read counts
  as a possible template, and one that does not parse counts when a second read (with
  unknown YAML tags and JSON comments allowed) finds `Resources` or its text contains
  `AWSTemplateFormatVersion` or a `Type: AWS::` resource type; an `mkdocs.yml` with
  `!!python/name:` tags, Helm templates and a `tsconfig.json` with comments do not
  count, and a truncated template does. The row's
  `skipped_reason` says what was looked for. npm-audit now counts each lockfile it
  audits as a target, so with npm installed and no lockfile it is `SKIPPED` rather
  than `PASSED`, and it audits `npm-shrinkwrap.json` too.

- cdk-nag and cfn-nag scan a JSON CloudFormation template indented with tabs. YAML
  forbids the tabs, so the YAML parser rejected the file and both scanners passed over
  it as not CloudFormation; a template is now read as JSON when YAML rejects it.

- cdk-nag and cfn-nag read a date-like value such as `2024-01-15` as text, as
  CloudFormation does, so a value no calendar holds (`2024-13-01`) no longer stops a
  template from loading. A cdk-nag finding's code snippet now quotes such a value:
  `Value: '2024-01-15'` where it printed `Value: 2024-01-15`. No finding fingerprint
  reads the snippet.

- cdk-nag and cfn-nag count a file as a template they could not evaluate only when
  its structure is one: a top-level `Resources` mapping. That covers a value YAML
  cannot build (`!!binary` text that is not base64, a merge key whose value is not a
  mapping) and a template nested past the YAML loader's recursion limit, about 330
  levels of mappings or 490 of sequences; each is a failed target, so the
  completeness gate sees it, on every Python version. A JSON template indented with
  tabs, which YAML refuses, is decided as the same template indented with spaces.
  One YAML refuses for another reason (a key longer than 1,024 characters) is read
  as JSON to 400 levels; nested deeper, it is passed over as a file ASH could not
  parse, on every Python version, because only a JSON read could see its structure,
  and JSON reads to a different depth on each version. The exception is one nested
  past 1,000 levels before YAML reaches the long key, after the deep part or inside
  it: that counts as a failed target, as any file nested that deep does. A file
  whose root is a mapping nested past 1,000 levels counts as a failed target without
  the rest of it being read, and a file whose root is a sequence is not a template,
  decided at its first node without a parse. A Helm
  chart or Kubernetes manifest that carries a template as text is passed over,
  whatever the text inside it says, tabs in it or not. A YAML merge key
  (`<<: *defaults`) is merged into its mapping, though CloudFormation itself rejects
  merge keys.

- The scanner rows in `ash_aggregated_results.json` and `ash.flat.json` carry their
  real values. The rows are rebuilt before the report phase, and the rebuild kept only
  the status and the counts, so a `MISSING` row said `dependencies_satisfied: true`
  (and `dependencies_missing: false` in `ash.flat.json`), a scanner
  `--exclude-scanners` removed said `excluded: false`, and every row said
  `exit_code: 0`. Now `dependencies_satisfied` is `false` on a `MISSING` row,
  `excluded` is `true` for a scanner the run left out, and `exit_code` is the tool's
  exit code (the highest over its targets) or `null` when no tool ran, which includes
  a scanner that had nothing to scan and one that started no tool for its targets
  (npm-audit with a `yarn.lock` and no yarn, cfn-nag with only a template the model
  rejects). Each `MISSING`
  row has a `missing_reason` (the tool that was not found, the reason the scanner's
  dependency check gave, or that it could not be sandboxed; cdk-nag names node or the
  CDK packages) and each `SKIPPED` row a `skipped_reason`; both fields are new in the
  schema and in `ash.flat.json`'s `scanner_metrics`, and are `null` on other rows. A
  path under the home directory in a reason is written with `~`; ash.log keeps it in
  full. ash.log names each `SKIPPED` and `MISSING` scanner with the reason its row
  carries, at WARNING or above for a `MISSING` one, including a scanner
  `--exclude-scanners` or a shard left out and one the scan found `MISSING` or
  `SKIPPED` after it ran; for one found so on a single tree, per tree, naming the
  tree and the reason. A scan started through the MCP workspace tool names the
  tool's `scanners` and `excluded_scanners` parameters where a CLI scan names
  `--scanners` and `--exclude-scanners`, in the `skipped_reason` and in the refusal
  of a selection no project could run. A workspace's own `ash_aggregated_results.json`
  carries the two fields too: a rolled-up `SKIPPED` or `MISSING` row names each
  project at that status with its reason (`api: <reason>; web: <reason>`), and each
  project's entry in the `workspace` block lists its own in `scanner_reasons`, with
  the first error each `ERROR` scanner's reports recorded.

- `./ash --offline` and `Invoke-ASH -Offline` rebuild an offline image with a current
  grype database and current semgrep and opengrep rulesets. Both passed the build date
  as `BUILD_DATE`, which the Dockerfile does not declare, so the step that downloads
  them was served from the build cache and a rebuild without `--force` kept the
  databases of an earlier build. They now pass `BUILD_DATE_EPOCH`, as `ash
  build-image` already did.
- An image rebuilt without `--force` gets current OS security updates from every
  entrypoint at most once a day, and an offline one also a current grype database and
  current semgrep and opengrep rulesets. `./ash` and `Invoke-ASH` passed the build date
  as `BUILD_DATE`, which the Dockerfile does not declare, so the `apt-get upgrade` step
  and the step that downloads the databases were served from the cache, and their
  rebuilds kept an earlier build's OS packages and databases. `ash build-image`,
  `ash scan --mode container` and the Terraform image pipeline passed
  `BUILD_DATE_EPOCH` as the current time, so each of their builds re-ran every step of
  the `core` stage. Every entrypoint, the CDK image build included, now passes
  `BUILD_DATE_EPOCH` on every build, set to UTC midnight of the day, and the Dockerfile
  declares it just above the `apt-get upgrade` step, which echoes it. What a rebuild
  costs: later the same day, nothing, since it is served from the cache. The first on
  a new day re-runs `core` from the `apt-get upgrade` step down (the OS packages,
  Node.js, the scanner tools, the ASH package and, offline, the database download) and
  the stage built on it, so it needs network access; the base image and the
  `uv-reqs` stage come from the cache. To scan on a host without network access, pass
  `--no-build` (`-NoBuild` to `Invoke-ASH`), which runs the image already there
  instead of rebuilding it first.

- **The CDK image build checks out the `AshVersion` it is given, commit SHAs
  included.** It cloned with `git clone --branch`, which refuses a commit SHA, so
  following deploy/README.md's advice to pin a commit failed every image build, and
  it then let ASH's Dockerfile clone the ref a second time. It now fetches that one
  ref and builds the fetched tree with `INSTALL_ASH_REVISION=LOCAL`, as the Terraform
  image pipeline does. A tag, a branch or a full commit SHA works; an abbreviated SHA
  does not. A value starting with `-` is no longer read as an option of `git fetch`.

- **The Terraform CodeCommit gate's docs recommend extra arguments the gate
  accepts, and both Terraform targets hand ASH the severity they validated.** The
  gate module's example and READMEs set `ash_scan_extra_args = "--changed-files-only
  --base-ref origin/main"`, which the gate refuses on purpose, so a gate deployed as
  documented reported an error on every pull request; they no longer do. The gate and
  the CodePipeline executor validated `lower(var.min_severity)` but passed ASH the
  value as typed; they now pass the lowered value.

- **The deploy targets default to the ASH release they ship in, and name a usage
  error.** Nothing moved the CDK `AshVersion` default or the Terraform examples'
  `ash_version` at a release, and the examples still named v3.6.0. They now all name
  the release these files belong to, and `cz bump` moves them, so at each release tag
  they name a release with the options the targets pass. ASH releases after 3.7.1
  exit 5 for a usage error, and the CDK and Terraform gates and the Terraform merge
  action report it as one and say what to check, instead of reporting an
  unexpected exit code.

- **`--changed-files-only` narrows every report, not only `ash.sarif`.** Scanners
  still scan every file; findings located outside the files changed against
  `--base-ref` are now dropped before the summary counts and any report are
  written, so the HTML, Markdown, text, CSV, flat-json, JUnit, GitLab SAST, OCSF,
  GHAS and YAML reports, the summary and the exit code agree. Before, only
  `ash.sarif`, `ash_aggregated_results.json` and the exit code were narrowed,
  after the other reports had been written with every finding. The per-scanner
  raw outputs under `scanners/` still contain every finding. Results record
  `metadata.changed_files_only: true`, and a report over saved results keeps it.

- **bandit `excluded_paths` entries naming a file, or a glob, now take effect, and
  no entry reaches above the scanned directory.** Each entry became
  `**/<path>/**`, which bandit matches only inside a directory of that name, so
  `app.py` never skipped `app.py` and `tests/*` skipped only files in
  subdirectories of `tests`. Unanchored, it also matched the scanned directory's
  own path: a project inside a directory named `venv` or `node_modules` (ASH's
  built-in entries) had every file skipped and bandit reported nothing, and
  `src/vendor` scanned from a directory named `src` skipped the top-level `vendor`
  too. Each entry is now anchored at the scanned directory and still names a path
  anywhere below it: a file or glob skips the files it matches and the files of the
  directories it matches, and `dir/` or `**/dir/**` the files of such directories.
  **A file or glob entry now skips files it did not before, so a scan can report
  fewer findings.** An entry with no bandit form (a `,`, or a `.` or empty path
  component) skips nothing and logs a warning.
- **`ash merge` reaches a verdict on a shard whose recorded reports do not name
  their scanner.** A scanner's status is read from the report recorded for it, a
  mapping that names the scanner. A results file from another ASH version, or one
  put together by hand, can hold something else there: the sample results under
  `tests/test_data/outputs` hold reports without `scanner_name`. Merged with
  `--no-fail-on-incomplete-scanners`, such a shard raised `KeyError:
  'scanner_name'` as a traceback, and a value that was not a mapping raised
  `TypeError`. A report that names another scanner was read as this one's status:
  under bandit, a grype report saying `PASSED` or `MISSING` gave bandit that status.
  None of these is read as a report now. The scanner then has no recorded
  status, which reads as an error, as it always has for a scanner with nothing
  recorded, and the merge exits on the findings. Without the flag the shard is
  still refused for completing none of its scanners.
- **`ash merge` says why a shard did not load without repeating the file.** The
  refusal for a `--results` file that does not parse or validate quoted pydantic's
  `input_value`, named the file's own keys in the error location, repeated values
  that ASH's validators quote (a suppression's expiration, `metadata.generated_at`),
  and printed control characters raw, so a key holding a newline could put a line
  starting `::error` on stdout, which GitHub Actions reads as a workflow command.
  Each error now reads `Invalid value at '<location>': <message>`: the location
  names only fields of the results schema and shows any other key as `<key>`, the
  file's strings are replaced by `<value>`, control characters are written as
  `\xNN`, and a file that is not UTF-8 is described by the offset of its first bad
  byte. The other refusals and warnings, the coverage refusals included, and every
  reason an exit 1 gives (incomplete scanners, no scanner run, a failed converter, a
  rule not evaluated, a stale content database) show the scanner, converter and
  rule names, statuses, reasons and paths they quote the same way, and are logged as
  text rather than markup: a scanner name or a `--results` directory name holding a
  newline put a `::error` line on stdout through them. Every control,
  format and line-separator character in such a value is written as `\xNN` or
  `\uNNNN` (a bidirectional override or a zero-width space included), and the
  first `#` of a `##[`, `##vso[` or `##teamcity[` command is written as `\x23`,
  because GitHub Actions and Azure Pipelines find those anywhere in a line. A line
  of a refusal that would start with `::` or `##` has its first character written
  out the same way. The two merge warnings are logged as text rather than markup: a
  scanner named `[/x]` raised a markup error that replaced the merge's exit code
  with 1. A named pipe called `ash_aggregated_results.json` beneath a `--results`
  directory is no longer taken as the shard's results (`ash merge` waited on it
  forever), and neither is a symlink beneath it: not one by that name, and not a
  linked `ash_output` or `.ash` directory at the places checked first, any of which
  could point outside the tree. The refusal says symlinks beneath `--results` are
  not followed. A `--results` path given directly is still followed.

- `ash dependencies install` judges a tool by the resolution a scan uses. A scan
  decides whether a scanner's tool is there with the plugin's own dependency
  check, which for some plugins can start a tool the PATH lookup does not find,
  so a requested tool every scan starts exited 1 with "requested tool(s) still
  not on PATH", and a full run counted it absent. For a plugin the verdict
  counts that is not run through uv and that declares its check can start the
  tool off PATH (`resolves_tool_off_path`, a class attribute that
  `ScannerPluginBase` declares False), the post-install sweep asks that check
  when the PATH lookup does not find the tool; a tool it can start is present,
  named in the summary under "Not on PATH; a scan can run them". A tool nothing
  can start keeps the exit-1 verdict, with the failure line "<plugin>: not on
  PATH, and its own dependency check (asked in check-only mode) did not find a
  tool to start", where the plugin is named with any programs it needs besides
  its command that the sweep did not find, followed by the plugin's own
  reason when it gives one: a reason its check recorded, or its own
  `missing_dependency_reason()`, with values read from the environment (the
  run's configuration's and the plugin's own) redacted and the home directory
  written as `~`. Neither of the base hook's generic answers is quoted there:
  its tool not found on PATH, whose advice is to run `ash dependencies
  install`, and its dependency check failed, which points at ash.log. That
  holds whether the plugin keeps that hook or its own hook falls back to it.
  An undeclared plugin's tool is judged by the lookups alone, and a tool run
  through `uv tool run` is judged by uv's tool list. detect-secrets declares
  it: its check runs the library in-process, so `ash dependencies install
  --tool detect-secrets` succeeds without the `detect-secrets` console script,
  which a scan does not start. The sweep says when it asks a check, the way
  each install command is shown, and the row says what the summary says:
  "INSTALLED (a scan can run it)", "VERIFIED (a scan can run it)" for a pinned
  binary already on disk with the pinned SHA256, or "RUNNABLE BY SCAN", with
  the check named in the Resolved to column, rather than a not-on-PATH warning
  beside "a scan can run them". A check that raises is said too, named by
  plugin and exception type without the exception's text. The sweep asks the
  check, and its reason, in the sandbox scope a scan asks it in, and in
  check-only mode, the way `ash plugin list` does: answering costs no install
  and no download, and an outcome whose install command failed keeps its
  exit-1 verdict unasked.

- `ash dependencies install --tool ArchiveConverter` works again. Building each plugin
  from its own config section renamed the archive converter's selector to `archive`,
  so the old spelling exited 2 as an unknown tool. It is now accepted as a deprecated
  alias for `archive` and prints a deprecation warning to stderr. An unknown name
  still exits 2 (see Breaking changes).

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
- **A spawn that raised anything other than `OSError` is reported as a tool that never
  started too.** A `RuntimeError` from preparing a sandbox wrapper, a `ValueError` from
  `Popen`'s own argument checks, or any other exception from the spawn still went to
  the helpers' catch-all, which returned exit code 1, and `ScannerPluginBase._run_subprocess`
  returned `{"error": ...}` with exit code 1 for anything raised before a run. A
  scanner whose `scan()` ignores the response was then reported PASSED. These now
  return 127 and `spawn_failed` with the reason as the stderr, log the reason on one
  line, and the scan is ERROR.
- **A tool that ran, and whose output ASH could not record, keeps its exit code and
  is an ERROR.** An exception after the tool exited, such as an `OSError` writing its
  stream logs or one in `_run_subprocess`'s own handling of the response, answered
  exit code 1, which most scanners read as "ran and found issues", so a scanner that
  ignores the response was PASSED. The response now keeps the tool's own exit code
  with `post_run_error: true` and the error, the uv path carries it too, and the
  scan is ERROR: "<scanner> ran on <target>, but ASH could not record the scanner's
  output". A response that carries an `error` always sets one of `spawn_failed`,
  `post_run_error` or `timed_out`.
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

- **What ASH reads from uv no longer depends on the terminal's width or color
  settings.** uv lays its messages out at the caller's `COLUMNS` and colors them
  under `FORCE_COLOR` or `CLICOLOR_FORCE` even into a pipe. At `COLUMNS=20` the
  check of a pre-installed tool read uv's "No solution found when resolving" split
  across lines, so a requirement the environment does not meet was reported as
  unverifiable, and `uv cache dir` returned the cache path wrapped in color codes.
  The uv calls whose output ASH reads (the pre-installed tool check and its version
  probe, `uv tool list`, the tool version probe and `uv cache`) now run without the
  caller's `COLUMNS`, `LINES`, `FORCE_COLOR`, `CLICOLOR_FORCE`, `TTY_COMPATIBLE`
  and `TTY_INTERACTIVE` and with `NO_COLOR=1`, and uv's resolver messages are
  matched however they are wrapped. The offline message that quotes uv's resolver
  error quotes it without color codes.

- **`-f`/`--output-formats` takes every reporter ASH ships.** `github-ghas`,
  `gitlab-sast`, `gitlab-cyclonedx`, `unused-suppressions`, `aws-security-hub`,
  `bedrock-summary-reporter`, `cloudwatch-logs` and `s3` were refused as "not a
  valid format" with exit 2, so no `-f` list could include them (and every list
  left them out). They are accepted by `ash scan` and `ash merge`. `ash report
  --format` already took any reporter's name; its help and shell completion now
  list these too.

- **`ash report` writes only the report to stdout.** Log lines and errors go to
  stderr, and the report is the reporter's output, not re-indented, highlighted
  or wrapped at 80 columns, so `ash report --format sarif > ash.sarif` is a SARIF
  file; on an interactive terminal JSON is still indented and Markdown rendered
  (a link shows its target and is not a terminal hyperlink), and control
  characters are shown as `\xNN` and Unicode bidirectional controls as `\uNNNN`
  (`\u00NN` in JSON, indented or not, so it still parses to the same document),
  with the backslashes of text that would read as such an escape doubled; a
  Markdown report holding either is printed as that escaped text, unrendered.
  With no results file the command names the paths it checked and exits 1 without
  creating anything; it used to fail with "expected str, bytes or
  os.PathLike object, not NoneType" after creating `.ash/ash_output`. Its error
  messages show the values they quote (paths, exception text, the `--format`
  value) as text: a `[/x]` in one no longer replaces the message with a
  MarkupError, a `[link=...]` is not made a hyperlink, and on a terminal their
  control characters, and those of the `--debug` traceback, are shown as in the
  report.

- **The exit code reads `reports/ash.sarif` only when this run wrote it.** A
  report over saved results (`--use-existing`) without the `sarif` format, or
  `ash merge` into a reused `--output-dir`, let an earlier run's `ash.sarif`
  decide the exit code. Only a regular file counts: a symlink at that path is
  never read as this run's, whatever it points at.

- **`ash.ghas.sarif` has a rule for every result it lists.** A result whose rule
  the run did not declare was written with no rule entry, so GitHub had no
  `security-severity` for it. The rule is now listed and scored from its results
  the way a declared rule is. A result that names its rule as `rule.id` rather
  than `ruleId` keeps it too; it was written with neither.

- **The GenAI guide no longer has a "Severity Discrepancies" section.** It, and
  the matching first known pitfall, said Markdown and HTML summaries may show
  CRITICAL where the JSON shows HIGH; every report now grades a finding the way
  the summary and the exit code do. `ash get-genai-guide` no longer offers the
  section in its help or in the message after a download.

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
  against the SPDX 2.3 schema; see [Output formats](https://awslabs.github.io/automated-security-helper/reference/reporters/#spdx).
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
  Without `-OCIRunner` and with no runner set in the environment, PowerShell bound
  the parameter to an empty string rather than `$null`, so `Invoke-ASH` tried to run
  a runner named `""` and always failed. It now falls back to the first of `finch`,
  `docker`, `nerdctl`, and `podman` on PATH, as `./ash` falls back when `OCI_RUNNER`
  is empty. Which variable it reads and the order it tries are under Behavior
  changes.

- **`Invoke-ASH` runs no part of a path or a value.** The runner is called with an
  argument array, and each value is one argument, never a string for
  `Invoke-Expression`, which parses its input as PowerShell: there a source or
  output directory or an image name holding `$(...)`, or a value holding one of
  the typographic single quotes U+2018, U+2019, U+201A, or U+201B, would run what
  it holds.

- **`utils/ash_helpers.sh` works when sourced.** It took the checkout's location
  from `$0`, which in a sourced file is the shell, so under bash `invoke-ash` ran an
  `ash` in the current directory; under dash, `sh` on Amazon Linux and macOS, and
  ksh93 the file did not load, because `invoke-ash() {` is not a valid function name
  there. It now finds itself under bash, zsh, and ksh93, following a symlink to it or
  to its directory. Under dash and other POSIX shells, set `ASH_ROOT_DIR` to the
  checkout before sourcing it, and without one it says so and returns 3, the code ASH
  uses for input it refuses. A preset `ASH_ROOT_DIR` is also used when the file's own
  location has no `ash` above it. The command is the function `invoke_ash`;
  `invoke-ash` remains, as a function in bash and zsh and as an alias elsewhere.

- **`devfile.yaml`'s install command runs `uv sync`.** It sourced an env script
  under `~/.cargo`, which uv's installer no longer writes, so the command stopped
  there. It now installs uv into `~/.local/bin` and puts that directory on PATH in
  each command. DEVELOPMENT.md shows the same commands, and the GitHub Actions
  example in the uv tool installation guide now adds `~/.local/bin` to PATH, where
  it added a directory under `~/.cargo`.

- **`quickstart/README.md` no longer describes a deleted Cloud9 template.** The
  template was removed in v3 and AWS Cloud9 no longer accepts new customers. The
  page now points to the quick start guide and to `deploy/`.

- **In a configuration file, an unquoted `off`, `no` or `false` for `sandbox.mode`
  means the mode `off`.** YAML reads those words as a boolean, so the usual way to
  write the mode `off` was refused as invalid. An unquoted `on`, `yes` or `true`
  names no mode and is refused with a hint to quote the value and a list of the modes.

- **An operator's configuration file that writes `sandbox` as anything but a mapping
  refuses the load.** This holds for the document and for its patch operations, and
  it refuses as a mode outside the known set does: with exit code 3, naming the file
  and never the value written. Before, a later file in the chain could replace the
  value, and the scan ran without the sandbox the operator's own file had tried to set.

- **The target counters in loaded results are integers, not coerced values.**
  `targets_attempted` and `targets_failed` on `ScanResultsContainer` and
  `ScannerMetrics` reject a string, a float or a boolean with a validation error.
  They used to be coerced: `"3"` became 3 attempted targets, and `False` became 0
  failed targets, which let a result that recorded a failure grade as if nothing had
  failed.

- **detect-secrets reads its baseline relative to the scanned directory.** A relative
  `baseline_file`, and the `.ash/.secrets.baseline` and `.secrets.baseline` files ASH
  looks for when none is configured, are resolved from the scanned directory instead
  of the working directory, and the file that is checked is the file that is read. A
  baseline under the output or work directory is ignored unless the operator's own
  configuration names it. A configured baseline that is missing or unreadable is
  logged as a warning, and the scan continues with the default settings.

- **A SARIF run that did not finish is no longer marked `executionSuccessful` for
  cfn-nag and npm-audit.** A run that timed out, was cancelled, was rejected or was
  signaled, or whose output ASH could not record, now reports `false` even when its
  exit code is one the scanner accepts. cfn-nag accepts any non-negative violation
  count, so the exit code alone never said whether the run completed.

- **The container image installs cfn-nag's gems from the committed `Gemfile.lock`.**
  The Dockerfile copied only `automated_security_helper/assets/Gemfile`, so every build
  resolved cfn-nag's dependencies again and could install gem versions the lockfile does
  not list. It now copies the lockfile beside the Gemfile and runs Bundler with
  `BUNDLE_FROZEN=true`, so a build installs exactly the locked gems and fails when the
  Gemfile and the lockfile disagree.

- **Checks of one pre-installed tool copy that run together probe it once.** The
  project instances of one scanner in a workspace scan check the same copy on PATH at
  the same time. Each ran its own `--version` probe (up to 120 seconds) and uv dry run,
  because a probe's answer was stored only when it ended. The checks now take a lock
  per copy, and the ones that wait answer from the answer the first probe leaves. A
  check the scanner sandbox refused stores nothing, so the next one probes for itself.
  A scan that is cancelled while a check waits stops there instead of waiting the
  probe out.

- **The sentence that says ASH could not stop a tool is written once.** The default
  reason, the generic reason, the spawn record's reason, and the two cancels the spawn
  layer raises (a kill the kernel refused at the server's stop, and a cancel whose stop
  did not end the child) each spelled "which may still be running" for themselves.
  They now share one ending and one composer in `utils/subprocess_utils.py`, so a
  change to the ending reaches all of them. The words each one says are unchanged.

- **A tool that could not start is reported once in the scan's failure message.**
  The first sentence of the message used to end with the stderr (or the error) of
  the failed start, and the "Stderr:" part then showed the same text again. The
  first sentence now says only that the tool could not start and produced no
  results file, and the text appears once, after "Stderr:", redacted as the
  scanner's other report lines are. The copy in the first sentence was the text as
  the runner wrote it, and where the scan executor redacted the message it got only
  the plain-value layer, which matches a value as written and so misses what uv
  respells and the `--from` and `--with` inputs that hold one. gitleaks keeps its
  stderr out of its messages by design, so its message for a tool that could not
  start now names its log and no longer quotes the cause.

- **A scan reads back its saved scan set only for the tree it was built from, and
  scanners that finish together for different trees no longer replace each other's
  pair.** The scan set is saved once per scan, in `ash-scan-set-files-list.txt` and
  `ash-ignore-report.txt` with a record in `ash-scan-set-run.json`, and the scan's
  scanners and converters read it back. The record names the source, as the caller
  spelled it and made absolute, and the ignore files, and a call reads the pair back
  only when they match. A call that asks about another source directory, or with other
  ignore files, walks its own tree and leaves the saved pair as the scan's first call
  wrote it; it is not handed the first tree's list. A relative source from another
  working directory is another tree, and so is the same directory spelled another
  way, which gets its paths in its own spelling. Scanners in threads that finish their
  walks together for different trees take one lock for the record check and the
  write, so the first writes the pair and the others leave it. On Windows with
  `PYTHONLEGACYWINDOWSFSENCODING=1`, which makes Python's filesystem encoding a code
  page, the git lookups (the changed files behind `--changed-files-only`, the
  repository root, the git directories and the worktree and index listings) now read
  git's output as UTF-8, as git for Windows prints it. A changed file with an accented
  letter in its name used to decode to other characters, match no file, and lose its
  findings.

- **A scan's saved scan set stays the scan's own when a later call lists another
  tree, and ignore files are compared by the file they name.** The scan's record in
  `ash-scan-set-run.json` alone says whether it wrote the pair. A pair that was changed
  after it was written, or that holds a file name with a newline in it, is still the
  scan's: a call for another source or other ignore files neither replaces it nor takes
  it over, so the scan set the scan reports stays the one its first call built, and a
  call with the first call's inputs writes it again. A record that is not the shape ASH
  writes names no owner, and the next call writes the pair. A scan set holding a name
  with a newline, which no newline-separated list can give back whole, is recorded with
  `sha256` set to null, and every call after the first still walks. The ignore files
  are compared by the file they name, joined below the source as the walk joins them.
  The same file written relative or absolute, with a `./` prefix or with repeated
  separators, named twice, or named in another order, is one ignore file and reads
  the saved pair back. `sub/../rules.txt` is not
  `rules.txt` where the kernel resolves `sub` first, which can be a link or nothing at
  all, so that spelling walks again.

- **`set_source_git` clones with LFS smudging off and says why a redirect failed.**
  Every git command of a delivery already ran with `http.followRedirects=false`.
  The environment git runs with now also sets `GIT_LFS_SKIP_SMUDGE=1`, so a checkout
  writes git-lfs pointer files and starts no transfer, whatever the server's own
  environment holds. A failed clone of an `https://` URL now adds, as a sentence of
  its own after git's text (alone when git printed nothing), that HTTP redirects are
  not followed and that the URL the host redirects to (for example with the `.git`
  suffix) is the one to give. The note is worded as a condition, because git's text
  does not say a redirect was the cause. The streamable-HTTP docs say the same.

- **An MCP session that ends keeps its tree while a scan in another server sharing the
  workspace root reads it, and the session registry no longer grows on a stateless
  server.** `end_session` now also looks for a running scan's locked entry under
  `<workspace root>/.ash-mcp-scans/<session id>/`, which any server sharing the root can
  hold, and not only for a scan in its own process. While one is held, the tree, the
  bound profile and the delivered-source record stay, and the TTL sweep removes them
  once the workspace is past its TTL and no scan holds it. The session is taken with
  `session_for`, so a scan that recreates the id right after the lookup is seen, and
  ending the stdio session opens no presence registry. A stateless server that takes
  the upstream session id sees a new id per client and no end of session; past 1024
  sessions the registry now drops the entries that were not requested for 5 minutes and
  hold no scan, claim, write, delivered tree or bound profile.
- **A scan whose coverage was incomplete is recorded as incomplete when its runner is
  cancelled while the previous results are settled.** The scan's thread marks a scan
  that returned, exited 0, or exited for incomplete coverage as one with results of its
  own, then drops the previous results. A runner cancelled in between closed the entry
  from the mark alone: an incomplete scan with the exit's own coverage payload, where the
  runner's own close records the coverage assessed from the results, and a completed scan
  with no coverage and no threshold. The thread now works out the
  status, coverage and severity threshold once, when it decides, and keeps them beside
  the mark. The runner's own close and the close through the mark both read them, so an
  incomplete scan is closed as incomplete with the coverage assessed from its results,
  a completed one with its assessed coverage and threshold, and one scan reports the same
  whether or not the loop cancelled its runner during the drop. The coverage of an
  incomplete scan is the facts assessed from its results when they name a gap, and the
  exit's own reasons when they do not.
- **The scan timeout leaves a scan that has kept its results alone.** The timer skipped
  such a scan only after the runner had finished, which comes after the previous results
  are dropped, so a timer falling due during the drop closed the entry as failed over
  results already on disk. The timer also closed the entry and set the cancel event in
  two steps, which the scan thread could fall between. The check of the mark, the close
  and the set of the event are now one step under the lock the thread decides under, and
  the note that a scan was recorded after its runner failed is written only when the
  close took effect.
- **Ending a session deletes its workspace under a hidden name, and a request for the
  same session id during the delete keeps the workspace it built.** The workspace is
  renamed to `.<session id>.deleting-<uuid>` first and that is deleted, and the registry
  entry is dropped without touching the disk. Before, the tree was deleted at the
  session's own path and the entry's drop then renamed and deleted whatever stood there.
  What a delete cannot remove stays under the hidden name, and the TTL sweep removes it
  once it is older than the TTL, with or without the session marker. The rename sets the
  directory's modification time to the time of the rename, so a delete in progress is
  never past the TTL, and the sweep logs once a leftover it cannot delete. The sweep
  removes an entry of that shape only when no registry entry and no scan-presence
  directory owns the name, and a session id with exactly that shape (a dot, a name,
  `.deleting-` and a uuid) is refused wherever ids are validated, because it would name a
  live tree the sweep took for a leftover.
- **A zip re-delivery keeps the previous source when it cannot be renamed aside.** A
  directory with a file held open, which Windows does for a scanner or an indexer,
  refuses the rename. The swap tries it up to five times, 0.2 seconds apart (see the
  entry on renaming a tree again), and when the file system refuses every attempt the
  delivery ends with `session_workspace_unavailable`: the previous tree stays whole at
  `source/`, the recorded source names it, the staging directory is deleted, and the
  uploaded zip is kept so the same `set_source_zip_finalize` can be sent again. The
  previous tree is not deleted where it stands, because whatever blocks the rename of a
  directory usually blocks deleting it too, and that fallback ended with a half-deleted
  tree, the new tree discarded and a record naming a path nothing creates. A plain
  `OSError` from the swap is reported with the same `error_type` by
  `set_source_zip_finalize`.
- **A scan that kept its results is closed even when recording its coverage fails.**
  When the close of a finished scan with its coverage and severity threshold raised, the
  runner's error arm closed the entry with the same two values, so a failure that came
  from them came again and left the entry running. The arm now closes the entry with its
  status alone and logs what it left out. On the scan's thread, an error while working
  out the coverage payload or the severity threshold of a scan that has results no longer
  leaves the previous results neither dropped nor put back and closes the scan as failed:
  the scan is settled as one with results, with its status alone. The runner's return arm
  and its incomplete-coverage arm work out the same two values for a scan whose thread
  recorded no close (its cancel event was set), and an error there used to leave the task
  with the entry still running, or close a scan that had ended normally as failed; they
  no longer raise either.
- **A scan that exited for incomplete coverage keeps its gap when its close cannot be
  worked out.** When the coverage payload or the severity threshold of such a scan could
  not be worked out on the scan's thread, the scan was settled as incomplete with no
  coverage, which the scan registry refuses, so the runner's own close raised and the
  entry was left unclosed. The scan is now closed as incomplete with the scanners the
  exit's own rows name and no severity threshold.
- **Ending a session deletes a workspace it could not examine.** The check that sets the
  workspace aside for its delete read EACCES, EIO and ESTALE as "nothing is on disk", so
  the end reported everything removed and dropped the record while the tree stayed. Only
  a missing path means nothing is there; any other error from the stat leaves the delete
  to run at the workspace's own path.
- **`session_workspace_unavailable` is answered only for the session's workspace.** A
  workspace directory that cannot be created is that error for the zip chunk and the git
  delivery as well as the zip finalize. An error from reading the uploaded archive or
  extracting one of its members is no longer mapped to it by `set_source_zip_finalize`:
  it reaches the tool's own handler and is answered with its class name.
- **The TTL sweep does not retry a leftover it has already reported.** A leftover under
  a hidden delete name that holds files this account cannot remove was logged once but
  walked again, with two full delete passes, on every sweep. It is now left alone for the
  life of the process once reported, until it is removed by hand or the server restarts.
- **The note on a failed https clone that redirects are not followed is a sentence of
  its own.** It follows git's text after a full stop, is worded as a condition because
  git's text does not say a redirect was the cause, and stands alone when git printed
  nothing. It was appended with no full stop, and with a leading space when git printed
  nothing.
- **A refused scan presence lock is reported once per run of refusals, with the error
  and the file that failed.** When the lock cannot be taken, `end_session` leaves the
  tree on disk and clears the server's own record of the session. The TTL sweep takes
  the same lock once per pass, before it looks up any session, and removes the tree at
  the first pass that can take it. The one warning names the lock path, the errno, its
  name and its text, the file that failed, and what the refusal means for the next pass:
  a filesystem that reports it cannot lock files repeats until `ASH_MCP_WORKSPACE_ROOT`
  names another directory, and any other failure may clear. `end_session`, the sweep and
  a scan share one latch, and a pass that takes the lock clears it, so a refusal after
  that is reported again. A scan whose sandbox cannot be examined (EACCES, EIO, ESTALE)
  runs unregistered with a warning of its own that names the session, the errno and the
  file, instead of silently; that warning does not use the latch. A stdio server or scan
  whose registry cannot be used at all runs unregistered with the lock warning.
- **A stdio server or scan that cannot lock its own presence entry does not start, and
  `ash mcp` prints why and exits 3.** Each stdio server and each scan holds a locked
  entry that tells the other servers sharing the workspace root it is alive. One that
  ran without it would read as dead to an exiting sibling, which would remove the
  default workspace under it. The error names the entry and the error that refused the
  lock, and `ash mcp` prints it alone, also with `--quiet`, instead of "MCP server
  failed" and a hint to check system resources. A stdio server that registers also
  drops the entries of killed servers.
- **A `set_source_git` delivery that fails in a way nothing handles leaves no clone
  behind and keeps the previous source.** A git command that exited non-zero, ran past
  its time or could not be started already removed the clone it made. A step that raised
  anything else left it on disk: an error from building the environment git runs with, an
  error from a git command that no handler of the delivery names, or an interrupt. The
  session's record named the directory the clone was made in, so `run_ash_scan` with no
  `source_dir` ran on an empty tree, or on a clone of the default branch when the
  failure came after the clone. The clone is now made in a staging directory of the
  delivery's own and replaces the delivered source only once it is complete, so every
  such failure deletes the staging directory and raises the exception it raised before,
  and the previous source, and the record that names it, are untouched. What cannot be
  deleted stays under its staging name, is logged, and is deleted by the next delivery.
- **`MCPSession` holds no binding, and the profile state lookups create nothing.**
  `MCPSession` no longer has `source_dir`, `config`, `profile_name` or `patch_ops`;
  nothing set them. A client's delivered directory is recorded by `source_delivery` and
  its selected profile by `profile_registry`, which are the only record of a binding.
  `profile_registry.get_session_state` returns None for a session with no binding and
  creates no entry, `session_has_binding` reads None as the stdio session,
  `clear_session_state` takes the session id as a required argument (None is the stdio
  session), and `clear_all_session_state` drops every session's state.
- **A repository with no CloudFormation is skipped, not failed, when cdk-nag cannot
  run.** When cdk-nag did not import, `node` was refused, or the worker process
  exited or timed out, the scanner counted every JSON and YAML file in the tree as a
  template that was not evaluated. A tree holding only a `package.json` or a
  `mkdocs.yml` ended with status ERROR and a non-zero exit, with those files named in
  the results. A failure is now counted against a file only when the file holds a
  template, by the test the scanner already uses to tell a missing cdk-nag from a
  skipped one. A template, a damaged template, a document ASH cannot model and a file
  it cannot read still fail the run. A tree with no template ends with no attempted
  target and is skipped, as it is when cdk-nag runs.
- **An end-of-session delete that skipped the presence guard on a filesystem error now
  takes the guarded path.** When the stat of the session directory fails (EACCES, EIO,
  ESTALE), `end_session` treats the workspace as one that may exist: it takes the
  presence lock and keeps the tree while a scan holds it, or, when the lock is refused,
  clears only the server's own record of the session. Only an id that names no directory
  and a missing workspace root mean there is no workspace. A failure while checking for a
  scan or while removing the session's state is logged with one warning, leaves the tree
  for the TTL sweep, and is no longer recorded as a scan holding the session.
- **Only `None` names the stdio session in the profile state accessors.** An empty
  session id is an id of its own. `get_session_state`, `session_has_binding`,
  `clear_session_state`, `bind_session_config`, `resolve_session_config_path`,
  `resolve_session_trusted_config_path`, `session_profile_entry`,
  `materialize_session_config`, `materialize_session_binding` and
  `writing_session_state` no longer read `""` as the stdio session, so ending, binding or
  holding the id `""` leaves the stdio session's binding, config copies and write hold
  alone.
- **The MCP server's refusal of an invocation option exits with the usage-error code
  the tests and docs now name.** `ash mcp` refuses an option value or a combination of
  options it cannot run with (the auth header value forms, a bind it will not make, the
  upstream session id declaration, the session workspace TTL) with the usage-error
  code, as the command always has. Its tests and the streamable-HTTP page said exit 3,
  which reports an invalid config, so they now agree with the command. A config or
  profile it cannot load still exits 3.
- **`set_source_git` answers a git failure as one, whatever bytes git wrote, and
  `invalid_session_id` only for the session id.** git's output is read so that a byte
  that is not valid in the server's encoding (a path or a remote's message written in
  another one) is kept as its `\xNN` escape instead of raising. A clone or a checkout
  that git fails with such output is `git_clone_failed` or `git_checkout_failed`, with
  git's message in `error` and no tree left; a fetch that fails is tolerated as before,
  and a step git completes delivers. The tool used to answer `invalid_session_id` and
  leave the clone on disk. A session id no workspace can be made for is now refused as
  `InvalidSessionIdError`, a `ValueError`, before the session is taken, and only that
  is answered `invalid_session_id`. A step git cannot be started for with an argument
  the url and ref checks did not refuse removes the clone, as a git that is not on PATH
  does, and is answered with the step's own type: `git_clone_failed` for the clone and
  the fetch, `git_checkout_failed` for the checkout. The failed clone is gone and the
  session's previous source, if it had one, is untouched. `set_source_git` raises that
  failure as `GitCommandError`, not as a `ValueError`. A url or ref holding a NUL character,
  another control character or a lone surrogate is refused as `clone_url_not_permitted`
  or `clone_ref_not_permitted` before the session's workspace is made and before git
  starts; a ref with a NUL character used to pass the checks, clone for up to ten
  minutes and fail at the fetch. A `ValueError` the delivery was not expected to raise
  is logged as unexpected and answered with its class name, not as a failed clone.
- **A source re-delivery that fails keeps the session's record, and scratch left by a
  delivery cannot block the next one.** A zip swap that could put neither tree in
  place, a staging directory that could not be deleted and a previous clone that could
  not be deleted each dropped the session's recorded source. A `run_ash_scan` with no
  `source_dir` then scanned the server's working directory on stdio, and answered
  `session_source_mismatch`, which names the wrong cause, on a network transport. The
  record now stays. A zip extraction and a git clone both go into a staging directory
  of the delivery's own (`.source.incoming-<id>`) and replace the previous tree only
  once they are complete, so a delivery that fails for any reason (git fails, runs too
  long or cannot be started, the archive is refused, the clone cannot be deleted)
  leaves the previous source and the record that names it in place, and
  `run_ash_scan` with no `source_dir` scans it. Only a swap that cannot complete (the
  previous tree was set aside, the new tree cannot take its path, and the previous
  tree cannot be put back) leaves the record naming a path with nothing at it, which
  `run_ash_scan` answers as `delivered_source_missing`; it never reads part of a tree
  or the server's working directory. Each delivery first deletes what earlier ones
  left beside `source/` and logs what it cannot, so one entry that cannot be deleted
  no longer ends every later delivery to the session. A swap that fails is
  `session_workspace_unavailable` whatever the operating system error was; a
  `PermissionError` or `OSError` used to be answered with its class name, and a
  `FileNotFoundError` with no `error_type` at all. The tool descriptions and the tool
  reference name every `error_type` `set_source_git` returns, including
  `clone_host_not_permitted`, `ssh_key_not_registered` and `clone_timed_out`, and say
  that a git that is not on `PATH` or cannot be started is `git_clone_failed`.
- **A tree that a source delivery is refused the rename of is renamed again.** A
  source delivery builds its tree in a staging directory, sets the previous tree aside
  and renames the staging directory onto `source/`. On Windows a program that holds a
  handle inside a tree (a virus scanner, a file indexer, or the `gc` that git starts in
  the background after a fetch) refuses a rename for a fraction of a second, and the
  delivery then deleted the finished tree and failed with
  `session_workspace_unavailable`, so the client fetched everything again. Each of the
  three renames (the previous tree aside, the staging directory into place, the
  previous tree back) is now tried up to five times, 0.2 seconds apart, with the tree
  left where it was between attempts, so a refusal that passes costs no second clone or
  extraction; when every attempt is refused the delivery ends as before, with the
  previous source in place. Only a refusal that a wait can clear is tried again: a
  permission error, a busy device, or Windows error 5 or 32. Any other error (the
  staging directory is gone, something took the place of `source/`, the file system is
  read-only or full, the move crosses devices) is raised at once, because the delivery
  runs inside the server's event loop and each wait stalls every other call. Every git
  command of a delivery also passes
  `-c gc.auto=0 -c maintenance.auto=false`, so git starts no background maintenance in
  the staging directory.
- **A previous source that cannot be put back is named.** When the new tree could not be
  moved into place and the previous source could not be moved back either, the error
  named only the failed move and nothing was logged. The error now also says the
  previous source could not be restored and gives the path it stays under, and one
  warning is logged with the same path. The next delivery to the session puts that
  previous source back first, when `source/` is missing, the session's record names it
  and it is the only such tree, instead of deleting it with the other scratch; a
  delivery that then fails leaves the previous source in place. When more than one such
  tree exists nothing says which is the source, so none is put back and none is
  deleted, and one warning says so. A tree that is refused its rename back again stays
  where it is and is logged. The tool description says that a
  `session_workspace_unavailable` that names a refused rename can be retried with the
  same call.
- **A delete that stops partway no longer leaves a half-deleted tree where a previous
  source is put back from.** A replaced tree was deleted under its hidden name
  (`.source.replaced-<id>`), so a delete that stopped partway left a half-deleted tree
  under the name the next delivery puts a lost previous source back from. If the whole
  previous tree was lost as well, the sweep deleted it and the half-deleted tree was
  the one left to become `source/`, so a scan would have missed the files that were
  deleted. A tree is now renamed to `.source.trash-<id>` before it is deleted, in a
  swap and in the sweep at the start of a delivery, so only whole trees carry the
  hidden name; trash trees are swept like other scratch and never put back. A tree
  that cannot be renamed for the delete is not deleted in place and stays whole.
- **A failed git step reports git's own error even when its partial clone cannot be
  deleted.** The clone, fetch and checkout steps deleted the staging directory
  themselves and raised a workspace error when part of it stayed on disk, so a
  mistyped ref came back as `session_workspace_unavailable` instead of
  `git_checkout_failed`, and the delivery then deleted the same directory a second
  time. The steps no longer delete anything; the delivery deletes its staging
  directory once, logs what it could not delete, and raises the failure that ended it.
  `session_workspace_unavailable` no longer covers a partial clone that stays on disk.
- **A clone, fetch or checkout that fails for want of disk space says what to do.** A
  re-delivery clones beside the source already delivered, so a repository that fits
  once may not fit twice, and the answer was git's words alone. When git's message
  names a full disk and the session has a delivered source, the error keeps it and adds
  that a re-delivery needs room for both trees and that `clear_source` frees the
  delivered one; the tool description says the same. A first delivery has nothing to
  free, so it is told only that the disk is full. A fetch that runs out of space ends
  the delivery as a failed fetch; before, its message was dropped and the checkout that
  followed failed with "pathspec did not match", which reads as a typo in the ref. git
  runs with `LC_MESSAGES=C`, so the message is English whatever the server's locale
  (the message Windows gives comes from the system and still follows its language). A
  full disk no longer gets the redirect advice an https url otherwise gets.
- **A remote's full disk is no longer read as a full disk here.** The full-disk check
  for a clone, fetch or checkout read all of git's output, including the `remote:`
  lines that relay the server's own messages. When the server's disk was full, a client
  with a delivered source was told to call `clear_source` and lose that source, and a
  fetch the remote could not serve ended the delivery instead of going on to the
  checkout. Lines that start with `remote:` are no longer read; a message git wrote
  itself still counts when it comes beside them.
- **A session that keeps previous source trees is told to clear them when the disk is
  full.** A session with no `source/` can still keep previous source trees under the
  hidden name (an earlier delivery could not tell which one is the source, or could not
  put it back). Each takes room, and `clear_source` frees them, but the client was told
  only that the disk is full. It is now told that those trees take room and that
  `clear_source` frees them; a session with neither a source nor kept trees is still
  told only that the disk is full. The error that leaves a full-disk delivery also
  keeps `disk_full` set, which the new error built for the advice had dropped.
- **The description of `cancel_scan` says once that only a scan the session started can
  be cancelled.** It said so twice, in different words, and every client received both
  paragraphs.
- **A scan that exits for incomplete coverage is closed as incomplete even when its
  coverage cannot be described.** When the exit's payload or the judged threshold
  could not be worked out, the close used for a scan that kept its results had no
  coverage gap, which the registry refuses for an incomplete scan. The close now
  carries the gap the exit's own scanner rows name, once, for every caller of the
  close.
- **A file lost during a zip extraction is not answered as a missing upload.**
  `set_source_zip_finalize` answered every `FileNotFoundError` with an `error` and no
  `error_type`, as for an upload that never received its last chunk. A file that
  vanishes while the archive is read or extracted is a failure on disk, and now leaves
  the tool for the server's own handler like the other disk failures of an extraction,
  which answers with the exception's class name; the missing upload raises its own
  `FileNotFoundError` subclass, `UploadNotFoundError`, and keeps its answer.
- **An auth header value is compared in the bytes the header carries.** The static
  header check encoded the configured value and the received one as latin-1 with
  replacement, so a character latin-1 can't carry became `?`, and a configured value
  with such a character was satisfied by a header of `?` characters. Both sides are
  now encoded strictly: the check is not built for a configured value with a
  character outside latin-1, and a received value with one matches nothing. Values
  latin-1 carries compare as before.
- **`validate_config` checks the runtime-override policy of the files it validated.**
  The policy check read the named file and its bases a second time after the
  validator had read them, so a file rewritten in place, or replaced, in between was
  judged with other bytes than the ones validated, and a read that failed there was
  dropped as already reported. The validator now holds what it read of the chain, and
  the policy check runs on that and reads no file. A remote caller's client files
  that read the environment are refused in the type the validator gives that refusal,
  and a file refused so is not judged. Every refusal of
  the check is reported beside the validator's errors, without repeating a message
  the validator gave, and every line of the reply, a denial's included, is typed by
  one classifier and shown on one line.
- **`validate_config` reads a remote caller's named file once, under the caller's
  rule.** For a remote caller every config file outside the operator's roots resolves
  no `${VAR}` or `!ENV` value, as for a scan of the file. The validator resolved every
  reference in a named file that is not one a client delivered, so the file was
  reported valid with the server's environment read into it, and a reference to a
  variable that was not set was answered with the "not set" error, which says which of
  the server's variables exist. The validator now takes the caller's rule and applies
  it in the one read it makes of the chain: a named file or a base it refuses is
  refused as `config_env_not_resolved` before any reference in it is resolved, in one
  sentence whether or not the variable is set. A file that reads the environment is
  refused before the rest of it is judged, so its other findings are reported once the
  read is gone from it.
- **A config file the server keeps from the environment is refused before any of its
  references is resolved.** The chain walk read such a file and resolved each
  reference before it refused the file, so a reference to a variable that was not set
  was answered with "is not set" and one to a variable that was set with the refusal,
  and the answer told a remote caller whether the server's variable exists. The text
  is now checked before it is parsed with the environment, and the refusal is the same
  sentence either way and quotes no value.
- **A scan of a profile bound with `patch_ops` or `override_yaml` compares against the
  registered profile.** The runner replaced the trusted base it built from the
  registered profile with a per-scan snapshot of the session's config path, which for
  a patched binding is the client's patched copy. The restrict-only comparison then
  held the client's settings against themselves, and the values redacted from the
  scan's output were read from the patched copy. The snapshot is now of the registered
  profile when it is the trusted base, and of the session's profile only when that is
  the scan's own config. It is written in the session's `config/` directory beside
  the registered profile, and the sweep of leftover scan copies at the next bind covers
  that directory too.
- **A scan's own copy of a server-written profile is a file the server wrote.** The
  copy a live scan makes of the bound profile is named for the scan, and only
  `ash.yaml` and the call profiles counted as the server's, so a bound profile that
  read the environment failed the scan with "!ENV is not resolved in a config an MCP
  client delivered". A copy a live scan of the session registered counts as the file it
  copies; a file that only carries such a name does not. The same reading pairs a
  patched profile's client copy with the scan's copy of the operator's profile, so a
  setting the patch leaves alone keeps the value the operator's profile read from the
  environment and not the reference text the client's copy holds.
- **MCP `get_config` with `raw=True` reads only the file it checked, reads a TOML file
  once, and loads a JSON file that starts with a byte order mark.** The raw read is held
  to the device and inode of the path when it was checked, and a path that led nowhere
  then is held to the identity no file has. A file swapped in after the check, or one
  that has come to be at a name that led nowhere, is refused as changed after it was
  checked; a name that still leads nowhere answers `file_not_found`. When the read
  could not parse a TOML file, or a `pyproject.toml` had no `[tool.ash]` table, it
  asked the loader for its error by reading the file again, and the loader resolves
  each `${VAR}` it reads: a file rewritten in place between the two reads was answered
  with the server's environment values in it. The refusal is now made of the text that
  was read, in the loader's words.
- **A workspace project that spells one scanner twice is refused when the workspace
  policy requires that scanner, and the plugin lookup reads a declared scanner's
  section under every name of its plugin.** Two extra scanner sections whose names
  reduce to one name, such as `snyk.code` beside `Snyk_Code`, give the lookup one
  section to read: the key spelled as the reduced name (`snykcode`) if there is one,
  else the first key written whose name without punctuation is the plugin's, else the
  first whose name is the plugin's only once its Converter, Scanner or Reporter word is
  removed. The lookup used to read the last of two such extra sections and now reads
  that one, so a configuration that relied on the other has it ignored, and the
  configuration logs a warning that names both keys and the one it reads. A lookup that
  names a key exactly (`acme-sink`) is warned of only the keys that claim the name in
  the same pass: `acme-sink-reporter` is another plugin, read by its own name, and
  draws no warning. A lookup that names no key (`AcmeSinkReporter`) cannot tell which
  plugin is meant, so it warns of every key it does not read. When the workspace policy
  requires that scanner, `ash --workspace`
  now refuses the project instead of recording a scanner the project runs as one only
  the policy added, and one refusal names every such project and both keys in each, a
  section with no body included. A workspace with no policy, or a policy that requires
  other scanners, plans the project and scans it, and the plan lists the scanner, and
  records its pin, only for the section the scan reads. `acme` and `acme-scanner` are
  two scanners, each listed by its own section, but the scan reads either one for the
  name `acme`, depending on the name the plugin is registered under, so a policy that
  requires `acme` refuses a project that holds both. It refuses `acme-scanner` beside
  `acme.scanner` too, whether or not `acme` is also there. When the plugin's
  registered name may select either of two sections, as with
  `Snyk_Code` beside `snyk-code` (the registered names are known only after the plugin
  modules load, so the plan cannot tell), the plan does not list the scanner as enabled
  unless both sections are, and a section with no body is off. It records the pin they
  share. When they set different tool versions it compares each of them with the pins
  the other projects record for that scanner under any spelling of it, whichever key
  their file order makes the lookup read, and refuses the workspace only when one does
  not fit; `acme` beside `acme-scanner` is compared the same way, and a workspace of
  one project is planned. The policy's scanner names
  fold with `reduced_plugin_name`: ASCII case only, the Converter, Scanner or Reporter
  word and every character outside `[a-z0-9+]` dropped. A spelling beside a declared
  scanner is not refused, and the lookup reads the declared scanner's section whether
  it is given the config key, the Python field name, the class name or the reduced
  name; a lookup by any of the last three used to read the spelling beside it. A
  section key with no ASCII letter, digit or `+`, and a key that is the empty string,
  are read by no plugin whose reduced name is empty.
- **Arguments to a batch program that cmd.exe would read differently are refused.** On
  Windows a tool that resolves to a `.bat` or `.cmd` file (a RubyGems `.bat`, an npm
  `.cmd`) is started through cmd.exe, which reads the command line, and the batch file
  then passes its arguments on, so cmd.exe reads them a second time. An argument
  holding `<`, `>`, `|`, `&`, `^`, `(` or `)` that Python writes without double quotes
  was read as a redirection, a pipe, a command separator, an escape or a parenthesis,
  and a caret put before an operator protects it in the first read only. A wrapper can
  hold the arguments inside a parenthesized block, where a bare `)` closes the block
  early. Where ASH resolves the program, such an argument is now refused with an
  `OSError` (`EINVAL`) before the program starts. So is a double quote or a line break
  in any argument, and a percent sign when the command line holds two or more of them.
  An argument that Python puts in double quotes (one with a space or tab, or an empty
  one) is passed as it is, so a version range written `>=1.0.0 <2.0.0` reaches the
  program where `^1.0.0` is refused, and the message for a caret says so. ASH refuses
  these arguments instead of quoting them, because quoting needs the command line as
  one string, which the spawn helpers, the sandbox plan and the callers of
  `resolve_command` do not carry. The program path is checked the same way and nothing
  is added to it: a path with an operator or a parenthesis and no space is refused, and
  a path with a single percent sign starts as before. The message names the program
  and the position of the argument, not its text. `run_command_with_output_handling`,
  `run_command_stream_output` and `create_process_with_pipes` resolve a copy of the
  caller's list, as `run_command` and `spawn_run` do, so a list passed twice is handed
  on the same both times. Programs that are not batch files, and other platforms, are
  unchanged. Known limitation: `!` under delayed expansion (the `DelayedExpansion`
  registry setting, or `cmd /v:on`) is neither refused nor protected. The tests check
  these rules against a model of cmd.exe's two reads on every host, and one test that
  runs only on Windows starts a real batch file, plain and with its arguments inside a
  parenthesized block, with each argument ASH accepts and compares what the program
  receives.

- **A non-absolute `GITLEAKS_CONFIG` is read where the operator set it.**
  gitleaks resolves a relative path against its working directory, which ASH
  sets to the scanned source directory, so `GITLEAKS_CONFIG=rules.toml` was read
  from the scanned tree: the repository supplied the config. The same held for
  `GITLEAKS_CONFIG=~/rules.toml`, which a CI `env:` block, a `.env` file or
  `--env-file` leaves unexpanded and gitleaks does not expand either. Outside the
  scanner sandbox such a value is now anchored to the directory ASH runs in,
  with `~` expanded, and passed as `--config`; the re-scan of the ignore file's
  copies uses the same anchor. An absolute `GITLEAKS_CONFIG`, and
  `GITLEAKS_CONFIG_TOML`, are left to gitleaks as before.

- **The operator's own `file://` detect-secrets filters keep the operator's
  judgment beside a baseline's filters.** Authorship of a `filters_used` entry
  was judged per option: once the baseline in use had any filter, every retained
  operator `file://` filter was checked as the baseline's, so one under the
  scan's own output or work directory, which the operator's configuration may
  name, was refused with a warning. Each entry is now judged by its own writer.

### Reporting changes

- **GitLab SAST reports a finding with several locations at its first located
  one.** The `location` of a vulnerability used to blend the locations: the last
  location's file with an earlier location's line and source excerpt, a position
  that exists in neither. It is now the first location with a file, with that
  location's own line and excerpt. GitLab's location fingerprint changes for such
  a vulnerability, so one pipeline marks the existing one as no longer detected
  and opens it anew at its real position; a vulnerability with one location is
  unchanged. The `id` and the ASH finding-id identifier of every vulnerability
  are now the finding's `id` in `ash.flat.json` (see the entry on that id below),
  so they change once with it.

- **Every OCSF `finding_info.uid` changes once, and then stays.** It was a fresh
  random UUID on every run, so no SIEM could match a finding across two scans. It
  is now derived (UUID version 5) from the finding's `id` in `ash.flat.json`, the
  same id the GitLab SAST report carries, so the same finding has the same uid in
  every scan of the same tree and the same identity across the reports. A finding
  the flattening cannot vouch for is keyed on the result alone: scanner, workspace
  project, rule, message, file and lines, with two identical results numbered.

- **The GitHub GHAS report leaves out results that state no failing finding, and
  names its category only when asked.** A result whose SARIF `kind` is `pass`,
  `open`, `review`, `notApplicable` or `informational` (a cdk-nag rule that was
  not evaluated) is left out of `ash.ghas.sarif` and out of its rules' scores;
  GitHub reads no `kind`, so uploaded it opened an alert like a failing result.
  Such results stay in every other report. The new reporter option
  `emit_automation_details` (off by default) writes `runAutomationDetails.id`
  `ash/<project key>/` into a workspace project's own report so that the
  per-project uploads for one repository are filed under separate categories; it
  is off by default because an id in the file takes precedence over the `category`
  the `upload-sarif` action is given, and turning it on moves existing uploads to
  a new category, leaving the old analysis's alerts open until they are closed by
  hand. The report also keeps a chained `originalUriBaseIds` entry's own
  `uriBaseId`, and writes a suppression's `kind` only when it has one.

- **A converter whose dependencies were unavailable says why in the results.**
  Its `converter_results` row in `ash_aggregated_results.json` carries
  `dependency_unavailable_reason`: the reason its dependency check recorded,
  with the home directory written as `~` and values read from the environment
  hidden, or a message naming the converter when the check recorded none or
  raised. It is None on every row whose `dependencies_satisfied` is true. The
  console's warning and `ash.log` already gave the reason; `ash merge` and an
  MCP client, which read the results, now have it too, as they have a MISSING
  scanner's `missing_reason`.

- **Reports name the configured project.** `project_name` (the config file,
  `ASH_PROJECT_NAME`, else `ash-scan`) is the project in the HTML, Markdown and
  text reports, `metadata.project` in `ash.flat.json` and
  `metadata.project_name` in `ash_aggregated_results.json`; it was always `ASH`.
  The SPDX document name, root package name and `documentNamespace` prefix change
  with it. A workspace project's reports keep the project's label.

- **`ash.sarif` describes each scanner by its own version and links each finding
  to its rule.** Each scanner's `tool.extensions[]` entry, and
  `properties.scanner_version` on its findings, carry the scanner's version (it
  was ASH's), left out when unknown. Each finding gains a `rule` reference
  (`rule.toolComponent` to the scanner's extension and `rule.index` to the rule
  in it), as SARIF 2.1.0 asks for rules defined in an extension (3.27.7), and an
  explicit `level`. `tool.driver.name`, rule ids and locations are unchanged.

- **`report_id` is unique per scan.** It is
  `ASH-<UTC YYYYMMDDHHMMSS>-<12 hex digits>`; it was `ASH-` and the UTC date, so
  every scan on a day shared one. `ash merge` gives the union an id derived from
  its shards' ids (the same shards give the same id in any order), and a
  workspace aggregate uses `ASH-WORKSPACE-<file stem>-<UTC time>-<12 hex digits>`,
  with characters of the stem outside ASCII letters, digits, `_`, `.` and `-`
  replaced by `-` and the result trimmed of leading and trailing `-` (a stem with
  a space used to make the results file unloadable).

- **`ash.cdx.json` without an SBOM is a valid CycloneDX document that says its
  inventory is unknown.** When no SBOM scanner produced one, it was `{}`; it is
  now `{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "components": [], "compositions": [{"aggregate": "unknown"}]}`, so a consumer
  does not read "no components" as "nothing to report".

- **Bedrock's `actionable_only` sends what the threshold counts.** It dropped
  suppressed findings but sent every unsuppressed one, LOW and INFO included; it
  now also leaves out findings below the threshold of the scanner that reported
  them (that scanner's `severity_threshold`, else the global one).

- **Reports now carry the age of every content database a scan used.** Additive:
  `ash.flat.json` gains a top-level `content_databases` list (an empty list when no
  scanner read one), each entry with `built`, `age`, `max_age`, `stale`, `policy` and
  `enforced`; each such scanner's SARIF invocation gains an `ash_content_databases`
  property and, when stale, a `toolConfigurationNotifications` entry; and the markdown
  and text summaries and the console gain a stale-database section, emitted only when
  there is one. See the breaking change above.

- **`metadata.validation_summary.scanner_tasks_validation` no longer has
  `successfully_retried`, and a scanner missing from the task list gets a different
  reason.** The key counted scanners re-registered after they were found missing
  from the task list. Nothing ever re-registered one, so it was always `0`, and it is
  removed from `ash_aggregated_results.json`; `missing_count` still counts them. The
  failure reason such a scanner carries, which the result completeness check copies
  into its `validation_checkpoints` discrepancy ("Scanner 'semgrep' was missing from
  results: ..."), is now "Scanner was expected to be queued but was not found in task
  queue" instead of "Scanner was missing from task queue, retry attempted". It used
  to be recorded only by the retry stub; it is now recorded whether or not the
  checkpoint has discrepancies. The log says "Found 1 enabled scanners with no task:
  semgrep" instead of "attempting retry registration" followed by "No scanners were
  successfully retried".

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
- **Every finding's `id` in `ash.flat.json`, `ash.csv` and the MCP tools changes
  once.** It was `<scanner>-<rule>-<8 hex digits of a hash of the message>`, so
  two findings of one rule with one message shared an `id`, and rewording a
  message changed it. It is now `<scanner>-<rule>-<12 hex digits>` of a hash over
  the finding's identity: its SARIF fingerprints when they tell findings apart,
  otherwise its file and lines, plus the package name and path and the workspace
  project. Findings that share all of that are told apart by a digest of their
  column and message, and only exact duplicates are numbered, so a newcomer does
  not take an existing finding's id. A converted file's findings are identified by
  the file's path under the converted files, not under the output directory.
  detect-secrets now reports the column each secret starts at, so two secrets on
  one line have two ids. Ids recorded from an earlier release, such as a saved
  `diff_scan_results` baseline, no longer match; take a new baseline. An
  `additional_reports` entry that carries its own `id` keeps it.

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

### Removed

- **`ScannerValidationManager.retry_scanner_registration()`.** It re-registered
  nothing and returned `[]` for every input. Code that called it now gets an
  `AttributeError`; a missing scanner's reason is recorded by
  `handle_queue_validation_errors`, as described under Reporting changes.

### Contributor changes

These affect working on ASH, not the installed package.

- **A default `pytest` run no longer measures coverage.** `pytest.ini` dropped its
  `--cov` options and `.coveragerc` its `fail_under = 80`, so a run of one directory
  or one test passes or fails on its own tests instead of on total coverage, and
  `--no-cov` is no longer needed. CI's unit-test step passes `--cov` and
  `--cov-fail-under=80` itself and still fails below 80%. DEVELOPMENT.md has the
  command to run the suite the way CI does.
- **The cdk-nag tests skip without the `cdk` extra.** After a plain `uv sync` they
  skip with a reason that names `uv sync --extra cdk`. CI sets
  `ASH_REQUIRE_CDK_EXTRA`, under which they fail instead.
- **The `serial` marker and the `--run-changed-only` and `--base-branch` pytest
  options are gone.** Nothing ever acted on them: a test marked `serial` still ran in
  parallel, and `--run-changed-only` ran the whole suite. A test that still uses the
  marker gets pytest's unknown-marker warning, and the options are now a usage
  error.
- **The `temp_env_vars` fixture restores the environment it found.** It used to
  delete every variable it had not set, `PATH` included.
- **`pre-commit run --all-files` leaves a clean checkout unchanged.** The JSON
  formatter no longer rewrites generated, vendored or byte-compared JSON, or fails
  on `deploy/cdk/tsconfig.json`, and the `sync-cdk-extra-fallback` hook no longer
  rebuilds the project `.venv` on Python 3.13 without its extras.
- **Each unit-test check lists the whole suite again.** The cdk-nag integration
  step overwrote the suite's JUnit report, so the check showed only that file.
- **Tests no longer write into the developer's home directory.** Each test that
  installed a fixture tool left an install receipt in `~/.ash/install-receipts`, and
  others wrote MCP session configs to `~/.cache/ash-mcp` and scanner state to
  `~/.semgrep` and `~/.cache/checkov`. `HOME`, `USERPROFILE` and the `XDG_*` base
  directories now point at a temporary directory for each test, and at one for the
  whole run from the moment pytest loads `tests/conftest.py`; uv's own directory
  variables (`UV_TOOL_DIR` and the like) are unset, and `UV_CACHE_DIR` stays on the
  developer's uv cache. On Linux and macOS a user-level `uv.toml`, `pip.conf`,
  `.npmrc` or `~/.netrc` is no longer read; behind a package mirror, export
  `UV_DEFAULT_INDEX`, `PIP_INDEX_URL` or `npm_config_registry` instead.
  On Windows, `%APPDATA%` and `%LOCALAPPDATA%` are not moved. Tools in
  `~/.ash/bin` are not found unless that directory is on `PATH`; the run's header
  says so, and so do the skip reasons of the tests that need one.
  `@pytest.mark.real_home` opts a test out. A test that starts
  `ash dependencies install` (or `ashv3` or `automated-security-helper`, the
  CLI's other names), or the `install_pinned_tool` child it runs, with
  HOME, uv's tool directories or the install destination (its own argument,
  `--bin-path` or `ASH_BIN_PATH`) in the developer's home, fails; the run's own
  temp directories, which on Windows are inside the home, do not count.
  The check follows symbolic links and reads through `env`, `nice`-style and shell
  `-c` wrappers, and an `install_pinned_tool` call or a shell line it cannot read
  fails too, as does any Python or `ash` child with the developer's HOME, or with a
  HOME a shell computes (`HOME=$(...) python`). A Python
  or `ash` child given an environment with no HOME, which would fall back to the
  developer's real home, gets the test's home instead (ASH's Landlock probe is one);
  one whose own command line removes HOME (`env -i`, `env -u HOME`,
  `unset HOME;`, `export -n HOME`) or sets it to the developer's (`HOME=...;`)
  fails, inside `{ }`, `if` and loops too, and so does one after `eval`, `source`,
  `readonly`, `declare`, `typeset` or `local`, which the check cannot follow. A Python or
  `ash` name anywhere in the argv counts, so `taskset` or `ionice` in front does
  not hide one. The check is at `subprocess.Popen`; a start that skips it
  (`os.posix_spawn`, `os.system`, multiprocessing's spawn and forkserver) is not
  checked there, and `tests/utils/home_rule.py` gives the same rule to code that
  sees such starts.
  A test whose own process writes under the developer's `~/.ash` by a path that
  does not come from `HOME` is refused by an audit hook, and fails at teardown;
  one after the last test's teardown fails the run, in an xdist worker too.
- **Tests cannot send botocore requests off the machine.** A test whose code sends
  one to anything but a loopback endpoint fails, whatever credentials the
  environment holds: stub the client with `botocore.stub.Stubber`, point it at a
  local fake service, or mark the test `allow_aws_network`. A child process is not
  covered.
- **The test-selection tool is `python -m tests.utils.selection`.** The docs named
  `tests.utils.test_selection`, which did not exist; the tool and its companion
  `tests/utils/optimization.py` lived in `tests/unit/utils/` under `test_` names.
- **The ferret-scan pre-push validator fails a keyword hit that only a suppression
  without line numbers covers.** The `SUPPRESSION-COVERAGE` check in
  `scripts/validate_ferret_plugin.py` could not fail, so a `SECRET-SECRET-KEYWORD` hit
  excused by an entry in `.ash/.ash_community_plugins.yaml` that has no `line_start`
  passed both that check and the keyword check. The run now fails and names the file
  and line; add `line_start` and `line_end` to the entry.
- **The two line-pinned `SECRET-SECRET-KEYWORD` entries name their lines again, and a
  test keeps them there.** The entries in `.ash/.ash_community_plugins.yaml` for the
  ferret plugin's `DEVELOPMENT.md` and for its test fixture `conftest.py` pinned lines
  501 and 146, which are blank now, so they excused nothing. They pin lines 595 and
  132. The rule id belongs to detect-secrets, which that config turns off, so the
  entries are accurate in case it is turned on.
  `tests/unit/test_ci_ferret_self_scan_pins.py` fails when a pinned entry lacks an
  integer `line_start` or `line_end`, or when its range does not include the line it
  was written for. A new pinned entry needs a row there.
- **Four more line-pinned suppressions for the ferret plugin's files name their lines
  again, and the same test checks them.** In `.ash/.ash_community_plugins.yaml` the B404
  entry for the `subprocess` import in `ferret_scanner.py` pinned line 9, the B603 and
  B607 entries for the call that runs ferret-scan pinned lines 410 to 435, and the hex
  string entry for the card narrative lines in `scripts/generate_test_docx.py` pinned
  lines 175 to 177. Those lines had moved, so the entries excused nothing. They pin
  lines 11, 826 to 832, and 227 to 230. The hex string rule id belongs to
  detect-secrets, which that config turns off, so that entry is accurate in case it is
  turned on. `tests/unit/test_ci_ferret_self_scan_pins.py` also checks these entries
  and the B311 and PASSPORT entries for the same script, and holds every pin it checks
  to exactly one marker: a second pin in a file needs a second marker, and a range that
  holds two markers, or two pins on one marker, fails.
- **The stand-in tools in the tests can be started on Windows.** `CreateProcess` does
  not start a script that begins with a shebang line, so a fake tool put on `PATH` was
  never run there. `tests/utils/stand_ins.py` writes a stand-in as a `<name>.py` script
  with a `<name>.bat` launcher on Windows, doubling a `%` in the launcher's paths, and
  as the script itself on other hosts, and builds the search path with the host's
  separator. A launcher whose directory or interpreter path holds a character outside
  ASCII is refused on every host with a `ValueError` that names the path, because
  cmd.exe reads a batch file in the console's active code page, which differs between
  shells. `tests/utils/fake_tool_paths.py` spells absolute fake tool paths so a Windows
  lookup counts them as anchored, reading `os.name` when the path is spelled. On a
  Windows host `tests/unit/utils/test_stand_ins.py` starts a launcher with an argument
  that holds a space, one that holds `=` and one that begins with dashes, and checks the
  arguments the script received and its exit code; it is skipped on other hosts. The
  jupyter converter tests can build the Windows configuration, which pins nbconvert to
  one version, on any host, and a test reads the version the convert phase's converter
  is asked for.

## v3.7.1 (2026-09-03)

### BREAKING CHANGE

- a requested cdk-nag pack whose name cannot be resolved now raises instead
of being skipped with a logged error, so a configuration naming a pack that does not exist
fails the scan rather than silently evaluating a subset of the requested rules. Separately,
`include_compliant_checks` no longer has any effect: cdk-nag 3.x reports through CDK's
policy validation framework, whose report contains violations only, so the compliant and
suppressed records 2.x listed alongside them are no longer available at any setting.
- a scanner that attempted at least one target and failed on all
of them now reports ERROR with a non-zero exit code and SARIF
executionSuccessful=false, where it previously reported PASSED with zero
findings. Pipelines running a scanner that cannot execute will begin failing
rather than completing.

### Fix

- **backport**: keep v3.7.0's own lockfile, not main's
- **cdk-nag**: count a template with no validation report as a failed target
- **cdk-nag**: hold the v3 migration to a test suite that can fail
- **cdk-nag**: migrate to cdk-nag 3.x and report per-target failures

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

<!-- doctest: illustrative reason="historical: the ASH v2 command line" -->
```sh
ash --no-run --build-target ci
```

_via `docker` or other OCI CLI_

<!-- doctest: illustrative reason="needs Docker" -->
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
