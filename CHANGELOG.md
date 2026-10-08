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

  `sandbox.network_scanners` and `sandbox.extra_read_paths` grant access, so a config
  file inside the scanned tree (discovered, `--config`, an `extends` base, or
  `ASH_CONFIG`) cannot set them; they come from `--config-overrides` or a config
  file outside the tree. Such a file's `network_scanners` can still remove network,
  and its `sandbox.mode` applies only when nothing trusted turned the sandbox on.
  The tree is the outermost enclosing checkout, not only the scanned directory, and
  when nothing outside the tree sets a sandbox mode, the operator's mode holds even
  when the operator's own file is in the tree. In workspace mode, an operator
  `--config` that does not validate is now refused (exit 3) even for projects that
  have their own config file, because the sandbox mode is read from it.

  If a sandbox was requested and cannot be provided, the scanner is recorded
  `MISSING` with the reason and the scan exits 1. ASH never falls back to running it
  unsandboxed. `auto` picks bubblewrap, then firejail, then Landlock on Linux, and
  sandbox-exec on macOS. There is no Windows backend: use WSL2 or container mode.
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
  installs the same pinned builds locally; and nix mode supplies them (cfn-guard from
  its pinned release asset, its rules and trivy's database seeded by the shell on first
  entry). A tool that is absent is MISSING, as for every builtin scanner. Under
  `--sandbox` each gets what it declares, listed in
  `docs/content/docs/scanner-sandbox.md`. See
  [Built-in Scanners](docs/content/docs/plugins/builtin/scanners.md).
  - actionlint 1.7.12 on `.github/workflows` files. Script
    injection from untrusted event data and hard-coded container credentials are
    HIGH, always-true `if:` conditions, invalid `permissions:` and
    `set-env`/`add-path` MEDIUM, other lint findings LOW. Its shellcheck and pyflakes
    integrations are off unless configured, so results do not depend on the host.
  - cfn-lint (`>=1.43.3,<2.0.0`, uv tool; E to MEDIUM, W to LOW,
    I to INFO) and cfn-guard 3.2.1 against the AWS Guard Rules Registry 1.0.2,
    default rule set `wa-Security-Pillar`, every violation HIGH. Both read the
    templates cfn-nag reads, and neither needs the network.
  - gitleaks 8.30.1 (`gitleaks dir`, working tree only),
    CRITICAL findings with values redacted (`--redact=100`), beside detect-secrets,
    which stays on and unchanged. `.gitleaks.toml`, `.gitleaksignore`,
    `gitleaks:allow` and `options.baseline_path` apply alongside ASH suppressions.
  - zizmor (`>=1.29.0,<2.0.0`) on workflows and composite
    actions, run with `--offline`; GitHub tokens are withheld unless
    `options.online_audits` is true.
  - trivy: `trivy fs` (0.75.0), `vuln` only by default, held to
    the trivy database's 24h bound; offline with no database it is MISSING with the
    reason. It does not read a `trivy.yaml` or `.trivyignore` from the scanned
    repository. trivy and trivy-repo share trivy's cache and run at the same time, so
    online ASH updates the database once per scan, under a lock in that cache, and
    both scanners then run with `--skip-db-update` (and `--skip-check-update` when
    `misconfig` is on). An image built with `OFFLINE=YES` ships the database, and the
    nix shell updates it on every entry.

  Options that name something a tool executes or loads are not taken from a config
  file inside the scanned tree: actionlint's `shellcheck` and `pyflakes` accept only
  their own names there, and cfn-lint's and trivy's `config_file` (a `.cfnlintrc`
  can import Python rules, a `trivy.yaml` can load WASM modules) are honored only
  from `--config-overrides` or a config file outside the tree, for a file outside
  it. cfn-lint's and zizmor's `tool_version` must be a version constraint.

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

- **A default scan runs six more scanners.** actionlint, cfn-lint, cfn-guard,
  gitleaks, trivy and zizmor are builtin and on by default, so a scan with an existing
  config now reports their findings too, and a run whose host lacks one of their tools
  records it MISSING, which fails the incomplete-scan gate (exit 1) exactly as a
  missing grype or semgrep does. Run `ash dependencies install`, use the container
  image, or set `scanners.<name>.enabled: false` for any you do not want. trivy reads
  its vulnerability database, so online it downloads it, and offline it needs the
  database in its cache (`TRIVY_CACHE_DIR`). Configs that list the community Trivy
  plugin for `trivy-repo` now run trivy twice; set `scanners.trivy.enabled: false` to
  keep only `trivy-repo`.
- **trivy-repo names its own config file and modules directory.** It always passes
  `--config` and `--module-dir`: by default an empty config file and an empty
  directory in its results directory, so trivy does not load a `trivy.yaml` from the
  scanned repository. New options `scanners.trivy-repo.options.config_file` and
  `module_dir` name others; they are honored when set through `--config-overrides`
  or a config file outside the scanned tree, for paths outside that tree, and are
  ignored with a warning otherwise.
- **A config file inside the scanned tree can no longer choose what ASH installs,
  imports or hands a scanner as its own configuration.** It applies to a discovered
  `.ash/.ash.yaml`, a `--config` inside the tree, an `extends` base, or `ASH_CONFIG`:
  - `tool_version` (bandit, checkov, semgrep, ferret-scan, the jupyter converter)
    must be a PEP 440 version specifier set such as `>=1.2,<2`, from any source.
    Any other value is replaced by the default, with a warning naming the key.
    `scanners.opengrep.options.version` likewise has to be a release tag.
  - `ash_plugin_modules` entries such a file adds are imported only when they name
    an installed module outside the tree. `--ash-plugin-modules`,
    `--config-overrides` and a config file outside the tree are unaffected.
  - checkov's and ferret-scan's `config_file`, the `.checkov.yaml` and `ferret.yaml`
    files they find by name, and detect-secrets plugins and filters that name a
    file are passed to the tool only when the file is outside the scanned tree.
    checkov and ferret-scan now run from the filesystem root, because each reads
    its config file from its working directory itself, and ferret-scan always
    gets a `--config`; the paths in their findings are unchanged.
  - trivy-repo no longer reads a `.trivyignore` or `trivy-secret.yaml` from the
    scanned repository, either of which could remove findings from the report. It
    gets an explicit `--ignorefile` and `--secret-config`: the
    `scanners.trivy-repo.options.ignore_file` / `secret_config_file` options, or
    `TRIVY_IGNOREFILE` / `TRIVY_SECRET_CONFIG`, when that file is outside the scanned
    tree, otherwise one that sets nothing. A repository that relied on either file
    now sees those findings, with a warning naming the file. Under `--sandbox`, an
    operator file outside the system paths also has to be listed in
    `sandbox.extra_read_paths`.
  - ferret-scan's `tool_version` no longer accepts a bare version or `latest`;
    write `==1.2.3`, or leave it unset for the supported range.

  Under the MCP server, a config a client delivered is limited the same way, and a
  file any MCP client delivered (under the MCP workspace root, except each session's
  `config/` directory) counts as inside the scanned tree for these checks. The
  workspace tools' `config_overrides` are checked against the session config's
  `runtime_overrides` allowlist, as `select_profile`'s `patch_ops` and
  `override_yaml` are, and are refused while runtime overrides are off (the
  default). Each override is checked by the key it names, so one whose value the
  session config already holds is checked too. A workspace policy file a client
  delivered, named or found beside the definition, is refused.
  `/ash_plugin_modules` joins the default `denied_paths`, and `denied_paths` and
  `denied_value_patterns` now match a key spelled with either `-` or `_`, and a
  plugin's section under every spelling ASH reads as that plugin's config.

  Each value that is not honored is logged once as a warning naming the key. See
  [Settings a repository's config cannot choose](docs/content/docs/configuration-guide.md#settings-a-repositorys-config-cannot-choose).

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
  notebook, so files in the scanned tree are not on its import path and its
  `jupyter_nbconvert_config` files are not read from there. The exporter is
  `python` for a Python notebook (or one that names no language) and `script`
  otherwise, and `language_info.nbconvert_exporter` is removed from the copy, so the
  notebook's metadata does not choose the exporter class. A Python notebook whose
  metadata named no exporter used to go through nbconvert's generic script template;
  it now goes through the Python exporter, which adds `# In[ ]:` cell markers to the
  converted file.

- **`ash dependencies install --tool` selects the archive converter as `archive`.**
  Every plugin is now listed and selected by its config key. The archive converter
  was the one bundled plugin listed under its class name, so its canonical `--tool`
  name is now `archive`; the other converters, scanners and reporters keep the names
  they had. The old name `ArchiveConverter` is deprecated: it still selects the
  archive converter, with the same result and exit code, and prints a warning to
  stderr naming `archive`.

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
  when one is behind, listing what the bump has to change.

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

  **What this does not reach.** The gate selects on scanner status, so it covers a
  failure only once that failure has reached the status. A tool that exits non-zero
  and writes an empty report is still graded `PASSED` from its zero findings, and
  this default is the same exit code on, off or unset for that case — the empty
  results branch in `base/scanner_plugin.py` returns a successful empty report
  without consulting the exit code. That is a separate defect, not fixed here, and
  turning this default on should not be read as having fixed it.

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
  file at all it still prints the defaults. `ash scan` is unchanged: it still falls
  back to the defaults and records a warning.

- **A `**` at either end of a multi-segment `ignore_paths` or `suppressions` pattern
  now takes effect.** The matcher anchored the first and last segments of a pattern
  with two or more `**` to the start and end of the path, so `tests/**/__snapshots__/**`
  matched nothing, `a/**/b/**` did not match `a/x/b/c`, and `**/x/**/y` did not match
  `p/x/q/y`. Patterns written that way were silently inert; **they now suppress or
  ignore what they say, so a scan they apply to can report fewer findings and change
  its exit code.** A `**` inside a longer component, as in `src/**.py`, is now an
  ordinary `*` (as in gitignore); it used to match only a file literally named `.py`.
  Every other pattern shape matches exactly what it did.

### Breaking changes

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
  the refresh is disabled.

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

### Fixes

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
