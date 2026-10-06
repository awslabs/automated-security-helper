# GuardDog scanner

[GuardDog](https://github.com/DataDog/guarddog) (Apache-2.0, by Datadog) looks for the
shapes malicious packages take: an install hook that downloads and runs a script,
`exec` of a base64-decoded payload, obfuscated JavaScript, exfiltration to a raw IP
address, and similar. Its YARA rules ship inside the GuardDog package, so scanning
local source needs no network.

GuardDog is an **opt-in** scanner. It is not part of a scan, and leaves no row in any
report, until you enable it.

## Enabling it

Either name it for one run:

```bash
ash scan --scanners guarddog
```

or enable it in `.ash/.ash.yaml`:

```yaml
scanners:
  guarddog:
    enabled: true
```

Once enabled it behaves like every other scanner: if GuardDog cannot be installed or
found, the scanner is reported `MISSING` and the scan exits 1.

## What ASH runs

For every enabled ecosystem, ASH finds each **package root** in the scanned directory,
a directory holding one of that ecosystem's manifests, and runs
`guarddog <ecosystem> scan <package root> --output-format json` on it:

| Ecosystem       | Package root manifest                       |
|-----------------|---------------------------------------------|
| `pypi`          | `setup.py`, `setup.cfg`, `pyproject.toml`   |
| `npm`           | `package.json`                              |
| `go`            | `go.mod`                                    |
| `github_action` | `action.yml`, `action.yaml`                 |
| `rubygems`      | `*.gemspec`                                 |
| `crates`        | `Cargo.toml`                                |

GuardDog reads every file under the directory it is given and has no exclusion option,
so ASH does not hand it the package root itself. It builds a temporary copy (hard links
where possible) holding only the files ASH would scan: the scan set after `.gitignore`
and `.ashignore`, without `node_modules/`, `.venv/` and `venv/` directories,
`global_settings.ignore_paths`, `options.excluded_paths`, ASH's output directory, and
any nested package root of the same ecosystem, which is scanned on its own. Symlinks
are never copied, so GuardDog cannot read anything outside the scanned directory
through one.

A file under two package roots of different ecosystems (a `.js` file in a Python
package that also contains a `package.json`) is matched by both scans; ASH reports
each finding once.

### Dependency verification (`verify`, off by default)

With `options.verify: true`, ASH also runs `guarddog <ecosystem> verify <manifest>` on
each dependency manifest: `requirements.txt` and `requirements-dev.txt` (pypi),
`package.json` (npm), `go.mod` (go), `Gemfile.lock` (rubygems), `Cargo.lock` (crates)
and workflow files under `.github/workflows/` (github_action). GuardDog downloads every
dependency the manifest names from its registry and scans it.

This needs network access and can take a long time on a large manifest. Each manifest
is bounded by `options.verify_timeout` (600 seconds by default). A finding in a
dependency is reported on the manifest line that names the dependency, and carries
`package_name` and `package_version`, so package-scoped suppressions apply to it.

## Severity mapping

GuardDog correlates its matches into **risks**: a threat pattern, optionally paired with
a capability that makes it actionable, with a severity taken from the threat rule and
lowered one band when the capability is in another file and two bands when it is in
another category. ASH uses that judgment directly.

| GuardDog output                                                    | ASH severity | SARIF level |
|--------------------------------------------------------------------|--------------|-------------|
| Risk with severity `high`                                          | HIGH         | `error`     |
| Risk with severity `medium`                                        | MEDIUM       | `warning`   |
| Risk with severity `low`                                           | LOW          | `note`      |
| Risk with any other severity value                                 | MEDIUM       | `warning`   |
| `threat-*` match that GuardDog did not correlate into a risk       | LOW          | `note`      |
| Metadata rule that fired (typosquatting, compromised email domain) | MEDIUM       | `warning`   |
| `capability-*` match not used by a risk                            | INFO         | `none`      |

Capability matches ("spawns a process", "reads a file") describe ordinary code as often
as malicious code, so they are only reported when `options.include_capabilities` is
true.

Why not GuardDog's own SARIF: GuardDog 3.2.0 offers SARIF only for `verify`, not for
`scan`, and gives every rule the level `warning`, which carries no severity. ASH reads
GuardDog's JSON in both modes and converts it.

## Suppressions

Every GuardDog finding has a rule id (the GuardDog rule name, for example
`threat-runtime-obfuscation-base64exec`), a file and a line in your repository, so these
apply:

- rule, path and line suppressions, as for any scanner;
- symbol-scoped suppressions (a function or class), for findings in source files ASH
  can parse;
- package-scoped suppressions (`package_name`, `package_version`) for `verify` findings,
  which are findings in a dependency.

To stop GuardDog evaluating a rule at all, use `options.exclude_rules`, or
`options.rules` to run only some rules. The two cannot be combined. Each ecosystem has
its own rule set (`guarddog <ecosystem> list-rules`), so ASH passes each ecosystem only
the configured names it knows: an exclusion it does not know is ignored for it, and an
ecosystem that knows none of the `rules` names is not scanned. A name no scanned
ecosystem knows is reported as an error, since it is most likely a typo.

## Offline and air-gapped use

`guarddog scan` runs offline. ASH does not install tools in offline mode, so GuardDog has
to be installed beforehand; the ASH container image includes it. With GuardDog absent
offline, the scanner is reported `MISSING`, with the install command in the log.

`verify` downloads packages, so under `ASH_OFFLINE` ASH does not attempt it: each
manifest it would have read is a failed target and the scanner reports `ERROR`, naming
the reason. Set `options.verify: false` for offline scans. Online, a `verify` run in
which GuardDog logged an error is also a failed target: when the registry cannot be
reached, GuardDog prints an empty result and exits 0, which would otherwise read as a
clean scan.

GuardDog is not packaged in nixpkgs, so `ash scan --mode nix` does not provide it.
Enabled under Nix without a separately installed GuardDog, the scanner is `MISSING`.

## Failures

Every GuardDog invocation that times out, exits non-zero, prints no result or prints
something other than a result, or reports a rule error, is a package or manifest
GuardDog did not check. The scanner then reports `ERROR` (and the scan exits 1) however
many other invocations succeeded. The findings that were produced are kept in
`<output dir>/scanners/guarddog/<source|converted>/guarddog.sarif`, and each
invocation's stdout and stderr are under `.../invocations/`.

## Kernel sandbox

GuardDog 3.x can run its scan inside a kernel sandbox (nono: Landlock on Linux,
Seatbelt on macOS) that blocks network access and limits reads to the scanned
directory. `options.sandbox` controls it:

- `auto` (default): use it where the platform supports it, otherwise scan without it
  and log a warning once per scan. It is available in the ASH image under Docker;
  some container runtimes, seccomp profiles and older kernels do not allow it.
- `required`: report `ERROR` where it is unavailable.
- `disabled`: never use it.

The sandbox applies to `scan` only; GuardDog does not offer it for `verify`.

## Installation

ASH installs GuardDog with `uv tool install`, pinned to the release its result parser
was tested against (`guarddog==3.2.0`) and to a Python interpreter between 3.10 and
3.13: pygit2 and yara-python, two of GuardDog's dependencies, publish no CPython 3.14
wheels at that version, so an install on 3.14 would have to compile them from source.
`ash dependencies install` and the container image do this for you. To install it
yourself:

```bash
uv tool install --python '>=3.10,<3.14' 'guarddog==3.2.0'
```

`options.tool_version` overrides the version constraint. A GuardDog release other
than 3.2.0 may print JSON the parser does not expect; if it does, the invocation is a
failed target rather than a silently empty result.

## Configuration

```yaml
scanners:
  guarddog:
    enabled: false              # opt-in
    options:
      ecosystems: [pypi, npm, go, github_action, rubygems, crates]
      verify: false             # downloads dependencies; refused offline
      verify_timeout: 600       # seconds per manifest
      verify_parallelism: 8     # GUARDDOG_PARALLELISM for verify
      sandbox: auto             # auto | required | disabled
      rules: []                 # run only these rules
      exclude_rules: []         # or skip these
      include_capabilities: false
      excluded_paths: []        # [{path: "vendor/**", reason: "..."}]
      scan_timeout: 1800        # seconds per package root
      tool_version: null        # default "==3.2.0"
      install_timeout: 300
```

## Known limitations

- GuardDog's `extension` ecosystem (editor extensions) is not offered: its manifest is an
  ordinary `package.json` and cannot be told apart from an npm package.
- A file reached only through a symlink is not scanned.
- The staging copy is made of hard links when the temporary directory (`TMPDIR`) is on
  the same filesystem as the source, and of copies otherwise. In the container, where
  the source is a bind mount, that means a copy of each package root's files; for a
  repository with a root `pyproject.toml` or `package.json` that is most of the
  repository.
- `verify` findings are located on the first manifest line naming the dependency, because
  GuardDog's JSON does not record where a dependency is declared.
- When any invocation fails, the scanner's findings appear in its own SARIF file but not
  in the aggregated reports, because the scanner's status is `ERROR`.
