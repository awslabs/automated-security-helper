# Scanner sandboxing

ASH runs third-party scanners against code you may not trust. In local mode those
scanners run as ordinary child processes with your user's full access: they can read
`~/.ssh`, write anywhere you can, and open network connections. `--sandbox` runs every
scanner subprocess inside an OS-level sandbox instead. It is off by default.

<!-- doctest: illustrative reason="needs a sandbox backend on the host and the tool of every enabled scanner" -->
```bash
ash scan --sandbox auto            # best sandbox this machine has
ash scan --sandbox bwrap --offline # bubblewrap, no scanner gets a network
```

or in your ASH config file (`.ashrc.yaml` in a new project):

```yaml
sandbox:
  mode: auto
```

If you ask for a sandbox and ASH cannot provide one, the affected scanners are recorded
`MISSING` with the reason, and the scan exits 1 like any other incomplete scan. ASH
never falls back to running a scanner unsandboxed after you asked for a sandbox. That
includes asking in a config file that cannot be loaded: a scan whose config file is
missing or does not parse stops with exit code 3, rather than running with the default
configuration, whose mode is `off`.

## Modes

| Mode | Platform | Needs | Notes |
|------|----------|-------|-------|
| `off` | any | nothing | Default. Scanners run as plain subprocesses. |
| `auto` | any | one of the below | Linux: `bwrap`, then `firejail`, then `landlock`. macOS: `sandbox-exec`. Windows: none. |
| `bwrap` | Linux | `bubblewrap`, unprivileged user namespaces | Recommended. |
| `firejail` | Linux | `firejail` | Fallback. Weaker filesystem hiding, see below. |
| `landlock` | Linux 6.2+ (Landlock ABI 3) | nothing (kernel LSM) | No package to install. Needs Landlock enabled in the kernel's LSM list. Below ABI 3 it counts as unavailable. |
| `sandbox-exec` | macOS | ships with macOS | Apple marks `sandbox-exec` deprecated. See risks. |

Container mode (`--mode container`) does not apply the setting: it never sandboxes the
scanners inside the image, and the container is the boundary. So `--sandbox` with any
mode but `off` is refused there, with exit 5 (a usage error), before the image is built
or run. When `sandbox.mode` in a config file or a `--config-overrides` value asks for a
sandbox, container mode prints a warning on stderr that it is not applied (whatever
`--quiet` or `--log-level` say), gives the scan inside
`sandbox.mode=off` as its last override, and runs the scan, so one config file can serve
local and container runs.

Running `ash scan --sandbox <mode>` yourself inside the image, as in
`docker run <image> ash scan --sandbox landlock`, is your own opt-in: the scan there is
a local one, and it applies the mode. The wrappers below never pass a mode other than
`off`. When the
backend cannot run in the image, each scanner is recorded MISSING with the reason, and
none runs unsandboxed.

`./ash`, `invoke-ash` and `Invoke-ASH`, which always run the container, refuse
`--sandbox` the same way (`Invoke-ASH` by throwing with `$LASTEXITCODE` set to 5). It is
the one refusal of theirs that exits 5, a usage error, as `ash` itself gives for it; the
others refuse a value the wrapper cannot use and exit 3. They also
give the scan inside `--sandbox off`, which it applies after every `--config-overrides`
value and above a `--cli-json-input` document's `sandbox`. Only `scan`, which also runs
when no command is named, takes `--sandbox`; another command is given nothing. They do
not read the config
file, so they print no warning about a mode set there. Nor do they pass `ASH_CONFIG` to
the scan in the container; when it is set they warn that it is not applied. Pass a config
with `--config` (`-Config` to `Invoke-ASH`) instead, as a path relative to the source
directory, which is all the scan in the container sees.

Use `--mode local` to sandbox each scanner. Nix mode composes with it: the inner scan
that runs inside `nix develop` applies the sandbox to each scanner.

ASH finds `bwrap` and `firejail`, and the `readlink` and `true` its probes run, the way
it finds scanners: on absolute `PATH` entries and in ASH's own bin directory, never
through the working directory, and not inside the scanned directory unless you pass
`--allow-in-tree-tools` or set `ASH_ALLOW_IN_TREE_TOOLS=1`. One found only inside the
scanned directory counts as not installed: `auto` moves on to the next backend, and a
mode that names that backend reports its scanners MISSING. See
[Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory).

## What a sandboxed scanner can do

Every scanner subprocess gets the same baseline policy, plus what that scanner declares
it needs.

- The source directory, and the converted-files directory, are read-only.
- The scanner's own results directory (`<output>/scanners/<name>/`) is the only
  persistent location it can write. The rest of the output directory is read-only.
- `/tmp` and `$HOME` are private and empty. Your real home directory is not visible.
  The tool locations a scanner needs (ASH's bin directory, uv's tool and Python
  directories, the scanner's declared caches) are mounted at their usual paths. A
  uv directory that `UV_TOOL_DIR`, `UV_PYTHON_INSTALL_DIR` or `UV_CACHE_DIR` names
  is not mounted, with a warning, when it is `/`, a home directory, a directory
  holding one, or a directory directly in one such as `~/.local`.
- Tool caches (uv's cache, grype's and trivy's databases, semgrep's settings) are
  writable only where the writes are thrown away: under bwrap (bubblewrap 0.8+ and
  Linux 5.11+) through an overlay, so writes succeed but are discarded when the
  scanner exits. firejail, Landlock, sandbox-exec, and bwrap without overlay support
  mount them read-only, because a write in place would change what later runs,
  sandboxed or not, read; uv hard-links its cache into the tool environments it
  builds. There, uv and the scanners that have to write a cache (semgrep, opengrep,
  npm-audit) get a private, empty one under the results directory, removed after the
  spawn, so uv starts from an empty cache: online it downloads what it runs, offline
  it has nothing cached.
- grype and trivy cannot update their databases from inside a sandbox, so before a
  sandboxed online scan ASH updates them itself, outside the sandbox: `grype db
  update`, and `trivy image --download-db-only` plus, for a misconfiguration scan,
  trivy's checks bundle. trivy and trivy-repo do this on every online scan, sandboxed
  or not, since they share the cache. Nothing from the scanned repository reaches
  these, or ASH's check of the database's age after the scan: they run from a
  directory outside the scanned tree or any other checkout, with an explicit config
  file (an empty one ASH ships, or for trivy the config the scan passes: the
  operator's `config_file` once it passes the rule for that option, else
  `TRIVY_CONFIG` for a file outside the scanned tree), against the cache directory
  the scan reads. A lock in that cache directory makes
  concurrent scans take turns, and each tool is updated once per scan. The scanners
  then run with their own update turned off (`trivy --skip-db-update`,
  `GRYPE_DB_AUTO_UPDATE=false`). Offline nothing is updated, and in both cases ASH's
  staleness check still holds the database to its bound. trivy's Java database
  (about 935 MiB) is not updated and trivy and trivy-repo run with
  `trivy --skip-java-db-update`: `trivy fs` and `trivy repository` do not analyze JAR, WAR
  or EAR files and never read it. In every run, sandboxed or not, online or offline,
  trivy and trivy-repo keep their scan cache in memory (`trivy --cache-backend=memory`),
  because trivy otherwise opens
  `fanal/fanal.db` in a cache directory it may only read, and exits 1. A cache can
  be read-only outside a sandbox too, when it is shared or baked into an image.
- The cache directory is the one grype or trivy itself uses on the host:
  `GRYPE_DB_CACHE_DIR` or `TRIVY_CACHE_DIR` when set, else `$XDG_CACHE_HOME` when it
  is an absolute path (trivy reads it only on Linux, and a relative one makes it use
  `$TMPDIR/trivy`), else `~/.cache` on Linux,
  `~/Library/Caches` on macOS, and `%LOCALAPPDATA%\cache` (grype) or
  `%LocalAppData%` (trivy) on Windows. grype keeps its database in `grype/db` under
  it and trivy in `trivy`. The sandbox does not pass `XDG_CACHE_HOME`, so in every
  run, sandboxed or not, ASH names the directory to the scan (`trivy --cache-dir`,
  `GRYPE_DB_CACHE_DIR`), to the update and to the staleness check, and all three read
  the same database. A `cache.dir` in a `trivy.yaml` or a `db.cache-dir` in a grype
  config does not move it; set the variable instead. ASH logs a warning naming the
  grype config when it sets `db.cache-dir`; a trivy `cache.dir` is overridden
  without one.
- The config files ASH writes for a scanner's tool (the empty config bandit, grype,
  syft, ferret-scan, trivy, trivy-repo, actionlint and cfn-lint get when you name
  none, gitleaks' default-rules config, trivy's and trivy-repo's empty ignore file
  and secret config, the empty directories ASH passes trivy and trivy-repo as their
  modules directory and gitleaks as its ignore path, the copies of your `rules_paths`
  files ASH gives cfn-guard, and the copies of the files a `.gitleaksignore` names
  that gitleaks re-scans) are in a directory of that scanner run's own, outside the
  scanned tree (normally in the system temporary directory, never under one another
  account can change), made with mode 0700 and removed when the run ends. The
  scanner can read it and cannot write to it. Under sandbox-exec, the one backend
  that limits where programs run from, it cannot run programs from it either.
- System directories (`/usr`, `/etc`, `/opt`, `/nix`) and the directories on `PATH`
  are read-only. A `PATH` entry inside the scanned tree or the output directory is
  not a tool directory; the tree is mounted only as the scan's data. The same goes
  for an entry of ASH's own `sys.path` there (`PYTHONPATH=src`): it stays readable
  for the imports, and nothing is run from it. Inside `$HOME`
  only `PATH` entries that are `bin`, `sbin` or `Scripts` directories are mounted,
  and a tool's install prefix only when it is deeper than a directory directly
  under `$HOME` (`~/.nvm/versions/node/v22` yes, `~/.cargo` no). A directory counts
  as a `bin` directory only by the directory it resolves to: that directory must be
  named `bin`, `sbin` or `Scripts`, must not be a home directory, and must not
  contain one. So a real `~/bin` is mounted, while a link spelled `bin` that
  resolves somewhere else (`~/bin` linked to `~/.aws`, or `$WORK/bin` linked to
  `$WORK`) is not a `bin` directory. An install prefix that is `/`, a home directory or a
  directory holding one is never mounted: a tool in `$WORK/bin` with
  `HOME=$WORK/home` gets `$WORK/bin`, and nothing of `$WORK` when `$WORK/bin` is a
  link to `$WORK` itself. When `HOME` names a directory other than your account's
  passwd entry's home, both directories are screened this way. A link at the top of
  a home that names a directory elsewhere, such as `~/.local` kept on another disk,
  counts as part of that home: the directory it names is screened as if it were
  directly in the home, so its `share` and keyrings are not mounted. A link to a
  system directory (`~/u` linked to `/usr`) changes nothing.
- A program that one of ASH's own checks has a spawn's tool start gets the grants
  that tool gets, through the same rules: its directory and its install prefix. The
  check of a pre-installed scanner runs `uv`, which starts the scanner's Python to
  inspect it, so that Python's environment is mounted for the check. Only ASH's own
  code names such a program, never a scanner's options or the scanned repository.
- ASH's own Python is mounted where it is installed, and `ASH_BIN_PATH` with it. A
  Python whose binary sits directly in a top-level system directory (`/opt/python3`,
  or `/bin/python3` where `/bin` is not merged into `/usr`) gets that directory,
  which is already mounted, and never `/`. One directly in any other top-level
  directory (`/mnt/python3`, `/srv/python3`) is refused, since it would mount that
  whole directory, and so is a Python whose `sys.prefix` is `/`. The scanner is
  refused rather than given the home when the Python's prefix is a home directory
  or a directory directly in one that is not a virtual environment or conda
  installation, when the Python is reached through a link kept in a home outside a
  `bin`, `sbin` or `Scripts` directory and outside the Python's own installation (a
  virtual environment made with `~/python3 -m venv`, or a link in `~/.config`), or
  when `ASH_BIN_PATH` names a home or a directory directly in one that is not a
  `bin` directory. Use an interpreter or virtual environment outside the home
  directory, or one created from the interpreter's real path. A virtual environment
  made from a Python whose prefix is refused keeps that prefix as its base, so it is
  refused too.
- A virtual environment or conda installation directly in a home is told apart from
  any other directory there by its marker (`pyvenv.cfg`, `conda-meta`) and by a short
  list of directories that never count as one, whatever marker they hold:
  `~/.local`, and any directory holding `share/keyrings`. That list is a heuristic,
  not a proof. Another directory with a marker, such as a venv made at `~/work`, is
  mounted whole. It is acceptable because `sys.prefix` is the Python the operator
  chose to run ASH with, so keep that environment free of files a scanner must not
  read.
- The offline rule cache of semgrep and opengrep, the directory
  `SEMGREP_RULES_CACHE_DIR` or `OPENGREP_RULES_CACHE_DIR` names, is mounted read-only
  for that scanner wherever it is, `$HOME` included. Under sandbox-exec, the backend
  that restricts which files may be executed, no program runs from it; bwrap,
  firejail and Landlock restrict writes and reads, not exec, there. Only the
  variable in ASH's own environment grants it, never a path in the scanner's options;
  an empty or relative value grants nothing, and one naming a file, `/`, `$HOME` or a
  directory above `$HOME` (or the passwd entry's home, or a directory above it, when
  `HOME` names another directory) is not mounted, with a warning. A directory directly under
  `$HOME`, such as `~/rules`, is mounted as named, so point the variable at the rules
  directory itself.
- The environment is filtered to an allowlist: locale, `PATH`, TLS and proxy settings,
  ASH's and uv's own variables, and the prefixes the scanner declares (`GRYPE_`,
  `SEMGREP_`, ...). Within those, a name containing `TOKEN`, `PASSWORD`, `SECRET`,
  `AUTH`, `CREDENTIAL`, `API_KEY` or `SESSION`, and any value carrying
  `user:password@` in a URL, is dropped unless the scanner names that exact variable
  (snyk-code names `SNYK_TOKEN`). Cloud credentials and tokens are not passed in.
- The proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` and the
  lowercase forms) and the certificate settings (`SSL_CERT_FILE`, `SSL_CERT_DIR`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) are the default of
  one environment list, `sandbox.environment`, which has the shape of a
  docker-compose `environment` list: a name passes the value ASH has, and
  `NAME=value` sets it. Every backend reads the same list, and a list you write
  replaces the default one, as a compose list replaces an image's (see
  [Pass other variables](#environment)). A proxy setting is passed only to a scanner
  that has a network. A name the rule above drops, `TMPDIR` (every backend gives each
  scanner a private one) and ASH's own run id are refused with the name, so the list
  is not a channel for secrets. A `NAME=value` entry whose value carries
  `user:password@` in a URL is refused with the variable named and no value shown,
  because the sandbox would drop it from every scanner and the entry would do
  nothing. A variable the list passes by name is held to the same rule when ASH is
  started with such a value: it is dropped without a message.
- A certificate setting you made is readable inside the sandbox, on every backend,
  where bwrap, firejail and Landlock hide the home directory, for a scanner that has
  a network (a scanner with none never verifies a peer, so it is granted no read,
  and the variables are still passed): the files that
  `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`
  name, read-only, and each directory `SSL_CERT_DIR` names. The grant is for the value
  ASH started with (or one the list sets), never for a value that appears later in
  the environment. A `SSL_CERT_DIR` entry that is a home directory or holds one is
  not granted, with a warning, because it would show far more than the certificates.
  So is an entry that the backend cannot write in its options (a path with `~` or `*`
  under firejail, or a control character under sandbox-exec): it is passed through
  but not granted, with a warning, and the scan goes on.
  A setting written through a symlink that sits inside your home directory
  (`~/.config/corp/ca.pem` pointing at `/etc/ssl/certs/corp.pem`) is readable under
  bwrap, which recreates the link inside the sandbox. Firejail cannot recreate a
  link: it grants the file the link points to, warns once, and the written path stays
  unreadable. Point the setting at the file itself there. Under firejail a file in a
  `HOME` that differs from the passwd entry's home stays unreadable too, because the
  sandbox hides that whole directory; keep the bundle outside it.
- No local IPC endpoint is reachable, with or without a network: not the Docker or
  Podman socket, the session bus, `$SSH_AUTH_SOCK`, the journal, nor a socket in a
  directory the sandbox mounts, such as the Nix daemon's under `/nix`. On Linux every
  backend refuses `socket(AF_UNIX)` and datagram `socketpair()` with a seccomp filter
  (see Landlock below), so neither a socket path nor an abstract socket can be
  reached. The variables that name these endpoints (`SSH_AUTH_SOCK`,
  `DBUS_SESSION_BUS_ADDRESS`, `DOCKER_HOST`, `CONTAINER_HOST`, `XDG_RUNTIME_DIR`)
  are not passed in. firejail sets `DBUS_SESSION_BUS_ADDRESS` itself, to a path of
  its own that `firejail --dbus-user=none` leaves unserved.
- A results directory that is, or is reached through, a symlink is refused (the
  scanner is recorded `MISSING`). The default output directory is inside the source
  tree, so the scanned repository could otherwise plant one pointing anywhere.
- So is an output directory that is a symlink, or that is reached through one below
  the source directory (a committed `build -> /some/host/dir` scanned with
  `--output-dir build/ash`), however either path is spelled, or that is inside the
  source directory by its path but outside it by its real path, or whose
  `analysis`, `reports`, `scanners` or `converted` directory, or a file ASH writes
  there by a fixed name such as `ash.log`, is one. The scan stops with an error that names the link before ASH
  writes anything there, whatever the sandbox mode, since ASH clears and writes
  those itself; pass `--output-dir` with a directory that is not a link. See
  [Links are refused](../reference/output-files.md#links) for the full list. Links above an
  output directory outside the source tree (`/tmp` on macOS) are your own and are
  not examined.
- ASH writes into the results directory after the scanner exits, and ASH is not
  sandboxed. So after every sandboxed spawn, and again after the scan, ASH removes
  every symlink and special file the scanner left there. A symlink already below the
  results directory when the scanner starts (one committed with the scanned tree) is
  refused instead, and the scanner is `ERROR`.
- ASH's own writes below the output directory never follow a symlink, with the
  sandbox on or off: `ash.log` and `ash.log.jsonl`, worker request files, stream
  logs, `ASH.ScanResults.json`, `ash_aggregated_results.json`, every report, the
  files a converter extracts and the files a scanner override writes. A link at
  `ash.log` stops the scan with exit 3 before it starts, as a linked output directory does. A symlink at any component of the path, the
  file name included, stops the write with "`<path>` was not written: `<link>` is a
  symlink, and ASH does not write through a symlink below its output directory"
  (`OutputLinkRefused`, an `OSError`). Nothing is written where the link points, the
  link is left in place, and the scanner whose write was refused is `ERROR`. A file
  there that another name also refers to (a hard link, which an extracted archive can
  hold) is refused the same way, before anything in it is changed, with "`<path>`
  was not written: `<n>` names refer to it" (`OutputHardLinkRefused`); so is one
  already below a sandboxed scanner's results directory when the scanner starts.
  Links at or above the output directory itself are not examined, as above. On
  Windows, which has no way to open a path relative to a directory without
  following a link, ASH checks each component by name before it opens the file,
  symlinks and reparse points such as junctions included: a link already there is
  refused, but one created between that check and the open is not. A process the scanner leaves running cannot keep
  planting links afterwards: bwrap and firejail end the whole process tree with the
  scanner, and the Landlock wrapper is a child subreaper that kills any process its
  scanner left behind before it exits. On a timeout ASH sends a sandboxed process
  SIGTERM first (SIGKILL after 10 seconds), so the Landlock wrapper gets to end its
  whole tree rather than being killed outright.
- Network: under `--offline` no scanner gets a network. Online, only scanners that
  declare a network need get one (to fetch a content database, a rule pack, or
  audit data from a package registry); everything else runs with no network.

### Per-scanner needs

| Scanner | Network when online | Caches | Runtime |
|---------|--------------------|--------|---------|
| bandit | no | uv cache | uv-managed Python |
| checkov | no | uv cache | uv-managed Python |
| semgrep | yes (registry rules, `p/ci`) | uv cache, `~/.semgrep`; `$SEMGREP_RULES_CACHE_DIR` read-only | uv-managed Python |
| opengrep | yes (registry rules) | `~/.opengrep`; `$OPENGREP_RULES_CACHE_DIR` read-only | single binary; on macOS it unpacks itself into a private directory per spawn |
| grype | yes (database update) | grype database cache (read-only, or a throwaway overlay under bwrap) | single binary |
| syft | no | syft cache | single binary |
| trivy-repo | yes (database update) | trivy cache (read-only, or a throwaway overlay under bwrap) | single binary |
| npm-audit | yes (registry audit API) | `~/.npm` | Node.js |
| cfn-nag | no | none | Ruby and its gem paths |
| detect-secrets | only when `sandbox.network_scanners` names it | none | ASH's Python, in a worker subprocess |
| cdk-nag | no | jsii's runtime cache, not used on macOS | ASH's Python with the cdk extra, and Node.js for jsii, in a worker subprocess |
| actionlint | no | none | single binary |
| cfn-lint | no | uv cache | uv-managed Python |
| cfn-guard | no; reads its rules bundle (`$ASH_CFN_GUARD_RULES_DIR`, or `share/cfn-guard-rules` beside ASH's bin directory) | none | single binary |
| gitleaks | no | none | single binary |
| zizmor | no; `online_audits` gets neither a network nor a GitHub token yet | uv cache | uv-managed binary |

### Community and third-party plugin scanners

The sandbox applies to every scanner, whatever module it comes from. A scanner from a
community module (snyk-code, ferret-scan, trivy-repo) or your own plugin package gets
its policy from its `sandbox_requirements` class attribute. A scanner that declares
none gets the strictest default: no network, the source tree read-only, its own
results directory as the only writable place, a private empty `$HOME` and `/tmp`, and
the baseline environment allowlist with nothing added. It still runs; it is never
skipped for lacking a declaration, and never run unsandboxed.

A plugin that needs more declares it:

<!-- doctest: illustrative reason="a fragment of a scanner plugin class that names a config class defined elsewhere" -->
```python
from typing import ClassVar

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.utils.sandbox.policy import SandboxRequirements


class MyScanner(ScannerPluginBase[MyScannerConfig]):
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        # A network when the scan is online; never under --offline.
        network=True,
        # Extra read-only paths.
        read_paths=("~/.my-tool/rules",),
        # Read-only, or writable through bwrap's throwaway overlay.
        cache_paths=("~/.cache/my-tool",),
        # Where the cache is read-only, these point at a private, empty
        # directory, for a tool that has to write its cache.
        cache_env=("MYTOOL_CACHE_DIR",),
        # Variables passed through.
        env_prefixes=("MYTOOL_",),
        # Credential-shaped names it needs.
        env_names=("MYTOOL_TOKEN",),
        # Set under sandbox-exec only, after the allowlist.
        sandbox_exec_env=(("MYTOOL_PACKAGE_CACHE", "disabled"),),
        # The tool unpacks itself where this variable says and runs what it
        # unpacked; sandbox-exec points it at a private directory per spawn.
        unpack_dir_env="XDG_CACHE_HOME",
        # True when read_paths come from the scanner's options, which the
        # scanned repository can write: they are then mounted only for scanners
        # named in sandbox.read_path_scanners, and cache_paths are not mounted.
        read_paths_require_grant=False,
        # The same for env_prefixes and env_names, with sandbox.env_scanners.
        env_requires_grant=False,
        # Variables in ASH's own environment naming a directory the tool reads
        # (semgrep's SEMGREP_RULES_CACHE_DIR): mounted read-only, and not
        # executable under sandbox-exec.
        # An unset or empty variable, or one naming /, $HOME or a directory above
        # it, grants nothing.
        read_path_env=("MYTOOL_RULES_DIR",),
        # True for a tool handed a staged copy of its input outside the tree
        # (the jupyter converter's nbconvert): it may not read the source or
        # output directory. See "Converters" below.
        staged_input_only=False,
    )
```

The community scanners declare theirs:

- snyk-code asks for a network, its `SNYK_` variables and `SNYK_TOKEN`, and read
  access to its token file.
- trivy-repo shares the builtin trivy's declaration: a network, the database cache and
  the `TRIVY_` variables.
- ferret-scan asks only for its `FERRET_` variables.

A file outside the source tree that a scanner option names is not mounted (cfn-guard's
`rules_paths` needs no mount: ASH copies those rules into the scanner run's own
directory above): a
`config_file` of actionlint, gitleaks, cfn-lint,
zizmor, trivy or trivy-repo, gitleaks' `baseline_path`, trivy's `ignore_file`, a
`secret_config_file` of trivy or trivy-repo, trivy-repo's `module_dir`, or a
path-valued actionlint `shellcheck` or `pyflakes`. Nor do gitleaks' `GITLEAKS_*` variables or
zizmor's GitHub token reach a sandbox. Grants derived from options or the environment
wait for the sandbox's grant gates; until then list such a path in
`sandbox.extra_read_paths`, from a config outside the tree.

detect-secrets needs a network only to verify candidate secrets with their issuers,
which it does when its settings list the verification filter. Only the operator's own
configuration can list it: ASH removes it from a `.secrets.baseline` inside the
scanned tree and from a config file the scanned repository or an MCP client wrote,
and offline from every source (see
[What each tier may set](../concepts/trust-model.md#what-each-tier-may-set)). A baseline the
operator names can still load a detect-secrets plugin from a file outside the tree, so
the sandbox doesn't take detect-secrets' own word for it either: detect-secrets gets a
network only when `sandbox.network_scanners` names it, and a repository can't set that
(see below). Without a network every candidate counts as unverified, so a sandboxed
scan whose settings verify reports the candidates that verification would have
dropped, and ASH logs a warning naming the setting.

detect-secrets and cdk-nag are Python libraries. They run in worker subprocesses,
not in the ASH process, where no OS sandbox could reach them. The workers use the
same interpreter and the same library calls, so their findings are unchanged
and the sandbox wraps them like any other scanner. To let detect-secrets verify
secrets under the sandbox, pass `--config-overrides 'sandbox.network_scanners=[detect-secrets]'`
(plus any other scanners that need a network). Under `--offline` it gets none.

### Give a scanner more access {#grants}

To give an extra scanner network access, or take it away:

```yaml
sandbox:
  mode: bwrap
  network_scanners: [grype, trivy-repo]   # replaces the per-scanner defaults
  extra_read_paths: [/opt/company-ca]
```

#### Pass other variables {#environment}

`sandbox.environment` lists the variables every sandboxed scanner is passed besides
its fixed baseline (`PATH`, the locale and terminal settings, and the `ASH_`, `UV_`,
`LC_` and `PYTHON` families). It is written as a docker-compose `environment` list:
`NAME` passes the value ASH has, `NAME=value` sets one, and a name listed twice takes
its last entry.

```yaml
sandbox:
  mode: bwrap
  environment:
    - HTTPS_PROXY
    - NO_PROXY
    - SSL_CERT_FILE
    - MY_TOOL_HOME=/opt/company/tool
```

The default list is the proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
`NO_PROXY` and the lowercase forms) and the certificate variables (`SSL_CERT_FILE`,
`SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`). A list
you write replaces it, as a compose list replaces an image's: the list above passes
four variables and drops every other proxy and certificate variable, so write each
one you still want. To change it for one run, pass
`--config-overrides 'sandbox.environment=[HTTPS_PROXY,SSL_CERT_FILE,MY_VAR]'`; there
is no separate flag.

A `NAME=value` entry sets a variable in every sandboxed scanner, `LD_PRELOAD` and
`NODE_OPTIONS` included, so the setting grants access like the others below and
follows the same rule about who may set it. A name that marks a credential, `TMPDIR`,
ASH's own run id and a `NAME=value` entry whose value is a URL with a user name and
password (a proxy such as `http://user:password@proxy:3128`) are refused when the
config is read, with the variable named and no value shown. A scanner that needs a credential is granted it with
`sandbox.env_scanners` and its own variable names instead.

#### Who may grant

Five settings grant access: `network_scanners`, `extra_read_paths`, `environment`,
and the two below that let a scanner have what its own options ask for. A config file the
scanned repository could have written can't grant any of them. That means a config
file inside any git checkout, where a directory at or above the file, by its own path
or its resolved path, holds a `.git` entry (a directory, or the file a submodule or
linked worktree has). Only `--config-overrides` and config files outside every git
checkout can grant; the `--sandbox` flag sets only the mode. For a scanned directory
outside any checkout, such as an extracted archive, a config file inside that
directory can't grant either, whether it is reached by the directory's own name, its
resolved path, or the shell's working directory (`$PWD`).

An in-tree `network_scanners` list still takes network away: a scanner it doesn't
name gets none, so a repository can keep its own scan offline with
`network_scanners: []`.

When any file the config was built from can't grant (the discovered `.ash/.ash.yaml`,
a `--config` path, an `extends` base, or the file `ASH_CONFIG` names), the five
settings are taken from the files that can: in workspace mode the operator's
default config (under the MCP server, the session's bound profile), else
`ASH_CONFIG`'s file, else the defaults, plus `--config-overrides`. A file that can
grant itself but extends a base that can't keeps the settings its own `sandbox`
section writes, `mode` included. For example, a `--config` outside every checkout
that extends the scanned repository's config keeps the grants it sets, and loses
what it inherits from any base, even one outside every checkout, and the grants it
adds with `patch`; a `mode` its own `patch` sets counts as written. ASH logs a
warning that names the files that can't grant and the settings it dropped. A `network_scanners` list in such a file still takes network away: a scanner
it doesn't name gets none, so a repository can keep its own scan offline with
`network_scanners: []`.

For a config in `/home/me/src/app/.ash/.ash.yaml` that grants grype a network and a
read path, the warning reads:

```text
WARNING  Ignoring sandbox.network_scanners, sandbox.extra_read_paths from /home/me/src/app/.ash/.ash.yaml: that config is inside a git checkout or the scanned tree, or was delivered by an MCP client. A network_scanners list there still removes network from scanners it does not name, and a sandbox mode there still applies when nothing else turns the sandbox on. To keep a setting, move the file outside every git checkout, or pass the setting with --config-overrides. A file inside the scanned directory has to move out of it as well.
```

This applies to a trusted config kept in a checkout of its own as well, such as an
ops or dotfiles repository: its grants are dropped with the same warning. Pass them
with `--config-overrides` instead, for example
`--config-overrides 'sandbox.network_scanners=[grype,trivy-repo]'`.

A plugin scanner can take its read paths or environment variables from its options,
such as a rules file outside the source tree, or a token for an online check. The
repository can write those options, so such a scanner declares it with
`read_paths_require_grant` or `env_requires_grant`, and the sandbox grants those
needs only to the scanners named in `sandbox.read_path_scanners` or
`sandbox.env_scanners`. None of the scanners ASH ships declares either;
detect-secrets' baseline, below, is gated by `read_path_scanners` directly. The two
settings follow the same rule as `network_scanners`, and ASH logs a warning when it
withholds such a need. Even when granted, a path a scanner's options name is
mounted only if it resolves inside the source tree or one of the operator's
`extra_read_paths` entries, and only if it is a regular file or directory, never a
socket or device. To let a scanner read a
rules file elsewhere on the host, put its directory in `sandbox.extra_read_paths`. A
cache path a scanner's options name is never mounted.

ASH itself reads some files that scanner options name, outside the sandbox, and
passes their contents on. detect-secrets' `baseline_file` is one. Under a sandbox,
ASH reads such a file only when it is inside the source tree, or when
`sandbox.read_path_scanners` names the scanner and the file is inside one of the
operator's `sandbox.extra_read_paths` entries, the same containment a path the
scanner reads itself gets. Otherwise it skips the file with a warning, and the
candidates the baseline would have marked are reported. A baseline an MCP client
delivered is not read at all.

A config file is judged by the name it was found under as well as by the file it
resolves to, so a `.ash/.ash.yaml` that is a symlink out of the scanned directory
still counts as inside it. An `extends` base is judged the same way, by the path its
`extends` entry names as well as by the file it resolves to, so a base the repository
turns into a symlink to some other file still counts as inside the checkout. Every
symlink met on the way counts too: a path that leads through a link inside a
checkout, even from a link of your own, counts as inside that checkout, and the
reason names the link.
Plugin modules are judged by the same rule. A tool config file a scanner option
names is judged by it too when a config inside the scanned tree names it; one the
operator names may sit in a checkout of the operator's own. See
[How a file's tier is decided](../concepts/trust-model.md#how-the-tier-is-decided).

Sandbox grants follow a scanner's own name, the one its code gives it. If a config
file renames a scanner's section, for example by setting `name: grype` on a plugin's
section, that scanner is not run sandboxed: it is recorded `MISSING` with the reason.

`mode` is a restriction, so it is honored from any source, as a floor. When
`--sandbox`, `ASH_CONFIG`, or the operator's config file turns the sandbox on, a
config file the repository could have written can't turn it off or switch it to
another backend. The operator's mode holds even if the operator's file is itself in
a checkout, because a mode other than `off` grants nothing. Only `--sandbox off` or a
`sandbox.mode` override turns it off. When nothing the operator set turns the
sandbox on, the repository's `mode` applies, because a sandbox the repository asks
for only takes access away. In workspace mode, the operator's `--config` decides for
a project that has its own config file, the same as for one that doesn't.

### Install tools before a sandboxed scan

A sandboxed scan does not install tools, for scanners and converters alike:
installing runs a package's build code and writes uv's tool directory, which a
sandboxed scanner may only read. Run `ash dependencies install` first; a scanner
whose tool is missing is recorded `MISSING`, and so is the jupyter converter when
nbconvert is missing, which fails the scan if the tree has notebooks.

### Converters

The jupyter converter runs nbconvert, a third-party tool, over the repository's
notebooks, so under a sandbox nbconvert runs with the confinement a scanner gets: no
network unless `sandbox.network_scanners` names `jupyter`, the environment allowlist,
and the converter's own `<output>/converted/jupyter/` directory as the only writable
place. Unlike a scanner, it may not read the source tree or the output directory:
nbconvert is handed a copy of one notebook in a private directory, and reads that
copy and its tools (`SandboxRequirements.staged_input_only`). bwrap mounts an empty
directory over the tree where a wider mount would show it (a checkout under `/opt`),
and sandbox-exec denies reading the tree and the output directory after the reads it
allows; both give back the results directory and any tool path inside them. Landlock
can only grant access and firejail shows everything outside `$HOME` and `/tmp`, so
under those two a tree inside a directory they show (`/opt`, `/usr/local`, or for
firejail any directory outside `$HOME` and `/tmp`) stays readable to nbconvert. Its
version probe and dependency check run sandboxed as well, with the same read scope. Under a sandbox the converter runs
nbconvert's own `jupyter-nbconvert` executable rather than `uv tool run`, which writes
uv's tools directory and so cannot run there. The convert phase applies the same scope
to every converter, so a third-party converter's tool is confined the same way.

If no sandbox backend can be used, or the backend cannot plan one notebook's run,
nbconvert is not run on that notebook, and it is listed in the converter's
`refused_inputs` with the reason. A notebook nbconvert fails on (a non-zero exit,
as for a notebook that is not JSON, a timeout, or a run that writes no output) is
not converted either, with or without a sandbox. Each such notebook is listed in
the converter row's `failed_inputs`, which the completeness gate reads, so with
`fail_on_incomplete_scanners` on (the default) the scan exits 1; exclude a notebook
that is malformed on purpose, such as a test fixture, with `ignore_paths`. The same
holds for
any converter: a process its `convert()` started that the sandbox refused is named
in its `failure`. Nothing a converter starts runs unsandboxed under a sandbox.

## Threat model

The sandbox is for three cases.

1. A scanner, plugin, or rule pack that does more than it says. A typosquatted or
   hijacked package on PyPI or npm, a scanner binary replaced on disk, a community
   rule pack that runs code.
2. Scanned content that takes control of a scanner. Scanners parse untrusted input and some
   execute it on purpose: tool configuration files committed to the repository
   (`trivy.yaml`, `.semgrep.yml`, `.checkov.yaml`, `.npmrc`, `.bandit`) change what a
   scanner does, plugin systems `eval` code found in the tree, and parser bugs give
   code execution or path traversal on write.
3. Data sent off the machine. Code running in any of the above reading credentials
   (`~/.ssh`, `~/.aws`, tokens in the environment) and sending them over the network.

Inside the sandbox such code can read the source tree (it is scanning it), write its
own results, and, if the scanner is allowed a network, talk to the network. It cannot
read the rest of your home directory, write outside its results directory, modify the
source tree, or see environment variables outside the allowlist.

A symlink in the tree is resolved inside the sandbox, so it reads only what the
sandbox shows. Under bwrap and Landlock a link to a file outside the read list, in
`$HOME` or anywhere else, cannot be read. firejail shows everything outside `$HOME`
and `/tmp`, and sandbox-exec reads everywhere except `$HOME` and the shared temporary
directories, so under those two a link can be read unless its target is in what they
hide.

A hard link is not a link to anything: it is the file, under another name, and
nothing tells it apart from an ordinary file. A file in the tree that is a hard link to
a file outside it is read as part of the tree, by ASH and by every scanner, sandbox or
not. ASH does not try to detect one; a git checkout never makes one, but a tree copied
or unpacked by another tool can. What contains a scanner that reads one is the
sandbox: with no network unless it is granted one, and writes only to its results
directory, what it read reaches only its results. ASH's own writes refuse a file
another name refers to (see [What a sandboxed scanner can do](#what-a-sandboxed-scanner-can-do)).

Out of scope:

- ASH itself and `git`, which run unsandboxed. ASH is the trusted base, and that
  includes the converters' own code: the archive converter unpacks archives into the
  work directory in ASH's process. The tools a converter starts are not ASH code and
  are sandboxed; see [Converters](#converters). `git` runs only for
  `--changed-files-only` and workspace planning, never inside a scanner.
- Links in the scanned tree. ASH's scan set leaves out a link to a file whose
  target, with every link on the way resolved, is outside the source directory, and
  warns about each one, as `Not scanning 'vendor/config.py': link leaves the scanned
  tree`, naming only the link (see
  [Ignore files and the scan set](../reference/coverage.md#what-decides-the-files)).
  So the scanners and converters that read the scan set
  are not given it, and npm-audit does not audit a package whose files link out of
  the tree. The scanners that walk the directory they scan themselves are told to
  skip each such link in their own exclusion option: `bandit --exclude`, one
  `checkov --skip-path` each, `ferret-scan --exclude`, `grype --exclude` and
  `syft --exclude`, and `trivy --skip-files` for trivy-repo. Where a link's path cannot be put in
  that option alone (a comma, a glob character or a line break, or a path another
  file's path holds, for bandit; values checkov's terraform module finder cannot
  compile into its one regex for checkov; a comma, or a path another file's path
  holds, for ferret-scan), that scanner is not run on the directory, and the scan
  fails naming the link. snyk-code tests a copy of the scan set.
- Plugin modules. A config file can list `ash_plugin_modules`, which ASH imports into
  its own process, so they run unsandboxed. From a config file inside the scanned
  tree, only installed modules outside the tree and outside every git checkout are
  imported (see
  [What each tier may set](../concepts/trust-model.md#what-each-tier-may-set)),
  but an installed package still runs with ASH's access. The sandbox doesn't change
  this; review the plugin modules a repository's config names before you scan it.
  ASH's own `ash_aws_plugins` and `ash_snyk_plugins` packages are not imported from
  such a file at all, because they send findings or source off the host with the
  operator's credentials.
  A virtualenv kept inside any git checkout counts as inside it, so a repository's
  config can't import plugins installed there; the warning names the checkout.
  Name such plugins with `--ash-plugin-modules` instead.
- Resource exhaustion. A scanner can still use all the CPU and memory it can get, or
  fork until a limit stops it; the existing per-scanner `scan_timeout` bounds how long.
- A scanner allowed a network shares the host's network, so TCP and UDP services
  listening on the host, loopback included, are reachable from it under every
  backend. Abstract Unix sockets bound by host processes are not: the socket filter
  refuses Unix sockets.
- A scanner allowed a network can still send what it can read (the source tree)
  wherever it likes. The online allowlist is per scanner, not per host. Host-level
  filtering would need a proxy inside the sandbox, which tools can go around unless the
  network namespace forces all traffic through it; that is future work.
- Results integrity. A scanner can still write false results to its own results file.
- Kernel defects. All backends share the host kernel.

## When a scanner cannot be sandboxed {#missing}

ASH records a scanner it cannot sandbox as `MISSING`, and under the default
`fail_on_incomplete_scanners` the scan exits 1. The reason is in the scan output, in
`ash.log`, and in the scanner's `missing_reason` in `ash_aggregated_results.json`:

```text
ERROR    bandit not run: scanner sandbox unavailable: firejail is not installed
```

| Message | Fix |
|---|---|
| `bwrap is not installed (install the 'bubblewrap' package)` | Install bubblewrap. |
| `bwrap cannot create a sandbox here (...)` | Allow unprivileged user namespaces, or use `landlock`. |
| `bwrap cannot apply the Unix-socket filter in its sandbox (...)` | Use the bwrap from your distribution, on x86_64 or aarch64, on a kernel that allows seccomp filters. |
| `Landlock is not available (...)` | Add `landlock` to the `lsm=` kernel parameter. |
| `Landlock ABI <n> is below 3 (Linux 6.2), ...` | Use bwrap, a kernel with Landlock ABI 3 or later, or container mode. |
| `firejail is not installed` | Install firejail, or use another backend. |
| `firejail ran a test command without a sandbox (...)` | Use `bwrap` or `landlock`; firejail does not sandbox inside this container. |
| `sandbox-exec is not present (it has been removed from this macOS)` | No macOS backend remains; scan in a container. |
| `--sandbox auto found no working sandbox (...)` | Lists why each backend failed; fix one of them. |
| `no scanner sandbox is available on Windows; ...` | Use WSL2 or container mode. |
| `<name>: the config names this scanner '<name>', but its own name is '<other>'` | Configure the scanner under its own name; grants follow a scanner's own name. |
| `<scanner> cannot be sandboxed as requested: ...` | Logged while ASH checks the scanner's tool; fix the reason that follows. |
| `the results directory path <path> is a symlink, ...` | Remove the link under the output directory, or pass another `--output-dir`. |
| `a scanner tried to start a shell command, which the sandbox does not wrap` | The scanner's plugin starts its tool through a shell. Leave that scanner out of sandboxed scans, or ask the plugin's author to start the tool directly. |

## Scan a repository you do not trust {#untrusted}

For a repository you do not trust, on Linux or macOS:

1. Install the scanners first, from a trusted environment, with
   `ash dependencies install`. Run it from a directory outside the repository, because
   it reads the ASH config of the directory it runs in. A sandboxed scan does not
   install tools (see
   [Install tools before a sandboxed scan](#install-tools-before-a-sandboxed-scan)),
   and a scanner whose tool is missing is recorded `MISSING`.
2. Keep your own config file outside every git checkout and outside the scanned
   directory, and pass it with `--config`. Only such a file and `--config-overrides`
   can grant sandbox access (see [Who may grant](#who-may-grant)).
3. Scan in local mode with the sandbox on. On Linux, name the backend with
   `--sandbox bwrap`, or set `sandbox.mode` to `bwrap` in that file: `--sandbox auto`
   falls back to firejail when bwrap is not usable, and firejail leaves readable every
   path outside `$HOME` that your user can read. On macOS the backend is sandbox-exec,
   which reads everywhere except the home directory and the shared temporary
   directories.
4. Scan with `--offline` if you can, so that no scanner gets a network. Otherwise set
   `sandbox.network_scanners` to the shortest list that works. Offline, npm-audit is
   `MISSING` for a project that has a lockfile, because npm, pnpm and yarn audit only
   against the package registry; leave it out with `--exclude-scanners npm-audit`.
5. Put the output directory outside the repository with `--output-dir`. The default
   output directory, `.ash/ash_output`, is inside the scanned directory.
6. Do not pass `--allow-in-tree-tools` or set `ASH_ALLOW_IN_TREE_TOOLS`, so that ASH
   starts no tool it finds only inside the repository (see
   [Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory)).
7. Name only plugin modules you trust. A plugin module runs in ASH's own process,
   outside the sandbox.

With the default `fail_on_incomplete_scanners`, a scanner whose tool is found only
inside the repository, or that cannot be sandboxed under `--sandbox auto` because no
backend works, is `MISSING`. A scanner whose sandbox backend you named and that is
unavailable, or whose sandbox is refused for another reason, is `ERROR`. Either way the
scan exits 1, rather than passing on fewer scanners than you asked for.

On Windows there is no sandbox backend. Run ASH under WSL2 with `--sandbox bwrap`, or
use container mode, where the container is the boundary.

## Design

### One choke point

Every scanner subprocess is started through one function,
`utils/subprocess_utils.py:_prepare_spawn`, whether the scanner is run directly, through
`uv tool run`, or as a version or availability probe. A sandbox scope (a context
variable holding the policy for that scanner) is active around each scanner's
construction and dependency check, which is when scanners probe their tools, around
its scan, and around the content-database check that runs `grype db status`.
`_prepare_spawn` rewrites the command line for the active backend when a scope is
active. Probes get a throwaway results directory. A scanner that cannot be sandboxed
as requested gets a refusing scope, so its probes fail instead of running unsandboxed.
The convert phase enters the same kind of scope around each converter's construction,
dependency check and `convert()`, and the jupyter converter enters one around each
nbconvert run, with the staged notebook as its scan target. Spawns made outside any
scope (ASH's own `git` calls, the container runtime) are unaffected. A sandboxed scan
never installs a tool.

`tests/unit/utils/test_sandbox_choke_point.py` fails the build if any module in the
package outside a short, reasoned exemption list calls `subprocess.run`,
`subprocess.Popen`, `os.system`, `os.exec*` or the like directly, so a new spawn site
cannot go around the choke point. The scope is per thread: a scanner that started a
process from a thread it created itself would not inherit it. No builtin scanner does.

### Linux: bubblewrap (preferred)

bubblewrap builds an empty root from a tmpfs and mounts into it only what the policy
lists, in new user, mount, PID, IPC, UTS, cgroup and (when the scanner gets no network)
network namespaces. It needs no setuid binary on distributions that allow unprivileged
user namespaces. ASH passes `bwrap --die-with-parent` and `bwrap --new-session`, so a scanner
cannot outlive ASH or inject keystrokes into the terminal through `TIOCSTI`.

bwrap's mounts hide `/run` and `$HOME`, but not a Unix socket inside a directory it
does mount (the Nix daemon's socket is under `/nix`), and a scanner with a network
shares the host's network namespace and every abstract Unix socket bound there. So
the scanner is started through the Landlock wrapper in its socket-filter mode, which
installs only its seccomp socket filter (described under Landlock) and then execs the
scanner. IP sockets are left to the network namespace, so a tool can still use its own
loopback when it has no network. ASH's probe runs the filter inside bwrap once, so an
architecture the filter does not cover makes bwrap unavailable rather than unfiltered.

Ubuntu 23.10 and later restrict unprivileged user namespaces through AppArmor
(`kernel.apparmor_restrict_unprivileged_userns=1`). Install bubblewrap from the
distribution (`apt install bubblewrap`); if `bwrap --unshare-all --ro-bind / / true`
still fails with "setting up uid map: Permission denied", the restriction applies to
it, and either an AppArmor profile that grants `userns` to `/usr/bin/bwrap` or
`sysctl kernel.apparmor_restrict_unprivileged_userns=0` lifts it. ASH probes by
running `bwrap ... true` once per process, so a `bwrap` that is installed but cannot
start is reported as unavailable with the error it printed, not used and found broken
mid-scan.

The throwaway cache overlay uses `bwrap --overlay-src` and `bwrap --tmp-overlay`, which need
bubblewrap 0.8 and Linux 5.11. On older systems those caches are mounted read-only
instead, as under the other backends, and the log says so.

### Linux: firejail (fallback)

firejail is a setuid-root binary, a privileged program of its own (it has had
privilege-escalation advisories), and its filesystem model is "everything visible, then
restrict" rather than "nothing visible, then allow". ASH uses
`--noprofile --private-dev --nonewprivs --caps.drop=all --seccomp --nogroups`,
`firejail --dbus-user=none --dbus-system=none`, `firejail --net=none` when the scanner gets no network,
makes `/` read-only, blacklists the container runtime sockets, `/run/user/<uid>` and
`$SSH_AUTH_SOCK`, whitelists inside `$HOME` (and `/tmp`) only the paths the policy
lists, uses `firejail --private-tmp` when the policy lists nothing under `/tmp`, and makes the
results directory read-write. Paths outside `$HOME` that your user can read remain readable, and scanner
caches are read-only because firejail has no throwaway overlay. Because
everything outside `$HOME` stays visible, `/run` and its sockets included, the
scanner is started through the same seccomp socket filter as under bwrap. Use bwrap
when you can.

firejail takes the home directory it hides from your account's passwd entry, not
from `HOME`. When `HOME` names another directory, ASH decides the whitelists inside
the home against the passwd entry's home, as firejail applies them, and also
blacklists the directory `HOME` names, unless it is under `/tmp`, which is already
private. A tool installed inside that directory then fails to start rather than the
directory being shown. sandbox-exec likewise denies reading both directories.

A directory that a link at the top of either home names outside the homes, such as
`~/.local` kept on another disk, is part of that home but lies outside it, where
both backends would otherwise show it. sandbox-exec denies reading it along with the
homes, before the policy's own paths are allowed again, so a tool's `bin` directory
inside it still runs while its `share` and keyrings stay unreadable. firejail
blacklists it, or, where the policy lists paths inside it (that `bin` directory, or a
scanned repository kept in a linked `~/code`), every entry beside the way to those
paths. A link to a system directory, such as `~/u` linked to `/usr`, is not hidden.

firejail also decides for itself whether to build a sandbox at all. When it finds no
kernel threads among the first ten PIDs, as inside a container that has its own PID
namespace, it concludes it is already sandboxed and runs the command with none of the
options above. The command still exits 0, and the only sign is a warning that
`--quiet` hides. So ASH's probe runs `readlink /proc/self/ns/mnt` under the same
options, without `--quiet`, and requires a mount namespace other than ASH's own, since
every sandbox firejail builds has one. When the command reports ASH's namespace, or
firejail prints that warning, firejail is unavailable with that reason:
`--sandbox firejail` records each scanner `MISSING`, and `--sandbox auto` moves on to
Landlock.

### Linux: Landlock

Landlock is an unprivileged kernel LSM, so this mode needs nothing installed. It
needs Landlock ABI 3 (Linux 6.2) or later, the first that controls truncation: on an
older kernel a scanner could truncate files it may only read, so ASH reports
Landlock unavailable there. `--sandbox landlock` then records each scanner `MISSING`
with the ABI in the reason, and `auto` does not use it. ASH starts a small wrapper
(`utils/sandbox/landlock_exec.py`, standard library only) that restricts itself and
then `exec`s the scanner:

- Landlock filesystem rules: read and execute beneath the read-only paths, full access
  beneath the results directory and a fresh private temporary directory (`TMPDIR`).
  Nothing else, including `$HOME` and `/tmp`, is reachable.
- Sockets: Landlock does not mediate `connect()` on a Unix socket path, so a scanner
  that could create a Unix socket could talk to the Docker socket or the session bus
  whatever the filesystem rules say. A seccomp filter therefore refuses
  `socket(AF_UNIX)` always. `socketpair()` of the stream and seqpacket kinds, which
  tools use for pipes, still works; a datagram pair is refused, because a datagram
  socket can `sendto()` or `connect()` any datagram socket by path, such as the
  journal's `/dev/log`, however it was created. The filter also refuses
  `socket()` for every family when the scanner has no network, which blocks UDP and
  DNS too, and refuses `io_uring_setup`, because io_uring can create sockets without
  the `socket` syscall. Landlock's own network rules (ABI 4, Linux 6.7) cover only TCP
  and are added as a second layer.
- A tool that creates a Unix socket of its own fails too, under this backend and, since
  bwrap and firejail run the same filter, under every Linux backend. Python 3.14's
  default multiprocessing start method, `forkserver`, is one: it listens on a Unix
  socket, so a Python tool on 3.14 that relies on the default fails with
  `PermissionError`, while the `fork` and `spawn` methods work. ASH's own workers
  select `fork`, and the builtin scanners do not rely on the default.
- The wrapper starts a new session before it execs the scanner, so the scanner has no
  controlling terminal to inject keystrokes into.
- `/dev/shm` is the host's and is writable, because POSIX semaphores live there and
  multiprocessing needs them (detect-secrets scans in a process pool). Landlock cannot
  make it private. A scanner can therefore leave files in, or read other processes'
  shared memory objects of your user from, `/dev/shm`. bwrap gives each scanner its
  own.
- `io_uring_setup` fails with ENOSYS rather than EACCES, so runtimes that use io_uring
  when it exists (semgrep-core) fall back to ordinary syscalls instead of aborting.
- ABI 6 (Linux 6.12) scoping blocks abstract Unix sockets and signals to processes
  outside the sandbox. Below ABI 6 those are not restricted, and the log says so.
- `/proc` is readable, but Landlock denies `ptrace`-mode access from a sandboxed
  process to processes outside its domain, so `/proc/<ASH's pid>/environ` cannot be
  read.

Landlock cannot mount an empty `/tmp` or `$HOME` over the real ones; it denies them
instead. `TMPDIR` and `HOME` point at a fresh private directory, and each path the
policy grants under the real home appears in the private one as a symlink to the real
path, so tools that write settings under `~` keep working. Granted caches are read-only,
as Landlock has no overlay. A tool that hard-codes `/tmp` fails rather
than escaping.

### macOS: sandbox-exec

`sandbox-exec` ships with macOS at `/usr/bin/sandbox-exec`; there is nothing to install.
`--sandbox auto` uses it.

`sandbox-exec` applies a Seatbelt (SBPL) profile. ASH generates one per scanner:
deny by default, read everywhere except the home directory and the shared temporary
directories, read the policy's tool paths inside home, write only to the results
directory and a private `TMPDIR`. With no network, no socket of any kind is allowed.
With a network, IP sockets are allowed and Unix sockets are not, except the
resolver's (`mDNSResponder`), so Docker Desktop's socket and the launchd SSH agent
stay out of reach. The scanner starts in a new session, with no controlling terminal.

The home directory is the one `HOME` names. When that is not the home your account's
passwd entry names, as in a CI job or `HOME=/tmp/x ash scan`, the profile denies
reading both, and the keychain rule covers `Library/Keychains` under both. The paths
the policy lists are allowed again after those denies, wherever they are, so a tool
path inside either home stays readable. With `HOME` set to the passwd entry's home,
the profile is the same as before.

Programs run only from the system and tool paths the policy makes readable, and from
two directories made for the spawn alone: its private uv cache, where `uv tool run`
keeps the environments of tools it was not asked to install, and a self-unpacking
tool's unpack directory (below). Nothing runs from the source tree, the output and
results directories, the host caches, the other private caches or the private
`TMPDIR`, even where a tool path contains one of them (a repository checked out under
`/opt`), so a program the scanner writes, or one the scanned repository ships, cannot
be started. A tool path inside the source tree, such as a virtualenv ASH itself runs
from, stays executable.

Mach service lookups are limited to a list measured on the macOS 14, 15 and 26 CI
runners, where the ten builtin scanners looked up the same thirteen services on all
three. Nine of them are allowed. Every scanner may reach preferences (`cfprefsd`),
logging (`logd`), notifications (`notifyd`) and user and group lookups
(`opendirectoryd`). A scanner with a network may also reach the DNS and network
configuration (`configd`) and certificate trust (`trustd`). The other four are not
allowed: LaunchServices, which node looks up on start and does without, and the
keychain daemon (`SecurityServer`) and a telemetry service, both looked up by
`/usr/bin/security`. LaunchServices (`launchservicesd`, `coreservicesd`,
`com.apple.lsd.*`), the pasteboard (`com.apple.pasteboard.*`) and the keychain daemon
are denied after every allow, so no allow can reach them: LaunchServices asks launchd
to start an app, and launchd starts it outside the sandbox. The keychain files
themselves (`/Library/Keychains` and `~/Library/Keychains`) are denied after every
file rule.

semgrep's core runs `/usr/bin/security` only to read the system root certificates,
through OCaml's ca-certs. For a scanner that declares this need
(`SandboxRequirements.system_trust_roots`), ASH exports the same certificates before
the spawn, outside the sandbox, with the same command (`security find-certificate -a
-p` on the system root and system keychains), writes them to a file the scanner can
read and not write, and sets `SSL_CERT_FILE` to it, which ca-certs reads instead. An
`SSL_CERT_FILE` you set yourself is passed through and wins.

sandbox-exec has no throwaway overlay, so caches are read-only there, as above. The
macOS-specific locations are declared per scanner and granted as narrowly as the tool
allows:

- grype's database at `~/Library/Caches/grype`, its default location on macOS, is
  a read-only cache, from which nothing may run. Before an online scan ASH updates it
  there, outside the sandbox, as it does `~/.cache/grype` on Linux. The database
  trivy and trivy-repo share at `~/Library/Caches/trivy` is handled the same way.
- cdk-nag runs with jsii's package cache disabled, so jsii unpacks into its own
  temporary directory instead of the shared `~/Library/Caches/com.amazonaws.jsii`,
  whose JavaScript every CDK process on the machine runs.
- opengrep's macOS binary unpacks itself to `$XDG_CACHE_HOME/opengrep/<version>` and
  runs `opengrep.bin` from there. `XDG_CACHE_HOME` points at a directory made for the
  spawn, writable and executable for it alone, and removed when it exits; it is the
  only writable directory a program may run from.
- `uv tool run` opens uv's tools-directory lock read-write before it looks for an
  installed tool. That one file is writable; the tools directory is not.
- A script's interpreter, from its `#!` line, has its install prefix readable, so a
  RubyGems wrapper finds its Ruby's library when Ruby is installed under `$HOME`.

sandbox-exec does not end processes the scanner leaves running. ASH's removal of
symlinks after each spawn and its non-following writes still apply, but a process that
outlives the scanner could replace a subdirectory of the results directory with a
link between the sweep and ASH's next write there. That is a known gap of this
backend.

A macOS release or a scanner update can make a tool look up a service that is not on
the list. The profile denies it, the tool usually fails or reports less, and the
unified log says which service it was:

<!-- doctest: illustrative reason="log is a macOS command" -->
```bash
log show --last 10m --predicate 'sender == "Sandbox"' | grep -E 'deny\(1\) (mach-lookup|process-exec)'
```

The list is `MACH_SERVICES` and `MACH_SERVICES_WITH_NETWORK` in
`automated_security_helper/utils/sandbox/backends.py`.

Risk to record: Apple has marked `sandbox-exec` deprecated since macOS 10.13 and
documents SBPL as private. It still works on current macOS and is what Apple's own
tools and several other developer tools use, but a future macOS could remove or change
it without notice. ASH probes it at startup like every other backend, so removal would
show up as "sandbox-exec unavailable" and `MISSING` scanners, not as an unsandboxed
scan.

### Windows

There is no sandbox backend on Windows. With `--sandbox auto`, every scanner is
reported `MISSING` with:

```text
no scanner sandbox is available on Windows; run ASH under WSL2 and use --sandbox bwrap there, or use --mode container
```

Run ASH under WSL2 and use `bwrap` there, or use container mode. A native backend would use an AppContainer or a restricted token plus
a job object; that is a larger piece of work and is not in this release.

### Why not gVisor or nsjail by default

gVisor (`runsc`) gives the strongest isolation here because scanner syscalls go to a
user-space kernel, but it is a container runtime: it wants an OCI bundle and root or a
rootless setup, which is what container mode already provides. nsjail is close to
bubblewrap in capability but is not packaged on most distributions and is configured
through protobuf files; bubblewrap is packaged everywhere (Flatpak depends on it) and
its command line maps one to one onto the policy above.

## Verifying it

`tests/integration/sandbox/` holds a fixture scanner that tries to read a
file outside the source tree (a planted `~/.ssh/id_rsa`), write outside its results
directory, open a network socket under `--offline`, and modify the source tree. CI runs
it under each backend available on the runner. Each attempt must fail with the sandbox
on, and succeed with `--sandbox off`, which is the negative control that proves the
attempts are real. The one exception is the links the fixture plants for ASH to write
through: ASH refuses those with the sandbox off too, and the control checks that it
does. CI also runs every builtin scanner under bubblewrap on Linux and
under sandbox-exec on macOS against the snapshot fixture, offline and online, and
asserts the findings match the unsandboxed run.

On macOS, `tests/integration/sandbox/test_sandbox_exec_services.py` has the fixture
scanner open TextEdit through LaunchServices, read a canary back from the pasteboard
and from the keychain, read the keychain files, and look up the LaunchServices,
pasteboard and keychain Mach services directly. Each must succeed unsandboxed and fail
under `sandbox-exec`.
