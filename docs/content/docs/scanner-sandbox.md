# Scanner sandboxing

ASH runs third-party scanners against code you may not trust. In local mode those
scanners run as ordinary child processes with your user's full access: they can read
`~/.ssh`, write anywhere you can, and open network connections. `--sandbox` runs every
scanner subprocess inside an OS-level sandbox instead. It is off by default.

```bash
ash scan --sandbox auto            # best sandbox this machine has
ash scan --sandbox bwrap --offline # bubblewrap, no scanner gets a network
```

or in `.ash/.ash.yaml`:

```yaml
sandbox:
  mode: auto
```

If you ask for a sandbox and ASH cannot provide one, the affected scanners are recorded
`MISSING` with the reason, and the scan exits 1 like any other incomplete scan. ASH
never falls back to running a scanner unsandboxed after you asked for a sandbox.

## Modes

| Mode | Platform | Needs | Notes |
|------|----------|-------|-------|
| `off` | any | nothing | Default. Scanners run as plain subprocesses. |
| `auto` | any | one of the below | Linux: `bwrap`, then `firejail`, then `landlock`. macOS: `sandbox-exec`. Windows: none. |
| `bwrap` | Linux | `bubblewrap`, unprivileged user namespaces | Recommended. |
| `firejail` | Linux | `firejail` | Fallback. Weaker filesystem hiding, see below. |
| `landlock` | Linux 5.13+ | nothing (kernel LSM) | No package to install. Needs Landlock enabled in the kernel's LSM list. |
| `sandbox-exec` | macOS | ships with macOS | Apple marks `sandbox-exec` deprecated. See risks. |

Container mode (`--mode container`) ignores the setting: the container is the boundary,
and the image does not need bubblewrap. Nix mode composes with it: the inner scan that
runs inside `nix develop` applies the sandbox to each scanner.

## What a sandboxed scanner can do

Every scanner subprocess gets the same baseline policy, plus what that scanner declares
it needs.

- The source directory, and the converted-files directory, are read-only.
- The scanner's own results directory (`<output>/scanners/<name>/`) is the only
  persistent location it can write. The rest of the output directory is read-only.
- `/tmp` and `$HOME` are private and empty. Your real home directory is not visible.
  The tool locations a scanner needs (ASH's bin directory, uv's tool and Python
  directories, the scanner's declared caches) are mounted at their usual paths.
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
  these: they run from an empty directory outside every checkout, with an explicit
  config file (an empty one, or for trivy the operator's `config_file` once it passes
  the rule for that option), against the cache directory the scan reads. A lock in that cache directory makes
  concurrent scans take turns, and each tool is updated once per scan. The scanners
  then run with their own update turned off (`--skip-db-update`,
  `GRYPE_DB_AUTO_UPDATE=false`). Offline nothing is updated, and in both cases ASH's
  staleness check still holds the database to its bound. trivy's Java database
  (about 935 MiB) is not updated and trivy and trivy-repo run with
  `--skip-java-db-update`: `trivy fs` and `trivy repository` do not analyze JAR, WAR
  or EAR files and never read it.
- System directories (`/usr`, `/etc`, `/opt`, `/nix`) and the directories on `PATH`
  are read-only. Inside `$HOME` only `PATH` entries named `bin`, `sbin` or `Scripts`
  are mounted, and a tool's install prefix only when it is deeper than a directory
  directly under `$HOME` (`~/.nvm/versions/node/v22` yes, `~/.cargo` no).
- The environment is filtered to an allowlist: locale, `PATH`, TLS and proxy settings,
  ASH's and uv's own variables, and the prefixes the scanner declares (`GRYPE_`,
  `SEMGREP_`, ...). Within those, a name containing `TOKEN`, `PASSWORD`, `SECRET`,
  `AUTH`, `CREDENTIAL`, `API_KEY` or `SESSION`, and any value carrying
  `user:password@` in a URL, is dropped unless the scanner names that exact variable
  (snyk-code names `SNYK_TOKEN`). Cloud credentials and tokens are not passed in.
- No local IPC endpoint is reachable, with or without a network: not the Docker or
  Podman socket, the session bus, `$SSH_AUTH_SOCK`, the journal, nor a socket in a
  directory the sandbox mounts, such as the Nix daemon's under `/nix`. On Linux every
  backend refuses `socket(AF_UNIX)` and datagram `socketpair()` with a seccomp filter
  (see Landlock below), so neither a socket path nor an abstract socket can be
  reached. The variables that name these endpoints (`SSH_AUTH_SOCK`,
  `DBUS_SESSION_BUS_ADDRESS`, `DOCKER_HOST`, `CONTAINER_HOST`, `XDG_RUNTIME_DIR`)
  are not passed in. firejail sets `DBUS_SESSION_BUS_ADDRESS` itself, to a path of
  its own that `--dbus-user=none` leaves unserved.
- A results directory that is, or is reached through, a symlink is refused (the
  scanner is recorded `MISSING`). The default output directory is inside the source
  tree, so the scanned repository could otherwise plant one pointing anywhere.
- So is an output directory that is a symlink, or that is reached through one below
  the source directory (a committed `build -> /some/host/dir` scanned with
  `--output-dir build/ash`), or whose real path differs from where its path inside
  the source directory reads. A sandboxed scan stops with an error before ASH writes
  anything there. Links at or above the source directory are your own and are not
  examined, and with the sandbox off the output goes where you send it, as before.
- ASH writes into the results directory after the scanner exits, and ASH is not
  sandboxed. So after every sandboxed spawn, and again after the scan, ASH removes
  every symlink and special file the scanner left there, and ASH's own writes there
  (stream logs, `ASH.ScanResults.json`, the files a scanner override writes) open
  without following a symlink. A process the scanner leaves running cannot keep
  planting links afterwards: bwrap and firejail end the whole process tree with the
  scanner, and the Landlock wrapper is a child subreaper that kills any process its
  scanner left behind before it exits. On a timeout ASH sends a sandboxed process
  SIGTERM first (SIGKILL after 10 seconds), so the Landlock wrapper gets to end its
  whole tree rather than being killed outright.
- Network: under `--offline` no scanner gets a network. Online, only scanners that
  declare a network need get one (to fetch a vulnerability database, a rule pack, or
  audit data from a package registry); everything else runs with no network.

### Per-scanner needs

| Scanner | Network when online | Caches | Runtime |
|---------|--------------------|--------|---------|
| bandit | no | uv cache | uv-managed Python |
| checkov | no | uv cache | uv-managed Python |
| semgrep | yes (registry rules, `p/ci`) | uv cache, `~/.semgrep` | uv-managed Python |
| opengrep | yes (registry rules) | `~/.opengrep` | single binary; on macOS it unpacks itself into a private directory per spawn |
| grype | yes (database update) | grype database cache; on macOS, `~/Library/Caches/grype` | single binary |
| syft | no | syft cache | single binary |
| trivy | yes (database update) | trivy cache; on macOS, `~/Library/Caches/trivy` | single binary |
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
    )
```

The community scanners declare theirs:

- snyk-code asks for a network, its `SNYK_` variables and `SNYK_TOKEN`, and read
  access to its token file.
- trivy-repo shares the builtin trivy's declaration: a network, the database cache and
  the `TRIVY_` variables.
- ferret-scan asks only for its `FERRET_` variables.

A file outside the source tree that a scanner option names is not mounted (cfn-guard's
`rules_paths` needs no mount: ASH copies those rules into the results directory): a
`config_file` of actionlint, gitleaks, cfn-lint,
zizmor, trivy or trivy-repo, gitleaks' `baseline_path`, trivy's `ignore_file`, a
`secret_config_file` of trivy or trivy-repo, trivy-repo's `module_dir`, or an
absolute actionlint `shellcheck` or `pyflakes`. Nor do gitleaks' `GITLEAKS_*` variables or
zizmor's GitHub token reach a sandbox. Grants derived from options or the environment
wait for the sandbox's grant gates; until then list such a path in
`sandbox.extra_read_paths`, from a config outside the tree.

detect-secrets needs a network only to verify candidate secrets with their issuers,
which it does when its settings list the verification filter. Those settings come
from a `.secrets.baseline` or an ASH config file, and the scanned repository can
commit either one. The same baseline can also load a detect-secrets plugin from the
repository. So the sandbox doesn't take detect-secrets' own word for it: detect-secrets
gets a network only when `sandbox.network_scanners` names it, and a repository can't
set that (see below). Without a network every candidate counts as unverified, so a
sandboxed scan whose settings verify reports the candidates that verification would
have dropped, and ASH logs a warning naming the setting.

detect-secrets and cdk-nag are Python libraries. They used to run inside the ASH
process, where no OS sandbox can reach them; they now run in worker subprocesses that
use the same interpreter and the same library calls, so their findings are unchanged
and the sandbox wraps them like any other scanner. To let detect-secrets verify
secrets under the sandbox, pass `--config-overrides 'sandbox.network_scanners=[detect-secrets]'`
(plus any other scanners that need a network). Under `--offline` it gets none.

To give an extra scanner network access, or take it away:

```yaml
sandbox:
  mode: bwrap
  network_scanners: [grype, trivy]   # replaces the per-scanner defaults
  extra_read_paths: [/opt/company-ca]
```

`network_scanners` and `extra_read_paths` grant access, so they are honored only from
`--config-overrides` or a config file outside the scanned tree. When any file the
config was built from is inside the tree, both settings are taken from the defaults
plus `--config-overrides`, and ASH logs a warning naming the file. That covers the
discovered `.ash/.ash.yaml`, a `--config` path, an `extends` base, and the file
`ASH_CONFIG` names. The tree is the whole checkout: the outermost directory at or
above the scanned directory (in workspace mode, the workspace root) that holds a
`.git` entry, or the scanned directory itself outside a repository. Outermost, so a
submodule's `.git` file can't make the superproject's config look outside. The
checkout is looked up from the scanned directory as given and from its resolved
path, so a scanned directory that is a symlink still counts the checkout it sits in. A symlink, a `..`
segment, or a case-only difference on a case-insensitive filesystem doesn't change
the answer, because ASH compares the files themselves, not their path strings. An
in-tree `network_scanners` list still takes network away: a scanner it doesn't name
gets none, so a repository can keep its own scan offline with `network_scanners: []`.

`mode` follows the same rule. When `--sandbox`, `ASH_CONFIG`, or the operator's
config file turns the sandbox on, an in-tree config can't turn it off or switch it
to another backend. A mode set by a file outside the tree comes first. When no file
outside the tree sets one, the operator's mode still holds even if the operator's
file is itself inside the tree, for example under a home directory that is a git
checkout: its grants are dropped, but its mode stays, because a mode other than
`off` grants nothing. Only `--sandbox off` or a `sandbox.mode` override turns it off.

The checkout is also looked up from the shell's working directory (`$PWD`), so
`cd vendor && ash scan`, where `vendor` is a symlink out of the checkout, still
counts the checkout. A bind mount of a directory inside a checkout can't be traced
back to it; scan the checkout itself, or keep its config out of the grants with
`--config-overrides`. When none of them does, an in-tree `mode` applies, because a
sandbox the repository asks for only takes access away. In workspace mode, the
operator's `--config` decides for a project that has its own config file, the same
as for one that doesn't.

A trusted config outside the tree that `extends` a base inside the tree loses its own
grants too, because the merged settings no longer record which file set them. Pass
the grants with `--config-overrides` in that layout.

A sandboxed scan does not install tools: installing runs a package's build code and
writes uv's tool directory, which a sandboxed scanner may only read. Run
`ash dependencies install` first; a scanner whose tool is missing is recorded
`MISSING`.

## Threat model

The sandbox is for three cases.

1. A malicious or compromised scanner, plugin, or rule pack. A typosquatted or
   hijacked package on PyPI or npm, a scanner binary replaced on disk, a community
   rule pack that runs code.
2. Scanned content that exploits a scanner. Scanners parse untrusted input and some
   execute it on purpose: tool configuration files committed to the repository
   (`trivy.yaml`, `.semgrep.yml`, `.checkov.yaml`, `.npmrc`, `.bandit`) change what a
   scanner does, plugin systems `eval` code found in the tree, and parser bugs give
   code execution or path traversal on write.
3. Exfiltration. Code running in any of the above reading credentials (`~/.ssh`,
   `~/.aws`, tokens in the environment) and sending them out over the network.

Inside the sandbox such code can read the source tree (it is scanning it), write its
own results, and, if the scanner is allowed a network, talk to the network. It cannot
read the rest of your home directory, write outside its results directory, modify the
source tree, or see environment variables outside the allowlist.

Out of scope:

- ASH itself, its converters, and `git`, which run unsandboxed. ASH is the trusted
  base. Converters unpack archives and notebooks into the work directory; they are
  ASH code, not third-party tools. `git` runs only for `--changed-files-only` and
  workspace planning, never inside a scanner.
- Plugin modules. A config file can list `ash_plugin_modules`, which ASH imports into
  its own process, so they run unsandboxed. From a config file inside the scanned
  tree, only installed modules outside the tree are imported (see
  [Settings a repository's config cannot choose](configuration-guide.md#settings-a-repositorys-config-cannot-choose)),
  but an installed package still runs with ASH's access. The sandbox doesn't change
  this; review the plugin modules a repository's config names before you scan it.
- Resource exhaustion. A scanner can still use all the CPU and memory it can get, or
  fork until a limit stops it; the existing per-scanner `scan_timeout` bounds how long.
- A scanner allowed a network shares the host's network, so TCP and UDP services
  listening on the host, loopback included, are reachable from it under every
  backend. Abstract Unix sockets bound by host processes are not: the socket filter
  refuses Unix sockets.
- A scanner allowed a network can still send what it can read (the source tree)
  wherever it likes. The online allowlist is per scanner, not per host. Host-level
  filtering would need a proxy inside the sandbox, which tools can bypass unless the
  network namespace forces all traffic through it; that is future work.
- Results integrity. A compromised scanner can still lie in its own results file.
- Kernel exploits. All backends share the host kernel.

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
Spawns made outside any scanner scope (ASH's own `git` calls, converters, the
container runtime) are unaffected. A sandboxed scan never installs a tool.

`tests/unit/utils/test_sandbox_choke_point.py` fails the build if any module in the
package outside a short, reasoned exemption list calls `subprocess.run`,
`subprocess.Popen`, `os.system`, `os.exec*` or the like directly, so a new spawn site
cannot bypass the choke point. The scope is per thread: a scanner that started a
process from a thread it created itself would not inherit it. No builtin scanner does.

### Linux: bubblewrap (preferred)

bubblewrap builds an empty root from a tmpfs and mounts into it only what the policy
lists, in new user, mount, PID, IPC, UTS, cgroup and (when the scanner gets no network)
network namespaces. It needs no setuid binary on distributions that allow unprivileged
user namespaces. ASH passes `--die-with-parent` and `--new-session`, so a scanner
cannot outlive ASH or inject keystrokes into the terminal through `TIOCSTI`.

bwrap's mounts hide `/run` and `$HOME`, but not a Unix socket inside a directory it
does mount (the Nix daemon's socket is under `/nix`), and a scanner with a network
shares the host's network namespace and every abstract Unix socket bound there. So
the scanner is started through the Landlock wrapper in `--socket-filter` mode, which
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

The throwaway cache overlay uses `--overlay-src`/`--tmp-overlay`, which needs
bubblewrap 0.8 and Linux 5.11. On older systems those caches are mounted read-only
instead, as under the other backends, and the log says so.

### Linux: firejail (fallback)

firejail is a setuid-root binary, which is attack surface of its own (it has had
privilege-escalation CVEs), and its filesystem model is "everything visible, then
restrict" rather than "nothing visible, then allow". ASH uses
`--noprofile --private-dev --nonewprivs --caps.drop=all --seccomp --nogroups`,
`--dbus-user=none --dbus-system=none`, `--net=none` when the scanner gets no network,
makes `/` read-only, blacklists the container runtime sockets, `/run/user/<uid>` and
`$SSH_AUTH_SOCK`, whitelists inside `$HOME` (and `/tmp`) only the paths the policy
lists, uses `--private-tmp` when the policy lists nothing under `/tmp`, and makes the
results directory read-write. Paths outside `$HOME` that your user can read remain readable, and scanner
caches are read-only because firejail has no throwaway overlay. Because
everything outside `$HOME` stays visible, `/run` and its sockets included, the
scanner is started through the same seccomp socket filter as under bwrap. Use bwrap
when you can.

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

Landlock is an unprivileged kernel LSM (Linux 5.13+), so this mode needs nothing
installed. ASH starts a small wrapper (`utils/sandbox/landlock_exec.py`, standard
library only) that restricts itself and then `exec`s the scanner:

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

`sandbox-exec` applies a Seatbelt (SBPL) profile. ASH generates one per scanner:
deny by default, read everywhere except the home directory and the shared temporary
directories, read the policy's tool paths inside home, write only to the results
directory and a private `TMPDIR`. With no network, no socket of any kind is allowed.
With a network, IP sockets are allowed and Unix sockets are not, except the
resolver's (`mDNSResponder`), so Docker Desktop's socket and the launchd SSH agent
stay out of reach. The scanner starts in a new session, with no controlling terminal.

Programs run only from the system and tool paths the policy makes readable, and from
two directories made for the spawn alone: its private uv cache, where `uv tool run`
keeps the environments of tools it was not asked to install, and a self-unpacking
tool's unpack directory (below). Nothing runs from the source tree, the output and
results directories, the host caches, the other private caches or the private
`TMPDIR`, even where a tool path contains one of them (a repository checked out under
`/opt`), so a program the scanner writes, or one the scanned repository ships, cannot
be started. A tool path inside the scanned tree, such as a virtualenv ASH itself runs
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
  read-only. Before an online scan ASH updates it there, outside the sandbox, as it
  does `~/.cache/grype` on Linux. trivy-repo's database at `~/Library/Caches/trivy`
  is handled the same way.
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

There is no Windows backend. `--sandbox auto` on Windows finds nothing and the
scanners are recorded `MISSING`. Run ASH under WSL2 and use `bwrap` there, or use
container mode. A native backend would use an AppContainer or a restricted token plus
a job object; that is a larger piece of work and is not in this release.

### Why not gVisor or nsjail by default

gVisor (`runsc`) gives the strongest isolation here because scanner syscalls go to a
user-space kernel, but it is a container runtime: it wants an OCI bundle and root or a
rootless setup, which is what container mode already provides. nsjail is close to
bubblewrap in capability but is not packaged on most distributions and is configured
through protobuf files; bubblewrap is packaged everywhere (Flatpak depends on it) and
its command line maps one to one onto the policy above.

## Verifying it

`tests/integration/sandbox/` holds a malicious fixture scanner that tries to read a
file outside the source tree (a planted `~/.ssh/id_rsa`), write outside its results
directory, open a network socket under `--offline`, and modify the source tree. CI runs
it under each backend available on the runner. Each attempt must fail with the sandbox
on, and succeed with `--sandbox off`, which is the negative control that proves the
attempts are real. CI also runs every builtin scanner under bubblewrap on Linux and
under sandbox-exec on macOS against the snapshot fixture, offline and online, and
asserts the findings match the unsandboxed run.

On macOS, `tests/integration/sandbox/test_sandbox_exec_services.py` has the fixture
scanner open TextEdit through LaunchServices, read a canary back from the pasteboard
and from the keychain, read the keychain files, and look up the LaunchServices,
pasteboard and keychain Mach services directly. Each must succeed unsandboxed and fail
under `sandbox-exec`.
