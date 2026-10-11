# Enable the scanner sandbox

`--sandbox` runs the processes a scanner starts through ASH under an operating-system
sandbox: the scanner reads only what the sandbox grants, writes only its results
directory, and gets a network only when it needs one. How strict that is depends on the
backend; on Linux, bubblewrap is the strictest. The sandbox is off by default. This page
shows how to turn it on, set up a backend, grant a scanner more access, and scan a
repository you do not trust. For what the sandbox protects and what it does not, read
[Scanner sandbox](../concepts/sandbox.md) first.

Prerequisites:

- Linux on x86_64 or aarch64, or macOS. Windows has no backend; see the Windows tab
  below.
- The scanner tools, installed before you scan. A sandboxed scan does not install
  scanner tools, so a scanner whose tool would otherwise be installed on first use is
  reported `MISSING`. Run `ash dependencies install` once, or see
  [Install ASH](../how-to/install.md). It also installs nbconvert for the notebook
  converter, which runs outside the sandbox and otherwise installs it during the scan.

## Turn the sandbox on for one scan

<!-- doctest: illustrative reason="needs a sandbox backend installed on the host" -->
```bash
ash --sandbox auto
```

`auto` uses the first backend that can start a sandbox on this machine: on Linux
`bwrap`, then `firejail`, then `landlock`; on macOS `sandbox-exec`. To require one
backend, name it: `ash scan --sandbox bwrap`. The value is not case-sensitive on the
command line. ASH never falls back to running a scanner unsandboxed: if the backend you
asked for cannot start, the scanners are reported `MISSING` (see
[When a scanner cannot be sandboxed](#missing)).

The scan output and `ash.log` say which backend ran each scanner:

```text
INFO     Scanner sandbox: using bwrap (--sandbox auto)
INFO     Scanner sandbox: bandit on source runs under bwrap
INFO     Scanner sandbox: detect-secrets on source runs under bwrap
```

The results record the mode you asked for (`ash_config.sandbox.mode` in
`ash_aggregated_results.json`), not the backend that ran.

## Set up a backend {#backends}

=== "Linux: bubblewrap"

    bubblewrap is the backend to use on Linux: it shows a scanner nothing but the paths
    ASH grants. Install it from your distribution:

    <!-- doctest: illustrative reason="installs a system package" -->
    ```bash
    sudo apt-get install -y bubblewrap   # Debian, Ubuntu
    sudo dnf install -y bubblewrap       # Fedora, Amazon Linux, RHEL
    ```

    bubblewrap needs unprivileged user namespaces. Check that it can start a sandbox,
    with the first command ASH's probe runs:

    <!-- doctest: illustrative reason="needs bubblewrap installed on the host" -->
    ```bash
    bwrap --unshare-all --die-with-parent --ro-bind / / --proc /proc --dev /dev true && echo ok
    ```

    Ubuntu 23.10 and later restrict unprivileged user namespaces through AppArmor. If
    the check fails there, and ASH reports `bwrap cannot create a sandbox here (...)`,
    either load an AppArmor profile that allows `userns` for `/usr/bin/bwrap`, or turn
    the restriction off:

    <!-- doctest: illustrative reason="changes a kernel setting as root" -->
    ```bash
    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
    echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | sudo tee /etc/sysctl.d/60-userns.conf
    ```

    The sysctl lifts the restriction for every program on the machine, not only for
    bubblewrap; the AppArmor profile is the narrower change. ASH's own CI runs the
    sysctl on its Ubuntu runners when the check fails there.

    ASH's probe then runs its Unix-socket filter inside bwrap and tries a throwaway
    overlay, so a host can pass the check above and still report
    `bwrap cannot apply the Unix-socket filter in its sandbox (...)`. Use the bwrap from
    your distribution, on a kernel that allows seccomp filters.

    With bubblewrap 0.8 or later on Linux 5.11 or later, scanner caches are mounted
    through a throwaway overlay, so a scanner can write to its cache and the writes are
    discarded. On older systems ASH logs a warning and mounts the caches read-only.

=== "Linux: Landlock"

    Landlock is part of the kernel, so there is nothing to install, and it needs no
    user namespaces. It must be enabled. Check the active security modules:

    <!-- doctest: illustrative reason="reads the host kernel's security modules" -->
    ```bash
    cat /sys/kernel/security/lsm
    ```

    If `landlock` is not in the list, add it to the `lsm=` kernel boot parameter. ASH
    reports `Landlock is not supported or not enabled (add 'landlock' to the lsm=
    kernel parameter)` until you do. ASH needs Landlock ABI 3 (Linux 6.2) or later, the
    first that can stop a scanner from truncating files it may only read. On an older
    kernel ASH reports `Landlock ABI <n> is below 3 (Linux 6.2), ...`, and `auto` skips
    Landlock. On a kernel whose Landlock ABI is below 6, ASH logs a warning: there, a
    scanner can still send signals to processes outside its sandbox.

    Landlock isolates less than bubblewrap: it uses no namespaces, and it shares the
    host's `/dev/shm`. Use it only where bubblewrap cannot run, for example where user
    namespaces are off.

=== "Linux: firejail"

    Install the `firejail` package from your distribution. firejail leaves everything
    outside your home directory and `/tmp` readable to the scanner, so prefer
    bubblewrap.

    Inside a container that has its own PID namespace, firejail runs commands without a
    sandbox. ASH's probe detects this and reports `firejail ran a test command without a
    sandbox`, so use `--sandbox bwrap` or `--sandbox landlock` there.

=== "macOS"

    `sandbox-exec` ships with macOS at `/usr/bin/sandbox-exec`; there is nothing to
    install. `--sandbox auto` uses it. It is the only backend that also stops a scanner
    from running programs from the scanned tree. Files outside your home directory and
    the temporary directories it hides (`/private/tmp` and `/private/var/folders`) stay
    readable.

=== "Windows"

    There is no sandbox backend on Windows. With `--sandbox auto`, every scanner is
    reported `MISSING` with:

    ```text
    no scanner sandbox is available on Windows; run ASH under WSL2 and use --sandbox bwrap there, or use --mode container
    ```

    A named backend reports `<backend> is not available on Windows` instead.

    Run ASH inside WSL2 and set up bubblewrap there, or scan in a container
    ([Run ASH in a container](../how-to/run-in-a-container.md)).

## Turn it on in a config file {#config}

Set `sandbox.mode` to keep the sandbox on for every scan:

```yaml
sandbox:
  mode: auto
```

The values are `off`, `auto`, `bwrap`, `firejail`, `landlock`, and `sandbox-exec`,
lowercase. Quote `"off"`. YAML reads an unquoted `off` as the boolean false, and the
scan then stops with exit code 3. `ash config validate` does not catch this in this
release.

<!-- doctest: config kind=ash-invalid reason="an unquoted off is the YAML boolean false" -->
```yaml
sandbox:
  mode: off
```

`--sandbox` overrides the config file. When you pass `--config` or set `ASH_CONFIG` for a
scan of one directory, ASH reads that file and not the repository's own. In workspace
mode, `--config` is only the default for projects that have no config file of their own;
use `--config-overrides` there. When ASH does read a repository's config file, that file
can turn the sandbox on, because that only takes access away, but it cannot turn off or
change a mode you set with `--sandbox` or with a `sandbox.mode` override in
`--config-overrides`.

## Give a scanner more access {#grants}

Four settings grant scanners more than the default policy. Only you, the operator, can
set them; see [Who may grant](#who-may-grant).

<!-- doctest: options of=sandbox -->
| Key | Default | Grants |
|---|---|---|
| `network_scanners` | `null` | A network to the scanners named. `null` means each scanner's own need: semgrep, opengrep, grype, trivy, and npm-audit have one, and so do snyk-code and trivy-repo when their plugins are loaded. A list replaces those defaults: a scanner it names gets a network on every online scan, and a scanner it leaves out gets none. |
| `extra_read_paths` | `[]` | Read-only access to more host paths, for every sandboxed scanner. `~` and `$VARS` are expanded. |
| `read_path_scanners` | `[]` | To the scanners named, the extra paths their own options point to. For a plugin scanner that declares such paths, a path is mounted only when it resolves inside the source tree or an `extra_read_paths` entry and is a regular file or a directory. Of the scanners ASH ships, only detect-secrets uses it, for a `baseline_file` outside the source tree, which ASH reads itself ([detect-secrets](#detect-secrets)). |
| `env_scanners` | `[]` | To the scanners named, the environment variables their own options ask for. No scanner ASH ships asks for any yet; it is for plugin scanners that declare such a need. |

`--offline` removes the network from every scanner whatever `network_scanners` says.
grype and trivy do not need a grant for their databases: before an online sandboxed
scan, ASH refreshes them outside the sandbox; see
[Content databases](../concepts/content-databases.md). cfn-guard needs none for its
installed rules either: it may read `$ASH_CFN_GUARD_RULES_DIR`, or `share/cfn-guard-rules`
beside ASH's bin directory.

A file that a scanner option names outside the source directory, such as any scanner's
`config_file`, gitleaks' `baseline_path`, trivy's `ignore_file` or `secret_config_file`, or a
path for actionlint's `shellcheck` or `pyflakes`, is not mounted for the scanner. Under bwrap
and landlock, add it to `extra_read_paths` unless it is under a directory the sandbox already
reads, such as `/etc`, `/opt`, or a directory on `PATH`; firejail and sandbox-exec leave files
outside the home and temporary directories readable. cfn-guard's `rules_paths` need no entry:
ASH copies those rules into the scanner's results directory.

Grant on the command line for one scan:

<!-- doctest: illustrative reason="needs a sandbox backend installed on the host" -->
```bash
ash --sandbox auto --config-overrides 'sandbox.extra_read_paths=[/srv/ash/semgrep-rules]'
```

Or in a config file outside every git checkout, passed with `--config`. To keep the
default network scanners and add detect-secrets, list them all, because the list
replaces the defaults:

```yaml
sandbox:
  mode: bwrap
  network_scanners: [semgrep, opengrep, grype, trivy, npm-audit, detect-secrets]
```

If you load the trivy-repo or snyk-code plugin, add `trivy-repo` or `snyk-code` to the
list too, or it loses its network.

### Offline semgrep and opengrep

An offline scan reads semgrep's and opengrep's rules from the directories that
`SEMGREP_RULES_CACHE_DIR` and `OPENGREP_RULES_CACHE_DIR` name, and under the sandbox a
scanner can read only directories the sandbox mounts. Keep the rules caches under a
system directory such as `/opt`, or add them to `extra_read_paths`, and check the result
on a file with a known finding. `--mode nix` always scans offline and keeps both caches
under `~/.cache/ash/`:

```yaml
sandbox:
  mode: auto
  extra_read_paths:
    - ~/.cache/ash/semgrep-rules
    - ~/.cache/ash/opengrep-rules
```

### detect-secrets

detect-secrets needs a network only when its verification filter is on, and gets one
only when `network_scanners` names it. Naming it gives it a network on every online scan,
whether or not the filter is on, so name it only when you use verification. ASH takes a
relative `baseline_file`, and the `.ash/.secrets.baseline` and `.secrets.baseline` it looks
for by name, from the source directory. It reads a `baseline_file` outside the source tree only when `read_path_scanners`
names it; without that, ASH logs a warning, ignores the baseline, and reports the findings
the baseline would have marked. A baseline that is not a regular file is skipped the same way,
with a warning.

## Who may grant {#who-may-grant}

A grant counts only when it comes from one of these:

- `--config-overrides`;
- a config file named with `--config` or `ASH_CONFIG`, when that file is outside every git
  checkout and outside the scanned directory;
- in workspace mode, the `--config` file the workspace scan was given, under the same
  rule: outside every git checkout and outside the workspace;
- under `ash mcp`, the server's own configuration, under the same rule.

`--sandbox` sets only the mode. When one of these files extends a base that cannot grant,
the file keeps the grants its own `sandbox` section writes, and loses what it inherits
from any base and what it changes with `patch`, so write each grant in the file itself.

A config file inside any git checkout, meaning a directory at or above it holds a
`.git` directory or file, by the file's own path, its resolved path, or any symbolic link it
passes through, cannot grant. Nor
can a config file inside the scanned directory, or, under `ash mcp`, one an MCP client
delivered. ASH drops its grants and logs, as `ash.log` records it:

```text
WARNING  Ignoring sandbox.network_scanners, sandbox.extra_read_paths from the config built
on /home/me/src/app/.ash/.ash.yaml: the file is inside a git checkout or the scanned
directory, so someone other than the operator may have written it, and it cannot grant
sandbox access. Of the files the config was built from, only the sandbox settings a file
outside every git checkout and the scanned directory writes itself are kept. A
network_scanners list there still removes network from scanners it does not name, and a
sandbox mode there still applies when nothing else turns the sandbox on. To grant access,
pass the setting with --config-overrides (for example 'sandbox.network_scanners=[grype]')
or put it in a config file outside every git checkout and the scanned directory.
```

The console shows the same warning with `[grype]` missing from the example. For a config
file an MCP client names as a scan's `config_path`, outside the directories
`ASH_MCP_ALLOWED_CONFIG_ROOTS` names, the reason reads `an MCP client supplied the file, not the
operator`. Under the MCP server's default policy, a delivered file whose own `sandbox` section gives a scanner a network or an `extra_read_paths` entry the server's settings do not, or changes a sandbox mode other than `off` that the server sets, is refused instead ([What a delivered config cannot set](../how-to/mcp-server.md#what-a-delivered-config-cannot-set)); its other grants are dropped the same way.

So a repository can take a network away from its own scan, but cannot add one. The rule
also covers your own files: a config kept in a checkout of its own, such as an ops or
dotfiles repository, cannot grant either, and a file outside every checkout that `extends`
one inside keeps only the grants it writes itself. Move the grants to `--config-overrides`
or to a file outside every checkout. [Configuration trust model](../concepts/trust-model.md) explains how ASH
decides where a config file belongs.

When a scanner's own settings ask for something the default policy does not allow, ASH
withholds it and logs which setting to add, for example: `add detect-secrets to
sandbox.network_scanners with --config-overrides or a config file outside every git
checkout and the scanned directory`.

## When a scanner cannot be sandboxed {#missing}

ASH records a scanner it cannot sandbox as `MISSING`, and under the default
`fail_on_incomplete_scanners` the scan exits 1. The reason is in the scan output and in
`ash.log`, not in the results file:

```text
ERROR    bandit not run: scanner sandbox unavailable: firejail is not installed
```

| Message | Fix |
|---|---|
| `bwrap is not installed (install the 'bubblewrap' package)` | Install bubblewrap. |
| `bwrap cannot create a sandbox here (...)` | Allow unprivileged user namespaces (see the bubblewrap tab), or use `landlock`. |
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

A scanner whose tool is not installed is reported `MISSING` too, with the log line
`<tool> is not installed, and a sandboxed scan does not install tools`. Run
`ash dependencies install`, then scan again.

ASH finds `bwrap` and `firejail` the way it finds scanner tools: never through the
working directory, and not inside the scanned directory unless you allow in-tree tools
(see [Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory)).
A copy found only inside the scanned directory counts as not installed.

## Scan a repository you do not trust {#untrusted}

For a repository you do not trust, on Linux or macOS:

1. Install the scanners first, from a trusted environment, with `ash dependencies install`,
   which also installs the notebook converter's nbconvert. A sandboxed scan does not
   install scanners, and you do not want an online scan installing tools while the
   hostile tree is present.
2. Keep your own config file outside every git checkout, and pass it with `--config`. In
   a scan of one directory, ASH then does not read the repository's ASH config, so the
   enabled scanners, the gate, and the suppressions in config files are yours. Inline
   suppression comments and scanner config files in the repository still apply (see
   [what the trust model does not protect](../concepts/trust-model.md#not-protected));
   for bandit, set `scanners.bandit.options.ignore_nosec: true` in your file. Only your
   file and `--config-overrides` may grant sandbox access. In workspace mode, `--config`
   is only the default for projects that have no config of their own, so give your
   settings with `--config-overrides` there.
3. Scan in local mode, the default, with the sandbox on: `sandbox.mode: auto` in that
   file, or `--sandbox auto`. Check `ash.log` for the backend it picked. Prefer `bwrap` on
   Linux, which hides everything you did not grant; use `landlock` only where bwrap
   cannot run. `firejail` and `sandbox-exec` leave most files outside your home
   directory readable (see [Set up a backend](#backends)).
4. Decide which scanners need the network. Scan with `--offline` and pre-seeded databases
   if you can, and keep the offline semgrep and opengrep rules cache where the sandbox
   can read it: under a system directory such as `/opt`, or in `sandbox.extra_read_paths`
   (see [Offline semgrep and opengrep](#offline-semgrep-and-opengrep)). Otherwise set
   `sandbox.network_scanners` to the shortest list that works, and leave detect-secrets
   out of it unless you use its verification filter.
5. Put the output directory outside the repository with `--output-dir`, and run ASH from
   a directory outside the repository with `--source-dir`. The default output directory
   is `.ash/ash_output` inside the scanned directory.
6. Do not pass `--allow-in-tree-tools`, and run ASH from an installation outside the
   repository, with none of the repository's directories on `PATH`. The in-tree refusal
   covers the programs ASH starts, not the Python running ASH.
7. Name only plugin modules you trust. Every plugin module runs inside ASH's own process,
   outside the sandbox.

An operator config for this setup can be as small as:

```yaml
project_name: untrusted-scan
sandbox:
  mode: auto
fail_on_findings: true
fail_on_incomplete_scanners: true
content_db_staleness: fail
scanners:
  bandit:
    options:
      ignore_nosec: true
```

And the scan, run from outside the repository:

<!-- doctest: illustrative reason="needs a working sandbox backend and an operator config outside the docs fixture" -->
```bash
ash scan --config /etc/ash/untrusted.yaml --source-dir /work/src/pr-1234 --output-dir /work/ash-output/pr-1234 --offline
```

The default `fail_on_incomplete_scanners` matters here. If a backend cannot sandbox a
scanner, or a scanner's tool exists only inside the repository, that scanner is
`MISSING` and the scan exits 1, rather than passing on fewer scanners than you asked
for.

On Windows there is no sandbox backend. Run ASH under WSL2 with `--sandbox bwrap`, or use
container mode with `--offline`, which gives the container no network. Keep the source
and the output in separate directory trees, such as `C:\work\src\pr-1234` and
`C:\work\ash-output\pr-1234`. In container mode the scan inside the container cannot see
your `--config` file, so give its settings with `--config-overrides`. The sandbox is off
inside the container, so every scanner in it shares the container's access.

## Container and Nix mode

`--mode container` turns the sandbox off for the scan inside the container, without a
warning, whatever `--sandbox` or the config says: the container is the boundary there,
and the image ships no sandbox backend. See
[Run ASH in a container](../how-to/run-in-a-container.md).

`--mode nix` forwards your `--sandbox` option to the scan it runs inside the Nix shell,
so that scan is sandboxed. Add the offline rule caches to `extra_read_paths`, as shown in
[Offline semgrep and opengrep](#offline-semgrep-and-opengrep).
