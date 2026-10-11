# Sandbox scanners

`--sandbox` runs every scanner process under an operating-system sandbox: the source is
read-only, the scanner can write only its own results directory, your home and
temporary directories are replaced by empty private ones, and only the scanners that
need a network get one. The sandbox is off by default. This page shows how to turn it
on, set up a backend, and grant a scanner more access. For what the sandbox protects and
what it does not, read [Scanner sandbox](../concepts/sandbox.md) first.

## Before you start

- Linux on x86_64 or aarch64, or macOS. Windows has no backend; see the Windows tab
  below.
- Install the scanner tools before you scan. A sandboxed scan does not install scanner
  tools, so a scanner whose tool would otherwise be installed on first use is reported
  `MISSING`. Run `ash dependencies install` once, or see
  [Install ASH](../how-to/install.md).

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

The backend is not recorded in `ash_aggregated_results.json` or the reports.

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
    with the same command ASH's probe runs:

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
    kernel parameter)` until you do. On a kernel whose Landlock ABI is below 6, ASH logs
    a warning: there, a scanner can still reach abstract Unix sockets and signal
    processes outside its sandbox.

    Landlock shares the host's `/dev/shm`. Use it where bubblewrap cannot run, for
    example where user namespaces are off.

=== "Linux: firejail"

    Install the `firejail` package from your distribution. firejail leaves everything
    outside your home and temporary directories readable to the scanner, so prefer
    bubblewrap or Landlock.

    Inside a container that has its own PID namespace, firejail runs commands without a
    sandbox. ASH's probe detects this and reports `firejail ran a test command without a
    sandbox`, so use `--sandbox bwrap` or `--sandbox landlock` there.

=== "macOS"

    `sandbox-exec` ships with macOS at `/usr/bin/sandbox-exec`; there is nothing to
    install. `--sandbox auto` uses it. It is the only backend that also stops a scanner
    from running programs from the scanned tree. Files outside your home and temporary
    directories stay readable.

=== "Windows"

    There is no sandbox backend on Windows. With the sandbox on, every scanner is
    reported `MISSING` with:

    ```text
    no scanner sandbox is available on Windows; run ASH under WSL2 and use --sandbox bwrap there, or use --mode container
    ```

    Run ASH inside WSL2 and set up bubblewrap there, or scan in a container
    ([Run ASH in a container](../how-to/run-in-a-container.md)).

## Turn it on in a config file {#config}

Set `sandbox.mode` to keep the sandbox on for every scan:

```yaml
sandbox:
  mode: auto
```

The values are `off`, `auto`, `bwrap`, `firejail`, `landlock` and `sandbox-exec`,
lowercase. Quote `"off"`. YAML reads an unquoted `off` as the boolean false, and the
scan then stops with exit code 3. `ash config validate` does not catch this in this
release.

<!-- doctest: config kind=ash-invalid reason="an unquoted off is the YAML boolean false" -->
```yaml
sandbox:
  mode: off
```

`--sandbox` overrides the config file. When you pass `--config` or set `ASH_CONFIG`, ASH
reads that file and not the repository's own. When it does read the repository's config
file, that file can turn the sandbox on, because that only takes access away, but it
cannot turn off or change a mode you set with `--sandbox` or with a `sandbox.mode`
override in `--config-overrides`.

## Give a scanner more access {#grants}

Four settings grant scanners more than the default policy. Only you, the operator, can
set them; see [Who may grant](#who-may-grant).

<!-- doctest: options of=sandbox -->
| Key | Default | Grants |
|---|---|---|
| `network_scanners` | `null` | A network to the scanners named. `null` means each scanner's own need: semgrep, opengrep, grype, trivy and npm-audit have one, and so do snyk-code and trivy-repo when their plugins are loaded. A list replaces those defaults, so a scanner it leaves out gets no network. |
| `extra_read_paths` | `[]` | Read-only access to more host paths, for every sandboxed scanner. `~` and `$VARS` are expanded. |
| `read_path_scanners` | `[]` | To the scanners named, the extra paths their own options point to. Of the scanners ASH ships, only detect-secrets uses it, for a baseline file outside the source tree. |
| `env_scanners` | `[]` | To the scanners named, the environment variables their own options ask for. No scanner ASH ships asks for any yet; it is for plugin scanners that declare such a need. |

`--offline` removes the network from every scanner whatever `network_scanners` says.
grype and trivy do not need a grant for their databases: before an online sandboxed
scan, ASH refreshes them outside the sandbox; see
[Content databases](../concepts/content-databases.md).

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

### Offline semgrep and opengrep

An offline scan reads semgrep's and opengrep's rules from the directories that
`SEMGREP_RULES_CACHE_DIR` and `OPENGREP_RULES_CACHE_DIR` name, and the sandbox does not
mount those directories for them. Unless a directory is under a system path such as
`/usr` or `/opt`, add it to `extra_read_paths`. Otherwise semgrep finds no rules, and in
this release ASH records it as `PASSED` with no findings. `--mode nix` always scans
offline and keeps both caches under `~/.cache/ash/`:

```yaml
sandbox:
  mode: auto
  extra_read_paths:
    - ~/.cache/ash/semgrep-rules
    - ~/.cache/ash/opengrep-rules
```

### detect-secrets

detect-secrets gets a network only when its settings turn on its verification filter
and `network_scanners` names it. It reads a `baseline_file` outside the source tree
only when `read_path_scanners` names it; without that, ASH logs a warning, ignores the
baseline, and reports the findings the baseline would have marked.

## Who may grant {#who-may-grant}

A grant counts only when it comes from one of these:

- `--config-overrides`;
- a config file named with `--config` or `ASH_CONFIG`, when that file and every file it
  `extends` are outside every git checkout and outside the scanned directory;
- in workspace mode, the workspace's default config file;
- under `ash mcp`, the server's own configuration.

`--sandbox` sets only the mode.

A config file inside any git checkout, meaning a directory at or above it holds a
`.git` directory or file, by the file's own path or its resolved path, cannot grant. Nor
can a config file inside the scanned directory, or one an MCP client delivered. ASH
drops its grants and logs:

```text
WARNING  Ignoring sandbox.network_scanners, sandbox.extra_read_paths from
/home/me/src/app/.ash/.ash.yaml: the file is inside a git checkout or the scanned
directory, so someone other than the operator may have written it, and it cannot grant
sandbox access. A network_scanners list there still removes network from
scanners it does not name, and a sandbox mode there still applies when nothing else turns
the sandbox on. To grant access, pass the setting with --config-overrides (for example
'sandbox.network_scanners=[grype]') or put it in a config file outside every git checkout
and the scanned directory.
```

So a repository can take a network away from its own scan, but cannot add one. The rule
also covers your own files: a config kept in a checkout of its own, such as an ops or
dotfiles repository, cannot grant either, and neither can a file outside every checkout
that `extends` one inside. Move the grants to `--config-overrides` or to a file outside
every checkout. [Configuration trust model](../concepts/trust-model.md) explains how ASH
decides where a config file belongs.

When a scanner's own settings ask for something the default policy does not allow, ASH
withholds it and logs which setting to add, for example: `add detect-secrets to
sandbox.network_scanners with --config-overrides or a config file outside every git
checkout and the scanned directory`.

## When a scanner cannot be sandboxed {#missing}

ASH records a scanner it cannot sandbox as `MISSING`, and under the default
`fail_on_incomplete_scanners` the scan exits 1. The reason is in the scan output and in
`ash.log`:

```text
ERROR    bandit not run: scanner sandbox unavailable: firejail is not installed
```

| Message | Fix |
|---|---|
| `bwrap is not installed (install the 'bubblewrap' package)` | Install bubblewrap. |
| `bwrap cannot create a sandbox here (...)` | Allow unprivileged user namespaces (see the bubblewrap tab), or use `landlock`. |
| `Landlock is not available (...)` | Add `landlock` to the `lsm=` kernel parameter. |
| `firejail is not installed` | Install firejail, or use another backend. |
| `firejail ran a test command without a sandbox (...)` | Use `bwrap` or `landlock`; firejail does not sandbox inside this container. |
| `sandbox-exec is not present (it has been removed from this macOS)` | No macOS backend remains; scan in a container. |
| `--sandbox auto found no working sandbox (...)` | Lists why each backend failed; fix one of them. |
| `no scanner sandbox is available on Windows; ...` | Use WSL2 or container mode. |
| `<name>: the config names this scanner '<name>', but its own name is '<other>'` | Configure the scanner under its own name; grants follow a scanner's own name. |
| `<tool> is not installed, and a sandboxed scan does not install tools` | Run `ash dependencies install`, then scan again. |

ASH finds `bwrap` and `firejail` the way it finds scanner tools: never through the
working directory, and not inside the scanned directory unless you allow in-tree tools
(see [Tools inside the scanned directory](advanced-usage.md#tools-inside-the-scanned-directory)).
A copy found only inside the scanned directory counts as not installed.

## Container and nix mode

`--mode container` turns the sandbox off for the scan inside the container, without a
warning, whatever `--sandbox` or the config says: the container is the boundary there,
and the image ships no sandbox backend. See
[Run ASH in a container](../how-to/run-in-a-container.md).

`--mode nix` passes `--sandbox` to the scan it runs inside the Nix shell, so that scan is
sandboxed. Add the offline rule caches to `extra_read_paths`, as shown in
[Offline semgrep and opengrep](#offline-semgrep-and-opengrep).
