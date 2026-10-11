# Scanner sandbox

Every scanner reads files the scanned repository wrote, and a scanner is a large program with its own parsers and plugins. The scanner sandbox runs each scanner's processes under an operating-system confinement, so that a repository that makes a scanner misbehave reaches less of the host. The sandbox is off by default. To turn it on and set it up on each platform, see [Sandbox scanners](../docs/scanner-sandbox.md).

## What it wraps

When the sandbox mode is anything other than `off`, ASH wraps every process a scanner starts through ASH's process helpers while that scanner runs. That includes the probes ASH runs to check each scanner's tool, and the detect-secrets and cdk-nag scans, which ASH runs in child processes so that the sandbox can wrap them.

It does not wrap:

- ASH's own process: configuration loading, the converters, parsing of scanner output, the reporters, and the Python code of every plugin module;
- git, which ASH runs to list changed files;
- the content database refresh, which ASH runs before an online scan, outside the sandbox and with network, from a working directory outside the scanned tree and with an empty tool configuration (see [Content databases](content-databases.md));
- any process a third-party plugin starts without ASH's helpers.

ASH refuses shell commands under the sandbox instead of wrapping them, and a sandboxed scan does not install missing tools. Install them first with `ash dependencies install`.

## What it enforces

The policy is the same for every backend:

- Reads are granted for the system directories (`/usr`, `/etc`, `/opt` and the like), the directories on `PATH`, ASH's own installation, the scanner tool's own installation, the paths the scanner declares, `sandbox.extra_read_paths`, and the source, output and target directories. Your home directory and the temporary directories are hidden, and the scanner gets private ones. How much else stays readable depends on the backend (table below).
- The only host directory a scanner can write to is its own results directory. Cache directories a scanner declares are available, but writes to them never reach the host.
- The environment is reduced to an allowlist (`PATH`, locale and terminal settings, certificate bundle paths, and names starting with `ASH_`, `UV_`, `PYTHON` or `LC_`) plus the prefixes each scanner declares. Any name containing `TOKEN`, `PASSWORD`, `SECRET`, `CREDENTIAL`, `AUTH`, `API_KEY`, `SESSION` or a similar marker is dropped unless the scanner names it exactly, and so is any value that is a URL with a user name and password in it. Proxy settings are passed only to scanners that have a network.
- A scanner gets a network only if it needs one (next section). On Linux, a seccomp filter also refuses Unix-domain sockets on every backend.
- After each sandboxed process, and again after the scanner finishes, ASH removes symbolic links and special files the scanner left in its results directory.

How each backend implements that policy differs, and so does what it can hold:

| Backend | Platform | Reads outside the granted paths | Network when none is granted | Running programs from the scanned tree | Notes |
|---|---|---|---|---|---|
| `bwrap` | Linux | Not visible | Separate network namespace | Allowed | Needs unprivileged user namespaces. Cache writes go to a throwaway overlay where bwrap and the kernel support one. |
| `firejail` | Linux | Everything outside the home and temporary directories stays readable | `firejail --net=none` | Allowed | Hides the Docker, Podman and containerd sockets and the SSH agent. Refuses to run inside a container that has its own PID namespace. |
| `landlock` | Linux | Denied | seccomp refuses every socket | Allowed | No namespaces. Shares the host's `/dev/shm`. Below Landlock ABI 6, signals to processes outside the sandbox are not restricted. |
| `sandbox-exec` | macOS | Everything outside the home and temporary directories stays readable | Denied | Denied in the scanned tree, the writable directories and the caches | The only backend that restricts which programs run. |

`auto` tries `bwrap`, then `firejail`, then `landlock` on Linux, and `sandbox-exec` on macOS, and uses the first one whose probe can start a real sandbox. Windows has no backend; run ASH under WSL2 with `bwrap`, or use container mode. The Linux socket filter exists only for x86_64 and aarch64, so on other Linux architectures every Linux backend fails its probe.

No backend limits CPU, memory, disk use or the number of processes. The scan timeout is the only bound on a runaway scanner.

## Network

Under the sandbox, a scanner has a network only when it declares that it needs one, or when `sandbox.network_scanners` names it. These scanners declare a need: semgrep and opengrep (registry rules), grype, trivy and trivy-repo (vulnerability data), npm-audit (the registry's audit endpoint) and snyk-code (Snyk's service). detect-secrets needs one only when its verification filters are on, and gets it only when `sandbox.network_scanners` names it. Every other scanner runs with no network. `--offline` removes the network from every scanner, whatever the grants say.

When `sandbox.network_scanners` is set, the list replaces the declarations: a scanner it does not name gets no network.

A scanner that has a network shares the host's network. There is no egress filter: it can reach any address the host can reach, including services on localhost and on the local network, and it can send anything it can read.

## Grants, and who may make them {#grants}

Four settings grant a sandboxed scanner more than the policy above:

- `sandbox.network_scanners` gives the scanners it names a network.
- `sandbox.extra_read_paths` mounts more host paths, read-only, into every sandbox.
- `sandbox.read_path_scanners` lets the scanners it names read paths their own options point to. Among the scanners ASH ships, only detect-secrets uses this, for a baseline file outside the source tree.
- `sandbox.env_scanners` lets the scanners it names receive environment variables their own options ask for. No scanner ASH ships asks for one today.

Only the operator may grant. A grant counts when it comes from `--config-overrides`, from a config file outside every git checkout and outside the scanned directory (named with `--config` or `ASH_CONFIG`), from the workspace's default config in workspace mode, or from the MCP server's own configuration. `--sandbox` sets the mode and grants nothing.

A config file inside a git checkout or the scanned directory, or one an MCP client delivered, cannot grant. ASH drops its grants and logs a warning that names the file and the settings. Its `network_scanners` list still counts as a limit, so a repository can take the network away from its own scan but cannot add one. Its `sandbox.mode` applies only when no operator source turns the sandbox on; it cannot turn off, or change, a mode you set. [Configuration trust model](trust-model.md) explains how ASH decides where a config file belongs.

## What fails closed

A scanner that cannot be sandboxed the way the configuration asks is never run unsandboxed. ASH records it as MISSING, and the default `fail_on_incomplete_scanners` makes the scan exit 1. The reason is in the scan output and `ash.log`, as a line such as `bandit not run: scanner sandbox unavailable: firejail is not installed`; the scanner's row in `ash_aggregated_results.json` does not carry it. That covers:

- an explicit backend that is not installed or cannot start a sandbox on this host;
- `auto` when no backend works, with a reason that lists why each one failed;
- turning the sandbox on at all on Windows;
- a scanner that the config file names under a different name than its own, because grants follow a scanner's own name.

ASH looks up the sandbox programs themselves (`bwrap`, `firejail`) the way it looks up scanner tools: never through the working directory or from inside the scanned tree, unless you allow in-tree tools. Which backend a scan used is written to `ash.log`; it is not recorded in the results.

## What it does not do

- It does not filter the traffic of a scanner that has a network.
- It does not confine ASH's own process, the converters, the reporters, plugin code, or the content database refresh.
- On `firejail` and `sandbox-exec`, files outside your home and temporary directories stay readable.
- On the Linux backends, a scanner can run programs from the scanned tree inside its sandbox.
- It shares the host's kernel and sets no resource limits.
- It does not apply in container mode. `ash scan --mode container` turns the sandbox off for the scan inside the container, without a warning; the container is the boundary there. See [Run ASH in a container](../how-to/run-in-a-container.md).
- It does not make a scanner's results trustworthy. A scanner still reads every file in the source tree, and a hostile file can still change what it reports.

One interaction to plan for: an offline semgrep or opengrep scan reads its rules from the directory `SEMGREP_RULES_CACHE_DIR` or `OPENGREP_RULES_CACHE_DIR` names. Under the sandbox that directory is visible only if it is under a system directory or listed in `sandbox.extra_read_paths`. If it is not, semgrep finds no rules, and ASH currently records the scanner as passed with no findings. Keep the rules cache under a system directory, or add it to `sandbox.extra_read_paths`.
