# Scanner sandbox

Every scanner reads files the scanned repository wrote, and a scanner is a large program with its own parsers and plugins. The scanner sandbox runs each scanner's processes under an operating-system confinement, so that a repository that makes a scanner misbehave reaches less of the host. The sandbox is off by default. To turn it on and set it up on each platform, see [Enable the scanner sandbox](../docs/scanner-sandbox.md).

## What it wraps

When the sandbox mode is anything other than `off`, ASH wraps every process a scanner starts through ASH's process helpers while that scanner runs. That includes the probes ASH runs to check each scanner's tool, and the detect-secrets and cdk-nag scans, which ASH runs in child processes so that the sandbox can wrap them.

It does not wrap:

- ASH's own process: configuration loading, the converters' own code, parsing of scanner output, the reporters, and the Python code of every plugin module. A tool a converter starts (nbconvert for notebooks) is not ASH's own process: it is held to the sandbox like a scanner's tool;
- git, which ASH runs to list changed files;
- the content database refresh that ASH runs itself before an online scan, outside the sandbox and with network, from a working directory outside the scanned tree and with an empty tool configuration (see [Content databases](content-databases.md));
- any process a third-party plugin starts without ASH's helpers.

ASH refuses shell commands under the sandbox instead of wrapping them, and a sandboxed scan does not install missing scanner tools. Install them first with `ash dependencies install`, which also installs the notebook converter's nbconvert.

## What it enforces

The policy is the same for every backend:

- Reads are granted for the system directories (`/usr`, `/etc`, `/opt`, and the like), the directories on `PATH`, ASH's own installation, uv's tool, interpreter, and cache directories, the scanner tool's own installation, the paths the scanner declares, `sandbox.extra_read_paths`, and the source, output, target, and working directories. Your home directory and `/tmp` are hidden, apart from the tool directories the policy grants. bwrap and Landlock give the scanner a private home and private temporary directories, and firejail a private home and `/tmp`. Under sandbox-exec the scanner gets a private temporary directory, and `HOME` points at your home, which it cannot read. On firejail and sandbox-exec, `/var/tmp` stays readable. How much else stays readable depends on the backend (table below).
- With bwrap, the only host directory a scanner can write to is its own results directory. Landlock isolates less (see the table); use it only where bwrap cannot run. Cache directories a scanner declares are available, but writes to them never reach the host.
- The environment is reduced to an allowlist (`PATH`, `TZ`, locale, terminal, and color settings, certificate bundle paths, `VIRTUAL_ENV`, `JAVA_HOME`, `GEM_HOME`, `GEM_PATH`, `SYSTEMROOT`, and names starting with `ASH_`, `UV_`, `PYTHON`, or `LC_`) plus the prefixes each scanner declares. Any name containing `TOKEN`, `PASSWORD`, `SECRET`, `CREDENTIAL`, `AUTH`, `API_KEY`, `SESSION`, or a similar marker is dropped unless the scanner names it exactly. Variables under the allowed prefixes reach every sandboxed scanner, so do not put credentials in their values; use a credential helper, or a variable whose name marks it as a credential. Proxy settings are passed only to scanners that have a network.
- A scanner gets a network only if it needs one (next section). On Linux, a seccomp filter also refuses Unix-domain sockets on every backend.
- After each sandboxed process, and again after the scanner finishes, ASH removes symbolic links and special files the scanner left in its results directory.

How each backend implements that policy differs, and so does what it can hold:

| Backend | Platform | Reads outside the granted paths | Network when none is granted | Running programs from the scanned tree | Notes |
|---|---|---|---|---|---|
| `bwrap` | Linux | Not visible | Separate network namespace | Allowed | The strictest Linux backend. Needs unprivileged user namespaces. Cache writes go to a throwaway overlay where bwrap and the kernel support one. |
| `firejail` | Linux | Everything outside the home and temporary directories stays readable | `firejail --net=none` | Allowed | Hides the Docker, Podman, and containerd sockets and the SSH agent. Refuses to run inside a container that has its own PID namespace. |
| `landlock` | Linux | Denied | seccomp refuses every socket | Allowed | Needs Landlock ABI 3 (Linux 6.2) or later; on an older kernel it counts as unavailable. No namespaces: the scanner sees the host's processes and their command lines, and shares the host's `/dev/shm`. Below Landlock ABI 6, signals to processes outside the sandbox are not restricted. |
| `sandbox-exec` | macOS | Everything outside the home and temporary directories stays readable | Denied | Denied in the scanned tree, the writable directories, and the caches | The only backend that restricts which programs run. |

`auto` tries `bwrap`, then `firejail`, then `landlock` on Linux, and `sandbox-exec` on macOS, and uses the first one whose probe can start a real sandbox. Windows has no backend; run ASH under WSL2 with `bwrap`, or use container mode. The Linux socket filter exists only for x86_64 and aarch64, so on other Linux architectures every Linux backend fails its probe.

No backend limits CPU, memory, disk use, or the number of processes. The scan timeout is the only bound on a runaway scanner.

## Network

Under the sandbox, a scanner has a network only when it declares that it needs one, or when `sandbox.network_scanners` names it. These scanners declare a need: semgrep and opengrep (registry rules), grype, trivy, and trivy-repo (vulnerability data), npm-audit (the registry's audit endpoint), and snyk-code (Snyk's service). detect-secrets needs a network only when its verification filter is on, and gets one only when `sandbox.network_scanners` names it. Every other scanner runs with no network. `--offline` removes the network from every scanner, whatever the grants say.

When `sandbox.network_scanners` is set, the list replaces the declarations: a scanner it names gets a network on every online scan, and a scanner it does not name gets none. Naming detect-secrets therefore gives it a network whether or not its verification filter is on.

A scanner that has a network shares the host's network. There is no egress filter: it can reach any address the host can reach, including services on localhost and on the local network, and it can send anything it can read.

## Grants, and who may make them {#grants}

Five settings grant a sandboxed scanner more than the policy above: `sandbox.network_scanners`, `sandbox.extra_read_paths`, `sandbox.read_path_scanners`, `sandbox.env_scanners`, and `sandbox.environment`. [Give a scanner more access](../docs/scanner-sandbox.md#grants) says what each one grants.

Only the operator may grant. A grant counts when it comes from `--config-overrides`; from a config file outside every git checkout and outside the scanned directory, named with `--config` or `ASH_CONFIG`; in workspace mode, from the `--config` file given to the workspace scan, under the same rule with the workspace root as the scanned directory; or from the MCP server's own configuration, under the same rule. When such a file extends a base that cannot grant, only the grants it writes in its own `sandbox` section count, not what it inherits from any base or changes with `patch`. `--sandbox` sets the mode and grants nothing.

A config file inside any git checkout, the scanned one or a separate one such as an ops or dotfiles repository, or inside the scanned directory, cannot grant, whether it is the file you name or a base it extends. Nor can, under `ash mcp`, one an MCP client delivered. ASH drops the grants of a file that cannot grant and logs a warning that names the file and the settings and says how to grant instead. Its `network_scanners` list still counts as a limit, so a repository can take the network away from its own scan but cannot add one. Its `sandbox.mode` applies only when no operator source turns the sandbox on; it cannot turn off, or change, a mode you set. Under the MCP server's default policy, a delivered file whose own `sandbox` section gives a scanner a network or an `extra_read_paths` entry the server's settings do not, or changes a sandbox mode other than `off` that the server sets, is refused instead ([What a delivered config cannot set](../how-to/mcp-server.md#what-a-delivered-config-cannot-set)); its other grants are dropped the same way. [Configuration trust model](trust-model.md) explains how ASH decides where a config file belongs.

## What fails closed

A scanner that cannot be sandboxed the way the configuration asks is never run unsandboxed. Its tool cannot start as asked, so each scan is recorded `ERROR` with the start-failure code 127 as the scanner's `exit_code` in `ash_aggregated_results.json`, and the default `fail_on_incomplete_scanners` makes the scan exit 1; 127 is the scanner's recorded code, not the exit status. The reason is in the scan output and `ash.log`, as a line such as `detect-secrets could not start its tool on source: sandbox-exec is not available: sandbox-exec is not available on Linux`. That covers:

- an explicit backend that is not installed or cannot start a sandbox on this host;
- `auto` when no backend works, with a reason that lists why each one failed;
- a Linux architecture for which bwrap cannot apply the Unix-socket filter;
- turning the sandbox on at all on Windows;
- a scanner that the config file names under a different name than its own, because grants follow a scanner's own name.

A converter's tool is held to the same rule. When the sandbox cannot be provided, nbconvert does not run: each notebook is listed in the converter's `refused_inputs` with the reason, the row's `failure` reads `jupyter could not start its tool: <reason>`, and its `dependencies_satisfied` stays true, since nothing was found missing. A tree with no notebooks loses nothing.

ASH also refuses, rather than runs unsandboxed, a shell command that a scanner tries to start, and a scanner whose results directory is reached through a symbolic link. ASH looks up the sandbox programs themselves (`bwrap`, `firejail`) the way it looks up scanner tools: never through the working directory or from inside the scanned tree, unless you allow in-tree tools. Which backend a scan used is written to `ash.log`; the results record only the requested mode, in `ash_config.sandbox.mode`.

## What it does not do {#what-it-does-not-do}

- It does not filter the traffic of a scanner that has a network.
- It does not confine ASH's own process, the converters' own code, the reporters, plugin code, or the content database refresh. The tools a converter starts are confined like a scanner's.
- On `firejail` and `sandbox-exec`, files outside your home and temporary directories stay readable.
- On the Linux backends, a scanner can run programs from the scanned tree inside its sandbox.
- It shares the host's kernel and sets no resource limits.
- It does not apply in container mode. `ash scan --mode container` turns the sandbox off for the scan inside the container, and logs a warning when the sandbox was asked for; the container is the boundary there. See [Run ASH in a container](../how-to/run-in-a-container.md).
- It does not make a scanner's results trustworthy. A scanner still reads every file in the source tree, and a hostile file can still change what it reports.

One setting to plan for: an offline semgrep or opengrep scan reads its rules from the directory `SEMGREP_RULES_CACHE_DIR` or `OPENGREP_RULES_CACHE_DIR` names, and under the sandbox it can read only directories the sandbox mounts. Keep the rules cache under a system directory such as `/opt`, or add it to `sandbox.extra_read_paths`.
