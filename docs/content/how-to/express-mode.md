# Express mode

A cold `ash scan` pays for the Python interpreter and the import of ASH's CLI, models and
built-in plugins before any scanning starts -- around two seconds on a typical machine.
Run once a day that is noise; run on every commit by a pre-commit hook, or dozens of times
an hour by an agent, it is most of the wait. Express mode removes it: one resident daemon
per user holds ASH warm, and each scan forks that process and starts working immediately.
The name means what it means for
[CloudFormation and CDK deployments](https://aws.amazon.com/about-aws/whats-new/2026/06/aws-cloudformation-cdk/):
the same operation, minus the waiting that is not the work.

The scan itself is unchanged. The forked child executes the same console entry a cold run
executes, with your command line, your working directory and your terminal, so its output,
reports and exit code are the cold run's. Express is an accelerator, never a different scan.

Unix only (Linux and macOS). On Windows, and anywhere else without unix-domain sockets,
there is no express mode: `ash express start` refuses with a clear message, `--express` is
accepted and means nothing, and every scan runs cold exactly as before.

## Use it {#use}

Nothing is required. When the daemon is running, every `ash scan` (and bare `ash`) uses it
automatically; when it is not, or anything about it is off, the scan silently runs cold.
Express can make a scan faster or leave it as it was -- there is no failure mode in which it
makes a scan wrong, and none in which it makes one fail.

Start the daemon on demand from a scan:

<!-- doctest: illustrative reason="starts a resident daemon that would outlive the docs run, and only on unix" -->
```bash
ash scan --source-dir . --express
```

`--express` starts the daemon if it is absent (and replaces it if it is stale), then runs
the scan through it. Later scans need no flag: the daemon's socket exists, so they use it.

Or manage it explicitly -- `start` is idempotent, takes `--idle-seconds` and
`--foreground`, and `status` takes `--json` for scripts:

<!-- doctest: illustrative reason="starts a resident daemon that would outlive the docs run, and only on unix" -->
```bash
ash express start
ash express status
ash express stop
```

Force a cold run without stopping the daemon:

<!-- doctest: illustrative reason="the cold run is the ordinary scan; running it here would only rescan the fixture" -->
```bash
ash scan --source-dir . --no-express
```

The daemon retires itself after 30 minutes without a request (configure with the
`--idle-seconds` option of `ash express start`, or the `ASH_EXPRESS_IDLE_SECONDS`
environment variable), so a daemon you forget about costs memory only until then.

## What a scan sends to the daemon {#protocol}

The client hands the daemon the scan's command line, its working directory, and the
environment variables ASH honours (every `ASH_*` and `GIT_*` variable -- a commit hook's
`GIT_INDEX_FILE` changes what the scan's git commands read, so it travels with the
request -- the documented inputs such as `OCI_RUNNER`, `CI` and the color controls, and
the execution basics `PATH`, `HOME`, `TMPDIR` and locale). The daemon's own environment
is scrubbed down to those basics when it autostarts, so nothing else from the invocation
that happened to start it becomes ambient state under later scans. The client also
passes its stdin, stdout and stderr as file descriptors, so
the forked scan writes to your terminal directly -- progress, colors and prompts behave as
a cold run's, and nothing of the scan's output travels over the socket. Ctrl-C in the
client is forwarded to the forked scan.

A variable outside the honoured set is not sent and not applied: the forked scan runs
with the daemon's value of it. If a scan depends on an environment variable ASH does not
document, run it with `--no-express` (and consider filing an issue naming the variable).

## Security model {#security}

- The socket is a **unix-domain socket**, never TCP: there is no port, no network
  listener, and nothing for another machine to connect to.
- It lives in a **0700 directory owned by you** (`$XDG_RUNTIME_DIR/ash-express`, or
  `~/.ash/run`), and the socket file itself is 0600. A directory that is a symlink, owned
  by someone else, or whose mode cannot be corrected is refused, and express mode simply
  does not run.
- The daemon reads every connecting peer's uid **from the kernel** (`SO_PEERCRED` on
  Linux, `LOCAL_PEERCRED` on macOS) and serves only its own uid. An unreadable peer is
  refused, not trusted: the check fails closed -- and a platform where the kernel offers
  no peer-credential read has no express mode at all, rather than a daemon that would
  look started while refusing everyone.
- The daemon runs as you, with your privileges, and executes only what a cold
  `ash` run of yours would execute.

## Staleness and invalidation {#invalidation}

The socket path is keyed by your uid and the ASH version, so upgrading ASH strands the
old daemon at the old path -- new scans do not find it, run cold (or start a fresh daemon
under `--express`), and the old daemon's idle timer retires it. On every request the daemon
also compares a fingerprint of the installed package set and the interpreter, taken when
it started, against the client's; a mismatch -- a reinstalled dependency, say -- is
refused, the client falls back cold, and `--express` replaces the daemon.

Configuration needs no invalidation at all: the resident daemon loads **no repository
config** -- it only imports modules. Every forked scan reads the config itself, from the
request's working directory, exactly as a cold run does, so editing `.ash/ash.yaml`
changes the very next scan with no daemon restart.

## When it falls back cold {#fallback}

Silently, by design, whenever the daemon cannot be used: no socket, a stale daemon, a
daemon already running as many scans as you have CPUs, a protocol hiccup, an unsupported
platform. The failure mode of express is a scan at the old speed, never a failed or wrong
scan. With `--express` on the command line the fallback additionally prints one line to
stderr saying why, since that invocation asked for the daemon explicitly.

Two commands never use the daemon: anything that is not a scan (`ash report`,
`ash inspect`, ...), and any scan with `--no-express`.

## Pre-commit hooks {#pre-commit}

The per-commit startup tax is the reason express exists. Start the daemon once
(`ash express start`, or one `ash scan --express`), and every hook run afterwards skips the
startup entirely; pair it with a scan scoped to what the commit touches (see
[Run ASH with pre-commit](pre-commit.md)) for the fastest hook. The daemon outlives the
hook process, so the warmth carries from commit to commit.

## Troubleshooting {#troubleshoot}

- `ash express status` says whether a daemon is running and what it has served.
- The daemon logs to `ash-<uid>-<key>.log` next to its socket; `ash express start
  --foreground` runs it attached to your terminal instead.
- A scan that seems to ignore a changed environment variable: check the honoured set
  above, and `--no-express` to compare against a cold run.
- Scans still slow with the daemon running: the first request after `ash express start`
  may wait briefly while the warm imports finish; later ones do not.
