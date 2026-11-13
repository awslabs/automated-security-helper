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
there is no express mode: `ash express start` refuses with a clear message,
`ash scan --express` prints one line on stderr saying the platform has no express mode
and runs cold, and every scan without the flag runs cold silently, exactly as before.

## Use it {#use}

Nothing is required. When the daemon is running, every `ash scan` (and bare `ash`) uses it
automatically; when it is not, or anything about it is off, the scan silently runs cold.
Up to the moment the daemon accepts a scan, express can only make it faster or leave it as
it was: every pre-acceptance failure is the cold run. Once a scan is running on the daemon
there is no silent fallback either way -- a daemon killed mid-scan is reported on stderr
and the scan exits 1 rather than being rerun behind your back -- so express never produces
a wrong result; the one failure you can see is that rare mid-scan report.

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

The client hands the daemon the scan's command line, its working directory, and its
whole environment, minus ASH's internal express child marker. That includes loader
variables such as `LD_PRELOAD`: a cold run hands every scanner subprocess the value, so
the forked scan's scanners get it too (the daemon's own process is not preloaded with
it, which is the one difference a forked process cannot avoid). The forked child's
environment becomes exactly what the request carries, so a variable a scanner reads --
whichever scanner, whatever the variable -- has the same value under express as in a
cold run; an allowlist here was always one forgotten scanner variable away from "same
command, different findings". The environment travels only inside the request, over
the same-user socket, to the one forked child -- the daemon's own resident environment
is scrubbed when it starts, so nothing from the invocation that happened to start it
becomes ambient state under later scans. What the scrub keeps is the execution basics
(`PATH`, `HOME`, the temporary-directory and locale variables, `TERM`, the
runtime-directory and idle-timeout settings) and the variables that decide which ASH
and which site packages the daemon's interpreter imports: `PYTHONPATH`, `PYTHONHOME`,
`PYTHONUSERBASE`, `PYTHONNOUSERSITE` and `VIRTUAL_ENV`. Those are kept because an ASH
reachable only through `PYTHONPATH` would not start without them, and their values are
part of the daemon's socket name: two shells that differ only in those values (a
pre-commit hook and an IDE terminal, tox and a plain shell) each reach a daemon of
their own, so neither reads the other's as stale or stops it. Relative `PYTHONPATH`
entries are made absolute against the directory the client runs in before they are
used, so the daemon imports the same tree the client names. The
client also passes its stdin, stdout and stderr as file descriptors, so the forked
scan writes to your terminal directly -- progress, colors and prompts behave as a cold
run's, and nothing of the scan's output travels over the socket. Ctrl-C in the client
is forwarded to the forked scan.

The handshake commits both sides exactly once: the daemon acknowledges a scan request
it will run, the client answers that acknowledgement, and only then does the daemon
fork -- so a client that gives up waiting (a daemon still warming its imports answers
only when they finish, and the client's handshake budget covers that on every path)
falls back to a cold run with certainty that no second scan runs behind it.

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

Silently, by design, whenever the daemon cannot be used *before it has accepted the
scan*: no socket, a stale daemon, a daemon already running as many scans as you have
CPUs, a protocol hiccup, an unsupported platform. Every one of those is a scan at the
old speed, never a failed or wrong one. With `--express` on the command line the
fallback additionally prints one line to stderr saying why, since that invocation asked
for the daemon explicitly. After acceptance the scan is running against your terminal,
so there is deliberately no fallback left: a daemon lost mid-scan (killed, machine
shutdown) is reported on stderr and the command exits 1 -- rerunning it silently could
double a scan's side effects. A Ctrl-C or termination signal that lands during the
handshake itself ends the command with the usual interrupt code instead of starting a
cold scan you just asked to stop.

Some invocations never use the daemon: anything that is not a scan (`ash report`,
`ash inspect`, shell tab-completion, ...), any scan with `--no-express`, and scans the
MCP server hosts in-process. The console script `ash` gets the full saving; running the
module form (`python -m automated_security_helper.cli.main`) delegates too, but it has
already paid the import cost by the time it does.

## Pre-commit hooks {#pre-commit}

The per-commit startup tax is the reason express exists -- with one pairing rule: the
daemon serves exactly the ASH installation that started it (the version keys the socket,
and a fingerprint of the installed packages is checked per request), and pre-commit runs
ASH from a hook environment of its own, which is a *different* installation than the
`ash` on your shell's PATH. A daemon started from your shell is therefore silently
ignored by the hook. Start the daemon from the hook's own ASH instead: add `--express`
to the hook's `args`, and the first commit starts a daemon paired with the hook
environment, which every later commit then uses with no flag needed. The hook's default
`--staged` already scopes the scan to what the commit touches (see
[Run ASH with pre-commit](pre-commit.md)), so the pair is the fastest hook. The daemon outlives the hook process, so the warmth carries from commit to
commit, and its idle timer retires it after a quiet half hour.

## Troubleshooting {#troubleshoot}

- `ash express status` says whether a daemon is running and what it has served -- and
  reports separately, with a non-zero exit, a socket that something holds without
  answering (a wedged daemon): find the holder with `fuser` or `lsof` on the socket,
  stop it, or remove the socket file.
- The daemon logs to `ash-<uid>-<key>.log` next to its socket; `ash express start
  --foreground` runs it attached to your terminal instead. A foreground daemon runs
  inside the CLI process, with its environment scrubbed and its signal handlers reset
  the way a detached daemon's are before it serves, but with the CLI's imports (typer,
  rich, the logging stack) already resident, which a detached start, a fresh
  interpreter, does not have. It is for watching the log; to reproduce a daemon's
  behavior exactly, start it detached.
- `ash express start` prints "started" only after a status query shows a daemon this
  installation's scans can use (the same fingerprint and protocol). Replacing a stale
  daemon first checks that the old one is really gone, and exits 1 if it is not.
- A scan that behaves differently under express than with `--no-express` is a bug to
  report: the scan's environment, arguments and working directory travel with each
  request precisely so the two cannot differ.
- Scans still slow with the daemon running: the first request after `ash express start`
  may wait briefly while the warm imports finish; later ones do not.
