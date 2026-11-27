# Supported configurations

ASH is built and tested for Linux, macOS and Windows, on x86-64 and arm64 processors, in
several modes. Not every combination gets the same support. This page lists each
configuration ASH has something to say about: how well it works there, what ASH does, and
what you can change to reach a supported configuration. A configuration this page does not
list is supported, except the few that ASH [declares nothing about](#not-declared).

The sentences on this page are the ones ASH itself uses for these configurations, so the
words you read here are the words ASH uses elsewhere.

## The four levels {#levels}

Every configuration has one of four levels, from best to worst:

- supported: ASH works here and has nothing to say about it.
- polyfilled: ASH works here through a named stand-in for something the platform or the
  runtime lacks. The stand-in can change what you see, such as speed, an interpreter or a
  refusal of some inputs, so ASH names it.
- degraded: ASH runs here and loses a named function. The sentence for the configuration
  says what is lost.
- unsupported: ASH refuses, skips the part that cannot work, or runs with results it
  cannot stand behind.

A run that matches several configurations has the level of the worst one. The level says
what ASH declares, and it is separate from what ASH's own CI tests: the
[install page](install.md) lists the platforms CI covers, and Intel Macs and Windows on
arm64 are supported without being tested.

## What is supported {#supported}

ASH is supported on Linux with glibc, on macOS and on Windows, on amd64 and arm64
processors, when it runs as native code, with a Python in the range the
[install page](install.md) states. The supported install channels are uv tool install,
uvx, pipx, pip, Homebrew, Nix, the container image and a source checkout. The supported
modes are local, container, pre-commit and Nix, with the limits listed below. WSL 2 is
supported, and it is one of the ways out of several Windows limits.

A supported processor is an arm64 one, or an x86-64 one with the instruction set that
polars' default runtime is built for.

## What ASH says nothing about {#not-declared}

ASH leaves a few things undeclared. It raises no notice for them, and it does not call
them unsupported:

- musl Linux: ASH does not declare support for Linux with musl libc, such as Alpine, and
  raises no notice there.
- WSL 1: ASH documents WSL 2 only and declares nothing about WSL 1.
- Free-threaded CPython: The free-threaded CPython build cannot use the stable ABI wheels
  polars' runtime ships, so installing ASH there means building polars from source, and
  ASH declares nothing about it.
- Other Python implementations: ASH declares nothing about Python implementations other
  than CPython.
- No polars runtime: ASH needs a polars runtime to start, so no run reaches the register
  without one.

## Adaptations {#adaptations}

An adaptation is the platform's own implementation of a function, with no loss you can
see. It does not change the level of a configuration and it raises no notice. These are
listed so that the support matrices and this page agree on what ASH does differently on
each platform:

- Windows executable lookup: On Windows the file that carries a tool's name is often not
  one Windows can run, so ASH looks for the .exe, .bat and .cmd wrappers that package
  managers write beside it.
- Windows command-line bounds: Windows can re-read a command line through cmd.exe, which
  splits it at characters other platforms pass through, so ASH writes the paths it gives
  Checkov in a form that survives that.
- Windows console rendering: Some Windows consoles cannot encode every character ASH
  prints, so ASH writes ASCII in place of emoji in log messages and sets its console
  streams to UTF-8.
- Windows atomic replace retry: On Windows a reader that holds a file open makes the
  rename that replaces it fail, so ASH retries the rename for a short time and reads the
  file again.
- Windows output decoding: Windows tools write text in the console's code page, so ASH
  decodes the partial output of a timed-out tool with the locale's encoding and not with
  UTF-8.
- Windows link open check: Windows cannot open a file relative to a directory handle, so
  ASH checks by path that a file it reads is not a link.
- macOS process wait: CPython has no waitid call on macOS, so ASH polls for the end of a
  tool process and forgets its process id once the process has ended.
- macOS quarantine removal: macOS marks a downloaded binary as quarantined, so ASH removes
  the mark from the tools it downloads before it runs them.
- Linux fork start: Linux starts worker processes with fork, so a worker begins with ASH's
  modules loaded; macOS and Windows start a fresh interpreter instead.

## How a configuration is reported {#notices}

Each configuration below is declared with the moment it applies. Most apply when a run
starts, because ASH can read the facts then: the operating system, the processor, the
Python, the mode and the wrapper. Others apply where ASH makes the decision the row is
about, because the facts are known only there: whether a sandbox backend works, whether
the image matches the machine, whether ignore paths are set and whether a scanner's own
sandbox is available. A few documented limits are never raised as a notice, because ASH
cannot see them in a run. They are listed on this page and in the support matrices only.

An unsupported configuration is always shown, once per run, with the ways out that apply
to the machine. A degraded configuration is shown as a warning, and straight on the
console when you asked for the function that is lost. A polyfilled configuration is shown
as one informational line that names the stand-ins in use. Every notice links to the
section of this page that explains it.

The ways out are split into two groups: on this machine, and elsewhere, which means
another machine or another operating system. A way out is listed only where it can apply:
WSL 2 is offered from Windows only.

## Configurations that are not fully supported {#configurations}

### Processor below the default polars runtime {#host-cpu-below-polars-runtime}

This x86-64 processor lacks instructions the installed polars runtime is built for, and
polars warns that running on it will likely crash.

Level: unsupported. ASH carries on after the notice. The container image is not a way out:
it runs on this machine's processor and carries the same default polars runtime. Ways out:
[add polars' compatibility runtime](#polars-compat-runtime) where the processor has the
compatibility runtime's instruction set, [use an arm64 build of Python](#native-arm64) when
the run is translated, [use another processor](#x86-host-with-features),
[use an arm64 machine](#arm64-host) or [scan in CI](#ci-runner).

### Processor below polars' compatibility runtime {#host-cpu-below-polars-compat}

This x86-64 processor lacks instructions even polars' compatibility runtime is built for,
and polars warns that running on it will likely crash.

Level: unsupported. ASH carries on after the notice. The compatibility runtime is already
installed here, so it cannot help. Ways out: [use an arm64 build of Python](#native-arm64)
when the run is translated, [use another processor](#x86-host-with-features),
[use an arm64 machine](#arm64-host) or [scan in CI](#ci-runner).

### Running with polars' compatibility runtime {#host-cpu-polars-compat-runtime}

ASH runs with polars' compatibility runtime, which runs on older x86-64 processors and is
slower than the default runtime.

Level: polyfilled. The stand-in is the Polars compatibility runtime. It stands in for the
default polars runtime, which is built for AVX2-class x86-64 processors. What you can see:
it runs on older x86-64 processors and is slower than the default runtime.

### x86-64 code translated by Rosetta 2 {#host-translation-rosetta}

ASH runs as x86-64 code translated by Rosetta 2, and in local mode so do the tools it
downloads for x86-64, which is slower than arm64 builds.

Level: degraded. ASH carries on. Way out: [use an arm64 build of Python](#native-arm64).

### x64 Python under Windows emulation {#host-translation-x64-on-arm64}

ASH runs as x86-64 code under Windows emulation on an arm64 processor, and in local mode so
do the tools it downloads for x86-64, which is slower.

Level: degraded. ASH carries on. Ways out: [use an arm64 build of Python](#native-arm64) or
[use WSL 2](#wsl2).

### An operating system other than Linux, macOS or Windows {#host-os-other}

ASH is built and tested for Linux, macOS and Windows, and this operating system is none of
them.

Level: unsupported. ASH carries on after the notice. Ways out:
[use Linux or macOS](#linux-or-macos-host) or [scan in CI](#ci-runner).

### A processor that is neither x86-64 nor arm64 {#host-arch-other}

ASH runs on 64-bit x86 and arm64 processors, and polars, which ASH needs, publishes no
build for this one.

Level: unsupported. ASH carries on after the notice. Ways out:
[use an x86-64 processor](#x86-host-with-features), [use an arm64 machine](#arm64-host) or
[scan in CI](#ci-runner).

### A Python outside the declared range {#host-python-outside-requires}

This Python version is outside the range ASH declares.

Level: unsupported. The installers refuse to install ASH on such a Python, and ASH does not
check the version again when it starts, so a scan on one carries on after the notice. Ways
out: [use a supported Python](#supported-python), [scan in the container image](#container-image)
or [scan in CI](#ci-runner). The [install page](install.md) states the range.

### Nix mode on Windows {#host-mode-nix-on-windows}

Nix mode runs on Linux and macOS, because native Nix on Windows cannot fetch the pinned
scanners.

Level: unsupported. ASH stops here. Ways out: [use WSL 2](#wsl2),
[scan in the container image](#container-image) or [use local mode](#mode-local).

### No per-scanner sandbox in container mode {#host-sandbox-not-applied-in-container}

The per-scanner sandbox is not applied in container mode, so the container is the only
boundary around the scanners.

Level: degraded. ASH carries on, and it tells you because you asked for a sandbox. Ways
out: [scan in local mode with a sandbox](#mode-local-sandboxed) or, from Windows,
[use WSL 2 with the sandbox](#wsl2-sandboxed). The scanner sandbox section of
[Run ASH in a container](run-in-a-container.md#sandbox) describes the sandbox.

### No scanner sandbox backend {#host-sandbox-unavailable-auto}

No scanner sandbox backend works on this host, so scanners that must run sandboxed are not
run.

Level: unsupported. The scanners that need the sandbox are reported as missing, and ASH
carries on with the rest. This applies where ASH chooses the backend itself. Container mode
is not a way out, because it applies no per-scanner sandbox. Ways out:
[install bubblewrap](#install-bubblewrap) on Linux, [use WSL 2 with the sandbox](#wsl2-sandboxed)
from Windows, or [use a machine where a sandbox backend works](#sandbox-capable-host).

### A named sandbox backend that does not work {#host-sandbox-unavailable-named}

The scanner sandbox backend you named does not work on this host, so scanners that must run
sandboxed report an error.

Level: unsupported. The scanners that need the sandbox report an error, and ASH carries on
with the rest. Container mode is not a way out, because it applies no per-scanner sandbox.
Ways out: [install bubblewrap](#install-bubblewrap) on Linux,
[use WSL 2 with the sandbox](#wsl2-sandboxed) from Windows, or
[use a machine where a sandbox backend works](#sandbox-capable-host).

### Landlock ABI below 6 {#host-sandbox-landlock-below-6}

Abstract Unix sockets and signals to processes outside the sandbox are not restricted,
because the kernel's Landlock ABI is below 6.

Level: degraded. ASH carries on and logs a warning. Ways out:
[use a kernel with Landlock ABI 6](#newer-kernel-landlock) or
[install bubblewrap](#install-bubblewrap).

### Bubblewrap mounts caches read-only {#host-sandbox-bwrap-caches-read-only}

Scanner caches are mounted read-only, and a tool that must write its cache gets an empty
private one.

Level: degraded. ASH carries on and logs a warning. Way out:
[use a newer bubblewrap](#newer-bubblewrap).

### Express mode is unavailable {#host-express-unavailable}

Express mode needs Unix sockets, descriptor passing and fork, so each scan starts cold.

Level: degraded. ASH carries on with a cold start, which changes speed and no finding.
Ways out: [use WSL 2](#wsl2) or [use Linux or macOS](#linux-or-macos-host). The
[express mode page](express-mode.md#fallback) says when a scan falls back cold.

### No graceful stop on Windows {#host-windows-no-graceful-stop}

A timed-out or cancelled scanner is ended at once with its process tree, with no graceful
stop, and Ctrl-C does not stop a scan cooperatively.

Level: degraded, and listed in the support matrices and here only. Ways out:
[use WSL 2](#wsl2), [scan in the container image](#container-image) or
[use Linux or macOS](#linux-or-macos-host). In container mode the scanners run in Linux, so
this limit does not apply there.

### No scanner database lock on Windows {#host-windows-no-tool-database-lock}

Scanner databases have no cross-process lock on Windows, so two scans at once can race on
one.

Level: degraded, and listed in the support matrices and here only. Ways out:
[use WSL 2](#wsl2) or [scan in the container image](#container-image).

### Containers left behind on Windows {#host-windows-container-leftovers}

Containers a cancelled scan leaves behind are not recorded or swept.

Level: degraded, and listed in the support matrices and here only. This is the limit that
container mode on a Windows host trades for the missing graceful stop. Way out:
[use WSL 2](#wsl2).

### The wrapper under PowerShell 5.1 {#host-shell-powershell-5}

The wrapper runs under PowerShell 5.1, which lacks behavior it relies on, so a
compatibility layer stands in for it.

Level: polyfilled. The stand-in is PowerShell 5 compatibility. It stands in for the
PowerShell 7 behavior the wrapper relies on: the IsWindows variable, link and file-mode
reads, and argument quoting. What you can see: values that PowerShell before 7.3 would pass
to a program wrongly are refused one by one, with exit 3. Way out:
[run the wrapper from PowerShell 7](#pwsh7).

### The wrapper in a POSIX shell on Windows {#host-shell-msys}

The wrapper runs in a POSIX shell on Windows, such as Git Bash, MSYS2 or Cygwin, so ASH's
own path rules stand in for Windows path handling.

Level: polyfilled. The stand-in is MSYS path rules. They stand in for Windows path handling
in a POSIX shell (Git Bash, MSYS2, Cygwin). What you can see: MSYS path conversion cannot be
turned off for ASH's arguments. Ways out: [run the wrapper from PowerShell 7](#pwsh7) or
[use WSL 2](#wsl2).

### A container image for another architecture {#host-container-image-arch-mismatch}

The image's architecture differs from this machine's, so the engine runs it under
emulation, which is slow.

Level: degraded. ASH carries on, and it tells you because the emulation is otherwise
unseen. Way out: [use an image for this machine's architecture](#native-image).

### Semgrep on Windows {#scanner-semgrep-windows}

The refusal reads: semgrep publishes no Windows build.

Level: unsupported. ASH skips the scanner, and the rest of the scan carries on, with the
scanner recorded as skipped for that reason. Ways out: [use WSL 2](#wsl2),
[scan in the container image](#container-image) or [use Linux or macOS](#linux-or-macos-host).

### GuardDog on Windows {#scanner-guarddog-windows}

The refusal reads: GuardDog 3.2.0 cannot be installed on Windows: its dependency nono-py
publishes no Windows build and does not compile there.

Level: unsupported. ASH skips the scanner, and the rest of the scan carries on, with the
scanner recorded as skipped for that reason. Ways out: [use WSL 2](#wsl2),
[scan in the container image](#container-image) or [use Linux or macOS](#linux-or-macos-host).

### GuardDog confined by ASH's sandbox {#scanner-guarddog-sandbox-replaced}

GuardDog runs inside ASH's sandbox-exec confinement instead of its own kernel sandbox.

Level: polyfilled. The stand-in is the ASH sandbox for GuardDog. It stands in for GuardDog's
kernel sandbox. What you can see: GuardDog's own nono policy is not applied; ASH's sandbox
confines the scan instead.

### GuardDog without a kernel sandbox {#scanner-guarddog-sandbox-unavailable}

GuardDog runs without its own kernel sandbox, because the kernel offers none here.

Level: degraded. ASH carries on, and it tells you because the scan is not confined by
GuardDog. When the scanner's options require the sandbox, the scan of that target fails
instead. Way out: [enable Landlock](#enable-landlock).

### Betterleaks with a private home directory {#scanner-betterleaks-private-home}

Betterleaks runs with a private home directory, which stands in for the cache directory
that sandbox-exec denies.

Level: polyfilled. The stand-in is the Betterleaks private home directory. What you can see:
its compile cache is not kept between runs.

### Ignore paths on Windows {#scanner-windows-ignore-paths}

Four scanners read files you ignored when they run on Windows, because ASH does not pass its
ignore paths to them there. ASH still suppresses their findings:

- ASH's ignore paths are not passed to trivy on Windows, so it reads files you ignored; ASH
  still suppresses their findings.
- ASH's ignore paths are not passed to trivy-repo on Windows, so it reads files you ignored;
  ASH still suppresses their findings.
- ASH's ignore paths are not passed to checkov on Windows, so it reads files you ignored;
  ASH still suppresses their findings.
- ASH's ignore paths are not passed to ferret-scan on Windows, so it reads files you
  ignored; ASH still suppresses their findings.

Level: degraded. ASH carries on. It applies where ignore paths are set, in local and
pre-commit modes. Ways out: [use WSL 2](#wsl2) or
[scan in the container image](#container-image).

### Scan input copies on Windows {#scanner-snyk-code-windows-leftovers}

Copies of the scan input that a run leaves behind are not swept on Windows.

Level: degraded, and listed in the support matrices and here only. This applies to the Snyk
Code scanner. Ways out: [use WSL 2](#wsl2) or [scan in the container image](#container-image).

### A scanner tool with no build for this platform {#scanner-no-build}

ASH downloads some scanner tools at a pinned version. When a tool has no build for the
platform ASH runs on, the notice names the tool, its version and the platform, and the
scanner is reported as missing. Several tools have no build for Windows on arm64, for
example. A copy of the tool that you put on the path, and that runs, raises nothing. Ways
out: [use WSL 2](#wsl2),
[scan in the container image](#container-image) or [use Linux or macOS](#linux-or-macos-host).
The [scanner reference](../reference/scanners.md) lists the scanners.

## Ways to a supported configuration {#ways-out}

Each way out has the sentence ASH uses for it. The commands live in the guides this page
links to, because ASH builds the command for your machine when it reports a configuration.

### Add polars' compatibility runtime {#polars-compat-runtime}

Add polars' compatibility runtime (its rtcompat extra) to ASH's environment, at the polars
version ASH uses.

On this machine. The extra adds the compatibility runtime next to the default one and
removes nothing, and polars loads the compatibility runtime first whenever it is installed.
It runs on processors the default runtime does not, and it is slower. It does not help a
processor below the compatibility runtime's own instruction set. ASH offers it only where
the environment is yours to change, which excludes Homebrew, Nix and the container image.
See the [polars installation guide](https://docs.pola.rs/user-guide/installation/).

### Use an arm64 build of Python {#native-arm64}

Install an arm64 build of Python and reinstall ASH with it, so nothing runs translated.

On this machine. This is offered when the run is translated, by Rosetta 2 on a Mac or by
Windows emulation on an arm64 PC. The [install page](install.md) covers installing ASH, and
uv and pipx can fetch a matching Python for you.

### Use a processor with the instruction set polars needs {#x86-host-with-features}

Run ASH on an x86-64 processor with the instruction set polars is built for (AVX2 and its
companions).

Elsewhere.

### Use an arm64 machine {#arm64-host}

Run ASH on an arm64 machine: Linux on arm64 or a Mac with Apple silicon.

Elsewhere.

### Scan in CI {#ci-runner}

Run the scan in CI on a hosted runner; ASH's reusable GitHub workflow runs on ubuntu-latest
by default.

Elsewhere. See [GitHub Actions](ci/github-actions.md).

### Use a supported Python {#supported-python}

Reinstall ASH on a Python inside the range it declares, for example 3.12.

On this machine. The [install page](install.md) states the range.

### Scan in the container image {#container-image}

Scan in ASH's Linux container image (container mode); it needs Docker, Finch, Podman or
nerdctl.

On this machine. The scanners then run in Linux, whatever the host is. The image runs on
this machine's processor, so it is not a way out of a missing instruction set. See
[Run ASH in a container](run-in-a-container.md), and
[Windows and macOS](run-in-a-container.md#platforms) for those hosts.

### Use WSL 2 {#wsl2}

Install ASH inside WSL 2 on this Windows machine and scan from there.

On this machine, and offered from Windows only. Inside the WSL 2 distribution, install ASH
as on any Linux machine; see the [install page](install.md).

### Use WSL 2 with the sandbox {#wsl2-sandboxed}

Install ASH inside WSL 2 and scan there in local mode with the bwrap sandbox.

On this machine, and offered from Windows only.

### Use Linux or macOS {#linux-or-macos-host}

Run ASH on Linux or macOS.

Elsewhere, and offered from Windows and other operating systems. See the
[install page](install.md).

### Use a machine where a sandbox backend works {#sandbox-capable-host}

Run ASH on a machine where a sandbox backend works: Linux that allows unprivileged user
namespaces, or macOS.

Elsewhere.

### Scan in local mode with a sandbox {#mode-local-sandboxed}

Scan in local mode with a working sandbox backend, so each scanner is sandboxed.

On this machine, on Linux or macOS. See the scanner sandbox section of
[Run ASH in a container](run-in-a-container.md#sandbox).

### Install bubblewrap {#install-bubblewrap}

Install bubblewrap and allow unprivileged user namespaces, or use the firejail or landlock
backend.

On this machine, on Linux.

### Use a kernel with Landlock ABI 6 {#newer-kernel-landlock}

Use a Linux kernel whose Landlock ABI is 6 or later, or the bwrap backend.

On this machine, on Linux.

### Use a newer bubblewrap {#newer-bubblewrap}

Use bubblewrap 0.8 or later on Linux 5.11 or later.

On this machine, on Linux.

### Enable Landlock {#enable-landlock}

Use a Linux kernel with Landlock enabled (add landlock to the lsm= kernel parameter), which
GuardDog's own sandbox needs.

On this machine, on Linux.

### Run the wrapper from PowerShell 7 {#pwsh7}

Run the wrapper from PowerShell 7.3 or later (pwsh).

On this machine. This is offered when the wrapper runs under PowerShell 5.1 or in a POSIX
shell on Windows. The PowerShell that ships with Windows is version 5.1, and pwsh is
PowerShell 7.

### Use local mode {#mode-local}

Scan in local mode on this machine.

On this machine. This is offered when Nix mode was asked for.

### Use an image for this machine's architecture {#native-image}

Build the image for this machine's architecture, which ASH's image build does by default,
and scan with it.

On this machine. This is offered in container mode.
