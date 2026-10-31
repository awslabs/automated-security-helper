# Install ASH

ASH is a Python command-line tool that you install from its GitHub repository. It is
not published on PyPI. The PyPI project named `automated-security-helper` is not
published by this project, so installing or running ASH by that name from PyPI gets that
project's package, not ASH. Always install from the GitHub URL, as on this page.

Installing ASH gives you the `ash` command. The scanners it runs are separate tools:
after installing, run `ash dependencies install`, described in
[Manage scanner tools](../docs/advanced-usage.md).

## Requirements

- Python 3.10 to 3.14. uv and pipx can fetch a matching Python for you.
- git, which the installer uses to fetch the repository.
- Linux (x86-64 or arm64), macOS, or Windows (x86-64). CI installs ASH with pip and
  pipx on Python 3.10 to 3.14 and with uvx on 3.12, on Ubuntu (x86-64 and arm64),
  macOS on Apple silicon, and Windows. Intel Macs and Windows on arm64 are not tested.

Some scanner tools are not available on every platform: see
[Platform limits](../docs/advanced-usage.md#platform-limits).

Always pass a Python version to uv and pipx, as the commands below do. The v3.7.x
releases accept any Python 3 version from 3.10 up, so on a machine with no suitable
Python, uv picks the newest release, 3.15, and the install fails while building a
dependency that does not support 3.15.

Every install on this page includes the `cdk` extra, which the cdk-nag scanner needs.
Without it, cdk-nag shows as MISSING in a project with CloudFormation templates, and the
scan exits 1. See [Extras](#extras).

## Choose an install method

| Method | Use it when | Status |
|---|---|---|
| [`uv tool install`](#install-with-uv) | you want `ash` on your `PATH` in its own environment | recommended |
| [`uvx`](#run-without-installing-uvx) | you want to run ASH without installing it | supported |
| [`pipx`](#install-with-pipx) | you already use pipx | supported |
| [`pip` in a virtual environment](#install-with-pip) | you manage Python environments yourself | supported |
| [Container image](#container-image) | you want every scanner without installing them | build it yourself |
| [Nix mode](#nix-mode) | you use Nix | not in any release; install from `main` or use a source checkout |
| [Homebrew](#homebrew) | you install your tools with Homebrew, on macOS or Linux | supported |
| pre-commit | you want a scan on every commit | see [Run ASH with pre-commit](pre-commit.md) |
| From a clone | you are changing ASH | see [Contribute to ASH](../contributing/index.md) |

## Install with uv

Install [uv](https://docs.astral.sh/uv/getting-started/installation/):

=== "Linux and macOS"

    The installer needs curl:

    <!-- doctest: illustrative reason="downloads and runs the uv installer from the network" -->
    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```

=== "Windows"

    In PowerShell:

    <!-- doctest: illustrative reason="Windows only; downloads and runs the uv installer from the network" -->
    ```powershell
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```

Open a new terminal so that uv's directory is on your `PATH`, then install ASH. The
command is the same in a POSIX shell and in PowerShell:

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
uv tool install --python 3.12 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1'
ash --version
```

```text
awslabs/automated-security-helper v3.7.1
```

The install provides three names for the same program: `ash`, `ashv3`, and
`automated-security-helper`. On Windows, Git Bash and MSYS2 ship an unrelated shell
named `ash` that can come first on your `PATH`. Use `ashv3` there.

To move to another version, run the same command with the new tag and add `--force`.

## Run without installing: uvx

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
uvx --python 3.12 --from 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1' ash --version
```

uvx builds the environment once and reuses it, so later runs start quickly. Every
command needs the full `uvx --from` specification, so you may want a shell alias:

```bash
alias ash="uvx --python 3.12 --from 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1' ash"
```

## Install with pipx

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
pipx install --python python3.12 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1'
```

Install pipx itself from your package manager, for example `apt install pipx` on
Ubuntu, or with `uv tool install pipx`. On systems whose Python is marked as
externally managed, such as Ubuntu 24.04, pip refuses to install pipx outside a
virtual environment. pipx needs the named Python on your `PATH`.

ASH installs bandit, checkov, and semgrep with uv. It uses the `uv`
that pipx installs into ASH's environment, so a pipx install needs no separate uv.

## Install with pip

Create a virtual environment outside the projects you will scan, activate it, and
install into it. Use any Python 3.10 to 3.14 in place of 3.12. On systems whose Python
is marked as externally managed, such as Ubuntu 24.04, pip installs only into a
virtual environment.

=== "Linux and macOS"

    <!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
    ```bash
    python3.12 -m venv ~/.venvs/ash
    . ~/.venvs/ash/bin/activate
    pip install 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1'
    ash --version
    ```

=== "Windows"

    In PowerShell:

    <!-- doctest: illustrative reason="Windows only; installs ASH from GitHub over the network" -->
    ```powershell
    py -3.12 -m venv $HOME\.venvs\ash
    & $HOME\.venvs\ash\Scripts\Activate.ps1
    pip install 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@v3.7.1'
    ash --version
    ```

Activate the environment in each new shell before you run `ash`, or run the
environment's `ash` by its path. Either way, ASH installs bandit, checkov, and
semgrep with the environment's own `uv`.

Keep the environment outside the scanned directory. During a scan ASH does not run
tools that it finds inside the directory it is scanning, so scanners installed into a
virtual environment inside the project show as MISSING. See
[Tools inside the scanned directory](../docs/advanced-usage.md#tools-inside-the-scanned-directory).

## Extras

| Extra | Adds | Needed for |
|---|---|---|
| `cdk` | `aws-cdk-lib`, `cdk-nag`, `constructs` | the cdk-nag scanner, which also needs Node.js |
| `symbols` | tree-sitter grammars for Python, JavaScript, TypeScript, and Java | `symbol` in suppressions; see [Suppress findings](suppress-findings.md) |

To install an extra from git, use the direct-reference form `name[extra] @ URL`, as
the commands on this page do. List several extras with commas, as in
`[cdk,symbols]`.

You can also add the cdk packages later: `ash dependencies install --tool cdk-nag`
installs them into ASH's environment, whichever way you installed ASH. A later
`uv tool upgrade` or `uv tool install --force` rebuilds a uv tool environment without
them, so installing the extra with ASH is simpler.

The `symbols` extra is in `main` and not in releases up to 3.7.x. Its tree-sitter
packages publish no wheels for Linux on arm64 with musl (Alpine), so on that platform
the install needs a C compiler.

## Choose a version to pin

| Reference | What you get |
|---|---|
| `@v3.7.1` | That release. The release process creates each version tag once and moves only the `v3` tag. |
| a full commit SHA | That commit. The only reference that cannot change. |
| `@v3` | The latest 3.x release. It moves with each release. |
| `@main` | The current development state. |

Release tags are lightweight and unsigned, and releases have no signed artifacts. If
you need a reference that cannot change, pin a commit SHA.

The `v3` tag moves to each new 3.x release, and a release is not always made from
`main`: v3.7.1 is a backport made on a separate branch, outside `main`'s history. While
`v3` points at a release like that, it lacks features of `main` that these docs
describe. A 3.x release can also include breaking changes, so read the release notes
before upgrading a `v3` or `<4` pin.

### Install from main

To use a feature that is on `main` before a release includes it, install from `main`:

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
uv tool install --python 3.12 'automated-security-helper[cdk] @ git+https://github.com/awslabs/automated-security-helper.git@main'
```

`main` reports the same version number as the latest release until the next release
is made, so `ash --version` does not tell the two apart. Pin a commit SHA instead of
`@main` when you need to know which code you ran.

## Container image

No ASH image is published. `ash --mode container` builds an image with every scanner
on your machine and scans inside it; it rebuilds the image on every run unless you
pass `--no-build`. `ash build-image` builds one to push to your own registry. See
[Run ASH in a container](run-in-a-container.md).

## Nix mode

`ash --mode nix` runs the scan inside a Nix shell whose scanner tools come from
ASH's `flake.nix`. It needs Nix with flakes enabled, on Linux or macOS (on Windows,
inside WSL2). It does not install ASH itself: the scan inside the shell runs the same
ASH you started, so install ASH with one of the methods above first.

The Nix shell supplies the tools of every built-in scanner except cdk-nag, which runs on
the Python environment ASH is installed in, so install ASH with the `cdk` extra for it.
It does not supply ferret-scan or the Snyk CLI, which two community plugins run.

The scan inside the shell gets your environment, so it reads the file `ASH_CONFIG` names
first, as a local scan does, and then the file `--config` names. With no `--config`, the
file `ASH_CONFIG` names is the config too, and with neither, the scan uses the config file
it discovers.
In a scan of one directory, ASH resolves that config on the host before the shell starts.
A file that is missing, cannot be read, does not parse, or is not a valid config stops the
scan with exit code 3 before the previous run's output is cleared, and that includes the
file `ASH_CONFIG` names when `--config` names a valid one.

Nix mode is not in any release: v3.7.x rejects `--mode nix`. Use it from a source
checkout or from an install of `main`:

- From a source checkout, ASH uses that checkout's `flake.nix`.
- An install of `main` looks for the flake at the release tag that matches its version
  number. Until a release contains `flake.nix`, that fails with an error saying
  `flake.nix` does not exist. Set `ASH_NIX_FLAKE_REF` to a flake reference that has
  it: a checkout, written `path:` followed by its absolute path, or a branch or commit,
  such as `github:awslabs/automated-security-helper/main`.

## Homebrew

The repository is a Homebrew tap: its formula is `Formula/ash.rb`. Add the tap and
install the formula by its full name:

<!-- doctest: illustrative reason="installs ASH with Homebrew over the network" -->
```bash
brew tap awslabs/automated-security-helper https://github.com/awslabs/automated-security-helper.git
brew install awslabs/automated-security-helper/ash
ash --version
```

Naming the formula in full installs it from a tap you have not trusted, and Homebrew
trusts that one formula as it installs it. To install it by its short name,
`brew install ash`, first run `brew trust awslabs/automated-security-helper`: Homebrew
refuses to load a formula by its short name from a tap you have not trusted. A Homebrew
release without `brew trust` has no such check.

The formula installs the release named on its `url` line, which is the latest release;
it cannot install `main`. It builds ASH on Homebrew's Python 3.12, with the `cdk` extra,
and installs the dependency versions locked in that release's `uv.lock`, each checked
against the sha256 the lock records. ASH's own build requirements, hatchling and the
packages it needs, are resolved from PyPI by version range and are not checked against
a hash. The formula downloads all of them during the install, so the install needs
network access, and building with `HOMEBREW_FORMULA_BUILD_NETWORK=deny` is not
supported. The formula also installs
Node.js, which cdk-nag and npm-audit run on; a `node` already on your `PATH` comes
first. It does not install the scanners that are separate programs, such as grype,
syft, opengrep, and cfn-nag, so run `ash dependencies install` as with the other
methods.

In container mode, a Homebrew install builds its image from the commit the formula
built. When Homebrew built ASH from a source tarball with no git metadata, it builds the
release tag of ASH's version instead and logs a warning that this is a guess.

CI installs the formula, built from the commit under test, with Homebrew on Ubuntu
(x86-64) and on macOS on Apple silicon, then runs `brew test` and scans with the
installed `ash`. Homebrew is not available on Windows, and Linux on arm64 is not tested.

## Uninstall

Remove ASH with the tool that installed it:

<!-- doctest: illustrative reason="removes software from the reader's machine" -->
```bash
uv tool uninstall automated-security-helper
pipx uninstall automated-security-helper
brew uninstall ash
```

For a pip install, delete the virtual environment. After `brew uninstall`, remove the tap
with `brew untap awslabs/automated-security-helper`.

The scanner tools and data that ASH installed stay behind. To remove them too:

- `~/.ash/`, which holds the binaries from `ash dependencies install`, their install
  records, and the cfn-guard rules. If you installed with `--bin-path` or
  `ASH_BIN_PATH`, the binaries are in that directory instead, and the cfn-guard rules
  are in `share/cfn-guard-rules` next to it.
- The scanners installed as uv tools. Name the ones `uv tool list` shows, because
  `uv tool uninstall` fails for a name that is not installed:
  `uv tool uninstall bandit checkov semgrep nbconvert`. Earlier ASH releases also
  installed `cfn-lint` and `zizmor` as uv tools, so add whichever of them
  `uv tool list` still shows.
- The cfn-nag gem: `gem uninstall cfn-nag`. The gems it depends on stay installed.
- The scanners' own caches, such as `~/.cache/grype` and `~/.cache/trivy`.
- The `.ash/ash_output/` directory that each scan writes in the project it scanned.
