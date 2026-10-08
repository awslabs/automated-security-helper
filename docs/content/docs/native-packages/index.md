# Native Packages

ASH builds four OS-native packages besides the wheel: an MSIX for Windows, a Chocolatey package, a winget manifest set that installs the MSIX, and a Flatpak for Linux. CI builds, installs, scans with, upgrades and uninstalls each one on every pull request that touches packaging (`.github/workflows/ash-package.yml`).

## Publication status

None of these packages is published to a public feed. Nothing in this repository submits to the Microsoft Store, `microsoft/winget-pkgs`, `community.chocolatey.org` or Flathub, and a GitHub release attaches only the wheel, the sdist and the MCPB bundle. So `winget install ash`, `choco install ash` without a `--source`, and `flatpak install flathub ...` for ASH do not work, and these pages do not tell you to run them.

To use a native package today you build it from a checkout, or for the MSIX, download the one a CI run built. Each page below gives the steps.

| Package | Identifier | File it produces | Page |
|---|---|---|---|
| MSIX | Identity name `AWSLabs.AutomatedSecurityHelper` | `automated-security-helper-<version>.msix` | [MSIX](msix.md) |
| winget | `Amazon.AutomatedSecurityHelper`, moniker `ash` | a manifest set that installs the MSIX | [winget](winget.md) |
| Chocolatey | package id `ash` | `ash.<version>.nupkg` | [Chocolatey](chocolatey.md) |
| Flatpak | app id `io.github.awslabs.automated_security_helper` | `ash-<version>-<arch>.flatpak` | [Flatpak](flatpak.md) |

## The command is `ashx`

Every native package puts `ashx` on your `PATH` (the Flatpak runs it inside its sandbox; see that page). Two other names come with it:

- `ashv3` is deprecated. It prints one warning on stderr and then runs the same command.
- `automated-security-helper` is kept indefinitely and is silent. Use it on a host where another program claims a short name.

`ash`, the v3 command, is a deprecated alias that only pip-based installs, Homebrew and the container image still provide. No native package installs it, because `ash` is the Almquist shell on MSYS2, Git for Windows, Alpine and BusyBox, and on Windows that shell has already shadowed ASH's entry point and failed with `Illegal option --`. If your scripts call `ash`, change them to `ashx`. Arguments, output and exit codes are the same.

`-V` is `--version` and `-v` is `--verbose`.

## What every native package has in common

Each package bundles ASH's own wheel and nothing else. On first use (Chocolatey: at install time) it creates a virtualenv and installs that wheel into it, which resolves ASH's runtime dependencies from whatever Python index the machine is configured for. You therefore need a reachable Python index, or a staged wheelhouse; each page shows how to stage one.

None of the packages contains a scanner. After installing, provision the scanners ASH can install itself:

```
ashx dependencies install
```

`detect-secrets` is a runtime dependency and works immediately. Scanners that are not installed are reported as `SKIPPED`.

The packaging sources, with the full reasoning behind each decision, are under [`packaging/`](https://github.com/awslabs/automated-security-helper/tree/main/packaging) in the repository.
