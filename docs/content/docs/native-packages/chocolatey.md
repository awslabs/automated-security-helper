# Installing with Chocolatey (Windows)

The Chocolatey package id is `ash`. That is what you pass to `choco`; the command it installs is `ashx`. The package is not on `community.chocolatey.org`, so you install it from a directory holding a `.nupkg`, one you downloaded from a GitHub release or built. See [Publication status](index.md#publication-status).

## Prerequisites

- Chocolatey, and an elevated shell. The install writes under `%ProgramData%` and creates shims in the Chocolatey `bin` directory.
- Python 3.10 to 3.13. The package declares `python3` in the range `[3.10,3.14)`, so Chocolatey installs one from the community feed if none is present. The install script then probes `py -3.13`, `-3.12`, `-3.11` and `-3.10` before falling back to `python` and `python3`, and uses the first in range.
- A reachable Python index at install time, or a staged wheelhouse (see [Offline machines](#offline-machines)).

## Build the package

A GitHub release attaches `ash.<version>.nupkg`; to use that one, put it in a directory such as `C:\ash-pkg` and go to [Install](#install):

```powershell
gh release download v<version> --repo awslabs/automated-security-helper --pattern '*.nupkg' --dir C:\ash-pkg
```

To build it instead, from a checkout, with `uv` and Chocolatey installed:

```powershell
uv build --out-dir dist
pwsh -File packaging/chocolatey/build.ps1 dist\automated_security_helper-<version>-py3-none-any.whl C:\ash-pkg
```

`build.ps1` writes `C:\ash-pkg\ash.<version>.nupkg` and prints its path. It refuses to pack when the version in `ash.nuspec` disagrees with the wheel's.

## Install

Name both your package directory and the community feed as sources. The community feed is only there to satisfy the `python3` dependency:

```powershell
choco install ash --source "C:\ash-pkg;https://community.chocolatey.org/api/v2/"
```

The install script creates a virtualenv in `%ProgramData%\ash\venv`, installs the bundled wheel into it, and shims three commands:

- `ashx`, the one to use
- `ashv3`, deprecated, which warns once on stderr
- `automated-security-helper`, kept indefinitely and silent

It does not shim `ash`. MSYS2 and Git for Windows ship the Almquist shell as `ash.exe`, and when that is earlier on `PATH` a bare `ash` reaches the shell instead of ASH.

## Run it

```powershell
ashx --version
ashx dependencies install
ashx scan --source-dir C:\path\to\repo
```

## Upgrade

Build the newer package into the same directory, then:

```powershell
choco upgrade ash --source "C:\ash-pkg;https://community.chocolatey.org/api/v2/"
```

An upgrade builds a new virtualenv rather than patching the old one.

## Uninstall

```powershell
choco uninstall ash
```

This removes the shims and the virtualenv in `%ProgramData%\ash`, since Chocolatey does not track files the install script wrote. Scanner binaries that `ashx dependencies install` put under `~\.ash\bin` stay.

## Offline machines

Stage a wheelhouse before `choco install`, as Administrator. Resolve it from ASH's own wheel, on a machine that can reach an index. Do not run `pip download automated-security-helper`: that name on PyPI belongs to an unrelated third party, not to this project.

```bat
pip download .\automated_security_helper-<version>-py3-none-any.whl -d C:\ash-wheels
mkdir %ProgramData%\pip
> %ProgramData%\pip\pip.ini echo [global]
>>%ProgramData%\pip\pip.ini echo no-index = true
>>%ProgramData%\pip\pip.ini echo find-links = C:\ash-wheels
```

The `python3` dependency still has to come from somewhere. On a machine with no route to the community feed, install Python 3.10 to 3.13 first and pass `--ignore-dependencies`.
