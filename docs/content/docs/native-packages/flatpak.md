# Installing the Flatpak (Linux)

The Flatpak app id is `io.github.awslabs.automated_security_helper`. It is not on Flathub, so you build the bundle from a checkout and install the file. See [Publication status](index.md#publication-status).

Read [The sandbox trade](#the-sandbox-trade) before choosing the Flatpak over a pip install: the app needs `--filesystem=host`, which gives up most of the file system confinement a Flatpak would otherwise provide.

## Build the bundle

You need `flatpak`, `flatpak-builder`, `uv`, and the `org.freedesktop.Sdk//24.08` runtime, which also has to be present on any machine you install the bundle on:

```bash
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install flathub org.freedesktop.Sdk//24.08

uv build --out-dir dist
./packaging/flatpak/build.sh dist/automated_security_helper-<version>-py3-none-any.whl out/
```

`build.sh` writes `out/ash-<version>-<arch>.flatpak`, where `<arch>` is what `flatpak --default-arch` prints, such as `x86_64`. `flatpak-builder` drives `bwrap`, which needs user namespaces; an ordinary Docker container does not allow them, so build on a host or in a privileged container.

## Install

```bash
flatpak install --bundle out/ash-<version>-<arch>.flatpak
```

## Run it

A Flatpak cannot put `ashx` on the host's `PATH`. The host-visible name is the app id, and `ashx` is the app's default command:

```bash
flatpak run io.github.awslabs.automated_security_helper --version
flatpak run io.github.awslabs.automated_security_helper scan --source-dir .
```

The other names are reachable inside the sandbox with `--command`: `ashx`, the deprecated `ashv3`, and `automated-security-helper`. The deprecated `ash` alias is not in the sandbox. For a short name on the host, define it yourself:

```bash
alias ashx='flatpak run io.github.awslabs.automated_security_helper'
```

The first run creates a virtualenv under `~/.var/app/io.github.awslabs.automated_security_helper/data/` and installs the bundled wheel into it, which needs a reachable Python index (see [Offline hosts](#offline-hosts)).

Install the scanners the same way:

```bash
flatpak run io.github.awslabs.automated_security_helper dependencies install
```

They go to `~/.ash/bin`. If your home directory is outside the paths the sandbox can see, such as `/root`, set `ASH_BIN_PATH` to a visible directory such as `/srv/ash-bin`.

## The sandbox trade

ASH reads whatever source tree you point it at and writes its report inside that tree. A Flatpak with no file system grant would install, run, see an empty directory where your code is, and report a clean scan with no findings. To avoid that, the manifest grants `--filesystem=host`. The app can then read and write your home directory, including SSH keys and cloud credentials, and every other project on the machine. What remains is process, IPC and network namespace separation, an immutable `/app`, and no display, audio or D-Bus access.

`--filesystem=host` does not cover `/tmp`, `/var` or `/root`. A source tree there scans as empty, without an error. Grant the path explicitly:

```bash
flatpak override --user --filesystem=/var/lib/jenkins io.github.awslabs.automated_security_helper
```

To narrow the grant to one tree instead:

```bash
flatpak override --user --nofilesystem=host --filesystem=~/src io.github.awslabs.automated_security_helper
flatpak info --show-permissions io.github.awslabs.automated_security_helper
```

Container mode (`--mode container`) and Nix mode do not work inside the Flatpak, because the sandbox cannot see a container runtime or `nix` on the host. Local mode, the default, is what the package is tested in.

## Upgrade

Remove the installed app with a plain `flatpak uninstall io.github.awslabs.automated_security_helper`, which keeps its data, then install the newer bundle as above. Each wheel gets its own virtualenv, so an upgrade never runs the old ASH. The old virtualenv stays on disk until you delete it from `~/.var/app/io.github.awslabs.automated_security_helper/data/`.

## Uninstall

```bash
flatpak uninstall --delete-data io.github.awslabs.automated_security_helper
```

Without `--delete-data`, the virtualenv and anything else the app wrote under `~/.var/app/io.github.awslabs.automated_security_helper` stay. If you already uninstalled without it, delete that directory directly. Scanner binaries under `~/.ash/bin` are not removed.

## Offline hosts

Stage a wheelhouse in a directory the sandbox can see, such as `/srv`. Resolve it from ASH's own wheel, on a machine that can reach an index. Do not run `pip download automated-security-helper`: that name on PyPI belongs to an unrelated third party, not to this project.

```bash
pip download ./automated_security_helper-<version>-py3-none-any.whl -d /srv/ash-wheels

PIP_NO_INDEX=1 PIP_FIND_LINKS=/srv/ash-wheels \
  flatpak run io.github.awslabs.automated_security_helper --version
```

A host `/etc/pip.conf` is invisible inside the sandbox. For a persistent setting, write `~/.var/app/io.github.awslabs.automated_security_helper/config/pip/pip.conf`.
