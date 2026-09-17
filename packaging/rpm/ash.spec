#
# ASH's rpm. Built by packaging/rpm/build.sh, which passes ash_version and ash_wheel;
# this spec does not derive either one itself.
#
# Unlike debian/control.in, an rpm spec accepts '#' comments, so the reasoning that the
# .deb had to displace into packaging/deb/build.sh lines 53-72 lives here instead.
#
# The install shape is the .deb's, deliberately, and packaging/README.md documents it as
# common to both: exactly one wheel under /usr/lib/ash/wheels, a venv built on the target
# by %%post rather than shipped, and a wrapper at /usr/bin/ash. A bug in one package is a
# bug in the other, which is only true while the two stay the same shape.
#
# Section names are written %%post and %%postun throughout the prose below. A bare %post
# mid-sentence is a macro rpm tries to expand, and %% is the spec file's escape for a
# literal percent.

# build.sh is the only supported entry point, so fail here with a message that names it
# rather than letting rpmbuild report an empty Version or a Source0 of ".whl".
%{!?ash_version:%{error:ash_version is not defined. Build with packaging/rpm/build.sh <wheel> <outdir>, which reads the version from the wheel filename.}}
%{!?ash_wheel:%{error:ash_wheel is not defined. Build with packaging/rpm/build.sh <wheel> <outdir>, which reads the wheel basename from its argument.}}

Name:           ash
Version:        %{ash_version}
Release:        1%{?dist}
Summary:        Automated Security Helper (ASH) security scan orchestrator

License:        Apache-2.0
URL:            https://github.com/awslabs/automated-security-helper

# Source0 is the wheel build.sh was handed, by basename. It is not fetched or rebuilt
# here: a packaging step that also builds its own payload can ship a different wheel than
# the one the contents gate approved.
Source0:        %{ash_wheel}
# The wrapper's failure message points users at this file, so it has to be in the package.
# An error message citing a path the package never installed is worse than no message.
Source1:        README.rpm

# The wheel is py3-none-any and carries no compiled extension. Dependencies that do build
# native code are resolved by pip on the target at %%post time, so they match the target's
# architecture rather than the builder's.
BuildArch:      noarch

# THIS IS THE LINE THAT BROKE THE FIRST CI RUN. `Requires: python3 >= 3.10` is
# unsatisfiable on the target: Amazon Linux 2023's python3 is 3.9, and dnf reports
#   "python3 >= 3.10 is needed by ash"
# rather than offering to install a newer interpreter. The same holds on RHEL 9.
#
# On both distributions the newer interpreters are separate, independently installable
# packages named for their minor version, and there is no python3.10 package on either.
# ASH's floor is >=3.10, so naming the three that exist and satisfy it is both the
# dependency and the floor check -- there is no arm of this expression that is too old.
#
# A boolean (rich) dependency needs rpm >= 4.13. Amazon Linux 2023 ships rpm 4.16 and
# RHEL 9 ships 4.16, so the expression is understood on both.
#
# Plain Requires rather than Requires(post): rpm orders a transaction so that a package's
# requirements are installed before its scriptlets run, which is what lets %%post below
# call the interpreter.
Requires:       (python3.11 or python3.12 or python3.13)
# pip talks to a Python index over TLS during %post. Amazon Linux 2023 happens to ship
# this in its base image; naming it keeps the package honest on an image that does not.
Requires:       ca-certificates

# rpm has no mandatory maintainer field, unlike a Debian control file, so there is none
# here. The .deb had to invent one and used the owning org's GitHub noreply address; this
# spec simply omits Packager rather than putting a personal address in a published
# artifact.

%description
ASH runs a suite of security scanners over a source tree and aggregates their findings
into a single report, in SARIF and several other formats.

This package installs ASH itself. It does not bundle any scanner: the scanners ASH drives
are third-party tools, and shipping their source inside this package is forbidden by the
project's artifact-contents rule. Install them with "ash dependencies install", optionally
selecting individual tools with --tool.

The post-install scriptlet needs a reachable Python package index to resolve ASH's runtime
dependencies. On a host with no index, stage a wheelhouse first; see
%{_docdir}/%{name}/README.rpm for why the package cannot carry them and for the exact
commands.

%prep
# Nothing to unpack. The payload is a wheel that ships as-is, and %%install reads both
# sources straight out of SOURCES.

%build
# Nothing to compile. The wheel was built upstream of this spec, on purpose.

%install
# /usr/lib, spelled out rather than %{_libdir}. On x86_64 %{_libdir} is /usr/lib64, and
# the path packaging/README.md documents -- and that the .deb, the wrapper below, and
# packaging/rpm/verify-in-container.sh all hardcode -- is /usr/lib/ash.
install -d -m 0755 %{buildroot}%{_prefix}/lib/%{name}/wheels
install -m 0644 %{SOURCE0} %{buildroot}%{_prefix}/lib/%{name}/wheels/

install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 %{SOURCE1} %{buildroot}%{_docdir}/%{name}/README.rpm

# A wrapper, not a symlink into the venv. `ash` shells out to sys.executable for the
# container runner, and a symlink leaves sys.executable pointing at /usr/bin/ash.
install -d -m 0755 %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/ash <<'WRAPPER'
#!/bin/sh
# Installed by the ash .rpm. The venv is created by the package's post-install
# scriptlet, not shipped inside it, so this is also the check for a half-completed
# install.
if [ ! -x /usr/lib/ash/venv/bin/ash ]; then
  echo "ash: /usr/lib/ash/venv is missing or incomplete." >&2
  echo "ash: reinstall the package: dnf reinstall ash" >&2
  exit 127
fi
# The .deb needs no equivalent of this second check, because it depends on one python3
# package. This package depends on (python3.11 or python3.12 or python3.13), so rpm still
# considers the dependency satisfied after the particular interpreter the venv was built
# against is removed -- leaving venv/bin/ash present but unable to start.
if [ ! -x /usr/lib/ash/venv/bin/python3 ]; then
  echo "ash: /usr/lib/ash/venv's interpreter is gone." >&2
  echo "ash: the Python it was built against was removed. Run: dnf reinstall ash" >&2
  exit 127
fi
exec /usr/lib/ash/venv/bin/ash "$@"
WRAPPER
chmod 0755 %{buildroot}%{_bindir}/ash

%files
%doc %{_docdir}/%{name}/README.rpm
%dir %{_docdir}/%{name}
%dir %{_prefix}/lib/%{name}
%dir %{_prefix}/lib/%{name}/wheels
%{_prefix}/lib/%{name}/wheels/%{ash_wheel}
%{_bindir}/ash

# Creates the venv and installs ASH's wheel into it.
#
# Deliberately NOT `set -e`: a bare failure here leaves the package "installed" with a
# broken venv and no explanation. Each step is checked and reported instead, so the
# failure names what to do about it. This mirrors packaging/deb/debian/postinst.
%post
set -u

VENV=/usr/lib/ash/venv
WHEELS=/usr/lib/ash/wheels
DOC=%{_docdir}/%{name}/README.rpm

# Remove any venv from a previous version before rebuilding. An in-place
# `pip install --upgrade` into an existing venv leaves the old distribution's entry points
# behind when a release renames one, and ASH ships three.
rm -rf "$VENV"

# Requires guarantees one of these is present but not which one, and rpm gives a scriptlet
# no way to ask which arm of a boolean was satisfied. So probe, newest first.
#
# The probe is `import ensurepip`, not `command -v`, because that is what decides whether
# `python3.N -m venv` can produce a pip inside the venv. An interpreter present without it
# would create a venv that cannot install the wheel, and the failure would surface one step
# later as a pip error rather than here as a missing prerequisite.
PY=
for CAND in python3.13 python3.12 python3.11; do
  if command -v "$CAND" >/dev/null 2>&1 && "$CAND" -c 'import ensurepip' >/dev/null 2>&1; then
    PY="$CAND"
    break
  fi
done

if [ -z "$PY" ]; then
  echo "ash: found no Python that can create a virtualenv." >&2
  echo "ash: this package requires one of python3.11, python3.12 or python3.13." >&2
  echo "ash: install one, then run: dnf reinstall ash" >&2
  exit 1
fi

if ! "$PY" -m venv "$VENV"; then
  echo "ash: failed to create a virtualenv at $VENV with $PY." >&2
  echo "ash: check that $VENV is writable and not on a noexec mount." >&2
  exit 1
fi

# A shell glob, not `find`. findutils is not in the amazonlinux:2023 base image --
# packaging/rpm/verify-in-container.sh installs it for build.sh's own use -- and this
# scriptlet runs on hosts that never installed it.
WHEEL=
for W in "$WHEELS"/*.whl; do
  if [ -f "$W" ]; then
    WHEEL="$W"
    break
  fi
done

if [ -z "$WHEEL" ]; then
  echo "ash: no wheel found under $WHEELS -- the package is malformed." >&2
  exit 1
fi

# The wheel is installed from the local path; its DEPENDENCIES come from the index. That
# split is the whole reason this package is not self-contained, and it is documented in
# README.rpm.
if ! "$VENV/bin/pip" install --quiet --disable-pip-version-check "$WHEEL"; then
  echo "ash: failed to install $WHEEL into $VENV." >&2
  echo "ash: this step needs a reachable Python package index to resolve ASH's runtime" >&2
  echo "ash: dependencies. See $DOC." >&2
  exit 1
fi

# Assert the entry point exists rather than trusting pip's exit code. A wheel can install
# cleanly and still not produce a console script if its metadata is wrong, and the wrapper
# in /usr/bin/ash would then fail for every user.
if [ ! -x "$VENV/bin/ash" ]; then
  echo "ash: $WHEEL installed but produced no 'ash' entry point." >&2
  exit 1
fi

exit 0

# Drops the venv on erase.
#
# rpm tracks only files shipped in the package, and the venv was written by %%post, so
# without this the package "removes" and leaves a few thousand files behind.
%postun
set -u

# $1 is the number of instances of this package left after the transaction: 0 on erase, 1
# on an upgrade or a reinstall. rpm runs the OLD package's %%postun AFTER the new one's
# %%post, so a %%postun that removed the venv unconditionally would delete the venv the
# new version had just built and break every upgrade. Guarding on 0 is what makes step 8
# of packaging/rpm/verify-in-container.sh pass.
if [ "$1" -eq 0 ]; then
  rm -rf /usr/lib/ash/venv
  # rpm removed its own files before this ran, but could not rmdir /usr/lib/ash while the
  # unowned venv was still inside it. Now that the venv is gone, take the empty parent.
  rmdir /usr/lib/ash 2>/dev/null || true
fi

exit 0

%changelog
# Intentionally empty. Releases are cut by the project's release workflow from git tags
# and CHANGELOG.md; a changelog maintained here as well would be a second place to forget.
