#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Installs nerdctl on Ubuntu Linux for CI environments.
#
# nerdctl is one of the four runners in _OCI_RUNNER_CANDIDATES
# (automated_security_helper/interactions/run_ash_container.py) and had no CI
# coverage at all, so this exists to give it some.
#
# WHY THE `nerdctl-full` BUNDLE RATHER THAN THE CLI ALONE
#
# The hosted runners already run the containerd that ships with Docker, so a
# CLI-only install would appear to be enough. It is not: `nerdctl build` needs
# buildkitd listening on a socket, which no runner image provides, so buildkit
# would have to be installed and version-matched separately. The `nerdctl-full`
# bundle carries nerdctl, containerd, buildkitd, runc and the CNI plugins that
# were built and tested together, which removes the version-skew question
# entirely. It costs a larger download and buys one self-consistent toolchain.
#
# WHY THE VERSION AND THE CHECKSUM ARE BOTH PINNED
#
# A pinned version alone still trusts whatever bytes the URL serves. The
# checksum below was taken from the release's own SHA256SUMS and then confirmed
# against the downloaded artifact, so a re-cut release fails here loudly rather
# than silently changing the toolchain under the gate.
#
# Usage: sudo bash scripts/setup-nerdctl-linux.sh

set -euo pipefail

NERDCTL_VERSION="2.3.5"
# sha256 of nerdctl-full-2.3.5-linux-amd64.tar.gz, from the release SHA256SUMS.
NERDCTL_SHA256_AMD64="b697295c623639734aaab737523c808fd3cc8d3046039fd94fff1744e4c317aa"

# WHY NOT `dpkg --print-architecture`
#
# That was the original probe, and dpkg exists only on Debian derivatives. On any
# other host the shell reports "command not found" and exits 127 -- via the
# command substitution, so `set -e` never sees a failing simple command and the
# error text is the shell's, naming dpkg rather than saying this script needs a
# Debian derivative. uname is in POSIX and on every runner, and the bundle's own
# filenames use Debian's amd64/arm64 spelling, so the mapping is explicit here.
case "$(uname -m)" in
    x86_64 | amd64) ARCH="amd64" ;;
    aarch64 | arm64) ARCH="arm64" ;;
    *)
        echo "ERROR: unsupported machine type '$(uname -m)'." >&2
        echo "containerd/nerdctl publishes linux-amd64 and linux-arm64 bundles only." >&2
        exit 1
        ;;
esac

case "${ARCH}" in
    amd64) EXPECTED_SHA256="${NERDCTL_SHA256_AMD64}" ;;
    *)
        echo "ERROR: no pinned checksum for architecture '${ARCH}'." >&2
        echo "Only linux-amd64 is wired up here. containerd/nerdctl does publish a" >&2
        echo "linux-arm64 bundle, so extending this is a matter of pinning that" >&2
        echo "checksum beside the amd64 one and adding the matrix cell. Downloading" >&2
        echo "unverified bytes instead is not an acceptable substitute, so this" >&2
        echo "fails rather than falling back." >&2
        exit 1
        ;;
esac

TARBALL="nerdctl-full-${NERDCTL_VERSION}-linux-${ARCH}.tar.gz"
URL="https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/${TARBALL}"

# Docker's containerd is the same unit name this bundle installs, so leaving
# Docker running means two things contending for one socket. nerdctl is the
# runtime under test in this job; nothing here needs Docker.
#
# THIS IS ONE-WAY, AND THAT IS DELIBERATE
#
# Nothing below restarts Docker, and no trap restores it on failure. The intended
# caller is an ephemeral GitHub-hosted runner that is destroyed at the end of the
# job -- `sudo bash scripts/setup-nerdctl-linux.sh`, from the nerdctl leg of
# .github/actions/validate-container/action.yml -- so there is nothing to restore
# to. Restoring would also be wrong mid-script: the bundle's containerd unit
# shadows the distro one from /usr/local/lib/systemd/system (see the note further
# down), so a restarted Docker would be talking to a containerd it did not start.
#
# The consequence on a developer machine is that this script stops your Docker and
# leaves it stopped, which is why the reversal is printed rather than left to be
# discovered. Run this in a throwaway VM or container, not on a workstation.
echo "=== Stopping Docker so it does not contend for containerd ==="
echo "    (one-way: to undo, 'sudo systemctl start docker.socket docker.service'"
echo "     after 'sudo systemctl stop buildkit' and a 'systemctl daemon-reload')"
# The previous form was `systemctl stop docker.socket docker.service 2>/dev/null ||
# true`, which discarded the message and the status together. A runner image with no
# Docker is a fine place to install nerdctl, so absence must be tolerated -- but a
# unit that is running and REFUSES to stop means something still holds the containerd
# socket, and `ashx build-image` would then fail a long way from that cause. So the two
# cases are separated: absence is checked for, and a real failure to stop is left to
# `set -e`.
#
# `is-active` rather than `list-unit-files`: it answers the question that matters
# (is there something running to stop) in one call, reports a socket unit's
# `listening` state as active, and needs no pipeline -- a `| grep -q` here would be
# subject to `pipefail` and could kill the script over a missing unit.
for unit in docker.socket docker.service; do
    if systemctl is-active --quiet "${unit}"; then
        echo "  ${unit}: active, stopping"
        systemctl stop "${unit}"
    else
        echo "  ${unit}: not active, nothing to stop"
    fi
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

echo "=== Downloading ${TARBALL} ==="
curl -fsSL --retry 3 --retry-delay 5 -o "${WORKDIR}/${TARBALL}" "${URL}"

echo "=== Verifying checksum ==="
echo "${EXPECTED_SHA256}  ${WORKDIR}/${TARBALL}" | sha256sum -c -

echo "=== Installing into /usr/local ==="
tar -C /usr/local -xzf "${WORKDIR}/${TARBALL}"

# nerdctl looks for CNI plugins in /opt/cni/bin before the bundle's own
# /usr/local/libexec/cni on some paths, and a container that cannot get a
# network interface fails at run time rather than at install time. Publishing
# them in both places costs nothing and removes the ordering question.
#
# WHY THIS COPY IS NOT ALLOWED TO FAIL QUIETLY
#
# It used to read `cp -n /usr/local/libexec/cni/* /opt/cni/bin/ 2>/dev/null || true`,
# which threw away both halves of the answer. If the bundle ever relocates its CNI
# plugins -- nerdctl 2.x has moved paths before -- the glob matches nothing, bash
# passes the pattern through literally, cp fails with ENOENT, and `|| true` records
# that as success. Nothing else in this script reads /opt/cni/bin, so the first
# symptom is a container with no network interface, roughly forty-five minutes later,
# inside `ashx scan --mode container`.
#
# Two changes, because dropping `|| true` alone is not enough. `cp -n` exits 0 when it
# skips a file that already exists, so on a runner whose Docker install already
# populated /opt/cni/bin the copy can succeed having copied nothing -- which is fine,
# but means a zero status is not evidence the plugins are there. So the source
# directory is required to exist and be non-empty first, and the result is asserted by
# name afterwards.
echo "=== Publishing CNI plugins to /opt/cni/bin ==="
CNI_SRC="/usr/local/libexec/cni"
if [ ! -d "${CNI_SRC}" ]; then
    echo "ERROR: ${CNI_SRC} does not exist after unpacking the nerdctl-full bundle." >&2
    echo "The bundle is expected to ship the CNI plugins; if v${NERDCTL_VERSION} moved" >&2
    echo "them, update CNI_SRC here rather than letting the copy fail silently." >&2
    exit 1
fi
mkdir -p /opt/cni/bin
# Unquoted glob on purpose -- it must expand. `set -u` does not apply to globs, and
# the guard above plus the assertion below cover the empty-match case.
cp -n "${CNI_SRC}"/* /opt/cni/bin/

# `bridge` is the plugin nerdctl's default network actually loads, so its presence is
# the specific fact worth asserting rather than a file count.
if [ ! -x /opt/cni/bin/bridge ]; then
    echo "ERROR: /opt/cni/bin/bridge is missing or not executable after the copy." >&2
    echo "nerdctl's default network needs it, and a container without it fails at run" >&2
    echo "time with an unhelpful network error. Contents of both directories:" >&2
    ls -la "${CNI_SRC}" /opt/cni/bin >&2 || true
    exit 1
fi
echo "  /opt/cni/bin/bridge: present"

# POINT BUILDKITD AT CONTAINERD'S IMAGE STORE, BECAUSE BY DEFAULT IT HAS NONE
#
# Without this file `nerdctl build` cannot see ANY image in containerd's store at
# `FROM`, so a base image already pulled and tagged locally is invisible to the
# build and BuildKit goes to the registry for it. That is what made the base-image
# fallback in .github/actions/prepull-base-image inert on this leg: the pre-pull
# retagged a Docker Hub pull under the Dockerfile's ECR reference, the step exited
# 0, and the build then died at `FROM ${BASE_IMAGE}` still asking the registry
# that had just refused it.
#
# WHY NO-CONFIG BUILDKITD HAS NO IMAGE STORE
#
# buildkitd has two worker backends and, with no config file, decides on each
# INDEPENDENTLY -- both `--oci-worker` and `--containerd-worker` default to the
# string "auto", and there is no rule that enabling one disables the other.
# `newWorkerController` adds every worker that initialises. The OCI worker
# registers at priority 0 and the containerd worker at priority 1; the
# initialiser list is sorted by priority and buildkit's own comment on
# `workercontroller.Add` reads "The first worker becomes the default", with
# `GetDefault` returning index 0. buildkitd then logs, verbatim,
# `found %d workers, default=%q` followed by `currently, only the default worker
# can be used.` So the OCI worker wins whenever it initialises at all --
# `validOCIBinary()` is just `exec.LookPath("runc")`, and the nerdctl-full tarball
# unpacks a static runc into /usr/local/bin, so it always does.
#
# And the OCI worker is the one that cannot help: `worker/runc/runc.go` constructs
# it with `ImageStore: nil, // explicitly` -- upstream's own comment. There is no
# store to look in, so no containerd namespace setting can make the local tag
# visible while the OCI worker is the default. Disabling it is the first condition
# and matching the namespace is only the second; a reader who sees the namespace
# line alone will not understand why it was not enough on its own.
#
# WHY THIS EXACT SHAPE, AND WHY /etc/buildkit
#
# This is not a guess. It is the shape two independent projects arrived at for the
# same reason. nerdctl's own `Dockerfile.d/etc_buildkit_buildkitd.toml` disables
# the OCI worker and enables the containerd worker -- but that file is only copied
# into nerdctl's test image, downstream of the `out-full` stage, so nothing puts it
# in the tarball this script unpacks. And finch ships
# /etc/finch/buildkit/buildkitd.toml with the identical three settings, differing
# only in the namespace (`finch`, matching its own nerdctl.toml). The maintainers
# having to explicitly disable the OCI worker in both places is the corroboration:
# it would be pointless if a no-config buildkitd already used containerd's store.
#
# /etc/buildkit/buildkitd.toml is buildkitd's DEFAULT config path, so the unit the
# bundle ships picks this up with no unit change. That unit is generated by `sed`
# from containerd's, giving a flagless `ExecStart=/usr/local/bin/buildkitd`. finch
# needs a `--config` flag only because its path is non-default; adding one here
# would be a second thing to keep in step with no benefit.
#
# The namespace must match the one the nerdctl CLI uses, or the store buildkitd
# reads is not the store `nerdctl pull` and `nerdctl tag` write to. nerdctl's
# default is containerd's `namespaces.Default`, the string "default"
# (`pkg/config/config.go`), and nothing in the bundle changes it.
echo "=== Configuring buildkitd to use containerd's image store ==="
mkdir -p /etc/buildkit
cat > /etc/buildkit/buildkitd.toml <<'EOF'
# Written by scripts/setup-nerdctl-linux.sh. See that script for why every line
# here is load-bearing. In short: a no-config buildkitd defaults to the OCI
# worker, which is constructed with no image store at all, so `nerdctl build`
# cannot resolve `FROM` against an image that `nerdctl pull` already fetched.
[worker.oci]
  enabled = false

[worker.containerd]
  enabled = true
  # Must equal the nerdctl CLI's namespace, or buildkitd reads a different store
  # than the one nerdctl pulls and tags into. nerdctl's default is "default".
  namespace = "default"
EOF
cat /etc/buildkit/buildkitd.toml

# The bundle ships units at /usr/local/lib/systemd/system, which systemd loads
# ahead of /lib/systemd/system, so `containerd` now resolves to the bundle's
# copy running /usr/local/bin/containerd. restart rather than start, because the
# distro containerd.io unit is already running and holding the socket.
#
# buildkit is `restart` rather than `start` for a different reason, and it is the
# one that would make the config above look like it had no effect: buildkitd reads
# its config ONCE at startup, and `systemctl start` on an already-active unit is a
# no-op that exits 0. On a re-run, or on any host where something already started
# buildkit, `start` would leave the old no-config daemon running and the worker
# check below would report `oci` having written a perfectly good toml.
echo "=== Reloading systemd and starting containerd and buildkit ==="
systemctl daemon-reload
systemctl restart containerd
systemctl restart buildkit

# Docker was stopped above, so if either unit is dead there is no runtime left to
# fall back on and the image build that follows blocks instead of failing.
# Confirm each unit is actually active, with a bound, and dump its logs if not.
echo "=== Waiting for containerd and buildkit to report active ==="
for unit in containerd buildkit; do
    for _ in $(seq 1 30); do
        if systemctl is-active --quiet "${unit}"; then break; fi
        sleep 2
    done
    if ! systemctl is-active --quiet "${unit}"; then
        echo "ERROR: ${unit} did not become active within 60s" >&2
        systemctl status "${unit}" --no-pager --lines=40 >&2 || true
        journalctl -u "${unit}" --no-pager --lines=60 >&2 || true
        exit 1
    fi
    echo "  ${unit}: active"
done

echo "=== Verifying nerdctl installation ==="
nerdctl --version

# `nerdctl --version` only proves the binary is on PATH; it passes even when
# containerd and buildkit are unreachable. Probe both daemons so a broken runtime
# surfaces here in under a minute rather than wedging `ashx build-image` until the
# job timeout. Both probes are bounded, so this step can never be the thing that
# hangs.
echo "=== Verifying the containerd daemon responds ==="
if ! timeout 60 sh -c 'nerdctl info >/dev/null 2>&1 || nerdctl images >/dev/null 2>&1'; then
    echo "ERROR: nerdctl did not answer a daemon query within 60s." >&2
    echo "containerd is installed but not usable; refusing to continue." >&2
    systemctl status containerd buildkit --no-pager --lines=40 >&2 || true
    journalctl -u containerd --no-pager --lines=60 >&2 || true
    exit 1
fi

# buildkit answers a different socket from containerd, and `ashx build-image` is
# the first thing that needs it. A build is where an unreachable buildkitd would
# otherwise hang, so it is probed separately rather than assumed from the above.
#
# The output is PRINTED rather than discarded, and then asserted on. It used to go
# to /dev/null, which is why the buildkitd this leg ran was never actually
# observed: `debug workers` names the default worker's executor and its containerd
# namespace, which is exactly the pair that decides whether a locally-tagged base
# image is visible at `FROM`, and the answer was sitting one redirect away the
# whole time.
#
# This is the control for the buildkitd.toml written above, and it is the reason
# that config cannot silently fail to apply. Reading `oci` here means the toml was
# not picked up -- a typo in the path, a buildkitd too old for these keys, or a
# `start` that no-opped against an already-running daemon -- and the local-store
# half of the base-image fallback is inert again. The build would still SUCCEED in
# that state, because ASH_BASE_IMAGE_OVERRIDE redirects `FROM` at the registry
# that answered regardless of any worker setting, which is precisely why this
# needs its own assertion: nothing downstream would notice.
echo "=== Verifying the buildkit daemon responds ==="
# Inside WORKDIR so the EXIT trap above removes it; a bare mktemp would leave one
# file per run behind, and this script's own tarball handling already established
# that directory as the place for scratch.
workers_json="${WORKDIR}/buildkit-workers.json"
if ! timeout 60 buildctl debug workers --format '{{json .}}' > "${workers_json}" 2>&1; then
    echo "ERROR: buildkitd did not answer within 60s." >&2
    echo "nerdctl can talk to containerd but cannot build; refusing to continue." >&2
    cat "${workers_json}" >&2 || true
    systemctl status buildkit --no-pager --lines=40 >&2 || true
    journalctl -u buildkit --no-pager --lines=60 >&2 || true
    exit 1
fi

echo "=== buildkitd workers (the control for the config above) ==="
cat "${workers_json}"

# `buildctl debug workers` also has a table form that names the labels plainly;
# printed too, because the JSON is one long line and this is what a human reads.
timeout 60 buildctl debug workers --verbose 2>&1 || true

# grep over the JSON rather than parsing it: jq is not guaranteed on the runner,
# and the label names are literal strings in buildkitd's output. The executor
# label is `org.mobyproject.buildkit.worker.executor`.
if ! grep -q '"org.mobyproject.buildkit.worker.executor":"containerd"' "${workers_json}"; then
    echo "ERROR: buildkitd's default worker is not the containerd worker." >&2
    echo "" >&2
    echo "/etc/buildkit/buildkitd.toml was written above to disable the OCI worker," >&2
    echo "so reading anything other than executor=containerd here means it did not" >&2
    echo "take effect. While the OCI worker is the default, buildkitd is built with" >&2
    echo "ImageStore: nil and 'nerdctl build' cannot resolve FROM against any image" >&2
    echo "in containerd's store -- so the base-image pre-pull's local tag is invisible" >&2
    echo "to the build and every build goes back to the registry." >&2
    echo "" >&2
    echo "Refusing to continue rather than running a leg whose local-image path is" >&2
    echo "silently inert. Workers reported:" >&2
    cat "${workers_json}" >&2
    echo "" >&2
    echo "buildkitd's own startup log says which workers it found and which it made" >&2
    echo "default ('found N workers, default=...'):" >&2
    journalctl -u buildkit --no-pager --lines=60 >&2 || true
    exit 1
fi
echo "  buildkitd default worker: containerd (can read containerd's image store)"

# The namespace is the second condition. The containerd worker being default only
# helps if the store it is bound to is the one the nerdctl CLI writes to; bound to
# any other namespace it reads a real store that is simply empty of our images,
# which looks identical to having no store at all.
# `ls` rather than `list`: `ls` is the spelling nerdctl's own command reference
# documents, and `list` is not documented as an alias for it. Purely diagnostic --
# it only feeds the error message below -- but a diagnostic that silently prints
# nothing is worse than no diagnostic, which is why the spelling is the documented
# one rather than the one that reads better. `|| true` keeps it from ever being the
# reason this script fails.
nerdctl_ns="$(nerdctl namespace ls --quiet 2>/dev/null | tr '\n' ' ' || true)"
if grep -q '"org.mobyproject.buildkit.worker.containerd.namespace":"default"' "${workers_json}"; then
    echo "  buildkitd containerd namespace: default (matches the nerdctl CLI)"
else
    echo "ERROR: buildkitd's containerd worker is not bound to the 'default' namespace." >&2
    echo "nerdctl pulls and tags into its own namespace (default unless configured)," >&2
    echo "so a buildkitd reading a different namespace sees a store with none of the" >&2
    echo "images this leg just pulled. nerdctl reports its namespaces as:" >&2
    echo "  ${nerdctl_ns:-<none reported>}" >&2
    cat "${workers_json}" >&2
    exit 1
fi

echo "=== nerdctl setup complete ==="
