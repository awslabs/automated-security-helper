#checkov:skip=CKV_DOCKER_7:Base image uses pinned tag via ARG, Checkov cannot parse ARG references
#checkov:skip=CKV_DOCKER_3:ASH container runs as root — scanners require root for package installs and system tool access
#checkov:skip=CKV_DOCKER_8:Same as CKV_DOCKER_3 — root is intentional for scanner tool execution
ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.12-slim-bookworm
# Change this in the same commit as the tag above. Why, and how to get the value: below.
ARG BASE_IMAGE_DIGEST=sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

# BASE_IMAGE_DIGEST
#
# The digest the tag above resolved to when it was last reviewed. Nothing in this file reads
# it; .github/actions/prepull-base-image does, and refuses to hand the build a base image
# whose digest is anything else. That pre-pull can source the image from either
# public.ecr.aws or docker.io, whichever will serve it -- so something has to establish that
# the two are serving the same bytes. This is that something, and it is the whole safety
# argument for having a second registry at all.
#
# It sits on the line after the tag, ahead of this note rather than after it, so that the
# three lines of context in a one-line tag bump's diff include it. A reviewer looking at
# `ARG BASE_IMAGE` changing sees this line unchanged directly underneath. Dependabot raises
# base-image pull requests here daily and moves the tag without knowing about this line, so
# that reviewer is a real person on a real recurring pull request, not a hypothetical.
#
# To recompute it after a tag bump:
#
#   docker pull public.ecr.aws/docker/library/python:<new tag>
#   docker image inspect --format '{{index .RepoDigests 0}}' public.ecr.aws/docker/library/python:<new tag>
#
# This is the multi-arch INDEX digest, not a per-platform manifest digest, which is why one
# value covers amd64 and arm64. Measured 2026-09-29: public.ecr.aws and docker.io both report
# this digest for this tag, with mediaType application/vnd.oci.image.index.v1+json.
#
# It is deliberately NOT folded into BASE_IMAGE as `repo:tag@sha256:...`. That form would let
# Dependabot keep both in step, which is the one thing it has going for it, but `docker tag`
# refuses a digest-suffixed target, and the pre-pull's fallback path tags a Docker Hub pull
# under the exact reference `FROM ${BASE_IMAGE}` resolves -- which is what keeps plain
# `docker build` and podman working. The reference has to stay taggable, so the digest has to
# live somewhere else.
#
# BASE_IMAGE IS ALSO AN OVERRIDE POINT, NOT ONLY A DEFAULT
#
# When the pre-pull's fallback fires it passes
# `--build-arg BASE_IMAGE=docker.io/library/<name>@<this digest>`, so
# `FROM ${BASE_IMAGE}` below asks Docker Hub for content rather than asking
# ECR Public for a tag. `FROM` accepts a digest-suffixed value even though `docker tag` does
# not, so the fallback is more tightly pinned than the default above rather than less. That
# redirect exists because the BuildKit runtimes -- nerdctl, finch, and `docker buildx` on a
# docker-container driver -- resolve `FROM` against the registry and never consult the local
# store, so the local tag alone did not reach them. See the pre-pull action for the
# measurement.

# First stage: Build UV requirements
FROM ${BASE_IMAGE} AS uv-reqs

ENV PYTHONDONTWRITEBYTECODE=1
# apt packages are pinned to the version apt selects today from the base image's
# own sources (bookworm, bookworm-updates, bookworm-security), identical on amd64
# and arm64. The same package carries the same pin in every stage. Debian keeps one
# version per suite, so a point release or security update retires a pin and the
# build fails with "Version '...' for '...' was not found"; take the new version
# from `apt-cache policy <package>` in the base image. nodejs pins come from the
# NodeSource repository, which keeps its old releases.
RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates=20250419~deb12u2 \
    python3-venv=3.11.2-1+b1 \
    git=1:2.39.5-0+deb12u3 \
    tree=2.1.0-1 \
    curl=7.88.1-10+deb12u15 && \
    rm -rf /var/lib/apt/lists/*

ARG INSTALL_ASH_REVISION="LOCAL"
ARG ASH_REPO_CLONE_URL="https://github.com/awslabs/automated-security-helper.git"
ENV INSTALL_ASH_REVISION=${INSTALL_ASH_REVISION}
ENV ASH_REPO_CLONE_URL=${ASH_REPO_CLONE_URL}

# Install UV
#
# From its pinned release asset, verified against the SHA256 in
# automated_security_helper/utils/tool_downloads.py, the same way the core stage
# installs syft, grype and trivy. This was `curl -LsSf https://astral.sh/uv/install.sh
# | sh`: a remote script piped into a shell, which pinned no version and no bytes and
# gave astral.sh code execution in the stage that builds the wheel the image ships.
# The installer and the two files it reads are copied here as well as in the core
# stage because a stage starts from the base image and sees nothing the other copied.
COPY automated_security_helper/assets/with-retry.sh /usr/local/bin/with-retry
RUN chmod +x /usr/local/bin/with-retry
COPY automated_security_helper/assets/install-pinned-tool.py /usr/local/bin/install-pinned-tool
COPY automated_security_helper/utils/tool_downloads.py /ash-pins/utils/tool_downloads.py
COPY automated_security_helper/core/exceptions.py /ash-pins/core/exceptions.py
RUN chmod +x /usr/local/bin/install-pinned-tool
ARG UV_VERSION="0.13.4"
RUN ASH_PINS_DIR=/ash-pins with-retry 'install-pinned-tool uv -b /root/.local/bin'
ENV PATH="/root/.local/bin:$PATH"
RUN uv --version

WORKDIR /src

# The build context, set aside until the step below has decided where the source
# comes from. "COPY . <dir>" rather than targeted globs: Podman/buildah fail on a
# glob that matches nothing, where Docker and Finch skip it.
COPY . /ash-context

# Re-runs the clone below when it has a new value. run_ash_container.py passes
# ASH_CLONE_DATE_EPOCH=<now> when INSTALL_ASH_REVISION names a branch and the build
# context is not ASH's source tree, and nothing for LOCAL, a release tag or a commit
# id. A branch moves, but the clone step is the same command on every build, so
# without a new value the build cache served the branch's first clone to every later
# build. Docker passes an ARG to every later RUN of its stage as an environment
# variable, so a new value is a cache miss for each of them ("Impact on build
# caching" in the Dockerfile reference). Declared here, directly above the clone, so
# the steps before it stay cached.
ARG ASH_CLONE_DATE_EPOCH="-1"

# Where the source comes from, in this order:
#   - LOCAL: the build context, and nothing is cloned.
#   - A build context that is ASH's source tree (its pyproject.toml names
#     automated-security-helper): that tree, and nothing is cloned. ./ash, which
#     always builds its own checkout, and the CDK image pipeline, which builds its own
#     clone, both build such a context with a revision other than LOCAL. A clone
#     there would only be overwritten by the context file by file, so it would buy
#     nothing but a way to fail.
#     The name is read as run_ash_container._is_ash_source_tree reads it: the
#     [project] table's name, parsed as TOML and normalized as
#     packaging.utils.canonicalize_name does. A grep for one exact line took another
#     table's `name` line, or one inside a string, for ASH's, and missed ASH's own
#     name written any other valid way. The base image's python3 (3.12) has tomllib;
#     tomli is the fallback for an older one, and without either the step clones.
#     tests/unit/interactions/test_container_clone_step_runs.py runs this step and
#     _is_ash_source_tree on the same files and requires the same answer.
#   - A full commit id, built only if a branch or a tag of the repository reaches
#     it. Package builds record the commit they were built from (hatch_build.py),
#     and an install from a git URL with no ref records one. The step clones the
#     repository's branches and tags without file contents (`--filter=blob:none`)
#     and with nothing checked out, looks for the id among the commits they reach,
#     and only then checks it out; otherwise it fails with exit 3.
#     It does not fetch the id itself (`git fetch <url> <id>`): GitHub serves any
#     object in a repository's fork network by id, a commit that only a fork or a
#     pull request holds included, so that would build such a commit as ASH. A clone takes
#     refs/heads/* and refs/tags/*, never refs/pull/*. The lookup is rev-list over
#     the fetched refs rather than `git merge-base --is-ancestor <id> <ref>`: in a
#     partial clone, asking about a commit it does not hold makes git fetch that
#     commit from the remote to answer, as git 2.50 did with a pull request's commit,
#     and GIT_NO_LAZY_FETCH, which stops that, is newer than this image's git 2.39.
#     tests/unit/interactions/test_container_clone_step_runs.py runs this against a
#     local repository with a commit only refs/pull/7/head reaches.
#     A commit id is the whole value, 40 lowercase hex digits and nothing else. The
#     value is checked whole, not line by line, so two ids on two lines do not
#     take this path.
#   - Anything else, cloned as a branch or a tag. `git clone --branch` takes only
#     those, so it reaches no pull request's commit either.
# The context is then copied over /src. A clone that fails fails this step with
# git's own message, so the build never goes on with the context alone, which from
# the packaged Dockerfile, whose context holds no pyproject.toml, would fail later
# at `uv build`.
RUN if [ "${INSTALL_ASH_REVISION}" = "LOCAL" ]; then \
        echo "Skipping clone of repo for LOCAL revision"; \
    elif python3 -c 'import re, sys; \
            toml = __import__("tomllib" if sys.version_info >= (3, 11) else "tomli"); \
            name = toml.load(open(sys.argv[1], "rb")).get("project", {}).get("name"); \
            sys.exit(not (isinstance(name, str) and re.sub(r"[-_.]+", "-", name).lower() == "automated-security-helper"))' \
            /ash-context/pyproject.toml 2>/dev/null; then \
        echo "The build context is an ASH checkout; building it instead of cloning ${INSTALL_ASH_REVISION}"; \
    elif [ "${#INSTALL_ASH_REVISION}" -eq 40 ] && \
            case "${INSTALL_ASH_REVISION}" in *[!0123456789abcdef]*) false ;; *) true ;; esac; then \
        git clone --quiet --filter=blob:none --no-checkout "${ASH_REPO_CLONE_URL}" . && \
        if ! git rev-list --remotes=origin --tags | grep -Fqx "${INSTALL_ASH_REVISION}"; then \
            echo "${INSTALL_ASH_REVISION} is not on a branch or tag of ${ASH_REPO_CLONE_URL}, so it is not built; pass a branch, a tag, or a commit one of them reaches" >&2; \
            exit 3; \
        fi && \
        git checkout --quiet --detach "${INSTALL_ASH_REVISION}"; \
    else \
        git clone --branch "${INSTALL_ASH_REVISION}" "${ASH_REPO_CLONE_URL}" .; \
    fi && \
    cp -a /ash-context/. . && \
    rm -rf /ash-context
RUN tree .
RUN git status --short || true
RUN uv build
# RUN uv export --format requirements-txt --no-hashes > requirements.txt && \
#     sed -i '/^-e \./d' requirements.txt && \
#     sed -i '/^\./d' requirements.txt

# Second stage: Core ASH image
FROM ${BASE_IMAGE} AS core
# No `SHELL ["/bin/bash", "-c"]`. It was here, and it is the reason a bashism in a
# RUN was correct under docker and silently skipped under podman and finch -- the
# worst way for a difference to be distributed, because the runtime most people
# develop against is the one that hides it.
#
# buildah honours SHELL only in `docker` image format; in OCI format it discards it
# and logs `SHELL is not supported for OCI image format, [/bin/bash -c] will be
# ignored` once per instruction (57 times in a full build). So the directive bought
# bash for exactly one of the three runtimes ASH supports.
#
# Removing it rather than forcing `--format docker` on every caller: the format is
# the caller's choice, `ash --mode container` supports docker, podman and finch, and
# a plain `podman build` by hand should behave like CI. With this gone, every RUN
# runs under /bin/sh everywhere, so a bashism fails the same way in all three.
#
# The contract is now: every RUN in this file must be POSIX sh. All 34 of them are;
# tests/unit/test_dockerfile_posix_shell.py enforces it, because the failure mode
# this replaced is invisible at review time. Where bash is genuinely needed, call it
# explicitly -- assets/with-retry.sh is `#!/bin/bash` and runs its argument under
# `bash -o pipefail -c`, which is how the piped installs keep pipefail.
#
# ENV SHELL is unrelated and stays: it is an environment variable for processes in
# the running container, not the shell `RUN` uses at build time.
ENV SHELL="bash"
ARG OFFLINE="NO"
ARG OFFLINE_SEMGREP_RULESETS="p/ci"
ARG ASH_BIN_PATH="/.ash/bin"

ARG INSTALL_ASH_REVISION="LOCAL"
ENV INSTALL_ASH_REVISION=${INSTALL_ASH_REVISION}

ENV ASH_BIN_PATH="${ASH_BIN_PATH}"
ENV OFFLINE="${OFFLINE}"
ENV OFFLINE_AT_BUILD_TIME="${OFFLINE}"
ENV ASH_OFFLINE="${OFFLINE}"
# YES only in an image built with OFFLINE=YES. ASH reads it as "this image carries the
# databases it was built with" and then holds trivy-db to warn rather than fail
# (OFFLINE_IMAGE_POLICIES in utils/content_databases.py), so it must keep following the
# build argument and nothing else.
ENV ASH_OFFLINE_AT_BUILD_TIME="${OFFLINE}"
ENV OFFLINE_SEMGREP_RULESETS="${OFFLINE_SEMGREP_RULESETS}"
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

#
# General / shared component installation
#
COPY automated_security_helper/assets/with-retry.sh /usr/local/bin/with-retry
RUN chmod +x /usr/local/bin/with-retry
WORKDIR /deps

#
# Add GitHub's public fingerprints to known_hosts inside the image to prevent fingerprint
# confirmation requests unexpectedly
#
RUN mkdir -p ${HOME}/.ssh && \
    echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" >> ${HOME}/.ssh/known_hosts && \
    echo "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=" >> ${HOME}/.ssh/known_hosts && \
    echo "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=" >> ${HOME}/.ssh/known_hosts

#
# Base dependency installation
#
# build-essential and ruby-dev are deliberately absent here: they are needed only
# to build cfn-nag's gems, and this layer is never purged, so anything listed here
# ships at runtime. They are installed and removed inside the gem build below.
#
# `ruby` is listed in its own right. It used to arrive only as a dependency of
# ruby-dev, which meant removing ruby-dev would have taken the interpreter
# cfn-nag runs on. Installing it explicitly also marks it manual, so the
# --auto-remove in the gem build cannot collect it.
#
# BUILD_DATE_EPOCH re-runs this step, and every later RUN of the stage, when its value
# changes. Two of those steps fetch content that goes stale while the step itself
# stays the same: the `apt-get upgrade` here (OS security updates) and the offline
# download of the grype database and the semgrep and opengrep rulesets further down.
# Without a new value both are served from the build cache, and a rebuilt image keeps
# whatever the build that filled the cache fetched. Docker passes an ARG to every
# later RUN of its stage as an environment variable, so a new value is a cache miss
# for each of them whether or not the command reads it ("Impact on build caching" in
# the Dockerfile reference); this step echoes it so the dependency is visible here.
#
# Every entrypoint passes UTC midnight of the current day, in epoch seconds, for
# online and offline builds alike: run_ash_container.py (ash build-image,
# --mode container), ./ash, utils/ash_helpers.ps1, the Terraform image pipeline's
# buildspec and the CDK image build construct (deploy/cdk/lib/ash-image-build.ts).
# Rebuilds on the same day come from the cache (unless --force, which is --no-cache),
# so an offline host can rebuild without network once a day has been built. The
# first build of a new day re-runs the stage from here down, so OS packages and
# offline databases are at most a day old when built. A plain `docker build` that
# passes no value gets the default and caches this step for good.
# tests/unit/test_build_date_reaches_every_build_entrypoint.py holds all of this.
ARG BUILD_DATE_EPOCH="-1"
RUN echo "Upgrading OS packages for BUILD_DATE_EPOCH=${BUILD_DATE_EPOCH}" && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates=20250419~deb12u2 \
    curl=7.88.1-10+deb12u15 \
    git=1:2.39.5-0+deb12u3 \
    gnupg=2.2.40-1.1+deb12u2 \
    python3-venv=3.11.2-1+b1 \
    ripgrep=13.0.0-4+b2 \
    ruby=1:3.1 \
    tree=2.1.0-1 && \
    rm -rf /var/lib/apt/lists/*

#
# Install nodejs using latest recommended method.
#
# The major version has to satisfy the package managers cached below. pnpm 11
# declares engines.node >=22.13 (pnpm 9 and 10 were >=18.12), and `corepack
# prepare pnpm@latest` caches whatever the current major is, so Node 20 left the
# image with a pnpm it could not run. tests/unit/test_dockerfile_node_toolchain.py
# fails if this drops back below what pnpm needs.
#
RUN set -uex; \
    mkdir -p /etc/apt/keyrings; \
    with-retry 'curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg'; \
    NODE_MAJOR=22; \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list; \
    apt-get -qy update; \
    apt-get -qy install --no-install-recommends nodejs=22.23.3-1nodesource1;
#
# uv is installed in the core stage below, after the pinned-tool installer is copied
# in, from the same verified release asset as the uv-reqs stage.
#
ENV PATH="/root/.local/bin:$PATH"

#
# Python (no-op other than updating pip --- Python deps managed via Poetry @ pyproject.toml)
#
# No get-pip.py. It was fetched from bootstrap.pypa.io and executed, unpinned and
# unverified, to install a pip the python base image already ships -- the upgrade on
# the next line is all this step ever needed.
RUN with-retry 'python3 -m pip install --no-cache-dir --upgrade pip'

# #
# # Git (git-secrets)
# #
# RUN git clone https://github.com/awslabs/git-secrets.git && \
#     cd git-secrets && \
#     make install


#
# cfn-nag (via Gemfile)
#
COPY automated_security_helper/assets/Gemfile automated_security_helper/assets/Gemfile.lock /deps/
ARG BUNDLER_VERSION="2.6.9"
# Bundler installs the committed Gemfile.lock and does not resolve again. Frozen,
# it refuses to run when the lockfile is missing or disagrees with the Gemfile, so
# every build of one ASH commit installs the same gems. An ARG rather than an ENV:
# it reaches the RUN below and is not left in the environment the image scans with.
ARG BUNDLE_FROZEN=true
# One RUN for install, build and purge. `core` is the base for both `ci` and
# `non-root`, so a C toolchain left here ships in every published image, which is
# its own finding in a security scanner. Docker layers are additive, so purging in
# a later RUN would remove the compiler from the container while the image still
# carried it -- keeping all three steps in one layer means it never lands at all.
#
# apt-get update runs again because the base layer clears the package lists.
#
# Some gems ship files mode 777 (lightly, which cfn-nag pulls in, does), and gem
# install keeps the modes the gem was packed with. The chmod clears group and other
# write in the same layer, so those modes never reach the image.
RUN echo "gem: --no-document" >> /etc/gemrc && \
    apt-get update && \
    apt-get install -y --no-install-recommends build-essential=12.9 ruby-dev=1:3.1 && \
    with-retry 'gem install bundler -v ${BUNDLER_VERSION}' && \
    with-retry 'bundle install --jobs=4' && \
    chmod -R go-w /var/lib/gems && \
    apt-get purge -y --auto-remove build-essential ruby-dev && \
    rm -rf /var/lib/apt/lists/*

#
# JavaScript: corepack manages npm/yarn/pnpm versions via package.json engines
# Prepare at build time so binaries are cached for offline runtime use
#
# A scanned repository pins its own version through `packageManager`, and corepack
# honours that at runtime. When the pinned version is not the one cached above,
# corepack asks before fetching it ("Do you want to continue? [Y/n]"). No tty is
# attached here, so that prompt blocks on stdin indefinitely and the scan looks
# like a hung `pnpm audit` rather than a failure. Setting this to 0 turns the
# prompt into a decision corepack makes on its own, so the audit either runs or
# fails with a message.
#
# ENV rather than a build-time export: the npm-audit scanner invokes pnpm at
# runtime, which is the case that reported the hang.
#
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN with-retry 'corepack enable && corepack prepare yarn@stable --activate && corepack prepare pnpm@latest --activate'


#
# Grype/Syft/Semgrep - Also sets default location env vars for root user for CI compat
#
# Owned by root and writable by root only: a scan reads the database and the rules
# in these caches, so they have one owner. The offline build below
# writes them as root. At scan time only grype's database update writes here,
# which the ci stage runs as root and for which the non-root stage hands
# GRYPE_DB_CACHE_DIR to its own user.
ENV GRYPE_DB_CACHE_DIR="/deps/.grype"
ENV SEMGREP_RULES_CACHE_DIR="/deps/.semgrep"
ENV OPENGREP_RULES_CACHE_DIR="/deps/.opengrep"
RUN mkdir -p ${GRYPE_DB_CACHE_DIR} ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR} && \
    chmod 755 /deps ${GRYPE_DB_CACHE_DIR} ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR}
ENV PATH="/usr/local/bin:$PATH"

#
# syft, grype and trivy come from their pinned release assets, verified against the
# SHA256 digests in automated_security_helper/utils/tool_downloads.py, which is the
# same table `ash dependencies install` and the nix flake resolve. Before this, all
# three were installed by piping a vendor install script into a shell, which pinned
# no bytes and gave the endpoint code execution during the build -- the alternative
# tool_downloads.py's own docstring rejects while naming this image as the place
# still doing it.
#
# It failed on availability too, not only on integrity. On run 35246976698 anchore's
# script could not resolve get.anchore.io, fell back to github.com, got the 302 that
# every release download answers with, and treated the redirect as an error; the
# tarball was never written, and `RUN syft --version` failed with exit 127. Going
# straight to the release asset removes raw.githubusercontent.com and get.anchore.io
# from the path and follows the redirect that broke it.
#
# ARG stays the declaration of intent for the version, and the installer resolves it
# from the table rather than from these values -- so a version bumped here without
# its digests cannot install a binary nobody reviewed. The versions are asserted
# equal to the table by tests/unit/assets/test_install_pinned_tool.py.
#
# The two COPY lines land before the installs on purpose. They invalidate only when
# the pins change, so the three downloads stay cached across ordinary source edits.
# Copying the built wheel earlier instead -- which is what calling
# download_utils.install_pinned_tool would require, since importing it needs 19 ASH
# modules and pydantic -- would put these layers downstream of every code change and
# re-fetch all three binaries on every build.
COPY automated_security_helper/assets/install-pinned-tool.py /usr/local/bin/install-pinned-tool
COPY automated_security_helper/utils/tool_downloads.py /ash-pins/utils/tool_downloads.py
COPY automated_security_helper/core/exceptions.py /ash-pins/core/exceptions.py
RUN chmod +x /usr/local/bin/install-pinned-tool
# Every `install-pinned-tool <tool>` from here on also installs that tool's license and
# notice files under this directory, read from the release archive it has just
# verified, and refuses a tool with no license entry. THIRD_PARTY_LICENSES in
# automated_security_helper/utils/tool_downloads.py says what goes there and why. An
# ARG, not an ENV: only this stage's build steps read it.
ARG ASH_THIRD_PARTY_DIR="/usr/share/doc/ash/third-party"
ENV ASH_PINS_DIR="/ash-pins"

ARG UV_VERSION="0.13.4"
RUN with-retry 'install-pinned-tool uv -b /root/.local/bin'
RUN uv --version

ARG SYFT_VERSION="v1.54.1"
RUN with-retry 'install-pinned-tool syft -b /usr/local/bin'
RUN syft --version

ARG GRYPE_VERSION="v0.120.1"
RUN with-retry 'install-pinned-tool grype -b /usr/local/bin'
RUN grype --version

# actionlint backs the builtin actionlint scanner. Same pinned-asset path as syft and
# grype.
ARG ACTIONLINT_VERSION="v1.7.12"
RUN with-retry 'install-pinned-tool actionlint -b /usr/local/bin'
RUN actionlint --version

# gitleaks backs the builtin gitleaks scanner, which runs beside detect-secrets.
ARG GITLEAKS_VERSION="v8.30.1"
RUN with-retry 'install-pinned-tool gitleaks -b /usr/local/bin'
RUN gitleaks --version

# POSIX `[ ... = ... ]`, not `[[ ... == ... ]]`. This block did not run at all under
# podman or finch, in either direction of the condition, and nothing said so.
#
# `[[` is a bash keyword. buildah discards `SHELL` in OCI image format -- it says so
# once per instruction, 57 times in a full build -- so every RUN executes under
# /bin/sh, which is dash in this base image. dash has no `[[`, and the failing
# command here was the CONDITION of an `if`, which under `set -e` is a false branch
# rather than an error. Measured on run 35177045049, job 105060929678:
#
#     [2/3] STEP 44/58: RUN set -uex; if [[ "${OFFLINE}" == "YES" ]]; then ...
#     + [[ NO == YES ]]
#     /bin/sh: 1: [[: not found
#     [2/3] STEP 45/58: ARG TRIVY_VERSION="v0.69.3"
#
# The `set -x` trace showing an evaluated comparison is what made it look like the
# test ran and took the false branch. It did not run. Confirmed in this exact base
# image with the value set to YES, where `[[` is still absent:
#
#     $ docker run --rm ...python:3.12-slim-bookworm sh -c \
#         'set -uex; if [[ "YES" == "YES" ]]; then echo TAKEN; fi; echo CONTINUED'
#     + [[ YES == YES ]]
#     sh: 1: [[: not found
#     + echo CONTINUED
#     CONTINUED            <- no TAKEN, exit 0
#
# So OFFLINE=YES provisioned nothing on podman or finch: no grype database, no
# semgrep or opengrep rules cache. CI never caught it because the only offline leg
# in the matrix is `oci-runner: docker`, where SHELL is honoured and bash runs it.
# The exposure was users building offline images with a non-docker runtime.
#
# .ash-rules-fetched-at records when the rulesets were downloaded. A rules file has no
# build time of its own, and ASH fails a scan whose offline rules are past the bound in
# automated_security_helper/utils/content_databases.py (RULESET_FETCHED_AT_FILE there),
# so the download time is written down rather than inferred from mtime, which a copy
# resets. The grype database needs no such file: `grype db status` reports its own
# build time.
#
# Every command is its own statement, separated by `;`, never joined by `&&`. `set -e`
# does not apply to a command in an AND-OR list other than the last, nor to anything
# that command runs, so when this block was one `&&` chain the `for` loop ran with
# `set -e` off: a ruleset that failed to download, other than the last, was skipped
# and the build passed without it. The trivy step below had the same defect.
# tests/unit/test_dockerfile_offline_provisioning.py runs both steps with failing
# stand-in downloads, and rejects `&&` in any RUN that sets `-e`.
RUN set -uex; if [ "${OFFLINE}" = "YES" ]; then \
    with-retry 'grype db update'; \
    mkdir -p ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR}; \
    for i in $OFFLINE_SEMGREP_RULESETS; do \
        outfile="${SEMGREP_RULES_CACHE_DIR}/$(basename "${i}").yml"; \
        with-retry "curl -sSf https://semgrep.dev/c/${i} -o ${outfile}"; \
        cp "${outfile}" "${OPENGREP_RULES_CACHE_DIR}/$(basename "${i}").yml"; \
    done; \
    fetched_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
    printf '%s\n' "${fetched_at}" > "${SEMGREP_RULES_CACHE_DIR}/.ash-rules-fetched-at"; \
    printf '%s\n' "${fetched_at}" > "${OPENGREP_RULES_CACHE_DIR}/.ash-rules-fetched-at"; \
    chmod -R u=rwX,go=rX ${GRYPE_DB_CACHE_DIR} ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR}; \
    fi

# Assert the block above actually provisioned something, so a repeat of the defect
# fails the build instead of shipping an image that reports itself offline-ready and
# has no rules to scan with. This is the part that was missing: the bracket fix stops
# today's bug, and this stops the next one, whatever silences the block next time --
# a shell difference, a renamed variable, a `with-retry` that exits 0 having done
# nothing.
#
# Deliberately checks the ARTIFACTS rather than re-testing OFFLINE: an assertion that
# re-evaluates the same condition through the same shell would be silenced by
# whatever silenced the block.
#
# Only the semgrep and opengrep caches are asserted non-empty. The grype database
# lands in GRYPE_DB_CACHE_DIR as a versioned subdirectory whose layout is grype's to
# change, so this asserts the directory is non-empty rather than naming a file in it.
RUN set -ue; if [ "${OFFLINE}" = "YES" ]; then \
    for d in "${GRYPE_DB_CACHE_DIR}" "${SEMGREP_RULES_CACHE_DIR}" "${OPENGREP_RULES_CACHE_DIR}"; do \
        if [ -z "$(ls -A "${d}" 2>/dev/null)" ]; then \
            echo "OFFLINE=YES but ${d} is empty: the offline provisioning step did not run." >&2; \
            echo "If this fired after a Dockerfile edit, check that the RUN above is POSIX sh --" >&2; \
            echo "buildah ignores SHELL in OCI format, so a bashism there is silently skipped." >&2; \
            exit 1; \
        fi; \
    done; \
    echo "offline provisioning verified: grype db, semgrep and opengrep caches are all non-empty"; \
    fi

ARG TRIVY_VERSION="v0.75.0"
RUN with-retry 'install-pinned-tool trivy -b /usr/local/bin'
RUN trivy --version

# trivy's cache, shared by the trivy and trivy-repo scanners. It is owned the way
# GRYPE_DB_CACHE_DIR is: root's and writable by root only here, handed to the
# non-root stage's user there because trivy's database update writes it at scan time,
# and left root's in an offline image, which never updates it. Not mode 777: only
# /src and /out may be writable by every user (see the chmod of /ash below), and a
# scan reads the database in this cache. An offline image downloads the
# vulnerability database into it here; trivy is a default scanner, and offline with no
# database it is MISSING, which fails the scan. trivy's own bound for that database is
# 24 hours (utils/content_databases.py); in this image ASH holds it to `warn` rather
# than `fail` (ASH_OFFLINE_AT_BUILD_TIME above), so once it is a day old the scans still
# pass and each report records the stale database until the image is rebuilt. The
# artifact is checked rather than OFFLINE re-tested, for the reason given above.
#
# `;` between the commands, not `&&`, for the reason given at the grype step: as an
# `&&` chain, a failed download skipped the emptiness check below and the step still
# printed "verified" and exited 0.
ENV TRIVY_CACHE_DIR="/deps/.trivy"
RUN set -ue; mkdir -p "${TRIVY_CACHE_DIR}"; chmod 755 "${TRIVY_CACHE_DIR}"; \
    if [ "${OFFLINE}" = "YES" ]; then \
        with-retry "trivy image --download-db-only --no-progress --cache-dir ${TRIVY_CACHE_DIR}"; \
        chmod -R u=rwX,go=rX "${TRIVY_CACHE_DIR}"; \
        if [ -z "$(ls -A "${TRIVY_CACHE_DIR}/db" 2>/dev/null)" ]; then \
            echo "OFFLINE=YES but ${TRIVY_CACHE_DIR}/db is empty: the trivy database was not downloaded." >&2; \
            exit 1; \
        fi; \
        echo "offline provisioning verified: trivy database present"; \
    fi

# cfn-guard, a builtin scanner, and the AWS Guard Rules Registry it evaluates
# templates against. The binary comes from its pinned release asset like the tools
# above. The rules archive is pinned the same way (RULES_BUNDLES in
# utils/tool_downloads.py) and installed here as root, mode 0755/0644, so the scan
# user cannot rewrite the rules a later scan trusts. `ash dependencies install`
# below finds the bundle already in place, its rule files matching the contents
# pinned beside the archive digest, and leaves it alone.
# Under /usr/share rather than /deps, whose cache directories stay writable for the
# scanners: the bundle and every directory above it are root's and writable by no one
# else, which `--assert-root-only` checks here and again in the final stage.
ARG CFN_GUARD_VERSION="3.2.1"
ENV ASH_CFN_GUARD_RULES_DIR="/usr/share/ash/cfn-guard-rules"
RUN with-retry 'install-pinned-tool cfn-guard -b /usr/local/bin' && \
    with-retry "install-pinned-tool aws-guard-rules-registry --rules-bundle -d ${ASH_CFN_GUARD_RULES_DIR}"
RUN cfn-guard --version && \
    test -s "${ASH_CFN_GUARD_RULES_DIR}/aws-guard-rules-registry-1.0.2/wa-Security-Pillar.guard" && \
    install-pinned-tool --assert-root-only "${ASH_CFN_GUARD_RULES_DIR}"

# opengrep has no release archive for install-pinned-tool to read license files from:
# it is a bare executable that `ash dependencies install` puts in place below. So its
# license files are fetched on their own, each pinned by SHA256 and by the upstream
# commit of the release the image carries. uv is not listed: `install-pinned-tool uv`
# above already fetched its URL-pinned license files, because ASH_THIRD_PARTY_DIR was
# set by then.
RUN with-retry 'install-pinned-tool --licenses-only opengrep'

#
# Setting default WORKDIR to /src
#
WORKDIR /src

#
# Make sure the default dirs are initialized
#
RUN mkdir -p /src && \
    mkdir -p /out && \
    mkdir -p /ash/utils && \
    mkdir -p ${ASH_BIN_PATH}

# Limit memory size available for Node to prevent segmentation faults during npm install
ENV NODE_OPTIONS=--max_old_space_size=512

#
# COPY ASH source to /ash instead of / to isolate
#
COPY --from=uv-reqs /src/dist/*.whl .
# [symbols] is tree-sitter and its grammars, for suppressions scoped by `symbol`.
# Without it every such suppression matches nothing, so the image ships it.
# UV_NO_CACHE on every uv install in this file: uv's download and wheel cache is
# only useful to a later install on the same machine, and in an image layer it is
# dead weight -- measured, it was most of the growth the new scanners' uv tool
# environments added. Set per RUN rather than as an ENV so a scan inside the
# container that installs a tool still gets uv's normal caching. The
# `ash dependencies install` RUNs below also give that install a TMPDIR of its own
# and remove it in the same RUN: uv keeps its no-cache cache in a temporary
# directory, and measured, `ash dependencies install` left about 437 MB of it in
# /tmp in each stage's layer.
RUN UV_NO_CACHE=1 uv pip install --system "$(ls *.whl)[cdk,symbols]" && rm -rf *.whl

#
# Make sure the ash script is executable
#
# /ash and ASH_BIN_PATH, which is first on PATH, belong to root: nothing writes to
# them at scan time, and a tool there has to stay the one installed here. /src and
# /out are where a run mounts the source and the output, so their modes matter only
# when the image is started without those mounts. They stay writable by every user,
# because the ci stage is for platforms that start the container under a UID they
# choose, and they carry the sticky bit so that one user cannot remove or replace
# another's files there.
RUN chmod -R 755 /ash ${ASH_BIN_PATH} && chmod 1777 /src /out

#
# Flag ASH as local execution mode since we are running in a container already
#
ENV _ASH_EXEC_MODE="local"

#
# Install dependencies via ASH CLI into
#
# bandit, checkov, semgrep, cfn-lint and zizmor are installed with `uv tool install`, and each scanner's
# own default is a version range, so on its own this would install whatever release
# PyPI had on the day. `--uv-tool-pins` prints the --config-overrides that pin each to
# the version of its THIRD_PARTY_LICENSES entry, so the license files and the source
# commit below describe the release in the image. Assigned first so a failure stops
# the build rather than leaving the install unpinned. UV_NO_CACHE=1 keeps uv's cache
# out of the layer.
# ASH_OFFLINE=NO for this process only: ENV ASH_OFFLINE above is YES in an OFFLINE=YES
# image, and in offline mode ASH downloads nothing, so opengrep, a bare executable
# that only this install fetches, was never put in place. The build is online either
# way (it fetched the rulesets and databases above); the finished image keeps the ENV.
RUN pins="$(install-pinned-tool --uv-tool-pins)" && \
    uv_tmp="$(mktemp -d)" && \
    { TMPDIR="${uv_tmp}" UV_NO_CACHE=1 ASH_OFFLINE=NO \
    ash dependencies install --bin-path "${ASH_BIN_PATH}" ${pins}; \
    status=$?; rm -rf "${uv_tmp:?}"; exit "${status}"; }
ENV PATH="${ASH_BIN_PATH}:$PATH"

# The Python tools' license files, read from each installed wheel's dist-info and,
# for semgrep, whose wheel carries none, fetched from its repository at the pinned
# commit and checked against their SHA256.
RUN with-retry 'install-pinned-tool --licenses-only bandit cfn-lint checkov semgrep zizmor'

# zizmor (builtin scanner) is installed by the line above through `uv tool install`
# within ZIZMOR_DEFAULT_VERSION_CONSTRAINT; this fails the build if it was not.
RUN zizmor --version

#
# Every bundled third-party tool has its license files, they match their pins, and
# they describe the release actually on PATH (each tool's --version is checked).
# After `ash dependencies install`, which is what puts opengrep in place. Writes
# ${ASH_THIRD_PARTY_DIR}/index.json, the list of what the image bundles.
#
RUN install-pinned-tool --verify-third-party

#
# Nothing in the image is writable by every user outside the sticky directories.
# Not every installer honors the umask: uv creates the lock files in its cache and
# tool directories mode 666. This clears group and other write on whatever an
# install step left writable by everyone, after the last one in this stage. It stays
# on the image's own filesystem (-xdev) and skips the sticky scratch directories,
# whose files belong to whoever wrote them; it changes only the files it finds, so
# this layer holds only those. The non-root stage repeats it after its own install.
# tests/snapshot/container/runtime/test_container_image_permissions.py checks the
# built image with the same find.
#
RUN find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /tmp \
        -o -path /var/tmp -o -path /run/lock \) -prune -o \
        ! -type l -perm -0002 ! -perm -1000 -exec chmod go-w {} +

#
# Flag ASH as running in container to prevent ProgressBar panel from showing (causes output blocking)
#
ENV ASH_IN_CONTAINER="YES"

#
# Build metadata, recorded in the image: the BUILD_DATE_EPOCH the build was given
# (see its ARG above the apt-get upgrade step), or -1 when it was given none. Nothing
# reads the value at runtime.
#
ENV BUILD_DATE_EPOCH="${BUILD_DATE_EPOCH}"


# CI stage -- any customizations specific to CI platform compatibility should be added
# in this stage if it is not applicable to ASH outside of CI usage
FROM core AS ci

ENV ASH_TARGET=ci


# Final stage: Non-root user final version. This image contains all dependencies
# for ASH from the `core` stage, but ensures it is launched as a non-root user.
# Running as a non-root user impacts the ability to run ASH reliably across CI
# platforms and other orchestrators where the initialization and launch of the image
# is not configurable for customizing the running UID/GID.
FROM core AS non-root

ENV ASH_TARGET=non-root

ARG UID=500
ARG GID=100
ARG ASH_USER=ash-user
ARG ASH_GROUP=ash-group
ARG ASHUSER_HOME=/home/${ASH_USER}

#
# Create a non-root user in the container and run as this user
#
# And add GitHub's public fingerprints to known_hosts inside the image to prevent fingerprint
# confirmation requests unexpectedly
#
# ignore a failure to add the group
RUN addgroup --gid ${GID} ${ASH_GROUP} || :
RUN adduser --disabled-password --disabled-login \
    --uid ${UID} --gid ${GID} \
    ${ASH_USER} && \
    mkdir -p ${ASHUSER_HOME}/.ssh && \
    cp ${HOME}/.ssh/known_hosts ${ASHUSER_HOME}/.ssh/known_hosts

# Change ownership and permissions now that we are running with a non-root
# user by default.
#
# GRYPE_DB_CACHE_DIR and TRIVY_CACHE_DIR are handed to this user because grype's
# and trivy's database updates write them at scan time (utils/content_db_refresh.py);
# one owner, not writable by others. Not in an offline image: its databases were
# downloaded at build time and are never updated at scan time, so they stay root's
# and the scan user can only read them.
# ASH_BIN_PATH is handed over only for this stage's own `ash dependencies install`
# below, which puts this user's cfn-nag binstub and its own copy of the pinned tools
# there, and is given back to root right after it.
RUN chown -R ${UID}:${GID} ${ASHUSER_HOME} /src /out && \
    chmod 750 -R ${ASHUSER_HOME} /src /out && \
    chown -R ${UID}:${GID} ${ASH_BIN_PATH} && \
    if [ "${OFFLINE}" != "YES" ]; then \
        chown -R ${UID}:${GID} ${GRYPE_DB_CACHE_DIR} ${TRIVY_CACHE_DIR}; \
    fi

# The rules bundle a scan trusts is still root's after every change above.
RUN install-pinned-tool --assert-root-only "${ASH_CFN_GUARD_RULES_DIR}"

USER ${UID}:${GID}

#
# Set the HOME environment variable to be the HOME folder for the non-root user,
# along with any additional details that were set to root user values by default
#
ENV HOME=${ASHUSER_HOME}
ENV ASH_USER=${ASH_USER}
ENV ASH_GROUP=${ASH_GROUP}

ENV PATH="${ASHUSER_HOME}/.local/bin:$PATH"
# Pinned as in the core stage: this user's uv tool directory starts empty, so the
# Python tools are installed again here and would otherwise float.
RUN pins="$(install-pinned-tool --uv-tool-pins)" && \
    uv_tmp="$(mktemp -d)" && \
    { TMPDIR="${uv_tmp}" UV_NO_CACHE=1 ASH_OFFLINE=NO \
    ash dependencies install --bin-path "${ASH_BIN_PATH}" ${pins}; \
    status=$?; rm -rf "${uv_tmp:?}"; exit "${status}"; }

# ASH_BIN_PATH back to root, readable and executable by this user but not writable:
# nothing writes there at scan time. Then the core stage's sweep again, for the lock
# files uv left mode 666 under this user's home.
USER root
RUN chown -R root:root ${ASH_BIN_PATH} && chmod -R u=rwX,go=rX ${ASH_BIN_PATH} && \
    find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /tmp \
        -o -path /var/tmp -o -path /run/lock \) -prune -o \
        ! -type l -perm -0002 ! -perm -1000 -exec chmod go-w {} +
USER ${UID}:${GID}

HEALTHCHECK --interval=12s --timeout=12s --start-period=30s \
    CMD ["/bin/sh", "-c", "command -v ash || exit 1"]

ENTRYPOINT [ ]
CMD [ "ash" ]
