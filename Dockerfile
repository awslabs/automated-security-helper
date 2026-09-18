#checkov:skip=CKV_DOCKER_7:Base image uses pinned tag via ARG, Checkov cannot parse ARG references
#checkov:skip=CKV_DOCKER_3:ASH container runs as root — scanners require root for package installs and system tool access
#checkov:skip=CKV_DOCKER_8:Same as CKV_DOCKER_3 — root is intentional for scanner tool execution
ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.12-slim-bookworm

# First stage: Build UV requirements
FROM ${BASE_IMAGE} AS uv-reqs

ENV PYTHONDONTWRITEBYTECODE=1
RUN apt-get clean && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates python3-venv git tree curl && \
    rm -rf /var/lib/apt/lists/*

ARG INSTALL_ASH_REVISION="LOCAL"
ARG ASH_REPO_CLONE_URL="https://github.com/awslabs/automated-security-helper.git"
ENV INSTALL_ASH_REVISION=${INSTALL_ASH_REVISION}
ENV ASH_REPO_CLONE_URL=${ASH_REPO_CLONE_URL}

# Install UV
COPY automated_security_helper/assets/with-retry.sh /usr/local/bin/with-retry
RUN chmod +x /usr/local/bin/with-retry
RUN with-retry 'curl -LsSf https://astral.sh/uv/install.sh | sh'
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /src
RUN [ "${INSTALL_ASH_REVISION}" != "LOCAL" ] && \
    git clone \
    --branch ${INSTALL_ASH_REVISION} \
    ${ASH_REPO_CLONE_URL} \
    . || echo "Skipping clone of repo for LOCAL revision"

# For LOCAL builds the build context is the repo root and supplies all sources.
# For non-LOCAL builds git clone above already populated /src; the COPY brings
# in any build-context overrides and is otherwise a no-op for files that only
# exist in the full repo.
# Using "COPY . ." instead of targeted globs avoids Podman/buildah errors on
# glob patterns that match nothing (Docker/Finch silently skip them, Podman doesn't).
COPY . .
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
ARG BUILD_DATE_EPOCH="-1"
ARG OFFLINE="NO"
ARG OFFLINE_SEMGREP_RULESETS="p/ci"
ARG ASH_BIN_PATH="/.ash/bin"

ARG INSTALL_ASH_REVISION="LOCAL"
ENV INSTALL_ASH_REVISION=${INSTALL_ASH_REVISION}

ENV ASH_BIN_PATH="${ASH_BIN_PATH}"
ENV OFFLINE="${OFFLINE}"
ENV OFFLINE_AT_BUILD_TIME="${OFFLINE}"
ENV ASH_OFFLINE="${OFFLINE}"
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
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gnupg \
    python3-venv \
    ripgrep \
    ruby \
    tree && \
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
    apt-get -qy install --no-install-recommends nodejs;
#
# Install UV in the core stage
#
RUN with-retry 'curl -LsSf https://astral.sh/uv/install.sh | sh'
ENV PATH="/root/.local/bin:$PATH"

#
# Python (no-op other than updating pip --- Python deps managed via Poetry @ pyproject.toml)
#
RUN with-retry 'curl -sSf https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3 get-pip.py'
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
COPY automated_security_helper/assets/Gemfile /deps/Gemfile
ARG BUNDLER_VERSION="2.4.22"
# One RUN for install, build and purge. `core` is the base for both `ci` and
# `non-root`, so a C toolchain left here ships in every published image, which is
# its own finding in a security scanner. Docker layers are additive, so purging in
# a later RUN would remove the compiler from the container while the image still
# carried it -- keeping all three steps in one layer means it never lands at all.
#
# apt-get update runs again because the base layer clears the package lists.
RUN echo "gem: --no-document" >> /etc/gemrc && \
    apt-get update && \
    apt-get install -y --no-install-recommends build-essential ruby-dev && \
    with-retry 'gem install bundler -v ${BUNDLER_VERSION}' && \
    with-retry 'bundle install --jobs=4' && \
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
ENV GRYPE_DB_CACHE_DIR="/deps/.grype"
ENV SEMGREP_RULES_CACHE_DIR="/deps/.semgrep"
ENV OPENGREP_RULES_CACHE_DIR="/deps/.opengrep"
RUN mkdir -p ${GRYPE_DB_CACHE_DIR} ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR} && \
    chmod 777 /deps ${GRYPE_DB_CACHE_DIR} ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR}
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
ENV ASH_PINS_DIR="/ash-pins"

ARG SYFT_VERSION="v1.42.4"
RUN with-retry 'install-pinned-tool syft -b /usr/local/bin'
RUN syft --version

ARG GRYPE_VERSION="v0.111.0"
RUN with-retry 'install-pinned-tool grype -b /usr/local/bin'
RUN grype --version

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
RUN set -uex; if [ "${OFFLINE}" = "YES" ]; then \
    with-retry 'grype db update' && \
    mkdir -p ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR} && \
    for i in $OFFLINE_SEMGREP_RULESETS; do \
        outfile="${SEMGREP_RULES_CACHE_DIR}/$(basename "${i}").yml"; \
        with-retry "curl -sSf https://semgrep.dev/c/${i} -o ${outfile}"; \
        cp "${outfile}" "${OPENGREP_RULES_CACHE_DIR}/$(basename "${i}").yml"; \
    done && \
    chmod -R 777 ${GRYPE_DB_CACHE_DIR} ${SEMGREP_RULES_CACHE_DIR} ${OPENGREP_RULES_CACHE_DIR}; \
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

ARG TRIVY_VERSION="v0.69.3"
RUN with-retry 'install-pinned-tool trivy -b /usr/local/bin'
RUN trivy --version

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
RUN uv pip install --system "$(ls *.whl)[cdk]" && rm -rf *.whl

#
# Make sure the ash script is executable
#
RUN chmod -R 755 /ash && chmod -R 777 /src /out ${ASH_BIN_PATH}

#
# Flag ASH as local execution mode since we are running in a container already
#
ENV _ASH_EXEC_MODE="local"

#
# Install dependencies via ASH CLI into
#
RUN ash dependencies install --bin-path "${ASH_BIN_PATH}"
ENV PATH="${ASH_BIN_PATH}:$PATH"

#
# Flag ASH as running in container to prevent ProgressBar panel from showing (causes output blocking)
#
ENV ASH_IN_CONTAINER="YES"

#
# Build metadata, deliberately last in this stage.
#
# BUILD_DATE_EPOCH changes on every invocation - run_ash_container.py passes
# --build-arg BUILD_DATE_EPOCH=<now>. Referencing it near the top of the stage
# invalidated every layer below it, so the apt/node/ruby/uv installs, the
# pinned syft+grype+trivy downloads and `ash dependencies install` were all
# rebuilt from scratch on every build, and no layer cache of any kind could
# ever hit. Nothing reads this value at runtime - it is referenced only here
# and in the ARG declaration - so evaluating it last keeps the metadata while
# leaving everything above it cacheable.
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
RUN chown -R ${UID}:${GID} ${ASHUSER_HOME} /src /out && \
    chmod 750 -R ${ASHUSER_HOME} /src /out

USER ${UID}:${GID}

#
# Set the HOME environment variable to be the HOME folder for the non-root user,
# along with any additional details that were set to root user values by default
#
ENV HOME=${ASHUSER_HOME}
ENV ASH_USER=${ASH_USER}
ENV ASH_GROUP=${ASH_GROUP}

ENV PATH="${ASHUSER_HOME}/.local/bin:$PATH"
RUN ash dependencies install --bin-path "${ASH_BIN_PATH}"

HEALTHCHECK --interval=12s --timeout=12s --start-period=30s \
    CMD command -v ash || exit 1

ENTRYPOINT [ ]
CMD [ "ash" ]
