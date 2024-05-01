#checkov:skip=CKV_DOCKER_7: Base image is using a non-latest version tag by default, Checkov is unable to parse due to the use of ARG
#
# Enable BASE_IMAGE as an overrideable ARG for proxy cache + private registry support
#
ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.10-bullseye
FROM ${BASE_IMAGE}

#
# Allow for UID and GID to be set as build arguments to this Dockerfile.
#
# Set the default values of UID/GID to non-zero (and above typical low-number UID/GID values which
# are defined by default).  500 and 100 are not special values or depended upon.
# Their selection as default values is only to set the default for this container to be non-zero.
#
# The actions performed in this image (CMD command) do not require root privileges.
# Thus, UID/GID are set non-zero to avoid someone inadvertantly running this image in a container
# that runs privileged and as as root(UID 0).
#
# If the environment in which the container will run requires a specific UID/GID, then --build-arg
# arguments on the ${OCI_RUNNER} build command can be used to over-ride these values.
#
ARG UID=500
ARG GID=100

#
# Setting timezone in the container to UTC to ensure logged times are universal.
#
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

#
# General / shared component installation
#
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
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
      curl \
      python3-venv \
      git \
      ripgrep \
      ruby-dev \
      tree && \
    rm -rf /var/lib/apt/lists/*

#
# Install nodejs@18 using latest recommended method
#
RUN set -uex; \
    apt-get update; \
    apt-get install -y ca-certificates curl gnupg; \
    mkdir -p /etc/apt/keyrings; \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
     | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
    NODE_MAJOR=18; \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" \
     > /etc/apt/sources.list.d/nodesource.list; \
    apt-get -qy update; \
    apt-get -qy install nodejs;
#
# Install and upgrade pip
#
RUN wget https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py
RUN python3 -m pip install --no-cache-dir --upgrade pip

#
# Git (git-secrets)
#
RUN git clone https://github.com/awslabs/git-secrets.git && \
    cd git-secrets && \
    make install

#
# Python
#
RUN python3 -m pip install --no-cache-dir \
    bandit \
    nbconvert \
    jupyterlab

#
# YAML (Checkov, cfn-nag)
#
RUN echo "gem: --no-document" >> /etc/gemrc && \
    python3 -m pip install checkov pathspec && \
    gem install cfn-nag

#
# JavaScript: (no-op --- node is already installed in the image, nothing else needed)
#

#
# Grype/Syft/Semgrep
#
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
    sh -s -- -b /usr/local/bin

RUN python3 -m pip install semgrep

# Setting PYTHONPATH so Jinja2 can resolve correctly
# IMPORTANT: This is predicated on the Python version that is installed!
#            Changing the BASE_IMAGE may result in this breaking.
ENV PYTHONPATH='/opt/bitnami/python/lib/python3.10/site-packages'

#
# Prerequisite installation complete, finishing up
#
#
# Setting default WORKDIR to /src
WORKDIR /src

#
# Make sure the default dirs are initialized
#
RUN mkdir -p /src && \
    mkdir -p /out && \
    mkdir -p /ash/utils

#
# Install CDK Nag stub dependencies
#
# Update NPM to latest
COPY ./utils/cdk-nag-scan /ash/utils/cdk-nag-scan/
RUN npm install -g npm pnpm yarn && \
    cd /ash/utils/cdk-nag-scan && \
    npm install --quiet

#
# COPY ASH source to /ash instead of / to isolate
#
COPY ./utils/cfn-to-cdk /ash/utils/cfn-to-cdk/
COPY ./utils/*.* /ash/utils/
COPY ./appsec_cfn_rules /ash/appsec_cfn_rules/
COPY ./ash-multi /ash/ash
COPY ./__version__ /ash/__version__

RUN chmod -R +r /ash && chmod +x /ash/ash

#
# Create a non-root user in the container and run as this user
#
# And add GitHub's public fingerprints to known_hosts inside the image to prevent fingerprint
# confirmation requests unexpectedly
#
ARG ASHUSER_HOME=/home/ash-user
RUN addgroup --gid ${GID} ash-group || \
    adduser --disabled-password --disabled-login --gecos "" \
        --uid ${UID} --gid ${GID} \
        ash-user && \
    mkdir -p ${ASHUSER_HOME}/.ssh && \
    echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" >> ${ASHUSER_HOME}/.ssh/known_hosts && \
    echo "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=" >> ${ASHUSER_HOME}/.ssh/known_hosts && \
    echo "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=" >> ${ASHUSER_HOME}/.ssh/known_hosts && \
    chown -R ${UID}:${GID} ${ASHUSER_HOME}
# Setting default WORKDIR to ${ASHUSER_HOME}
WORKDIR ${ASHUSER_HOME}

USER ${UID}:${GID}

#
# Set the HOME environment variable to be the HOME folder for the non-root user
#
ENV HOME=${ASHUSER_HOME}

#
# Flag ASH as local execution mode since we are running in a container already
#
ENV _ASH_EXEC_MODE="local"

#
# Append /ash to PATH to allow calling `ash` directly
#
ENV PATH="$PATH:/ash"

# nosemgrep
HEALTHCHECK --interval=12s --timeout=12s --start-period=30s \
    CMD type ash || exit 1

#
# The ENTRYPOINT needs to be NULL for CI platform support
# This needs to be an empty array ([ ]), as nerdctl-based runners will attempt to
# resolve an empty string in PATH, unlike Docker which treats an empty string the
# same as a literal NULL
#
ENTRYPOINT [ ]

#
# CMD will be run when invoking it via `$OCI_RUNNER run ...`, but will
# be overridden during CI execution when used as the job image directly.
#
CMD [ "ash" ]
