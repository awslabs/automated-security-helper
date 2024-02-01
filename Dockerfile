#checkov:skip=CKV_DOCKER_7: Base image is using a non-latest version tag by default, Checkov is unable to parse due to the use of ARG
#checkov:skip=CKV_DOCKER_3: ASH is focused on mounting source code into the container and scanning it, not running services. Setting USER breaks the ability for certain scanners to work correctly.
#
# Enable BASE_IMAGE as an overrideable ARG for proxy cache + private registry support
#
ARG BASE_IMAGE=public.ecr.aws/bitnami/python:3.10
#
# Platform is set to `linux/amd64` as that is the only platform
# the current BASE_IMAGE supports while we identify a solution
# for supporting arm64 as well.
#
FROM --platform=linux/amd64 ${BASE_IMAGE}

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
# Base dependency installation
#
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
      curl \
      python3-venv \
      git \
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
    python3 -m pip install checkov && \
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
    mkdir -p /run/scan/src \
    mkdir -p /ash

#
# COPY ASH source to /ash instead of / to isolate
#
COPY . /ash/

#
# Install CDK Nag stub dependencies
#
# Update NPM to latest
RUN npm install -g npm && \
    cd /ash/utils/cdk-nag-scan && \
    npm install --quiet

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
