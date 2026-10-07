# syntax=docker/dockerfile:1
#checkov:skip=CKV_DOCKER_2:Lambda manages the execution environment's lifecycle through the Runtime API and never reads a Docker HEALTHCHECK, so the instruction would have no effect here. Nor could an inherited one be relied on: the base image target is configurable, and only its non-root target declares a HEALTHCHECK.
#checkov:skip=CKV_DOCKER_7:The base image arrives through the ASH_BASE_IMAGE build argument, which has no default for Checkov to resolve. The buildspec supplies a tagged ECR URI.
#
# Makes the shared ASH image runnable as a Lambda container image.
#
# Two things are missing from a plain ASH image for this target:
#
#   1. A Lambda runtime interface client. The ASH image is not built from an AWS
#      Lambda base image, so it has no RIC and Lambda cannot invoke it. The
#      documented way to run a non-Lambda base image is to install awslambdaric
#      and make it the entrypoint.
#   2. git-remote-codecommit, which lets `git clone codecommit::<region>://<repo>`
#      authenticate with the Lambda role's own credentials. The alternative is
#      long-lived Git credentials or an AWS CLI credential helper, and the ASH
#      image ships neither the CLI nor a reason to hold static credentials.
#
# This is a separate build from ash-image-pipeline on purpose. Neither addition
# is useful to the AgentCore, Fargate, or CodeBuild targets, and awslambdaric
# needs an index reachable at build time, which would break an otherwise offline
# image build for all three.

ARG ASH_BASE_IMAGE
FROM ${ASH_BASE_IMAGE}

# The ASH non-root target sets a USER, and pip needs to write to site-packages.
USER root

# Versions and SHA256 digests are in the requirements file; see its header for
# why botocore is not listed.
COPY --chmod=0644 gate-requirements.txt /tmp/gate-requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/gate-requirements.txt && \
    rm /tmp/gate-requirements.txt

WORKDIR /var/task
COPY --chmod=0644 ash_pr_gate.py /var/task/ash_pr_gate.py

# Back to the ASH non-root target's identity (its UID and GID build-arg
# defaults), so the image does not end on root. Lambda does not use this: it
# runs a container image as its own least-privileged default user whatever USER
# says, which is why nothing here may depend on running as root. Numeric, so it
# resolves on the core and ci targets too, which create no named user.
ARG ASH_UID=500
ARG ASH_GID=100
USER ${ASH_UID}:${ASH_GID}

# The shared entrypoint runs first so the base ASH config from SSM is on disk
# before the runtime interface client starts accepting invocations, then execs
# into the RIC. Lambda appends the handler from CMD.
ENTRYPOINT ["/usr/local/bin/ash-container-init", "python", "-m", "awslambdaric"]
CMD ["ash_pr_gate.handler"]
