# syntax=docker/dockerfile:1
#checkov:skip=CKV_DOCKER_2:Lambda manages the execution environment's lifecycle through the Runtime API and never reads a Docker HEALTHCHECK, so the instruction would have no effect here. The base ASH image declares one regardless, which this image inherits.
#checkov:skip=CKV_DOCKER_7:The base image arrives through the ASH_BASE_IMAGE build argument, which has no default for Checkov to resolve. The buildspec supplies a tagged ECR URI.
#checkov:skip=CKV_DOCKER_8:The USER root below is not reverted, and reverting it would break the image. ASH's scanners need root to run -- the reason the repository's own Dockerfile carries this same skip -- and this image is a Lambda function, where each invocation gets a single-tenant microVM with a read-only root filesystem outside /tmp, so root confers nothing across a boundary. No fixed UID could be restored in any case: the base image target is configurable, and only its non-root target defines one.
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

RUN pip install --no-cache-dir awslambdaric git-remote-codecommit

WORKDIR /var/task
COPY --chmod=0644 ash_pr_gate.py /var/task/ash_pr_gate.py

# The shared entrypoint runs first so the base ASH config from SSM is on disk
# before the runtime interface client starts accepting invocations, then execs
# into the RIC. Lambda appends the handler from CMD.
ENTRYPOINT ["/usr/local/bin/ash-container-init", "python", "-m", "awslambdaric"]
CMD ["ash_pr_gate.handler"]
