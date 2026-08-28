# syntax=docker/dockerfile:1
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
