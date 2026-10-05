# syntax=docker/dockerfile:1
#checkov:skip=CKV_DOCKER_2:Nothing that runs this image reads a Docker HEALTHCHECK. Bedrock AgentCore Runtime probes the container over its own protocol, and the Fargate target is health-checked by its ALB target group rather than by the task definition. Inheriting one from the base could not be relied on in any case: the base image target is configurable, and only its non-root target declares a HEALTHCHECK.
#checkov:skip=CKV_DOCKER_7:The base image arrives through the ASH_BASE_IMAGE build argument, which has no default for Checkov to resolve. The buildspec supplies a tagged ECR URI.
#checkov:skip=CKV_DOCKER_3:No USER is set here, and no fixed uid could be: the base image target is configurable, and only its non-root target defines one -- the core and ci targets create no such user and chown nothing to it. Whether the running container is unprivileged is therefore decided by ash-image-pipeline's ash_image_target, which defaults to non-root and whose own description records that ci runs as root. See the COPY --chmod comment below, which exists because a USER may or may not be in effect.
#
# Thin wrapper over a freshly built ASH image.
#
# Why this stage exists: Amazon Bedrock AgentCore Runtime has no container
# command override — its container_configuration block accepts only
# container_uri. Anything the runtime needs to execute must therefore be the
# image's own ENTRYPOINT/CMD. Baking a fixed argv would freeze the MCP flags at
# image-build time, so instead the baked CMD is a launcher that reads its flags
# from environment variables. Every deployment target can then change transport,
# port, mount path, stateless mode, and the Host allowlist without a rebuild.
#
# ENTRYPOINT stays separate from CMD so that targets which *can* override the
# command (ECS, Lambda, CodeBuild) still get config and secret materialization.

ARG ASH_BASE_IMAGE
FROM ${ASH_BASE_IMAGE}

# COPY --chmod rather than a RUN chmod: the ASH image's non-root target sets a
# USER, under which a RUN could not write to /usr/local/bin. COPY always writes
# as uid 0 regardless of USER, so this works against every ASH build target.
# Requires BuildKit, which the buildspec enables explicitly.
#
# ASH declares boto3 as a runtime dependency, so both scripts reach SSM and
# Secrets Manager without adding anything to the image.
COPY --chmod=0755 ash-container-init /usr/local/bin/ash-container-init
COPY --chmod=0755 ash-mcp-serve /usr/local/bin/ash-mcp-serve

#
# Record where this build put the things a scan reads, under names no runtime
# rewrites.
#
# WHY: the Lambda gate in ../../codecommit-gate builds on this image, and Lambda
# runs a container image with a read-only root filesystem -- only /tmp is
# writable -- while also replacing PATH with its own. Every scanner path the ASH
# stage set up therefore points somewhere unwritable at scan time:
# GRYPE_DB_CACHE_DIR, SEMGREP_RULES_CACHE_DIR and OPENGREP_RULES_CACHE_DIR are
# under /deps, HOME is under / or /home, and uv writes a lock inside its own
# tool directory. The gate handler redirects all of them into /tmp and then seeds
# the writable copies from the locations recorded here.
#
# Without these, the redirection alone points the scanners at empty /tmp
# directories: uv reinstalls its tools from PyPI (which fails with no egress),
# and an image built with OFFLINE=YES cannot reach the vulnerability database and
# rulesets its own build proved are present -- so grype scans nothing and reports
# no findings. See _scan_env in
# ../../codecommit-gate/files/ash_pr_gate.py, which reads exactly these names.
#
# READ OFF THE STAGE, not written out as literals. ash-image-pipeline's
# ash_image_target selects which ASH stage this wraps, and the stages differ:
# only the non-root one declares ENV HOME. A literal path would be right for one
# target and silently wrong for another, and "silently wrong" here means an
# unseeded cache, which is the defect itself. Docker expands these against the
# values already present in the stage, so each records what this build produced.
#
# The HOME default covers the root-running stages (core, ci), which set no ENV
# HOME, so ${HOME} alone would expand to nothing. /root is what those stages
# resolve: the CDK flavor of this same Lambda image bakes
# ASH_BAKED_UV_TOOL_DIR="/root/.local/share/uv/tools" over the ci stage, and the
# read-only-filesystem failure recorded in deploy/cdk/lib/ash-container-scripts.ts
# names /root/.local/share/uv/tools as a measured write path.
ENV ASH_IMAGE_PATH="${PATH}"
ENV ASH_BAKED_UV_TOOL_DIR="${HOME:-/root}/.local/share/uv/tools"
ENV ASH_BAKED_GRYPE_DB_DIR="${GRYPE_DB_CACHE_DIR}"
ENV ASH_BAKED_SEMGREP_RULES_DIR="${SEMGREP_RULES_CACHE_DIR}"
ENV ASH_BAKED_OPENGREP_RULES_DIR="${OPENGREP_RULES_CACHE_DIR}"

ENTRYPOINT ["/usr/local/bin/ash-container-init"]
CMD ["/usr/local/bin/ash-mcp-serve"]
