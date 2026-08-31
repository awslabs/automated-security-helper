# syntax=docker/dockerfile:1
#checkov:skip=CKV_DOCKER_2:The base ASH image declares its own HEALTHCHECK and a derived image inherits it, which Checkov cannot see reading only this file. This image's target is Bedrock AgentCore Runtime, which probes the container over its own protocol rather than through Docker's healthcheck.
#checkov:skip=CKV_DOCKER_7:The base image arrives through the ASH_BASE_IMAGE build argument, which has no default for Checkov to resolve. The buildspec supplies a tagged ECR URI.
#checkov:skip=CKV_DOCKER_3:USER comes from the base ASH image, whose non-root target sets one. Checkov reads only this file and cannot see it. See the COPY --chmod comment below, which exists for that same reason.
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

ENTRYPOINT ["/usr/local/bin/ash-container-init"]
CMD ["/usr/local/bin/ash-mcp-serve"]
