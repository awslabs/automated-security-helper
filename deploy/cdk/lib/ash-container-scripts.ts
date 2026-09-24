/**
 * The scripts baked into the ASH container images.
 *
 * WHY THESE LIVE IN TYPESCRIPT
 * ----------------------------
 * They are written into the image by the CodeBuild buildspec, so they must
 * travel with the CDK app rather than with the ASH source tree. Keeping them as
 * exported constants means the unit tests can assert on their contents, and a
 * reviewer can read the container's real entrypoint without decoding a
 * buildspec.
 *
 * THE CONSTRAINT THAT SHAPES THE MCP ENTRYPOINT
 * ---------------------------------------------
 * `AWS::BedrockAgentCore::Runtime` exposes exactly one knob for the container:
 * `AgentRuntimeArtifact.ContainerConfiguration.ContainerUri`. There is no
 * `Command`, `EntryPoint` or `Args` property. So the MCP invocation CANNOT be
 * supplied by the template — it has to be baked into the image. ASH's own
 * Dockerfile ends with `ENTRYPOINT [] / CMD ["ash"]`, which would run `ash` with
 * no arguments and exit.
 * https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-bedrockagentcore-runtime-containerconfiguration.html
 *
 * That is why the entrypoint is a script rather than a fixed `CMD` line: the
 * command must be inside the image, but adopters still need to change the mount
 * path, the stateless flag and the allowed hosts without rebuilding. The script
 * reads those from environment variables, which every target CAN set.
 *
 * WHY `python3` AND NOT THE AWS CLI
 * ---------------------------------
 * The ASH image does not install the AWS CLI. It does depend on `boto3`
 * (declared in ASH's pyproject.toml `dependencies`), so `python3 -c` with boto3
 * is the only AWS API client guaranteed to be present. An entrypoint that
 * shelled out to `aws ssm get-parameter` would fail at container start.
 */

/**
 * Path the base ASH configuration is materialized to inside the container.
 *
 * It is exported via `ASH_CONFIG` rather than dropped into a scan directory.
 * `get_default_config()` in ASH reads `ASH_CONFIG` from the process environment
 * directly, so the deployment-wide default applies to every scan the process
 * runs — including MCP-initiated scans of arbitrary directories, which never see
 * a config placed next to the server. A `.ash.yaml` inside the scanned
 * repository still wins, which is the precedence adopters expect: project config
 * overrides the deployment default.
 */
export const ASH_MATERIALIZED_CONFIG_PATH = '/tmp/ash-config/.ash.yaml';

/**
 * Path the S3 helper below is written to inside the build container.
 *
 * Under `/tmp` rather than in the build's working directory, which for a
 * CodeBuild build is the source tree ASH is about to scan. A helper dropped there
 * would become part of the scanned repository and show up in the findings as the
 * deployment's own file.
 */
export const ASH_S3_SYNC_PATH = '/tmp/ash-s3-sync.py';

/**
 * Recursive S3 upload and download, for the buildspecs that run in the ASH image.
 *
 * WHY THIS EXISTS AT ALL
 * ---------------------
 * The shard and merge actions of the distributed pipeline use the ASH image as
 * their CodeBuild environment image. That is what puts `ash` directly on PATH with
 * no Docker-in-Docker and no privileged build, and the trade is the constraint the
 * header of this file describes: the image ships git, curl and boto3, but no AWS
 * CLI. `aws s3 cp --recursive` is not available there. It exits 127.
 *
 * WHY A SCRIPT RATHER THAN AN INLINE `python3 -c`
 * ----------------------------------------------
 * The SSM and Secrets Manager reads elsewhere in this file are single API calls
 * and fit on one line. A recursive download does not: it has to paginate
 * ListObjectsV2, recreate the key hierarchy as directories, and refuse a key that
 * would escape the destination. Squeezed into a `-c` one-liner, the part that gets
 * dropped first is the containment check, which is the part that matters.
 *
 * RELATIONSHIP TO THE TERRAFORM MIRROR
 * -----------------------------------
 * `deploy/terraform/modules/codepipeline-executor/files/ash_s3_sync.py` is the
 * same helper for the same reason, and this is deliberately kept behaviourally
 * identical to it. The two are separate copies because the two deployment trees
 * are independently consumable — an adopter vendoring `deploy/terraform` gets no
 * `deploy/cdk` — and each tree already keeps its own copy of the scripts it
 * injects. They differ in exactly one respect, and only because of how each tool
 * renders: Terraform base64-encodes the file into its buildspec, because
 * `templatefile` would otherwise interpolate `${...}` inside the Python. CDK has
 * no such rendering step, so this is written out through a quoted heredoc instead
 * and stays readable in the committed CloudFormation template.
 *
 * NOT REPRESENTED: empty directories. S3 has no such object, so a directory that
 * held no files upstream is not recreated on download. Nothing here depends on
 * one — every consumer looks for `ash_aggregated_results.json`.
 */
export const ASH_S3_SYNC_SCRIPT = `#!/usr/bin/env python3
"""Minimal recursive S3 upload and download, using boto3.

Written into the build container by the ASH CDK deployment targets; see
deploy/cdk/lib/ash-container-scripts.ts. Exists because these builds run inside
the ASH image, which ships boto3 but not the AWS CLI.

Usage:
    ash-s3-sync.py upload   <local-dir> <bucket> <key-prefix>
    ash-s3-sync.py download <bucket> <key-prefix> <local-dir>

Both directions are recursive. Empty directories are not represented in S3 and
are therefore not recreated on download.
"""

from __future__ import annotations

import pathlib
import sys

import boto3


def _fail(message: str) -> None:
    print(f"ash-s3-sync: {message}", file=sys.stderr)
    raise SystemExit(2)


def upload(local_dir: str, bucket: str, prefix: str) -> int:
    root = pathlib.Path(local_dir)
    if not root.is_dir():
        _fail(f"{local_dir} is not a directory")

    client = boto3.client("s3")
    prefix = prefix.strip("/")
    count = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        key = f"{prefix}/{relative}" if prefix else relative
        client.upload_file(str(path), bucket, key)
        count += 1

    print(f"ash-s3-sync: uploaded {count} file(s) to s3://{bucket}/{prefix}/")
    return count


def download(bucket: str, prefix: str, local_dir: str) -> int:
    client = boto3.client("s3")
    prefix = prefix.strip("/")
    root = pathlib.Path(local_dir)
    root.mkdir(parents=True, exist_ok=True)

    paginator = client.get_paginator("list_objects_v2")
    count = 0

    for page in paginator.paginate(Bucket=bucket, Prefix=f"{prefix}/" if prefix else ""):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            relative = key[len(prefix) + 1 :] if prefix else key
            if not relative:
                continue
            destination = root / relative

            # Refuse a key that would escape the destination directory. S3 keys
            # are attacker-influenced in the general case, and a key containing
            # ".." would otherwise write outside local_dir.
            resolved = destination.resolve()
            if not resolved.is_relative_to(root.resolve()):
                _fail(f"key {key!r} would write outside {local_dir}")

            destination.parent.mkdir(parents=True, exist_ok=True)
            client.download_file(bucket, key, str(destination))
            count += 1

    print(f"ash-s3-sync: downloaded {count} file(s) from s3://{bucket}/{prefix}/")
    return count


def main(argv: list[str]) -> int:
    if not argv:
        _fail("expected a subcommand: upload or download")

    action, rest = argv[0], argv[1:]

    if action == "upload":
        if len(rest) != 3:
            _fail("upload takes <local-dir> <bucket> <key-prefix>")
        upload(rest[0], rest[1], rest[2])
    elif action == "download":
        if len(rest) != 3:
            _fail("download takes <bucket> <key-prefix> <local-dir>")
        download(rest[0], rest[1], rest[2])
    else:
        _fail(f"unknown subcommand {action!r}; expected upload or download")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
`;

/**
 * Write the S3 helper into the container, for a buildspec phase to use later.
 *
 * A QUOTED heredoc delimiter. With `<<'PY'` the shell performs no expansion on
 * the body at all, so the Python's `$`, backticks and `{}` reach the file
 * verbatim. An unquoted `<<PY` would let the shell eat them, and the failure would
 * be a syntax error inside a generated file nobody is looking at.
 *
 * This has to run in a phase that precedes every use of the helper. CodeBuild
 * phases of one build share a filesystem, so `pre_build` covers a later
 * `post_build`, which is the shape both projects below need.
 */
export const MATERIALIZE_S3_SYNC_COMMAND = `cat > ${ASH_S3_SYNC_PATH} <<'PY'
${ASH_S3_SYNC_SCRIPT}PY`;

/**
 * Shell entrypoint for the MCP-serving image flavor.
 *
 * WHY IT PROBES ASH INSTEAD OF ASSUMING ITS OPTIONS
 * ------------------------------------------------
 * This script is fixed when the image is built, but the ASH inside the image is
 * whatever `AshVersion` names at deploy time. Measured across the repository:
 * `--stateless-http` and `--allowed-host` exist on neither v3.5.x, v3.6.0,
 * v3.7.0, `main` nor `beta` — the word `stateless` appears nowhere under
 * `automated_security_helper/cli` at v3.7.0. Emitting them unconditionally made
 * the shipped default (`AshVersion=v3.7.0`) undeployable: Typer rejects the
 * unknown option, the server never binds, and CloudFormation reports a
 * health-check timeout rather than the flag that caused it.
 *
 * So the script asks `ash mcp --help` once and branches on what it finds.
 *
 * WHAT WAS TRIED AND REJECTED
 * ---------------------------
 * - Pointing `DEFAULT_ASH_VERSION` at a ref that has the flags: rejected. The
 *   only such ref is a feature branch. A moving branch is not a reproducible
 *   default, and pinning adopters to someone's in-flight work is worse than
 *   pinning them to a release.
 * - Emitting the flags conditionally with NO refusal path: rejected outright.
 *   Dropping `--stateless-http` yields a stateful server, which is the exact
 *   failure the flag prevents. A quiet downgrade there produces a container that
 *   passes its health check and answers 404 to every real request.
 * - Asserting the flags at BUILD time and failing the image build: rejected as a
 *   guard that would make the runtime branch unreachable. The build cannot see
 *   `ASH_MCP_STATELESS`, which is a deploy-time value, so it could only refuse on
 *   the flags' absence — banning the one combination that genuinely works on an
 *   older ASH (stateful, single replica). It would also be a second guard for the
 *   same fault, and the untaken one would never be exercised.
 * - Probing by running `ash mcp --stateless-http --help` and reading the exit
 *   code: rejected. Whether Click services the eager `--help` before or after it
 *   rejects an unknown option is version-dependent, so the probe could report
 *   success for a flag that does not exist — the one error direction that must
 *   not happen.
 *
 * `ASH_MCP_STATELESS_FALLBACK`, AND WHY THE SHIPPED DEFAULTS NEEDED IT
 * -------------------------------------------------------------------
 * The refusal above is correct and it made the one-click templates undeployable
 * with their own defaults. `AshVersion` defaults to `v3.7.0`, whose `ash mcp` has
 * no `--stateless-http`, and `McpStatelessHttp` defaults to `true`, so the
 * entrypoint took the refusal branch and exited 65 before the server ever bound.
 * An adopter who changed nothing got a container that never started and a
 * CloudFormation health-check timeout naming no cause.
 *
 * Both defaults are individually right. `v3.7.0` is the newest release, and
 * pinning adopters to a feature branch is worse; `true` is what AWS documents as
 * the AgentCore default and what is correct behind any multi-replica load
 * balancer. The defect is the COMBINATION, so the fix is a third value that lets a
 * deployment say which way to resolve it.
 *
 * `refuse` is the default when the variable is unset, so nothing an existing
 * deployment does changes. `warn` starts stateful and says so loudly. Only the
 * AgentCore stack sets `warn`, and only because that is where stateful was
 * MEASURED to work — a live runtime completed initialize, tools/list and
 * tools/call, with controls proving sessions were genuinely enforced. The residual
 * hazard there is narrower than the old refusal message claimed: not "rejects
 * every session id the platform injects", which was measured false, but a client
 * that follows AgentCore's own guidance to adopt the rotating id it returns, which
 * is refused on its third call. That message has been corrected to say so.
 *
 * This is maintainer decision D6's second option. The first — moving
 * `DEFAULT_ASH_VERSION` to a ref whose `ash mcp` accepts the flag — is the right
 * end state and needs a release cut from `main`, which no change here can make.
 * When that release exists, delete this fallback rather than keeping both.
 *
 * The Fargate stack deliberately does NOT set it. Its hazard is a load balancer
 * routing consecutive requests to different replicas, which no measurement here
 * excuses, so that target keeps exiting 65 until its `AshVersion` can serve
 * stateless.
 *
 * KNOWN LIMITATION: ASH takes the shared-secret value as `--auth-header-value`,
 * a command-line argument, and exposes no environment-variable equivalent for
 * it. The resolved secret is therefore visible in the container's own process
 * list. Nothing outside the container can read it, and it never reaches the
 * template or the task definition, but a process running inside the same
 * container could. Closing that would need an env-var option in ASH itself.
 *
 * WHY THE ALLOWED HOSTS ARE FOLDED TO LOWER CASE
 * ---------------------------------------------
 * Every request through the Fargate load balancer returned HTTP 421 "Invalid Host
 * header". The load balancer lowercases the `Host` header it forwards, and the MCP
 * SDK compares case-sensitively — `mcp/server/transport_security.py`
 * `_validate_host` tries `if host in self.settings.allowed_hosts` and then a
 * `":*"` port-suffix loop built on `host.startswith(...)`. NEITHER path folds
 * case, so a mixed-case allowed value matches on neither. The stack feeds it
 * `loadBalancerDnsName`, which CloudFormation returns mixed-case, so the
 * comparison could never succeed.
 *
 * Diagnosed by a same-instant differential rather than by reading alone: through
 * the load balancer the container logged an all-lowercase host and answered 421,
 * while the identical mixed-case value sent straight to the task's private IP
 * answered 200. A port-suffix explanation was raised and refuted with controls.
 * After the fold, via-load-balancer returned 200 with a full `tools/list`, and a
 * bogus Host on the same path still returned 421 — so the guard still guards.
 *
 * REJECTED: lowercasing in TypeScript instead. `loadBalancerDnsName` is a
 * deploy-time attribute, so at synth time there is no string to fold and
 * CloudFormation has no lower-case intrinsic. Same constraint that put the Docker
 * tag folding in the buildspec rather than in the CDK.
 *
 * REJECTED: relying on a future `mcp` release comparing case-insensitively. ASH
 * declares `mcp>=2.0.0,<3`, so the resolved version moves under us; a fix that
 * depends on library behaviour we do not pin would regress silently.
 *
 * KNOWN LIMITATION: the probe costs one `ash mcp --help` — a Python import of
 * ASH's CLI — at every container start. That is well inside the five-minute
 * health-check grace period the Fargate target allows.
 *
 * WHERE TO PUT AN EXPLANATION, AND WHY IT MATTERS HERE
 * ---------------------------------------------------
 * Comments inside the script below are not free. The script is inlined into the
 * buildspec, which is inlined into every synthesized template, and CloudFormation
 * refuses an inline `--template-body` over 51,200 bytes — a ceiling two of these
 * templates sit just under. This JSDoc, by contrast, is stripped at synth and
 * costs nothing.
 *
 * So the reasoning lives here and the script carries only what an operator
 * reading the container's entrypoint needs. Please keep that split; re-expanding
 * the shell comments spends template budget that the launch path depends on.
 */
export const MCP_ENTRYPOINT_SCRIPT = `#!/bin/sh
# Entrypoint for the ASH MCP server. Generated by the ASH CDK deployment
# targets; see deploy/cdk/lib/ash-container-scripts.ts.
set -eu

# Materialize the deployment-wide ASH config, when one was supplied. Written to
# a fixed path and exported through ASH_CONFIG so it applies to every scan this
# process runs, not just scans of one directory.
if [ -n "\${ASH_BASE_CONFIG_SSM_PARAMETER:-}" ]; then
  mkdir -p "$(dirname "\${ASH_CONFIG:-/tmp/ash-config/.ash.yaml}")"
  python3 -c "import os, sys, boto3; sys.stdout.write(boto3.client('ssm').get_parameter(Name=os.environ['ASH_BASE_CONFIG_SSM_PARAMETER'], WithDecryption=True)['Parameter']['Value'])" \\
    > "\${ASH_CONFIG:-/tmp/ash-config/.ash.yaml}"
else
  # No config supplied. Unset ASH_CONFIG so ASH does not log a missing-file
  # notice on every scan and falls through to its built-in defaults.
  unset ASH_CONFIG || true
fi

# Resolve the shared secret from its ARN. The ARN travels in the environment;
# the value never does, so it stays out of the template, the task definition and
# the runtime's environment-variable map.
ASH_AUTH_VALUE=""
if [ -n "\${ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN:-}" ]; then
  ASH_AUTH_VALUE=$(python3 -c "import os, sys, boto3; sys.stdout.write(boto3.client('secretsmanager').get_secret_value(SecretId=os.environ['ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN'])['SecretString'])")
fi

# Ask this image's ASH which MCP options it accepts, once. AshVersion decides
# which ASH is in here at deploy time, and older releases have neither
# --stateless-http nor --allowed-host; passing an unknown option would leave the
# server unable to bind. COLUMNS is wide so rich cannot wrap a flag name across
# lines and make a supported option measure as missing.
if ! ASH_MCP_HELP="$(COLUMNS=200 ash mcp --help 2>&1)"; then
  echo "ash-mcp-entrypoint: 'ash mcp --help' exited non-zero, so this image cannot serve MCP at all. This is not a missing option; it is a broken ASH install. Its output was:" >&2
  printf '%s\\n' "\${ASH_MCP_HELP}" >&2
  exit 69
fi

# Fixed-string match, so a flag name is never interpreted as a regex.
ash_mcp_supports() {
  printf '%s' "\${ASH_MCP_HELP}" | grep -qF -- "$1"
}

set -- ash mcp --transport streamable-http \\
  --host "\${ASH_MCP_HOST:-0.0.0.0}" \\
  --port "\${ASH_MCP_PORT:-8000}" \\
  --mount-path "\${ASH_MCP_MOUNT_PATH:-/mcp}"

# --stateless-http is a paired flag, so state the intent rather than inheriting
# ASH's default. Refuses to start if stateless was asked for and this ASH has no
# such option: running stateful instead would answer 404 to every session id the
# platform injects while still passing the health check.
if [ "\${ASH_MCP_STATELESS:-true}" = "true" ]; then
  if ash_mcp_supports '--stateless-http'; then
    set -- "$@" --stateless-http
  elif [ "\${ASH_MCP_STATELESS_FALLBACK:-refuse}" = "warn" ]; then
    echo "ash-mcp-entrypoint: WARNING: stateless was asked for, but the ASH in this image has no --stateless-http option, so this server runs STATEFUL. It honors only the session id it issued at initialize, so a client that adopts the id returned on each response is refused on its third call. Deploy an AshVersion whose 'ash mcp' accepts --stateless-http to remove this." >&2
  else
    echo "ash-mcp-entrypoint: this deployment asks for a stateless MCP server, but the ASH in this image has no --stateless-http option, so the server would run stateful and honor only the session id it issued at initialize. Deploy an AshVersion whose 'ash mcp' accepts --stateless-http, set McpStatelessHttp=false to run stateful deliberately, or set ASH_MCP_STATELESS_FALLBACK=warn to start stateful with a warning." >&2
    exit 65
  fi
elif ash_mcp_supports '--no-stateless-http'; then
  set -- "$@" --no-stateless-http
fi
# The remaining case needs no flag and is not a degradation: stateful was asked
# for, and an ASH without the option is already stateful.

# --allowed-host is repeatable, so split the comma-separated value and pass one
# flag per hostname; a comma-joined single value would match nothing. Warns
# rather than refusing when the option is absent: the Fargate stack always
# substitutes its load balancer DNS name here, so there is no parameter value an
# operator could set to satisfy a refusal.
if [ -n "\${ASH_MCP_ALLOWED_HOST:-}" ]; then
  if ash_mcp_supports '--allowed-host'; then
    ASH_SAVED_IFS=$IFS
    IFS=,
    for ash_host in \${ASH_MCP_ALLOWED_HOST}; do
      if [ -n "$ash_host" ]; then
        # Lower-cased because a load balancer lowercases Host while the MCP SDK
        # matches case-sensitively; mixed case yields 421 on every request.
        ash_host=$(printf '%s' "$ash_host" | tr 'A-Z' 'a-z')
        set -- "$@" --allowed-host "$ash_host"
      fi
    done
    IFS=$ASH_SAVED_IFS
  else
    echo "ash-mcp-entrypoint: WARNING: a Host allowlist of '\${ASH_MCP_ALLOWED_HOST}' was requested, but the ASH in this image has no --allowed-host option, so EVERY Host header will be accepted. Deploy an AshVersion whose 'ash mcp' accepts --allowed-host to enforce the allowlist." >&2
  fi
fi

# Both halves are required: a header name with no value would make ASH compare
# against an empty secret.
if [ -n "\${ASH_MCP_AUTH_HEADER_NAME:-}" ] && [ -n "$ASH_AUTH_VALUE" ]; then
  set -- "$@" --auth-header-name "\${ASH_MCP_AUTH_HEADER_NAME}" --auth-header-value "$ASH_AUTH_VALUE"
elif [ -n "\${ASH_MCP_AUTH_HEADER_NAME:-}" ]; then
  echo "ash-mcp-entrypoint: McpAuthHeaderName was set but no secret value resolved; refusing to start an unauthenticated server that the deployment expected to authenticate." >&2
  exit 64
fi

exec "$@"
`;

/**
 * Lambda handler for the one-shot CodeCommit pull-request gate.
 *
 * WHY A FULL CLONE AND NOT THE CodeCommit BLOB APIs: reconstructing the tree
 * from `GetDifferences` + `GetBlob` would only ever give ASH the changed files,
 * and several ASH scanners need whole-repository context — a lockfile to
 * resolve dependencies, a project file to detect the language. Installing
 * `git-remote-codecommit` into this image flavor lets git clone over the
 * `codecommit::` transport using the function's own IAM role, so ASH sees a real
 * working tree. ASH's own `--changed-files-only --base-ref` then narrows the
 * scan to the pull request's diff while keeping that context.
 *
 * FAILURE MODES:
 * - Lambda's ceiling is 900 seconds. A large repository or a slow scanner set
 *   will hit it. The scan is killed and the gate reports failure rather than
 *   silently passing; adopters who outgrow it should use the CodePipeline target.
 * - The clone and the scan output both land in /tmp, which is sized by the
 *   function's ephemeral storage. A repository plus ASH's output larger than
 *   that fails the scan.
 * - `PullRequestCannotBeApprovedByAuthorException` is caught: if the function's
 *   role happens to have opened the pull request, the comment is still posted
 *   and only the approval is skipped.
 */
/**
 * WHY `_scan_env` EXISTS — A MEASURED FAILURE, NOT A PRECAUTION
 * ------------------------------------------------------------
 * This prose lives in a TypeScript comment rather than in the handler's own
 * docstring because every byte inside the template literal below is copied into
 * the synthesized CloudFormation template, and `AshCodeCommitGate` is launched
 * inline. CreateStack/UpdateStack/ValidateTemplate cap `TemplateBody` at 51,200
 * bytes, and that template has almost no room left. Explaining the fix here
 * costs nothing; explaining it in the docstring cost ~2.5 KB of the budget.
 * https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ValidateTemplate.html
 *
 * Lambda requires a container image to run on a READ-ONLY root filesystem with
 * only /tmp writable, and it sets its own PATH. Deployed without `_scan_env`, a
 * real scan of a three-file repository reported bandit, checkov and semgrep as
 * MISSING, opengrep as ERROR, and — worst of the four — grype as PASSED with
 * zero findings, because ASH's scanner toolchain writes to the root filesystem
 * at scan time:
 *
 *   /root/.cache/uv/.tmpXXXX               uv's lock (bandit, checkov, semgrep)
 *   /root/.local/share/uv/tools/.tmpXXXX   uv's tool dir, same three
 *   /root/.cache/opengrep/<ver>/*.bin      opengrep extracts its binary
 *   /root/.opengrep                        opengrep state
 *   /deps/.grype                           grype's vulnerability database
 *
 * Every one of those raised "Read-only file system (os error 30)". The scan
 * finished in 9.9s instead of ~80s and the gate reported "passed", so a pull
 * request could be approved by a gate that had scanned nothing. Redirecting
 * these into /tmp restores all ten scanners and every finding.
 *
 * WHY THE uv TOOL DIR IS SYMLINKED RATHER THAN COPIED
 * ---------------------------------------------------
 * uv needs to write a lock INSIDE its tool dir, but the tools themselves are
 * already baked into the image. Pointing UV_TOOL_DIR at an empty /tmp path makes
 * uv reinstall all three from PyPI, which happens to work today only because
 * this function is not attached to a VPC and therefore has internet egress — it
 * fails outright with no network, and would fail in an OFFLINE=YES image.
 * Copying the baked tree instead costs 506 MB of the same ephemeral storage the
 * clone and ASH's output draw on. Symlinking each entry gives uv a writable
 * parent while the tools resolve to the baked copies: no network, no bytes.
 * Verified against the deployed image with the root filesystem read-only and
 * networking disabled.
 *
 * DIRECTORIES ONLY, AND WHY THAT LINE IS LOAD-BEARING
 * ---------------------------------------------------
 * The baked tree also holds uv's own `.lock` and a `.gitignore`. A shell glob
 * skips those; `os.listdir` does not. Linking `.lock` aims uv's lock at a file
 * on the read-only root filesystem — reintroducing the exact failure this
 * function prevents, while looking correctly seeded. The first version of this
 * fix did precisely that and three scanners still ERRORed. Do not remove the
 * `isdir` check.
 *
 * THE SAME PROBLEM FOR THE SCANNERS' OWN DATA, AND WHY IT IS FATAL OFFLINE
 * -----------------------------------------------------------------------
 * Redirecting the three data caches (`/deps/.grype`, `/deps/.semgrep`,
 * `/deps/.opengrep`) into /tmp makes them writable and, on its own, makes them
 * EMPTY. An image built with `AshOfflineMode=YES` has a vulnerability database
 * and semgrep/opengrep rulesets baked into those directories — the Dockerfile
 * asserts they are non-empty at build time, at Dockerfile:312 — and the redirect
 * put them out of reach at scan time. grype with no database reports PASSED with
 * zero findings, so the build-time assertion was defeated by the runtime and the
 * gate reported a clean scan of an unexamined tree.
 *
 * So each redirected cache is seeded from the location the image recorded, and an
 * OFFLINE scan whose redirected caches are still empty afterwards REFUSES rather
 * than scanning. The refusal is checked on the outcome — is the writable path
 * empty — rather than on whether the variables are set, because an assertion that
 * re-tested the inputs would be silenced by whatever silenced the seeding. That is
 * the same reasoning as the Dockerfile's own assertion, which deliberately checks
 * the artifacts rather than re-testing OFFLINE.
 *
 * DIRECTORIES ARE LINKED, FILES ARE COPIED
 * ----------------------------------------
 * A baked directory holds content a scanner only reads — grype's database lands in
 * a versioned subdirectory — so a link costs none of the ephemeral storage the
 * clone and ASH's output already draw on. A baked FILE is what a scanner is most
 * likely to rewrite in place, and a link to one aims that write at the read-only
 * layer: it would look seeded and fail at scan time. So files are copied, which is
 * what makes the semgrep and opengrep rulesets usable.
 *
 * The uv tool dir keeps its directories-only rule and does NOT copy files, for the
 * reason in the section above: uv must create its own lock inside UV_TOOL_DIR, and
 * a copy of the baked one is a stale lock rather than an absent one.
 *
 * OTHER FAILURE MODES
 * -------------------
 * If ASH_IMAGE_PATH is absent the current PATH is kept, so a locally-run handler
 * behaves normally. If the baked tool dir is absent, seeding is skipped rather
 * than fatal, and the affected scanners degrade to MISSING as they did before —
 * visibly, in the report. Seeding is idempotent, so a warm invocation re-uses
 * what the cold one linked. HOME is set last-ish on purpose: several tools
 * derive their own paths from it, and /root is not writable.
 *
 * An ONLINE scan whose caches are empty is logged and allowed: grype can still
 * fetch a database, so the scan is slow rather than blind.
 *
 * WHERE THE REFUSAL GOES, AND WHY IT IS NOT JUST A RAISE
 * -----------------------------------------------------
 * `_scan_env` is called BEFORE the clone, and a `RuntimeError` from it is caught,
 * commented onto the pull request, and routed through `_set_approval` with an
 * errored verdict before being re-raised. A bare raise would fail the invocation
 * with nothing on the pull request and — worse — would leave an APPROVE standing
 * from an earlier, cleaner commit on code this gate has just declined to examine.
 * That is the same stale-approval shape the Terraform flavor of this gate was
 * fixed for, so `_set_approval` exists to be shared by both paths rather than
 * having the approval logic inline on only one of them.
 */
export const CODECOMMIT_GATE_HANDLER = `# ASH one-shot CodeCommit pull-request gate.
# Generated by the ASH CDK deployment targets; see
# deploy/cdk/lib/ash-container-scripts.ts.
import os
import pathlib
import shutil
import subprocess
import tempfile
import uuid

import boto3

# ASH's documented exit codes. 2 means a scan completed and found actionable
# findings, which is a gate failure but NOT an operational error; 1 and 3 mean
# ASH could not do its job. Treating them alike would report a broken scanner as
# a clean repository.
EXIT_SUCCESS = 0
EXIT_SCANNER_ERROR = 1
EXIT_ACTIONABLE_FINDINGS = 2
EXIT_INVALID_CONFIG = 3

# Defensive bound. The PostCommentForPullRequest reference documents no length
# constraint on "content", so this is a safety margin rather than the API limit.
MAX_COMMENT_CHARS = 10000

# Baked scanner data, paired with the writable path it is redirected to. Read off
# the environment, not hardcoded; see ash-container-scripts.ts.
BAKED_SCANNER_DATA = (
    ("ASH_BAKED_GRYPE_DB_DIR", "GRYPE_DB_CACHE_DIR"),
    ("ASH_BAKED_SEMGREP_RULES_DIR", "SEMGREP_RULES_CACHE_DIR"),
    ("ASH_BAKED_OPENGREP_RULES_DIR", "OPENGREP_RULES_CACHE_DIR"),
)

# What is_offline_mode() in core/constants.py reads as offline.
OFFLINE_VALUES = ("YES", "TRUE", "1")


def _run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


def _seed_from_baked(baked, writable, directories_only):
    """Link baked directories, copy baked files. See ash-container-scripts.ts."""
    if not baked or not os.path.isdir(baked):
        return
    for name in sorted(os.listdir(baked)):
        target = os.path.join(baked, name)
        link = os.path.join(writable, name)
        if os.path.lexists(link):
            continue
        if os.path.isdir(target):
            os.symlink(target, link)
        elif not directories_only and os.path.isfile(target):
            shutil.copy2(target, link)


def _scan_env(workdir):
    """Redirect scanner writes into /tmp. See the note in ash-container-scripts.ts."""
    env = dict(os.environ)
    cache = os.path.join(workdir, "cache")
    tool_dir = os.path.join(workdir, "uv-tools")

    env["HOME"] = workdir
    env["XDG_CACHE_HOME"] = cache
    env["XDG_DATA_HOME"] = os.path.join(workdir, "share")
    env["UV_CACHE_DIR"] = os.path.join(cache, "uv")
    env["UV_TOOL_DIR"] = tool_dir
    env["GRYPE_DB_CACHE_DIR"] = os.path.join(cache, "grype")
    env["SEMGREP_RULES_CACHE_DIR"] = os.path.join(cache, "semgrep")
    env["OPENGREP_RULES_CACHE_DIR"] = os.path.join(cache, "opengrep")

    image_path = os.environ.get("ASH_IMAGE_PATH")
    if image_path:
        env["PATH"] = image_path

    for path in (cache, tool_dir, env["XDG_DATA_HOME"]):
        os.makedirs(path, exist_ok=True)

    # Directories only. Do not change this to False; see ash-container-scripts.ts.
    _seed_from_baked(os.environ.get("ASH_BAKED_UV_TOOL_DIR"), tool_dir, True)

    empty = []
    for baked_var, cache_var in BAKED_SCANNER_DATA:
        writable = env[cache_var]
        os.makedirs(writable, exist_ok=True)
        _seed_from_baked(os.environ.get(baked_var), writable, False)
        if not os.listdir(writable):
            empty.append("%s (from %s)" % (cache_var, baked_var))

    if empty:
        offline = os.environ.get("ASH_OFFLINE", "NO").strip().upper() in OFFLINE_VALUES
        if offline:
            raise RuntimeError(
                "ASH_OFFLINE is set, so this scan cannot fetch what it is missing, "
                "and these redirected scanner caches are empty after seeding: %s. "
                "Refusing to scan rather than reporting no findings from an empty "
                "vulnerability database and no rulesets. Rebuild the image with "
                "AshOfflineMode=YES so they are baked in, or set it to NO so the "
                "scanners may fetch them." % "; ".join(empty)
            )
        print("ash-gate: empty after seeding, will be fetched: %s" % "; ".join(empty))

    return env


def _scan_summary(output_dir):
    """Prefer ASH's own markdown report; fall back to something truthful."""
    report = pathlib.Path(output_dir) / "reports" / "ash.summary.md"
    if report.is_file():
        text = report.read_text(encoding="utf-8", errors="replace")
        if text.strip():
            return text
    return None


def _verdict(exit_code):
    if exit_code == EXIT_SUCCESS:
        return "passed", "No actionable findings at or above the configured threshold."
    if exit_code == EXIT_ACTIONABLE_FINDINGS:
        return "failed", "ASH found actionable findings at or above the configured threshold."
    if exit_code == EXIT_INVALID_CONFIG:
        return "errored", "ASH rejected its configuration, so nothing was scanned."
    if exit_code == EXIT_SCANNER_ERROR:
        return "errored", "One or more scanners failed, so this result is incomplete."
    return "errored", "ASH exited with unexpected code %d." % exit_code


def handler(event, context):
    detail = event.get("detail") or {}
    pull_request_id = detail.get("pullRequestId")
    repository_names = detail.get("repositoryNames") or []
    source_commit = detail.get("sourceCommit")
    destination_commit = detail.get("destinationCommit")
    revision_id = detail.get("revisionId")

    # repositoryNames is a list in the CodeCommit event payload, not a string.
    if not (pull_request_id and repository_names and source_commit and destination_commit):
        return {"skipped": "event did not carry a complete pull request", "detail": detail}

    repository_name = repository_names[0]
    region = os.environ["AWS_REGION"]
    codecommit = boto3.client("codecommit")

    workdir = tempfile.mkdtemp(dir="/tmp")
    source_dir = os.path.join(workdir, "src")
    output_dir = os.path.join(workdir, "out")

    # Before the clone so a refusal reaches the pull request and withdraws a
    # standing approval rather than failing the invocation silently.
    try:
        scan_env = _scan_env(workdir)
    except RuntimeError as exc:
        _post(codecommit, pull_request_id, repository_name, destination_commit,
              source_commit, "## ASH scan errored\\n\\n%s\\n" % exc)
        _set_approval(codecommit, pull_request_id, revision_id, "errored")
        raise

    clone = _run(["git", "clone", "--no-single-branch", "--quiet",
                  "codecommit::%s://%s" % (region, repository_name), source_dir])
    if clone.returncode != 0:
        body = "## ASH scan errored\\n\\nCould not clone the repository:\\n\\n\`\`\`\\n%s\\n\`\`\`\\n" % (
            (clone.stderr or "").strip()[:2000],
        )
        _post(codecommit, pull_request_id, repository_name, destination_commit, source_commit, body)
        raise RuntimeError("git clone failed for %s" % repository_name)

    checkout = _run(["git", "-C", source_dir, "checkout", "--quiet", source_commit])
    if checkout.returncode != 0:
        raise RuntimeError("could not check out %s: %s" % (source_commit, checkout.stderr))

    argv = ["ash", "scan", "--source-dir", source_dir, "--output-dir", output_dir,
            "--no-progress", "--simple", "--compact-report"]
    if os.environ.get("ASH_CHANGED_FILES_ONLY", "true") == "true":
        # Diff against the pull request's destination commit, which is what the
        # reviewer is being asked to merge into.
        argv += ["--changed-files-only", "--base-ref", destination_commit]
    min_severity = os.environ.get("ASH_MIN_SEVERITY")
    if min_severity:
        argv += ["--min-severity", min_severity]

    # env= is load-bearing; see _scan_env.
    scan = _run(argv, cwd=source_dir, env=scan_env)
    verdict, explanation = _verdict(scan.returncode)

    summary = _scan_summary(output_dir)
    parts = ["## ASH scan %s\\n" % verdict, explanation, ""]
    if summary:
        parts += [summary]
    else:
        tail = ((scan.stderr or scan.stdout or "").strip())[-2000:]
        parts += ["ASH produced no markdown report. Tail of its output:", "", "\`\`\`", tail, "\`\`\`"]
    parts += ["", "_Scanned commit \`%s\` against \`%s\`._" % (source_commit[:12], destination_commit[:12])]
    body = "\\n".join(parts)

    _post(codecommit, pull_request_id, repository_name, destination_commit, source_commit, body)

    _set_approval(codecommit, pull_request_id, revision_id, verdict)

    return {"verdict": verdict, "exitCode": scan.returncode, "pullRequestId": pull_request_id}


def _set_approval(codecommit, pull_request_id, revision_id, verdict):
    """APPROVE only a passing scan. Shared with the refusal path; see the .ts note."""
    if os.environ.get("ASH_APPROVAL_GATE", "false") != "true" or not revision_id:
        return
    state = "APPROVE" if verdict == "passed" else "REVOKE"
    try:
        codecommit.update_pull_request_approval_state(
            pullRequestId=pull_request_id, revisionId=revision_id, approvalState=state)
    except codecommit.exceptions.PullRequestCannotBeApprovedByAuthorException:
        # The comment is already posted; only the vote is unavailable.
        pass


def _post(codecommit, pull_request_id, repository_name, before_commit_id, after_commit_id, content):
    """beforeCommitId is the destination tip and afterCommitId the source tip.

    That ordering is the API's, not ours: PostCommentForPullRequest documents
    beforeCommitId as the destination-branch commit and afterCommitId as the
    current tip of the source branch. Swapping them attaches the comment to the
    wrong diff.
    """
    codecommit.post_comment_for_pull_request(
        pullRequestId=pull_request_id,
        repositoryName=repository_name,
        beforeCommitId=before_commit_id,
        afterCommitId=after_commit_id,
        content=content[:MAX_COMMENT_CHARS],
        clientRequestToken=str(uuid.uuid4()),
    )
`;
