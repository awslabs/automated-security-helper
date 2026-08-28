/**
 * The shared building block: an ECR repository plus the CodeBuild project that
 * fills it with ASH images.
 *
 * WHY THIS EXISTS AT ALL — READ THIS FIRST
 * ----------------------------------------
 * ASH publishes no container image to any public registry, and that is a settled
 * decision rather than a gap waiting to be filled. Every deployment target here
 * therefore has to build ASH into the ADOPTER'S OWN ECR repository as part of
 * deployment. This construct is the BOOTSTRAP, not a freshness mechanism bolted
 * onto a prebuilt image: without it there is no image, and the workload cannot
 * start. The scheduled rebuild is the secondary purpose.
 *
 * HOW THE BOOTSTRAP ORDERING WORKS, AND WHY IT IS NOT A LAMBDA POLLING LOOP
 * ------------------------------------------------------------------------
 * `AWS::BedrockAgentCore::Runtime`, an ECS service and a container Lambda all
 * need the image to exist when CloudFormation creates them. So the image build
 * has to finish BEFORE those resources are created, and they have to depend on
 * it. Three designs were considered:
 *
 * 1. `AwsCustomResource` calling StartBuild. Rejected: it returns as soon as the
 *    build starts, so the workload would still be created against an empty
 *    repository.
 * 2. A Lambda that starts the build and polls until it finishes. Rejected: an
 *    ASH image build installs a dozen scanners and routinely runs longer than
 *    Lambda's 900-second ceiling
 *    (https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html),
 *    so the bootstrap would time out on exactly the slow builds that matter.
 * 3. WHAT IS IMPLEMENTED: a Lambda starts the build, passing CloudFormation's
 *    own response URL into the build as an environment variable, and does not
 *    respond. The buildspec's `post_build` phase sends the CloudFormation
 *    response itself. CodeBuild's timeout, not Lambda's, becomes the bound.
 *
 * FAILURE MODE OF DESIGN 3, STATED PLAINLY: if the build is *stopped* or exceeds
 * the project timeout, `post_build` may not run, nothing answers CloudFormation,
 * and the stack sits in CREATE_IN_PROGRESS on this resource until its internal
 * timeout. Cancel the stack operation if that happens. A build that merely
 * *fails* is fine — `post_build` still runs and reports FAILED, and the stack
 * rolls back with the CodeBuild log id in the reason.
 *
 * WHY THE SOURCE IS `NO_SOURCE` AND THE BUILDSPEC CLONES
 * -----------------------------------------------------
 * A CodeBuild GitHub source needs a stored source credential in the account,
 * which an adopter launching a template from the console has not set up. An
 * anonymous HTTPS clone of a public repository needs nothing. So the project
 * takes no source and the buildspec clones the pinned ASH ref itself. That also
 * makes `AshVersion` a plain deploy-time parameter rather than a synth-time
 * source configuration.
 */

import { Aws, CfnParameter, CustomResource, Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

import { suppressCodeBuildRoleWildcards, suppressLambdaLogWildcard, suppressUnevaluableRules } from './ash-nag-suppressions';
import { MCP_ENTRYPOINT_SCRIPT, CODECOMMIT_GATE_HANDLER, ASH_MATERIALIZED_CONFIG_PATH } from './ash-container-scripts';

/** Upstream ASH repository. Public, so an anonymous clone works. */
export const ASH_REPOSITORY_URL = 'https://github.com/awslabs/automated-security-helper.git';

/**
 * Which image is being produced.
 *
 * - `mcp`    — the MCP server entrypoint baked in. Used by AgentCore and Fargate.
 * - `lambda` — the Lambda Runtime Interface Client plus the gate handler.
 * - `cli`    — plain ASH, used as a CodeBuild environment image by the sharded
 *              executor, where `ash scan` is invoked directly.
 */
export type AshImageFlavor = 'mcp' | 'lambda' | 'cli';

/** Target CPU architecture. AgentCore requires `arm64`. */
export type AshBuildPlatform = 'arm64' | 'amd64';

/**
 * Which ASH Dockerfile stage each flavor builds from.
 *
 * `non-root` runs as UID 500 and is the right base for a long-lived server.
 * `ci` runs as root, which the Lambda flavor needs so it can pip-install the
 * runtime interface client, and which the CLI flavor needs to work as a
 * CodeBuild environment image.
 */
const DOCKER_TARGET_FOR_FLAVOR: Record<AshImageFlavor, string> = {
  mcp: 'non-root',
  lambda: 'ci',
  cli: 'ci',
};

/**
 * Longest string a Docker tag may be.
 *
 * From the canonical grammar, `tag := /[\w][\w.-]{0,127}/` — one leading
 * `[A-Za-z0-9_]` followed by up to 127 more of `[A-Za-z0-9_.-]`, so 128
 * characters, no `/`, and no leading `.` or `-`.
 * https://pkg.go.dev/github.com/distribution/reference
 *
 * ECR's own API accepts an `imageTag` of up to 300 characters, but that ceiling
 * never applies: `docker tag` parses the reference on the client and rejects it
 * before ECR is ever contacted.
 * https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ImageIdentifier.html
 */
const DOCKER_TAG_MAX_LENGTH = 128;

/** Hex digits of the ref digest appended to the audit tag. See `sanitizeRefCommand`. */
const REF_DIGEST_LENGTH = 8;

export interface AshImageBuildProps {
  /** Architecture to build. `arm64` builds natively on ARM CodeBuild compute. */
  readonly platform: AshBuildPlatform;
  /** Flavors to produce. Each becomes one tag in the repository. */
  readonly flavors: AshImageFlavor[];
  /** ASH git ref to build. */
  readonly ashVersion: CfnParameter;
  /** `YES`/`NO`, forwarded to the ASH Dockerfile's `OFFLINE` build argument. */
  readonly offlineMode: CfnParameter;
  /** Rebuild cadence. */
  readonly rebuildSchedule: CfnParameter;
  /**
   * Run a build during stack creation and make it gate the workload.
   *
   * Leave this on for any stack whose workload cannot be created against an
   * empty repository. Turn it off where the deployment bootstraps itself another
   * way — the sharded executor builds the image in its own first pipeline stage.
   */
  readonly bootstrapOnDeploy?: boolean;
  /**
   * Customer-managed key for the build project's encryption.
   *
   * Shared across every project in a stack rather than created per project: one
   * key is enough to encrypt build output for all of them, and a key per project
   * would multiply the standing charge for no additional isolation.
   */
  readonly encryptionKey: kms.IKey;
}

export class AshImageBuild extends Construct {
  /** The adopter's repository. Retained on stack deletion; see below. */
  public readonly repository: ecr.Repository;
  public readonly project: codebuild.Project;
  /**
   * The gate to hang workloads off. Undefined when `bootstrapOnDeploy` is false.
   *
   * Call `workload.node.addDependency(build.bootstrap!)` — or `addDependency` on
   * the L1 — so CloudFormation does not create the workload before an image
   * exists.
   */
  public readonly bootstrap?: CustomResource;

  private readonly platform: AshBuildPlatform;

  constructor(scope: Construct, id: string, props: AshImageBuildProps) {
    super(scope, id);
    this.platform = props.platform;

    if (props.flavors.length === 0) {
      throw new Error('AshImageBuild needs at least one flavor to build.');
    }

    // RETAIN, deliberately. `emptyOnDelete` would make CDK synthesize an
    // asset-backed custom resource to purge images, which drags in a staging
    // bucket and therefore `cdk bootstrap` — and these templates are meant to
    // launch straight from the CloudFormation console. Retaining also means a
    // rolled-back stack does not throw away an image that took 20 minutes to
    // build.
    this.repository = new ecr.Repository(this, 'Repository', {
      imageScanOnPush: true,
      imageTagMutability: ecr.TagMutability.MUTABLE,
      removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [
        {
          description: 'Keep the ten most recent images; older rebuilds are unreachable.',
          maxImageCount: 10,
        },
      ],
    });

    const logGroup = new logs.LogGroup(this, 'BuildLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.project = new codebuild.Project(this, 'Build', {
      description:
        `Builds the ASH ${props.platform} image (${props.flavors.join(', ')}) into this ` +
        "account's ECR repository. ASH publishes no public image, so this build is what " +
        'makes the deployment possible.',
      environment: {
        buildImage:
          props.platform === 'arm64'
            ? codebuild.LinuxArmBuildImage.AMAZON_LINUX_2023_STANDARD_3_0
            : codebuild.LinuxBuildImage.AMAZON_LINUX_2023_5,
        // An ASH image build compiles and installs a dozen scanners. SMALL runs
        // out of disk on an offline build.
        computeType: codebuild.ComputeType.LARGE,
        // Required to run `docker build`. There is no way to build a container
        // image in CodeBuild without it.
        privileged: true,
      },
      // An offline build vendors scanner rulesets and tools into the image and
      // is markedly slower than an online one. This is the ceiling, not the
      // expectation.
      timeout: Duration.hours(2),
      logging: { cloudWatch: { logGroup } },
      encryptionKey: props.encryptionKey,
      environmentVariables: {
        ASH_ECR_REPOSITORY_URI: { value: this.repository.repositoryUri },
        ASH_VERSION: { value: props.ashVersion.valueAsString },
        ASH_OFFLINE: { value: props.offlineMode.valueAsString },
        ASH_REPOSITORY_URL: { value: ASH_REPOSITORY_URL },
        ASH_BUILD_PLATFORM: { value: props.platform },
        ASH_BUILD_FLAVORS: { value: props.flavors.join(' ') },
      },
      buildSpec: codebuild.BuildSpec.fromObject(
        this.buildSpecObject(props.flavors),
      ),
    });

    this.repository.grantPullPush(this.project);
    // ECR's authorization token is account-wide and not addressable per
    // repository, so it cannot be scoped further than `*`.
    this.project.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['ecr:GetAuthorizationToken'],
        resources: ['*'],
      }),
    );

    new events.Rule(this, 'RebuildSchedule', {
      description:
        'Rebuilds the ASH image so a long-lived deployment keeps receiving base-image, ' +
        'OS and scanner patches for the pinned ASH revision.',
      schedule: events.Schedule.expression(props.rebuildSchedule.valueAsString),
      targets: [new targets.CodeBuildProject(this.project)],
    });

    if (props.bootstrapOnDeploy ?? true) {
      this.bootstrap = this.addBootstrap(props);
    }

    suppressCodeBuildRoleWildcards(this.project);
    // AwsSolutions-CB5 pins the build image; it cannot evaluate one supplied as
    // an Fn::Join over ECR attributes, which is how every consumer of this
    // construct references the image it just built.
    suppressUnevaluableRules(this.project, ['AwsSolutions-CB5']);
  }

  /**
   * The image URI a workload should reference, for one flavor.
   *
   * This is the MOVING tag, so a scheduled rebuild replaces what the tag points
   * at. See the note in the README about what that does and does not roll out
   * on its own.
   */
  public imageUriForFlavor(flavor: AshImageFlavor): string {
    return this.repository.repositoryUriForTag(this.tagForFlavor(flavor));
  }

  /** The moving tag for a flavor, for example `mcp-arm64`. */
  public tagForFlavor(flavor: AshImageFlavor): string {
    return `${flavor}-${this.platform}`;
  }

  /**
   * Start a build during stack creation and answer CloudFormation from the build.
   *
   * The handler deliberately does NOT respond on the success path. Responding
   * there is the bug this design exists to avoid: it would unblock the workload
   * while the image was still building.
   */
  private addBootstrap(props: AshImageBuildProps): CustomResource {
    // Its own log group, so the role can be scoped to exactly one group instead
    // of carrying the AWS managed AWSLambdaBasicExecutionRole.
    const starterLogs = new logs.LogGroup(this, 'BootstrapStarterLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const starterRole = new iam.Role(this, 'BootstrapStarterRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description:
        'Execution role for the image-build bootstrap. Deliberately not using ' +
        'AWSLambdaBasicExecutionRole: the only logging grant it needs is on one log group.',
    });
    starterRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [starterLogs.logGroupArn, `${starterLogs.logGroupArn}:*`],
      }),
    );

    const starter = new lambda.Function(this, 'BootstrapStarter', {
      role: starterRole,
      logGroup: starterLogs,
      // Inline code, not an asset: an asset needs a staging bucket and therefore
      // `cdk bootstrap`, which an adopter launching this template from the
      // console has not run.
      code: lambda.Code.fromInline(BOOTSTRAP_STARTER_CODE),
      handler: 'index.handler',
      runtime: lambda.Runtime.PYTHON_3_14,
      timeout: Duration.minutes(1),
      description:
        'Starts the ASH image build during stack creation and hands CloudFormation’s ' +
        'response URL to the build, which answers once the image exists.',
      environment: { PROJECT_NAME: this.project.projectName },
    });
    // codebuild.Project exposes no grantStartBuild, so the statement is written
    // out. Scoped to this one project's ARN.
    starter.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['codebuild:StartBuild'],
        resources: [this.project.projectArn],
      }),
    );

    suppressLambdaLogWildcard(starterRole);

    return new CustomResource(this, 'BootstrapBuild', {
      serviceToken: starter.functionArn,
      resourceType: 'Custom::AshImageBootstrap',
      properties: {
        // These are read by nobody. They exist so that changing the ASH version
        // or the offline flag changes the custom resource's properties, which is
        // what makes CloudFormation re-invoke it on a stack update. Without them
        // a version bump would leave the old image in place and the workload
        // would keep running the previous ASH.
        AshVersion: props.ashVersion.valueAsString,
        AshOfflineMode: props.offlineMode.valueAsString,
        Flavors: props.flavors.join(' '),
      },
    });
  }

  private buildSpecObject(flavors: AshImageFlavor[]): Record<string, unknown> {
    const targetsNeeded = Array.from(new Set(flavors.map((f) => DOCKER_TARGET_FOR_FLAVOR[f])));

    return {
      version: '0.2',
      phases: {
        pre_build: {
          commands: [
            'echo "Building ASH ${ASH_VERSION} for ${ASH_BUILD_PLATFORM}: ${ASH_BUILD_FLAVORS}"',
            `aws ecr get-login-password --region ${Aws.REGION} | docker login --username AWS --password-stdin ${Aws.ACCOUNT_ID}.dkr.ecr.${Aws.REGION}.${Aws.URL_SUFFIX}`,
            // Shallow, single-ref clone of the public repository. No credential
            // needed, which is the whole reason the project takes no source.
            'git clone --depth 1 --branch "${ASH_VERSION}" "${ASH_REPOSITORY_URL}" ash-src',
          ],
        },
        build: {
          commands: [
            // First, so a build that cannot compute a usable tag dies in seconds
            // rather than after twenty minutes of `docker build`.
            this.sanitizeRefCommand(flavors),

            // Write the container scripts next to the cloned Dockerfile so the
            // derived builds can COPY them.
            this.writeFileCommand('ash-src/ash-mcp-entrypoint.sh', MCP_ENTRYPOINT_SCRIPT),
            this.writeFileCommand('ash-src/ash_gate_handler.py', CODECOMMIT_GATE_HANDLER),

            // Build each ASH Dockerfile stage this image set needs. --platform is
            // explicit even though the compute already matches, so a build on the
            // wrong fleet fails loudly instead of producing an image AgentCore
            // will refuse.
            ...targetsNeeded.map(
              (target) =>
                'docker build ' +
                '--platform "linux/${ASH_BUILD_PLATFORM}" ' +
                `--target ${target} ` +
                '--build-arg "OFFLINE=${ASH_OFFLINE}" ' +
                '--build-arg "INSTALL_ASH_REVISION=${ASH_VERSION}" ' +
                `-t "ash-base-${target}:local" ash-src`,
            ),

            ...flavors.flatMap((flavor) => this.flavorBuildCommands(flavor)),
          ],
        },
        post_build: {
          commands: [
            // Runs whether the build phase passed or failed, which is what makes
            // it a usable CloudFormation responder.
            CFN_SIGNAL_COMMAND,
          ],
        },
      },
    };
  }

  /**
   * Fold `$ASH_VERSION` into something a Docker tag may hold, once per build.
   *
   * WHY THIS EXISTS — A REAL DEPLOYMENT, NOT A HYPOTHETICAL
   * ------------------------------------------------------
   * `AshVersion` is a git ref handed to `git clone --branch`, and branch refs
   * routinely contain a `/`, which a Docker tag may not. Deployed with
   * `AshVersion=feat/distributed-execute-and-collect`, a CodeBuild run built the
   * image successfully and then died on the version-qualified tag:
   *
   *   docker tag "ash-mcp:local" "<repo-uri>:mcp-arm64-feat/distributed-execute-and-collect"
   *   Error parsing reference: "<repo-uri>:mcp-arm64-feat/distributed-execute-and-collect"
   *   Phase complete: BUILD State: FAILED
   *
   * The expensive work had already succeeded; the tag threw it away and nothing
   * reached ECR. `feat/`, `release/`, `dependabot/` and `users/` refs all did
   * this, so it was the normal case rather than an edge one.
   *
   * WHY IT IS SHELL AND NOT A TYPESCRIPT STRING OPERATION
   * -----------------------------------------------------
   * `ASH_VERSION` carries `props.ashVersion.valueAsString`, a deploy-time
   * CloudFormation parameter. At synth time its value is an `Fn::Ref`, so there
   * is no string to fold. Sanitizing in TypeScript would synthesize cleanly and
   * then fail in CodeBuild in exactly the same way.
   *
   * WHAT IT DOES ABOUT COLLISIONS
   * -----------------------------
   * Folding is many-to-one: `feat/x` and `feat-x` land on the same string, and so
   * do two refs that differ only past the truncation point. The repository is
   * MUTABLE by design — the moving tag depends on it — so a collision would let
   * one build silently overwrite another build's audit tag, destroying the one
   * property that tag exists to provide. The first eight hex digits of the
   * SHA-256 of the RAW ref are therefore appended: distinct refs get distinct
   * tags, and the same ref always gets the same tag, so a rebuild republishes
   * instead of accumulating. Digesting the raw value rather than the folded one
   * is what makes truncated refs distinguishable. The build echoes the result,
   * because an operator looking for a rollback target reads it out of the log
   * rather than recomputing it.
   *
   * The digest is appended UNCONDITIONALLY, which is a deliberate cost: a plain
   * `v3.7.0` now tags as `mcp-arm64-v3.7.0-<digest>` rather than
   * `mcp-arm64-v3.7.0`. Appending it only when folding changed something was
   * considered and rejected — it makes the tag's shape depend on the ref, so an
   * operator cannot predict it, and it is no longer injective, because a branch
   * literally named `feat-x-<somedigest>` could still collide with a folded
   * `feat/x`. Nothing in this repository reads the version-qualified tag
   * programmatically; workloads reference `tagForFlavor`, the moving tag.
   *
   * WHY `tr` RATHER THAN `sed`
   * -------------------------
   * `AshVersion` declares no `AllowedPattern`, so CloudFormation accepts a value
   * containing a newline. `sed` substitutes within a line and would pass one
   * straight through into the tag; `tr` folds it like any other byte.
   *
   * The grammar's leading-character rule needs no work here. Every tag this
   * construct writes is `<flavor>-<platform>-<suffix>`, so the first character
   * always comes from a flavor name, and a ref like `-foo` or `.hidden` lands
   * mid-tag where `[\w.-]` allows it. Drop that prefix and this stops being true.
   */
  private sanitizeRefCommand(flavors: AshImageFlavor[]): string {
    // Budget the folded ref against the longest tag this build will compose, so
    // the result is provably inside the grammar's 128 characters rather than
    // inside a number someone once guessed. Two hyphens: `<tag>-<ref>-<digest>`.
    const longestTag = Math.max(...flavors.map((f) => this.tagForFlavor(f).length));
    const refBudget = DOCKER_TAG_MAX_LENGTH - longestTag - REF_DIGEST_LENGTH - 2;

    return [
      `ASH_SAFE_REF="$(printf '%s' "\${ASH_VERSION}" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-${refBudget})"`,
      `ASH_REF_DIGEST="$(printf '%s' "\${ASH_VERSION}" | sha256sum | cut -c1-${REF_DIGEST_LENGTH})"`,
      '# The digest is what keeps two refs that fold to the same string on separate',
      '# tags. A pipeline reports only its last command\'s status, so a missing',
      '# sha256sum would leave it empty and let one build overwrite another\'s audit',
      '# tag. Fail here instead.',
      `[ \${#ASH_REF_DIGEST} -eq ${REF_DIGEST_LENGTH} ] || { echo "cannot digest ASH_VERSION" >&2; exit 1; }`,
      'ASH_VERSION_TAG_SUFFIX="${ASH_SAFE_REF}-${ASH_REF_DIGEST}"',
      'echo "version-qualified audit tag suffix: ${ASH_VERSION_TAG_SUFFIX}"',
    ].join('\n');
  }

  private flavorBuildCommands(flavor: AshImageFlavor): string[] {
    const base = `ash-base-${DOCKER_TARGET_FOR_FLAVOR[flavor]}:local`;
    const tag = this.tagForFlavor(flavor);
    // Composed from the folded suffix, never from `$ASH_VERSION` directly — see
    // `sanitizeRefCommand`. The moving tag above is untouched.
    const versionedTag = `${tag}-\${ASH_VERSION_TAG_SUFFIX}`;
    const push = [
      `docker tag "ash-${flavor}:local" "\${ASH_ECR_REPOSITORY_URI}:${tag}"`,
      `docker tag "ash-${flavor}:local" "\${ASH_ECR_REPOSITORY_URI}:${versionedTag}"`,
      `docker push "\${ASH_ECR_REPOSITORY_URI}:${tag}"`,
      `docker push "\${ASH_ECR_REPOSITORY_URI}:${versionedTag}"`,
    ];

    if (flavor === 'cli') {
      // Nothing to derive: the sharded executor invokes `ash scan` directly, so
      // ASH's own image is exactly what it needs.
      return [`docker tag "${base}" "ash-cli:local"`, ...push];
    }

    if (flavor === 'mcp') {
      return [
        this.writeFileCommand(
          'ash-src/Dockerfile.mcp',
          [
            `FROM ${base}`,
            '# The ASH stage already dropped to UID 500; step back up to install.',
            'USER root',
            'COPY ash-mcp-entrypoint.sh /usr/local/bin/ash-mcp-entrypoint.sh',
            'RUN chmod 0755 /usr/local/bin/ash-mcp-entrypoint.sh',
            `ENV ASH_CONFIG=${ASH_MATERIALIZED_CONFIG_PATH}`,
            '# 500:100 are the ASH Dockerfile UID/GID defaults, and this build',
            '# overrides neither.',
            'USER 500:100',
            '# Documentation only; AgentCore fixes the port at 8000 regardless.',
            'EXPOSE 8000',
            'ENTRYPOINT ["/usr/local/bin/ash-mcp-entrypoint.sh"]',
          ].join('\n'),
        ),
        'docker build --platform "linux/${ASH_BUILD_PLATFORM}" -f ash-src/Dockerfile.mcp -t "ash-mcp:local" ash-src',
        ...push,
      ];
    }

    return [
      this.writeFileCommand(
        'ash-src/Dockerfile.lambda',
        [
          `FROM ${base}`,
          '# A container Lambda must speak the Lambda Runtime API, so the runtime',
          '# interface client is mandatory — ASH’s image has no notion of Lambda.',
          '# git-remote-codecommit gives git the codecommit:// transport so the',
          '# handler can clone using the function role. boto3 is named explicitly',
          '# rather than relied on transitively: the handler imports it from the',
          '# system interpreter, while `ash` runs from its own environment.',
          'RUN python3 -m pip install --no-cache-dir --break-system-packages \\',
          '      awslambdaric boto3 git-remote-codecommit',
          'COPY ash_gate_handler.py /var/task/ash_gate_handler.py',
          'WORKDIR /var/task',
          'ENTRYPOINT ["/usr/local/bin/python3", "-m", "awslambdaric"]',
          'CMD ["ash_gate_handler.handler"]',
        ].join('\n'),
      ),
      'docker build --platform "linux/${ASH_BUILD_PLATFORM}" -f ash-src/Dockerfile.lambda -t "ash-lambda:local" ash-src',
      ...push,
    ];
  }

  /**
   * Emit a shell command that writes `content` to `path`.
   *
   * A quoted heredoc is used so nothing inside the payload is expanded — these
   * files are full of `${...}` that must survive verbatim into the container.
   * The delimiter is quoted for exactly that reason; an unquoted one would let
   * the build shell eat every variable reference and every backtick.
   */
  private writeFileCommand(path: string, content: string): string {
    return [`cat > ${path} <<'ASH_CDK_EOF'`, content, 'ASH_CDK_EOF'].join('\n');
  }
}

/**
 * Signals CloudFormation from `post_build`, when a bootstrap started this build.
 *
 * Skipped entirely for scheduled rebuilds, which carry no response URL. The
 * physical id is the logical id so it stays stable across stack updates —
 * returning a fresh one would make CloudFormation delete the "replaced"
 * resource.
 */
const CFN_SIGNAL_COMMAND = `if [ -n "\${CFN_RESPONSE_URL:-}" ]; then
  if [ "\${CODEBUILD_BUILD_SUCCEEDING:-0}" = "1" ]; then
    ASH_STATUS=SUCCESS
    ASH_REASON="ASH image build succeeded"
  else
    ASH_STATUS=FAILED
    ASH_REASON="ASH image build failed; see CodeBuild build \${CODEBUILD_BUILD_ID:-unknown}"
  fi
  python3 -c "import json, os, sys, urllib.request; body = json.dumps({'Status': sys.argv[1], 'Reason': sys.argv[2], 'PhysicalResourceId': os.environ['CFN_LOGICAL_ID'], 'StackId': os.environ['CFN_STACK_ID'], 'RequestId': os.environ['CFN_REQUEST_ID'], 'LogicalResourceId': os.environ['CFN_LOGICAL_ID'], 'Data': {}}).encode(); req = urllib.request.Request(os.environ['CFN_RESPONSE_URL'], data=body, method='PUT', headers={'content-type': '', 'content-length': str(len(body))}); urllib.request.urlopen(req)" "\$ASH_STATUS" "\$ASH_REASON"
fi`;

/**
 * Inline handler that starts the build and stays silent on success.
 *
 * Kept small on purpose: `lambda.Code.fromInline` writes into the template's
 * `ZipFile`, which CloudFormation caps at 4096 characters.
 */
const BOOTSTRAP_STARTER_CODE = `import json
import os
import urllib.request

import boto3


def send(event, status, reason):
    body = json.dumps({
        "Status": status,
        "Reason": reason,
        "PhysicalResourceId": event["LogicalResourceId"],
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": {},
    }).encode()
    urllib.request.urlopen(urllib.request.Request(
        event["ResponseURL"], data=body, method="PUT",
        headers={"content-type": "", "content-length": str(len(body))}))


def handler(event, context):
    # Never block a teardown on an image build.
    if event["RequestType"] == "Delete":
        send(event, "SUCCESS", "Nothing to undo")
        return
    try:
        boto3.client("codebuild").start_build(
            projectName=os.environ["PROJECT_NAME"],
            environmentVariablesOverride=[
                {"name": "CFN_RESPONSE_URL", "value": event["ResponseURL"], "type": "PLAINTEXT"},
                {"name": "CFN_STACK_ID", "value": event["StackId"], "type": "PLAINTEXT"},
                {"name": "CFN_REQUEST_ID", "value": event["RequestId"], "type": "PLAINTEXT"},
                {"name": "CFN_LOGICAL_ID", "value": event["LogicalResourceId"], "type": "PLAINTEXT"},
            ],
        )
    except Exception as exc:
        # The build never started, so nothing else will ever answer.
        send(event, "FAILED", "Could not start the ASH image build: %s" % exc)
    # Success path is silent by design: the build itself responds when the image
    # exists. Responding here would let the workload be created too early.
`;
