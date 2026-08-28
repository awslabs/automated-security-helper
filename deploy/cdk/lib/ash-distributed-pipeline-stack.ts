/**
 * A CodePipeline that fans an ASH scan out across N CodeBuild jobs and then
 * merges the shard results into one verdict.
 *
 * THE ONE THING THAT IS EASY TO GET WRONG
 * --------------------------------------
 * THE MERGE ACTION OWNS THE PASS/FAIL VERDICT. Shard actions must not gate.
 *
 * ASH's shard selection splits the SCANNER set, so a shard can legitimately
 * finish with nothing to report and exit 0 while another shard exits 2 for
 * findings. Gating on shard exit codes gets this wrong in both directions: a
 * clean shard looks like a clean scan, and one shard with findings fails the
 * pipeline before the other shards' findings have been collected at all. So each
 * shard captures ASH's exit code, records it alongside its results, and exits 0.
 * Only the merge action fails.
 *
 * The shard contract is fixed and this stack honours it exactly: zero-based
 * index, `--shard-index` and `--shard-count` always passed together, and
 * `--results` repeatable on the merge side. Shards also pass
 * `--no-fail-on-findings` to state the intent.
 *
 * That flag was NOT verified from this worktree — ASH is not installed here, so
 * `ash scan --help` could not be run. Correctness deliberately does not depend on
 * it. A shard succeeds if and only if ASH wrote `ash_aggregated_results.json`, and
 * the merge independently requires that file from every shard. Exit codes are only
 * recorded, never trusted, because Click reports a usage error as exit 2 and ASH
 * reports actionable findings as exit 2 — indistinguishable, and one of them means
 * nothing was scanned.
 *
 * WHY SHARD RESULTS TRAVEL THROUGH S3 AND NOT PIPELINE ARTIFACTS
 * -------------------------------------------------------------
 * The obvious wiring is one output artifact per shard, all fed into the merge
 * action. It does not scale: a CodeBuild pipeline action accepts 1 to 5 input
 * artifacts
 * (https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-action-artifacts.html),
 * so a six-way split cannot be merged in one action at all. Shards therefore
 * write to a results bucket under the pipeline execution id, and the merge action
 * pulls them back. Shard count is then bounded by CodeBuild concurrency rather
 * than by an artifact limit.
 *
 * WHY THE IMAGE BUILD IS THE FIRST STAGE
 * --------------------------------------
 * The shard and merge actions use the ASH image as their CodeBuild ENVIRONMENT
 * image, which CodeBuild resolves when a build starts rather than when the stack
 * deploys. Making the build the first stage means the image always exists by the
 * time stage two starts, so this stack needs no deploy-time bootstrap custom
 * resource — the pipeline bootstraps itself on its first run.
 *
 * WHY `ShardCount` IS SYNTH-TIME AND NOT A CLOUDFORMATION PARAMETER
 * ----------------------------------------------------------------
 * How many CodeBuild actions exist is decided when the template is written. See
 * `resolveShardCount` in ash-config.ts for the full reasoning, including why
 * emitting a fixed action count while letting a parameter set `--shard-count`
 * would silently drop findings. The Terraform mirror CAN expose this as a real
 * variable; CDK cannot.
 *
 * A NOTE ON HOW FAR SHARDING ACTUALLY GETS YOU
 * -------------------------------------------
 * Because the split is over scanners and not over files, a shard count higher
 * than the number of enabled scanners produces empty shards and no extra
 * parallelism. Run `ash plugin list` against the pinned version to see how many
 * scanners are enabled before raising it.
 */

import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as codepipeline from 'aws-cdk-lib/aws-codepipeline';
import * as codepipeline_actions from 'aws-cdk-lib/aws-codepipeline-actions';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';

import {
  ashSynthesizer,
  ashOfflineMode, ashVersion, rebuildSchedule, resolveShardCount,
} from './ash-config';
import { ASH_MATERIALIZED_CONFIG_PATH } from './ash-container-scripts';
import { AshImageBuild } from './ash-image-build';
import {
  suppressCodeBuildRoleWildcards,
  suppressPipelineRoleWildcards,
  suppressSecretRotation,
  suppressUnevaluableRules,
} from './ash-nag-suppressions';
import { AshRuntimeConfig } from './ash-runtime-config';

/** Object key the adopter uploads the source archive to. */
const SOURCE_OBJECT_KEY = 'source.zip';

export class AshDistributedPipelineStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, {
      // Before ...props, so a caller can still override it.
      synthesizer: ashSynthesizer(),
      ...props,
      description:
        'Sharded ASH scan on CodePipeline: builds the ASH image, fans the scan across N ' +
        'CodeBuild jobs, then merges the shard results into a single verdict.',
    });

    const shardCount = resolveShardCount(this);
    const version = ashVersion(this);
    const offline = ashOfflineMode(this);
    const schedule = rebuildSchedule(this);
    const config = new AshRuntimeConfig(this, 'Config', { includeMcpParameters: false });

    // One customer-managed key per stack, shared by every CodeBuild project here.
    // Rotation is on: the key only protects build output, so a rotated key needs
    // no coordination with anything outside the stack.
    const encryptionKey = new kms.Key(this, 'EncryptionKey', {
      description: 'Encrypts ASH CodeBuild project output for this stack.',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const image = new AshImageBuild(this, 'Image', {
      platform: 'amd64',
      flavors: ['cli'],
      ashVersion: version,
      offlineMode: offline,
      rebuildSchedule: schedule,
      // The pipeline's own first stage builds the image, so a deploy-time
      // bootstrap would duplicate it.
      bootstrapOnDeploy: false,
      encryptionKey,
    });

    const accessLogsBucket = new s3.Bucket(this, 'AccessLogs', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      // RETAIN everywhere in this stack: `autoDeleteObjects` synthesizes an
      // asset-backed custom resource, which needs a staging bucket and therefore
      // `cdk bootstrap` — and these templates launch from the console.
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const sourceBucket = new s3.Bucket(this, 'Source', {
      // CodePipeline S3 sources require a versioned bucket; it identifies a
      // revision by object version.
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'source/',
    });

    const resultsBucket = new s3.Bucket(this, 'Results', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'results/',
      // Shard results are consumed by the merge action in the same execution;
      // the retention window is for after-the-fact inspection, not for the
      // pipeline itself.
      lifecycleRules: [{ id: 'ExpireShardResults', expiration: Duration.days(30) }],
    });

    const artifactBucket = new s3.Bucket(this, 'Artifacts', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'artifacts/',
    });

    /**
     * The ASH image as a CodeBuild environment image.
     *
     * Resolved at build start, not at deploy, which is what lets stage one create
     * the image the later stages run inside.
     */
    const ashBuildImage = codebuild.LinuxBuildImage.fromEcrRepository(
      image.repository,
      image.tagForFlavor('cli'),
    );

    const sourceOutput = new codepipeline.Artifact('Source');

    const shardProjects = Array.from({ length: shardCount }, (_, index) =>
      this.shardProject(index, shardCount, ashBuildImage, resultsBucket, config, encryptionKey),
    );
    const mergeProject = this.mergeProject(
      shardCount,
      ashBuildImage,
      resultsBucket,
      config.configParameterNameOrEmpty(),
      encryptionKey,
    );

    resultsBucket.grantReadWrite(mergeProject);
    shardProjects.forEach((project) => resultsBucket.grantWrite(project));
    shardProjects.forEach((project) => config.grantRead(project));
    config.grantRead(mergeProject);

    const pipeline = new codepipeline.Pipeline(this, 'Pipeline', {
      artifactBucket,
      restartExecutionOnUpdate: false,
      // V1 explicitly. V2 bills per action-execution minute, which a fan-out of N
      // shards multiplies, and nothing here needs a V2-only feature — the
      // `#{codepipeline.PipelineExecutionId}` variable used below predates V2.
      pipelineType: codepipeline.PipelineType.V1,
      stages: [
        {
          stageName: 'Source',
          actions: [
            new codepipeline_actions.S3SourceAction({
              actionName: 'Source',
              bucket: sourceBucket,
              bucketKey: SOURCE_OBJECT_KEY,
              output: sourceOutput,
              // NONE, not EVENTS: EVENTS makes CDK create a CloudTrail trail, and
              // POLL is the deprecated path. Adopters usually kick this off from
              // their own CI, and the start command is in the outputs.
              trigger: codepipeline_actions.S3Trigger.NONE,
            }),
          ],
        },
        {
          stageName: 'BuildImage',
          actions: [
            new codepipeline_actions.CodeBuildAction({
              actionName: 'BuildAshImage',
              project: image.project,
              // The build clones ASH itself and ignores this input; CodePipeline
              // requires every CodeBuild action to have one.
              input: sourceOutput,
            }),
          ],
        },
        {
          stageName: 'Scan',
          actions: shardProjects.map(
            (project, index) =>
              new codepipeline_actions.CodeBuildAction({
                actionName: `Shard${index}`,
                project,
                input: sourceOutput,
                // Same runOrder across every shard, so CodePipeline runs them
                // concurrently rather than in sequence.
                runOrder: 1,
                environmentVariables: {
                  ASH_RESULTS_PREFIX: {
                    value: 'executions/#{codepipeline.PipelineExecutionId}',
                  },
                },
              }),
          ),
        },
        {
          stageName: 'Merge',
          actions: [
            new codepipeline_actions.CodeBuildAction({
              actionName: 'MergeAndGate',
              project: mergeProject,
              input: sourceOutput,
              environmentVariables: {
                ASH_RESULTS_PREFIX: {
                  value: 'executions/#{codepipeline.PipelineExecutionId}',
                },
              },
            }),
          ],
        },
      ],
    });

    suppressSecretRotation(config.authSecret);
    suppressPipelineRoleWildcards(pipeline.role);
    shardProjects.forEach((project) => {
      suppressCodeBuildRoleWildcards(project);
      suppressUnevaluableRules(project, ['AwsSolutions-CB5']);
    });
    suppressCodeBuildRoleWildcards(mergeProject);
    suppressUnevaluableRules(mergeProject, ['AwsSolutions-CB5']);
    // The S3 source action gets its own generated role, separate from the
    // pipeline role, with the same object-level wildcard.
    suppressPipelineRoleWildcards(pipeline);

    new CfnOutput(this, 'ShardCount', {
      description:
        'Number of shard actions in this template. Changing it requires re-synthesizing ' +
        'with -c shardCount=N; it is not a deploy-time parameter.',
      value: String(shardCount),
    });
    new CfnOutput(this, 'SourceBucketName', {
      description: `Upload the archive to scan as s3://<bucket>/${SOURCE_OBJECT_KEY}.`,
      value: sourceBucket.bucketName,
    });
    new CfnOutput(this, 'ResultsBucketName', {
      description: 'Shard results and the merged report, keyed by pipeline execution id.',
      value: resultsBucket.bucketName,
    });
    new CfnOutput(this, 'PipelineName', {
      description:
        'Start a scan with `aws codepipeline start-pipeline-execution --name <this>` after ' +
        'uploading the source archive.',
      value: pipeline.pipelineName,
    });
    new CfnOutput(this, 'EcrRepositoryUri', { value: image.repository.repositoryUri });
    new CfnOutput(this, 'BaseConfigParameterName', {
      value: config.configParameter.parameterName,
    });
  }

  /**
   * One shard: run the scanners assigned to this index and publish the results.
   *
   * The exit code is captured rather than propagated. That is the whole point —
   * see the header. `set -e` is left alone around the upload so a failed upload
   * still fails the shard: a shard that silently uploaded nothing would make the
   * merge action under-report.
   */
  private shardProject(
    index: number,
    shardCount: number,
    buildImage: codebuild.IBuildImage,
    resultsBucket: s3.IBucket,
    config: AshRuntimeConfig,
    encryptionKey: kms.IKey,
  ): codebuild.Project {
    return new codebuild.Project(this, `Shard${index}Project`, {
      description: `ASH scan shard ${index} of ${shardCount}.`,
      environment: { buildImage, computeType: codebuild.ComputeType.LARGE },
      encryptionKey,
      timeout: Duration.hours(1),
      environmentVariables: {
        ASH_SHARD_INDEX: { value: String(index) },
        ASH_SHARD_COUNT: { value: String(shardCount) },
        ASH_RESULTS_BUCKET: { value: resultsBucket.bucketName },
        ASH_BASE_CONFIG_SSM_PARAMETER: { value: config.configParameterNameOrEmpty() },
        ASH_CONFIG: { value: ASH_MATERIALIZED_CONFIG_PATH },
      },
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          pre_build: { commands: [MATERIALIZE_CONFIG_COMMAND] },
          build: {
            commands: [
              'echo "Scanning shard ${ASH_SHARD_INDEX} of ${ASH_SHARD_COUNT}"',
              // Indices are zero-based and both flags are always passed together:
              // ASH rejects one without the other rather than defaulting.
              //
              // --no-fail-on-findings states the intent: findings are the merge
              // action's business, not this shard's. But the shard's success does
              // NOT depend on that flag behaving, or on any exit code, because
              // exit-code semantics here are genuinely ambiguous — Click uses
              // exit 2 for a usage error and ASH uses exit 2 for actionable
              // findings. So the shard succeeds if and only if ASH produced its
              // aggregated results file, which is the thing the merge actually
              // consumes. That is robust whether the flag is absent (usage error,
              // no results), a scanner crashed (no results), findings were found
              // (results present) or the shard was clean (results present).
              [
                'set +e',
                'ash scan --source-dir "$CODEBUILD_SRC_DIR" --output-dir ./ash-shard-output \\',
                '  --shard-index "$ASH_SHARD_INDEX" --shard-count "$ASH_SHARD_COUNT" \\',
                '  --no-fail-on-findings --no-progress --simple',
                'ASH_EXIT=$?',
                'set -e',
                '# ASH may have died before creating its output directory.',
                'mkdir -p ./ash-shard-output',
                'echo "$ASH_EXIT" > ./ash-shard-output/.shard-exit-code',
                'echo "shard ${ASH_SHARD_INDEX} finished with ASH exit code $ASH_EXIT"',
                'if [ ! -f ./ash-shard-output/ash_aggregated_results.json ]; then',
                '  echo "shard ${ASH_SHARD_INDEX} produced no ash_aggregated_results.json." >&2',
                '  echo "ASH exit code was $ASH_EXIT. Exit 2 from a usage error (for example an" >&2',
                '  echo "unrecognized --no-fail-on-findings on an older ASH) looks identical to" >&2',
                '  echo "exit 2 for findings, which is why this check looks for the results file" >&2',
                '  echo "instead. Failing here rather than letting the merge report a clean scan" >&2',
                '  echo "for scanners that never ran." >&2',
                '  exit 1',
                'fi',
              ].join('\n'),
            ],
          },
          post_build: {
            commands: [
              // Under errexit: a failed upload must fail the shard.
              'aws s3 cp --recursive --only-show-errors ./ash-shard-output ' +
                '"s3://${ASH_RESULTS_BUCKET}/${ASH_RESULTS_PREFIX}/shard-${ASH_SHARD_INDEX}/"',
              // Reaching here means ASH produced results and they uploaded, so the
              // shard has done its job. The pass/fail verdict on those findings is
              // the merge action's to make, never this shard's: a shard runs a
              // subset of the scanners, so one that finds nothing proves nothing
              // about the others.
              'exit 0',
            ],
          },
        },
      }),
    });
  }

  /**
   * Collect every shard's results and produce the single verdict.
   *
   * Every shard directory is asserted present before merging. A missing shard is
   * a hard failure, not a smaller merge: silently merging four of five shards
   * would report a clean scan while a fifth of the scanners' findings were never
   * looked at.
   */
  private mergeProject(
    shardCount: number,
    buildImage: codebuild.IBuildImage,
    resultsBucket: s3.IBucket,
    configParameterName: string,
    encryptionKey: kms.IKey,
  ): codebuild.Project {
    const resultsFlags = Array.from(
      { length: shardCount },
      (_, index) => `  --results ./shard-results/shard-${index} \\`,
    );

    return new codebuild.Project(this, 'MergeProject', {
      description:
        `Merges ${shardCount} ASH shard result sets and owns the pass/fail verdict for ` +
        'the pipeline.',
      environment: { buildImage, computeType: codebuild.ComputeType.LARGE },
      encryptionKey,
      timeout: Duration.minutes(30),
      environmentVariables: {
        ASH_SHARD_COUNT: { value: String(shardCount) },
        ASH_RESULTS_BUCKET: { value: resultsBucket.bucketName },
        ASH_BASE_CONFIG_SSM_PARAMETER: { value: configParameterName },
        ASH_CONFIG: { value: ASH_MATERIALIZED_CONFIG_PATH },
      },
      buildSpec: codebuild.BuildSpec.fromObject({
        version: '0.2',
        phases: {
          pre_build: {
            commands: [
              MATERIALIZE_CONFIG_COMMAND,
              'aws s3 cp --recursive --only-show-errors ' +
                '"s3://${ASH_RESULTS_BUCKET}/${ASH_RESULTS_PREFIX}/" ./shard-results/',
              [
                '# Refuse to merge a partial result set. The test is for ASH\'s',
                '# aggregated results FILE, not merely for a shard directory: an',
                '# empty directory is exactly what a shard that failed early leaves',
                '# behind, and merging it would report a clean scan for scanners',
                '# that never ran.',
                'ASH_PRESENT=0',
                'ASH_MISSING=""',
                'ASH_INDEX=0',
                'while [ "$ASH_INDEX" -lt "$ASH_SHARD_COUNT" ]; do',
                '  if [ -f "./shard-results/shard-${ASH_INDEX}/ash_aggregated_results.json" ]; then',
                '    ASH_PRESENT=$((ASH_PRESENT + 1))',
                '  else',
                '    ASH_MISSING="${ASH_MISSING} ${ASH_INDEX}"',
                '  fi',
                '  ASH_INDEX=$((ASH_INDEX + 1))',
                'done',
                'if [ "$ASH_PRESENT" -eq 0 ]; then',
                '  echo "Collected 0 of ${ASH_SHARD_COUNT} shard result sets. Refusing to run:" >&2',
                '  echo "a merge over nothing would exit 0 and report a clean scan for a" >&2',
                '  echo "repository nothing actually scanned." >&2',
                '  exit 1',
                'fi',
                'if [ -n "$ASH_MISSING" ]; then',
                '  echo "Missing results for shard(s):${ASH_MISSING} (collected ${ASH_PRESENT} of" >&2',
                '  echo "${ASH_SHARD_COUNT}). Refusing to merge a partial result set, which would" >&2',
                '  echo "report a clean scan for scanners that never ran." >&2',
                '  exit 1',
                'fi',
                'echo "Collected all ${ASH_SHARD_COUNT} shard result sets."',
              ].join('\n'),
              [
                '# Surface each shard\'s own exit code for diagnosis. These do NOT',
                '# decide the verdict; the merge below does.',
                'for ash_dir in ./shard-results/shard-*; do',
                '  if [ -f "$ash_dir/.shard-exit-code" ]; then',
                '    echo "$ash_dir reported ASH exit code $(cat "$ash_dir/.shard-exit-code")"',
                '  fi',
                'done',
              ].join('\n'),
            ],
          },
          build: {
            commands: [
              // --results is repeatable and accepts a file or a directory. One
              // flag per shard directory, so a shard that vanished between the
              // check above and here still fails rather than being skipped.
              ['ash merge \\', ...resultsFlags, '  --output-dir ./ash-merged-output'].join('\n'),
            ],
          },
          post_build: {
            commands: [
              // Publish the merged report even when the merge failed the build, so
              // the findings that caused the failure are readable.
              'aws s3 cp --recursive --only-show-errors ./ash-merged-output ' +
                '"s3://${ASH_RESULTS_BUCKET}/${ASH_RESULTS_PREFIX}/merged/" || true',
            ],
          },
        },
        // No `artifacts` block on purpose: the merge action declares no output
        // artifact, and CodeBuild fails a CODEPIPELINE build that emits artifacts
        // the action cannot store. The merged report goes to the results bucket.
      }),
    });
  }
}

/**
 * Write the deployment-wide ASH config into the build, when one was supplied.
 *
 * The CodeBuild environment runs the ASH image but not its MCP entrypoint, so
 * nothing has materialized the config yet. Same mechanism as the entrypoint:
 * write the file, point `ASH_CONFIG` at it.
 *
 * `ASH_CONFIG` is set as a PROJECT environment variable, not exported here. An
 * `export` inside one buildspec command is not guaranteed to reach a later
 * phase's shell, so the path is always set and only the FILE is conditional.
 * That is safe because ASH's `get_default_config` tests the path for existence
 * before reading it and falls through to its defaults when it is absent.
 */
const MATERIALIZE_CONFIG_COMMAND = `if [ -n "\${ASH_BASE_CONFIG_SSM_PARAMETER:-}" ]; then
  mkdir -p "$(dirname "$ASH_CONFIG")"
  aws ssm get-parameter --name "$ASH_BASE_CONFIG_SSM_PARAMETER" --with-decryption \\
    --query Parameter.Value --output text > "$ASH_CONFIG"
else
  echo "No ASH base configuration supplied; ASH will use its built-in defaults."
fi`;
