// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as codebuild from 'aws-cdk-lib/aws-codebuild';
import * as codepipeline from 'aws-cdk-lib/aws-codepipeline';
import * as codepipeline_actions from 'aws-cdk-lib/aws-codepipeline-actions';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as pipelines from 'aws-cdk-lib/pipelines';
import { Construct } from 'constructs';
import {
  DEFAULT_ASH_REPOSITORY,
  installCommands,
  InstallOptions,
  mergeCommands,
  scanCommands,
  shardOutputDirectory,
  shardScanCommands,
} from './private/commands';
import { ASHInstallMode, ASHSeverityThreshold } from './types';

/**
 * Upper bound on `shardCount`.
 *
 * Not a service limit. Sharding splits the scanner list, so once the shard count
 * passes the number of scanners the extra shards have nothing to run and cost a
 * CodeBuild start each. A typo like `shardCount: 300` should fail loudly rather
 * than bill for 300 empty builds.
 */
const MAX_SHARD_COUNT = 50;

/**
 * Configuration for `ASHScanStep`.
 */
export interface ASHScanStepProps {
  /**
   * The file set to scan, normally the pipeline's source.
   *
   * Pass the source output of your pipeline, or any earlier step that produces
   * the tree you want scanned.
   */
  readonly input: pipelines.IFileSetProducer;

  /**
   * How many parallel shards to split the scan across.
   *
   * `1` runs a single scan that owns its own verdict. Any value above `1` fans
   * the scanners out across that many CodeBuild actions and adds one merge
   * action that reduces their partial results to a single verdict.
   *
   * @default 1
   */
  readonly shardCount?: number;

  /**
   * How the ASH CLI gets into the build container.
   *
   * @default ASHInstallMode.PIP
   */
  readonly installMode?: ASHInstallMode;

  /**
   * Git ref of ASH to install: a release tag such as `v3.7.0`, a branch, or a
   * commit.
   *
   * A git ref rather than a distribution version because ASH is installed from
   * its repository, not from PyPI. Ignored by `PREINSTALLED`, where the image
   * already decides.
   *
   * The default is a pinned release tag, so two runs of the same pipeline
   * definition scan with the same ASH. Pointing this at a branch gives up that
   * property.
   *
   * @default - a pinned ASH release tag
   */
  readonly version?: string;

  /**
   * Repository to install ASH from.
   *
   * Must be an `https://` URL. Used by `PIP` and `UVX`; ignored by
   * `PREINSTALLED`, which installs nothing.
   *
   * @default - the upstream ASH repository
   */
  readonly sourceRepository?: string;

  /**
   * Lowest finding severity that fails the build.
   *
   * @default ASHSeverityThreshold.LOW
   */
  readonly severityThreshold?: ASHSeverityThreshold;

  /**
   * Directory ASH writes its results into, relative to the build's working
   * directory.
   *
   * @default '.ash/ash_output'
   */
  readonly outputDirectory?: string;

  /**
   * Build image for the scan and merge projects.
   *
   * ASH publishes no container image to any public registry, so the default is
   * a generic AWS-managed image that ASH is installed into. To run an image
   * that already contains ASH, supply it here and set `installMode` to
   * `ASHInstallMode.PREINSTALLED` -- and note that the image has to be one you
   * built and host yourself.
   *
   * @default codebuild.LinuxBuildImage.STANDARD_7_0
   */
  readonly buildImage?: codebuild.IBuildImage;

  /**
   * Compute size for the scan and merge projects.
   *
   * @default codebuild.ComputeType.SMALL
   */
  readonly computeType?: codebuild.ComputeType;

  /**
   * Extra environment variables for every project this step creates.
   *
   * @default - none
   */
  readonly environmentVariables?: { [name: string]: string };

  /**
   * Extra arguments appended to each `ash scan` invocation.
   *
   * Escape hatch for ASH options this construct does not model. Arguments are
   * passed through verbatim, so quote anything containing whitespace yourself.
   *
   * Shard and fail-on-findings options are rejected here: the construct decides
   * those, because letting a shard gate on its own findings would replace the
   * aggregate verdict with a partial one.
   *
   * @default - none
   */
  readonly extraScanArguments?: string[];

  /**
   * Additional IAM policy statements for the scan and merge project roles.
   *
   * @default - none
   */
  readonly rolePolicyStatements?: iam.PolicyStatement[];
}

/**
 * Options a caller may not set, because the construct's correctness depends on
 * them.
 *
 * `--shard-index` and `--shard-count` are computed per shard. The
 * fail-on-findings pair decides which action owns the verdict, and a shard is
 * never allowed to own it.
 */
const RESERVED_SCAN_ARGUMENTS = [
  '--shard-index',
  '--shard-count',
  '--fail-on-findings',
  '--no-fail-on-findings',
];

/**
 * A CDK Pipelines step that runs an Automated Security Helper scan.
 *
 * With the default `shardCount` of 1 the step is a single CodeBuild action that
 * scans the input and fails the stage on findings. Raising `shardCount` fans the
 * scanners out across that many parallel actions and appends a merge action; the
 * shards then run without gating and the merge action owns the verdict.
 *
 * That split is not configurable, and the reason is worth stating. A shard runs
 * only its slice of the scanner list, so a shard that finds nothing exits 0 no
 * matter what the other shards found. A pipeline that gated on shard exit codes
 * would pass whenever each individual slice happened to be clean, and a shard
 * that failed early would stop the merge from running at all, leaving the
 * pipeline to judge the repository on partial results. So shards always run with
 * `--no-fail-on-findings`, the merge action always exists when `shardCount > 1`,
 * and it always runs in a later run order than every shard.
 *
 * @example
 * declare const source: pipelines.CodePipelineSource;
 * const step = new ASHScanStep('SecurityScan', {
 *   input: source,
 *   shardCount: 4,
 *   severityThreshold: ASHSeverityThreshold.MEDIUM,
 * });
 */
export class ASHScanStep extends pipelines.Step implements pipelines.ICodePipelineActionFactory {
  /**
   * Number of parallel shards, after defaulting and validation.
   *
   * `1` means no fan-out and no merge action.
   */
  public readonly shardCount: number;

  /** Lowest finding severity that fails the build. */
  public readonly severityThreshold: ASHSeverityThreshold;

  /** How the ASH CLI is provisioned into the build container. */
  public readonly installMode: ASHInstallMode;

  /** Directory ASH writes results into. */
  public readonly outputDirectory: string;

  private readonly props: ASHScanStepProps;
  private readonly inputFileSet: pipelines.FileSet;
  private readonly version?: string;
  private readonly sourceRepository: string;
  private readonly extraScanArguments: string[];

  /**
   * @param id Identifier for this step, used to name the pipeline actions.
   * @param props Configuration for the scan.
   */
  public constructor(id: string, props: ASHScanStepProps) {
    super(id);

    this.props = props;
    this.shardCount = props.shardCount ?? 1;
    this.severityThreshold = props.severityThreshold ?? ASHSeverityThreshold.LOW;
    this.installMode = props.installMode ?? ASHInstallMode.PIP;
    this.outputDirectory = props.outputDirectory ?? '.ash/ash_output';
    this.version = props.version;
    this.sourceRepository =
      props.sourceRepository ?? DEFAULT_ASH_REPOSITORY;
    this.extraScanArguments = props.extraScanArguments ?? [];

    this.validateShardCount();
    this.validateExtraScanArguments();

    const primaryOutput = props.input.primaryOutput;
    if (!primaryOutput) {
      throw new Error(
        `ASHScanStep '${id}': props.input does not produce a file set. Pass a pipeline ` +
          'source or a step that produces one.',
      );
    }
    this.inputFileSet = primaryOutput;
    this.addDependencyFileSet(primaryOutput);
  }

  /**
   * Reject a shard count that is not a usable whole number.
   *
   * Non-integers matter because `shardCount` reaches Python as `--shard-count`,
   * where `2.5` is not a count; catching it at synth time turns a mid-pipeline
   * CLI error into a stack trace next to the offending code.
   */
  private validateShardCount(): void {
    const value = this.shardCount;
    if (!Number.isInteger(value)) {
      throw new Error(
        `ASHScanStep '${this.id}': shardCount must be a whole number, got ${value}.`,
      );
    }
    if (value < 1) {
      throw new Error(
        `ASHScanStep '${this.id}': shardCount must be at least 1, got ${value}. ` +
          'Use 1 for a single unsharded scan.',
      );
    }
    if (value > MAX_SHARD_COUNT) {
      throw new Error(
        `ASHScanStep '${this.id}': shardCount must be at most ${MAX_SHARD_COUNT}, got ${value}. ` +
          'Sharding splits the scanner list, so shards beyond the scanner count run nothing.',
      );
    }
  }

  /** Reject escape-hatch arguments that would take over the verdict. */
  private validateExtraScanArguments(): void {
    for (const argument of this.extraScanArguments) {
      const flag = argument.split('=')[0];
      if (RESERVED_SCAN_ARGUMENTS.includes(flag)) {
        throw new Error(
          `ASHScanStep '${this.id}': ${flag} cannot be passed through extraScanArguments. ` +
            'The construct sets the shard and fail-on-findings options itself so that the ' +
            'merge step owns the pass/fail verdict.',
        );
      }
    }
  }

  /**
   * Create the CodeBuild actions for this step and add them to the stage.
   *
   * Unsharded, this adds one action at the requested run order. Sharded, it adds
   * every shard at the requested run order so they run in parallel, then the
   * merge action one run order later so CodePipeline holds it until all shards
   * finish. The merge action consumes each shard's output artifact, so its
   * verdict is computed over every shard's results.
   */
  public produceAction(
    stage: codepipeline.IStage,
    options: pipelines.ProduceActionOptions,
  ): pipelines.CodePipelineActionFactoryResult {
    const inputArtifact = options.artifacts.toCodePipeline(this.inputFileSet);

    if (this.shardCount === 1) {
      const project = this.createProject(options.scope, 'Scan', this.unshardedBuildSpec());
      stage.addAction(
        new codepipeline_actions.CodeBuildAction({
          actionName: options.actionName,
          input: inputArtifact,
          project,
          runOrder: options.runOrder,
          variablesNamespace: options.variablesNamespace,
        }),
      );
      return { runOrdersConsumed: 1, project };
    }

    const shardArtifacts: codepipeline.Artifact[] = [];
    for (let shardIndex = 0; shardIndex < this.shardCount; shardIndex++) {
      const shardArtifact = options.artifacts.toCodePipeline(
        new pipelines.FileSet(`${this.id}-shard-${shardIndex}`, this),
      );
      shardArtifacts.push(shardArtifact);

      stage.addAction(
        new codepipeline_actions.CodeBuildAction({
          actionName: `${options.actionName}Shard${shardIndex}`,
          input: inputArtifact,
          outputs: [shardArtifact],
          project: this.createProject(
            options.scope,
            `Shard${shardIndex}`,
            this.shardBuildSpec(shardIndex),
          ),
          runOrder: options.runOrder,
        }),
      );
    }

    // CodeBuild exposes each secondary source at CODEBUILD_SRC_DIR_<artifactName>.
    // aws-cdk-lib's own CodeBuild factory builds this variable name the same way.
    const resultsPaths = shardArtifacts.map(
      (artifact) => `$CODEBUILD_SRC_DIR_${artifact.artifactName}`,
    );
    const mergeProject = this.createProject(
      options.scope,
      'Merge',
      this.mergeBuildSpec(resultsPaths),
    );

    stage.addAction(
      new codepipeline_actions.CodeBuildAction({
        actionName: `${options.actionName}Merge`,
        input: shardArtifacts[0],
        extraInputs: shardArtifacts.slice(1),
        project: mergeProject,
        // One run order later than the shards, which is what makes CodePipeline
        // wait for all of them and what makes this action the gate.
        runOrder: options.runOrder + 1,
        variablesNamespace: options.variablesNamespace,
      }),
    );

    return { runOrdersConsumed: 2, project: mergeProject };
  }

  /** Buildspec for the single unsharded scan, which owns its own verdict. */
  private unshardedBuildSpec(): codebuild.BuildSpec {
    return codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        install: {
          commands: this.installCommandList(),
        },
        build: {
          commands: scanCommands(
            {
              sourceDirectory: '.',
              outputDirectory: this.outputDirectory,
              severityThreshold: this.severityThreshold,
              extraScanArguments: this.extraScanArguments,
            },
            this.installOptions(),
          ),
        },
      },
      artifacts: {
        'base-directory': this.outputDirectory,
        files: ['**/*'],
      },
    });
  }

  /**
   * Buildspec for one shard.
   *
   * Each shard writes to its own subdirectory: ASH clears the output directory
   * before scanning, so shards sharing one directory would delete each other's
   * results. The artifact is taken from that subdirectory, which is what lets
   * the merge action treat each input as one shard's results.
   */
  private shardBuildSpec(shardIndex: number): codebuild.BuildSpec {
    const outputDirectory = shardOutputDirectory(this.outputDirectory, shardIndex);
    return codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        install: {
          commands: this.installCommandList(),
        },
        build: {
          commands: shardScanCommands(
            {
              sourceDirectory: '.',
              outputDirectory,
              shardIndex: String(shardIndex),
              shardCount: String(this.shardCount),
              severityThreshold: this.severityThreshold,
              extraScanArguments: this.extraScanArguments,
            },
            this.installOptions(),
          ),
        },
      },
      artifacts: {
        'base-directory': outputDirectory,
        files: ['**/*'],
      },
    });
  }

  /** Buildspec for the merge action, whose exit code is the verdict. */
  private mergeBuildSpec(resultsPaths: string[]): codebuild.BuildSpec {
    return codebuild.BuildSpec.fromObject({
      version: '0.2',
      phases: {
        install: {
          commands: this.installCommandList(),
        },
        build: {
          commands: mergeCommands(
            resultsPaths,
            this.outputDirectory,
            this.installOptions(),
          ),
        },
      },
      artifacts: {
        'base-directory': this.outputDirectory,
        files: ['**/*'],
      },
    });
  }

  /** Where ASH comes from, shared by every command this step renders. */
  private installOptions(): InstallOptions {
    return {
      mode: this.installMode,
      version: this.version,
      sourceRepository: this.sourceRepository,
    };
  }

  private installCommandList(): string[] {
    return installCommands(this.installOptions());
  }

  /** Create one CodeBuild project for a scan, shard or merge action. */
  private createProject(
    scope: Construct,
    name: string,
    buildSpec: codebuild.BuildSpec,
  ): codebuild.Project {
    const project = new codebuild.PipelineProject(scope, `${this.id}${name}`, {
      buildSpec,
      environment: {
        buildImage: this.props.buildImage ?? codebuild.LinuxBuildImage.STANDARD_7_0,
        computeType: this.props.computeType ?? codebuild.ComputeType.SMALL,
      },
      environmentVariables: renderEnvironmentVariables(this.props.environmentVariables),
    });

    for (const statement of this.props.rolePolicyStatements ?? []) {
      project.addToRolePolicy(statement);
    }

    return project;
  }
}

/** Translate a plain string map into CodeBuild's environment variable shape. */
function renderEnvironmentVariables(
  variables: { [name: string]: string } | undefined,
): { [name: string]: codebuild.BuildEnvironmentVariable } {
  const rendered: { [name: string]: codebuild.BuildEnvironmentVariable } = {};
  for (const [name, value] of Object.entries(variables ?? {})) {
    rendered[name] = { value };
  }
  return rendered;
}
