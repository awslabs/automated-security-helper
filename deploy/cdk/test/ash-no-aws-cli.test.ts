/**
 * The class-level gate: nothing that runs inside the ASH image may invoke the
 * `aws` CLI.
 *
 * WHY THIS GATE EXISTS
 * --------------------
 * The ASH image installs no AWS CLI. It does depend on `boto3`, declared in ASH's
 * pyproject.toml `dependencies`, so `python3` with boto3 is the only AWS API
 * client guaranteed to be present. `deploy/cdk/lib/ash-container-scripts.ts` has
 * recorded that constraint since it was written, and its MCP entrypoint honours
 * it — but the distributed pipeline's buildspecs did not, and shipped four `aws`
 * invocations into projects whose CodeBuild environment image is the ASH image.
 * A deployed AshDistributedPipeline failed every shard identically:
 *
 *   /codebuild/output/tmp/script.sh: 4: aws: not found
 *   Reason: exit status 127
 *
 * The scan itself succeeded; the shards died afterwards, on upload. So the Scan
 * stage failed, Merge never ran, and the target was unreachable at runtime while
 * deployment reported success. Fixing those four sites without a gate would leave
 * the fifth to be found the same way, in a deployed pipeline.
 *
 * WHY THE CHECK IS KEYED ON THE IMAGE AND NOT ON A FILE OR A DENYLIST
 * ------------------------------------------------------------------
 * `aws` is correct in this app — just not everywhere. The image build runs on a
 * CodeBuild *standard* image, which does ship the CLI, and it needs
 * `aws ecr get-login-password` to push. So the question is never "does this
 * string appear" but "which image does this command run in", and the template is
 * where that is decided. Every CodeBuild project is classified by its
 * `Environment.Image` and only the ones running the ASH image are held to the
 * rule.
 *
 * THE MEASUREMENT TRAP THIS FILE IS BUILT AROUND
 * ---------------------------------------------
 * A gate like this fails open in two ways, and both look exactly like a pass:
 *
 *   1. The classifier stops recognizing any project as ASH-image — a construct
 *      swap, a refactor — and the gate iterates over nothing.
 *   2. The detector regex stops matching an `aws` invocation, so every buildspec
 *      reads as clean.
 *
 * Neither would ever go red on its own. So the gate carries its own positive
 * controls: it asserts that it found ASH-image projects to check, and it asserts
 * that the detector still fires on the image build's real, legitimate
 * `aws ecr get-login-password`. That second control is the load-bearing one, and
 * it is deliberately built from code that is supposed to keep using the CLI
 * rather than from a synthetic fixture — a fixture proves the regex matches the
 * fixture, not that it matches this repository.
 */

import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import {
  ASH_S3_SYNC_SCRIPT,
  CODECOMMIT_GATE_HANDLER,
  MCP_ENTRYPOINT_SCRIPT,
} from '../lib/ash-container-scripts';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';

/**
 * An `aws` CLI invocation: the bare word `aws` used as a command, followed by a
 * subcommand.
 *
 * The lookbehind is what keeps this from firing on the many legitimate places
 * the letters appear. Excluded by it: `amazonaws` and `.amazonaws.com` (preceded
 * by a word character), `aws-cdk-lib` and `aws-sdk` (no whitespace after `aws`),
 * `aws/codebuild/...` image ids (likewise), `arn:aws:iam:...` (colon, not
 * whitespace) and `AWS_REGION` (this pattern is case-sensitive on purpose).
 *
 * `/` is deliberately NOT in the lookbehind class, so an absolute invocation such
 * as `/usr/local/bin/aws s3 cp` is still caught.
 */
const AWS_CLI_INVOCATION = /(?<![\w.-])aws\s+[a-z][a-z0-9-]*/;

/**
 * Every string anywhere inside a rendered template fragment.
 *
 * The strings are matched individually rather than against `JSON.stringify` of
 * the fragment, because stringify turns a real newline into the two characters
 * `\` and `n`. A command split as `aws \<newline>  s3 cp` would then no longer
 * contain `aws` followed by whitespace, and the detector would miss it — the gate
 * would pass on precisely the formatting a developer reaches for when a command
 * gets long.
 *
 * A BuildSpec is a string when it holds no tokens and an `Fn::Join` of string
 * fragments when it does, so both shapes have to be walked.
 */
function collectStrings(node: unknown, into: string[] = []): string[] {
  if (typeof node === 'string') {
    into.push(node);
  } else if (Array.isArray(node)) {
    for (const item of node) {
      collectStrings(item, into);
    }
  } else if (node !== null && typeof node === 'object') {
    for (const value of Object.values(node)) {
      collectStrings(value, into);
    }
  }
  return into;
}

/**
 * Does this CodeBuild project's environment image ship the AWS CLI?
 *
 * CodeBuild's own managed images are named `aws/codebuild/<family>:<version>`
 * and carry the CLI. Anything else in this app is an image this app built, which
 * is the ASH image.
 *
 * Fails CLOSED: an image this function cannot read as a managed image — an
 * `Fn::Join` over an ECR repository URI, or a shape added later — is treated as
 * the ASH image and held to the rule. The cost of being wrong that way is a test
 * that asks for a boto3 call where the CLI would have worked; the cost of failing
 * open is another exit 127 in a deployed pipeline.
 */
function runsInAshImage(image: unknown): boolean {
  return !(typeof image === 'string' && image.startsWith('aws/codebuild/'));
}

interface CodeBuildProject {
  readonly stack: string;
  readonly logicalId: string;
  readonly image: unknown;
  readonly buildSpecStrings: string[];
}

/** Every CodeBuild project across every stack the app synthesizes. */
function allCodeBuildProjects(): CodeBuildProject[] {
  const app = new App({ analyticsReporting: false });
  const stacks = {
    AshImagePipeline: new AshImagePipelineStack(app, 'AshImagePipeline'),
    AshAgentCore: new AshAgentCoreStack(app, 'AshAgentCore'),
    AshFargate: new AshFargateStack(app, 'AshFargate'),
    AshCodeCommitGate: new AshCodeCommitGateStack(app, 'AshCodeCommitGate'),
    AshDistributedPipeline: new AshDistributedPipelineStack(app, 'AshDistributedPipeline'),
  };

  const projects: CodeBuildProject[] = [];
  for (const [stackName, stack] of Object.entries(stacks)) {
    const template = Template.fromStack(stack);
    for (const [logicalId, resource] of Object.entries(
      template.findResources('AWS::CodeBuild::Project'),
    )) {
      projects.push({
        stack: stackName,
        logicalId,
        image: resource.Properties?.Environment?.Image,
        buildSpecStrings: collectStrings(resource.Properties?.Source?.BuildSpec ?? {}),
      });
    }
  }
  return projects;
}

/** Each offending line, labelled, so a failure names the site rather than the count. */
function awsCliInvocations(project: CodeBuildProject): string[] {
  const found: string[] = [];
  for (const value of project.buildSpecStrings) {
    for (const line of value.split('\n')) {
      if (AWS_CLI_INVOCATION.test(line)) {
        found.push(`${project.stack}/${project.logicalId}: ${line.trim()}`);
      }
    }
  }
  return found;
}

describe('the detector itself', () => {
  // A silently-broken regex is the single likeliest way this whole file starts
  // reporting a clean repository. These cases are the ones that actually occur
  // in this tree, in both directions.
  test.each([
    'aws s3 cp --recursive ./out s3://bucket/prefix/',
    'aws ssm get-parameter --name "$ASH_BASE_CONFIG_SSM_PARAMETER"',
    'aws ecr get-login-password --region us-east-1',
    '  aws s3 cp ./a s3://b/c',
    '/usr/local/bin/aws s3 cp ./a s3://b/c',
    'if [ -n "$X" ]; then aws s3 cp ./a s3://b/c; fi',
  ])('flags %p', (line) => {
    expect(AWS_CLI_INVOCATION.test(line)).toBe(true);
  });

  test.each([
    'python3 ash_s3_sync.py upload ash_output "$RESULTS_BUCKET" "$KEY_PREFIX"',
    "python3 -c \"import os, sys, boto3; boto3.client('ssm')\"",
    '123456789012.dkr.ecr.us-east-1.amazonaws.com/ash:cli-amd64',
    'arn:aws:iam::123456789012:role/AshRole',
    'aws/codebuild/amazonlinux-x86_64-standard:6.0',
    'echo "$AWS_REGION"',
    'import * as codebuild from "aws-cdk-lib/aws-codebuild";',
    's3://bucket/prefix/',
  ])('does not flag %p', (line) => {
    expect(AWS_CLI_INVOCATION.test(line)).toBe(false);
  });
});

describe('no command destined for the ASH image invokes the aws CLI', () => {
  const projects = allCodeBuildProjects();
  const ashImageProjects = projects.filter((p) => runsInAshImage(p.image));
  const managedImageProjects = projects.filter((p) => !runsInAshImage(p.image));

  test('POSITIVE CONTROL: there are ASH-image projects to check', () => {
    // Without this, a classifier that stopped recognizing the ASH image would
    // make the gate below iterate over an empty list and report success.
    expect(ashImageProjects.length).toBeGreaterThan(0);
  });

  test('POSITIVE CONTROL: the detector still fires on the image build', () => {
    // The image build runs on a CodeBuild managed image and legitimately uses
    // `aws ecr get-login-password` to authenticate its push. It is therefore a
    // live example of the thing the gate looks for, in code that is supposed to
    // keep using the CLI. If this stops matching, the detector has gone blind and
    // the gate below is meaningless — which is why this is asserted rather than
    // assumed.
    expect(managedImageProjects.length).toBeGreaterThan(0);
    const detected = managedImageProjects.flatMap((p) => awsCliInvocations(p));
    expect(detected.join('\n')).toContain('aws ecr get-login-password');
  });

  test('the ASH image ships no AWS CLI, so no buildspec running in it may use one', () => {
    const offenders = ashImageProjects.flatMap((p) => awsCliInvocations(p));
    // The message carries every site, because fixing one instance of this and
    // leaving the rest is how it shipped the first time.
    expect(offenders).toEqual([]);
  });
});

describe('the scripts baked into or written by the ASH image use boto3', () => {
  // These run inside the ASH image too, but never appear in a buildspec — the
  // entrypoint is baked into the image and the gate handler is a Lambda handler
  // in an image derived from it. The image-keyed check above cannot see either,
  // so they are named explicitly.
  const scripts: Record<string, string> = {
    MCP_ENTRYPOINT_SCRIPT,
    CODECOMMIT_GATE_HANDLER,
    ASH_S3_SYNC_SCRIPT,
  };

  test.each(Object.keys(scripts))('%s invokes no aws CLI', (name) => {
    const offenders = scripts[name]
      .split('\n')
      .filter((line) => AWS_CLI_INVOCATION.test(line))
      .map((line) => line.trim());
    expect(offenders).toEqual([]);
  });

  test.each(Object.keys(scripts))('%s reaches AWS through boto3', (name) => {
    // The converse of the check above. A script that dropped its AWS access
    // entirely would satisfy "no aws CLI" while no longer doing its job.
    expect(scripts[name]).toContain('boto3');
  });
});
