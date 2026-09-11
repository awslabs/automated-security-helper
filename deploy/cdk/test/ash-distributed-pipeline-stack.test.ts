import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';

function synth(shardCount?: string): Template {
  const app = new App({
    analyticsReporting: false,
    context: shardCount === undefined ? {} : { shardCount },
  });
  return Template.fromStack(new AshDistributedPipelineStack(app, 'AshDistributedPipeline'));
}

function buildSpecsByName(template: Template): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [logicalId, resource] of Object.entries(
    template.findResources('AWS::CodeBuild::Project'),
  )) {
    out[logicalId] = JSON.stringify(resource.Properties?.Source?.BuildSpec ?? {});
  }
  return out;
}

describe('sharded scan contract', () => {
  const template = synth();

  test('every shard passes a zero-based index together with the count', () => {
    // ASH refuses one flag without the other, and indices are zero-based. A
    // one-based index would silently skip shard 0's scanners and double-run
    // another shard's.
    const shardEnvs = Object.values(template.findResources('AWS::CodeBuild::Project'))
      .map((r) => r.Properties?.Environment?.EnvironmentVariables ?? [])
      .filter((vars: { Name: string }[]) => vars.some((v) => v.Name === 'ASH_SHARD_INDEX'));

    expect(shardEnvs).toHaveLength(4);
    const indices = shardEnvs
      .map((vars: { Name: string; Value: string }[]) =>
        Number(vars.find((v) => v.Name === 'ASH_SHARD_INDEX')!.Value),
      )
      .sort((a, b) => a - b);
    expect(indices).toEqual([0, 1, 2, 3]);

    for (const vars of shardEnvs) {
      const count = (vars as { Name: string; Value: string }[]).find(
        (v) => v.Name === 'ASH_SHARD_COUNT',
      )!.Value;
      expect(Number(count)).toBe(4);
    }
  });

  test('shards do not gate: each captures ASH exit code and exits 0', () => {
    // THE central correctness property of this stack. A shard with no findings
    // exits 0 and a shard with findings exits 2, so gating per shard both passes
    // scans that should fail and fails the pipeline before other shards' findings
    // have been collected.
    const specs = Object.entries(buildSpecsByName(template)).filter(([, spec]) =>
      spec.includes('ASH_SHARD_INDEX'),
    );
    expect(specs).toHaveLength(4);
    for (const [, spec] of specs) {
      expect(spec).toContain('set +e');
      expect(spec).toContain('ASH_EXIT=$?');
      expect(spec).toContain('.shard-exit-code');
      expect(spec).toContain('exit 0');
    }
  });

  test('shards pass --no-fail-on-findings', () => {
    // States the intent: findings are the merge action's business. Correctness
    // does not rest on this flag; the results-file check below is what does.
    const specs = Object.values(buildSpecsByName(template)).filter((s) =>
      s.includes('ASH_SHARD_INDEX'),
    );
    expect(specs).toHaveLength(4);
    for (const spec of specs) {
      expect(spec).toContain('--no-fail-on-findings');
    }
  });

  test('a shard that produced no results file fails instead of passing empty', () => {
    // Click reports a usage error as exit 2 and ASH reports actionable findings as
    // exit 2. Trusting the code would let an unrecognized flag look like "found
    // findings" and upload an empty shard, which the merge would then treat as a
    // clean subset. Gating on the artifact the merge consumes removes the
    // ambiguity entirely.
    const specs = Object.values(buildSpecsByName(template)).filter((s) =>
      s.includes('ASH_SHARD_INDEX'),
    );
    for (const spec of specs) {
      expect(spec).toContain('if [ ! -f ./ash-shard-output/ash_aggregated_results.json ]');
      expect(spec).toContain('exit 1');
    }
  });

  test('the merge requires an actual results file from every shard', () => {
    // An empty directory is exactly what an early-failing shard leaves behind, so
    // a directory check would pass it.
    const [, spec] = Object.entries(buildSpecsByName(template)).find(([, s]) =>
      s.includes('ash merge'),
    )!;
    expect(spec).toContain('shard-results/shard-');
    expect(spec).toContain('ash_aggregated_results.json');
  });

  test('the merge refuses to run on zero collected shards', () => {
    // Distinct from the partial case: merging nothing would exit 0 and report a
    // clean scan for a repository nothing scanned.
    const [, spec] = Object.entries(buildSpecsByName(template)).find(([, s]) =>
      s.includes('ash merge'),
    )!;
    expect(spec).toContain('ASH_PRESENT');
    expect(spec).toContain('-eq 0');
    expect(spec).toContain('Refusing to run');
  });

  test('the shard upload runs under errexit so a lost upload fails the shard', () => {
    // The exit-code suppression is deliberately narrow. If it wrapped the upload
    // too, a shard could publish nothing and still report success, and the merge
    // would under-report.
    const [, spec] = Object.entries(buildSpecsByName(template)).find(([, s]) =>
      s.includes('ASH_SHARD_INDEX'),
    )!;
    // Matched without a trailing newline on purpose. The buildspec is rendered
    // into a JSON string and then stringified again for this assertion, so each
    // real newline arrives double-escaped; pinning the escaping would make this
    // test fail on a rendering change rather than on a behaviour change.
    //
    // Matched with the `python3 /tmp/` prefix, not on the bare script name: the
    // helper's own docstring carries a usage line reading `ash-s3-sync.py upload
    // <local-dir> ...`, and that text is written into pre_build by the heredoc. A
    // bare-name search finds the documentation and reports the upload as
    // happening before the scan.
    const restoreAt = spec.indexOf('set -e');
    const uploadAt = spec.indexOf('python3 /tmp/ash-s3-sync.py upload');
    expect(restoreAt).toBeGreaterThan(-1);
    expect(uploadAt).toBeGreaterThan(restoreAt);
  });

  test('S3 transfers use boto3, because the ASH image has no AWS CLI', () => {
    // The shard and merge projects run IN the ASH image, which ships no `aws`.
    // This shipped once as `aws s3 cp` and failed every shard at post_build with
    // exit 127, after the scan had already succeeded. The class-level gate lives
    // in ash-no-aws-cli.test.ts; this pins the specific commands.
    const specs = buildSpecsByName(template);
    const shardSpecs = Object.values(specs).filter((s) => s.includes('ASH_SHARD_INDEX'));
    expect(shardSpecs).toHaveLength(4);
    for (const spec of shardSpecs) {
      expect(spec).toContain('python3 /tmp/ash-s3-sync.py upload ./ash-shard-output');
    }

    const [, mergeSpec] = Object.entries(specs).find(([, s]) => s.includes('ash merge'))!;
    expect(mergeSpec).toContain('python3 /tmp/ash-s3-sync.py download');
    expect(mergeSpec).toContain('python3 /tmp/ash-s3-sync.py upload ./ash-merged-output');
  });

  test('the helper is written in pre_build, before any phase that uses it', () => {
    // post_build runs even when the build phase failed, so a helper materialized
    // on the success path only would replace a scan failure with a confusing
    // "no such file" failure.
    const users = Object.values(buildSpecsByName(template)).filter((s) =>
      s.includes('python3 /tmp/ash-s3-sync.py'),
    );
    // Four shards plus the merge. A zero here would make the ordering assertion
    // below vacuous.
    expect(users).toHaveLength(5);
    for (const spec of users) {
      const writtenAt = spec.indexOf("cat > /tmp/ash-s3-sync.py <<'PY'");
      const firstUseAt = spec.indexOf('python3 /tmp/ash-s3-sync.py');
      expect(writtenAt).toBeGreaterThan(-1);
      expect(firstUseAt).toBeGreaterThan(writtenAt);
    }
  });

  test('the base config is read with boto3, not the AWS CLI', () => {
    // Latent rather than correct before: AshBaseConfigYaml defaults empty, so the
    // else branch ran and nobody hit `aws ssm get-parameter`. An adopter who
    // supplied a base config would have.
    //
    // Scoped by MATERIALIZE_CONFIG_COMMAND's own message rather than by the
    // parameter name. The image-build project in this same stack bakes the MCP
    // entrypoint into the image with a heredoc, and that script reads the same
    // ASH_BASE_CONFIG_SSM_PARAMETER — so filtering on the variable name picks up
    // six buildspecs, one of which is a managed-image build that materializes no
    // config of its own.
    const configConsumers = Object.values(buildSpecsByName(template)).filter((s) =>
      s.includes('No ASH base configuration supplied'),
    );
    expect(configConsumers).toHaveLength(5);
    for (const spec of configConsumers) {
      expect(spec).toContain("boto3.client('ssm')");
      expect(spec).not.toContain('aws ssm get-parameter');
    }
  });

  test('the merge action passes one repeatable --results per shard', () => {
    const [, spec] = Object.entries(buildSpecsByName(template)).find(([, s]) =>
      s.includes('ash merge'),
    )!;
    for (let index = 0; index < 4; index += 1) {
      expect(spec).toContain(`--results ./shard-results/shard-${index}`);
    }
    expect(spec).toContain('--output-dir ./ash-merged-output');
  });

  test('the merge refuses a partial result set', () => {
    // Merging four of five shards would report a clean scan for scanners that
    // never ran, which is worse than failing.
    const [, spec] = Object.entries(buildSpecsByName(template)).find(([, s]) =>
      s.includes('ash merge'),
    )!;
    expect(spec).toContain('Refusing to merge a partial');
    expect(spec).toContain('exit 1');
  });

  test('shard results travel through S3, not pipeline artifacts', () => {
    // A CodeBuild pipeline action accepts 1 to 5 input artifacts, so an artifact
    // per shard cannot express a six-way split at all.
    const stages = Object.values(template.findResources('AWS::CodePipeline::Pipeline'))[0]
      .Properties.Stages;
    const scanStage = stages.find((s: { Name: string }) => s.Name === 'Scan');
    expect(scanStage.Actions).toHaveLength(4);
    for (const action of scanStage.Actions) {
      expect(action.OutputArtifacts ?? []).toHaveLength(0);
      expect(action.RunOrder).toBe(1);
    }
    const mergeStage = stages.find((s: { Name: string }) => s.Name === 'Merge');
    expect(mergeStage.Actions).toHaveLength(1);
    expect(mergeStage.Actions[0].InputArtifacts).toHaveLength(1);
  });

  test('the image build is the first stage after source, so the pipeline self-bootstraps', () => {
    const stages = Object.values(template.findResources('AWS::CodePipeline::Pipeline'))[0]
      .Properties.Stages;
    expect(stages.map((s: { Name: string }) => s.Name)).toEqual([
      'Source',
      'BuildImage',
      'Scan',
      'Merge',
    ]);
  });

  test('this stack runs no deploy-time bootstrap, because the pipeline is one', () => {
    template.resourceCountIs('Custom::AshImageBootstrap', 0);
  });

  test('shard and merge jobs run inside the ASH image from this account', () => {
    for (const resource of Object.values(template.findResources('AWS::CodeBuild::Project'))) {
      const image = JSON.stringify(resource.Properties?.Environment?.Image ?? '');
      if (image.includes('dkr.ecr')) {
        expect(image).toContain('cli-amd64');
      }
    }
  });
});

describe('shard count is a synthesis-time decision', () => {
  test('context changes the number of shard actions', () => {
    const template = synth('7');
    const stages = Object.values(template.findResources('AWS::CodePipeline::Pipeline'))[0]
      .Properties.Stages;
    expect(stages.find((s: { Name: string }) => s.Name === 'Scan').Actions).toHaveLength(7);
    const [, spec] = Object.entries(buildSpecsByName(template)).find(([, s]) =>
      s.includes('ash merge'),
    )!;
    expect(spec).toContain('--results ./shard-results/shard-6');
  });

  test('ShardCount is NOT a CloudFormation parameter, and says so in an output', () => {
    // Exposing it as a deploy-time parameter while the action count was fixed at
    // synthesis would let shards above the action count silently never run.
    const template = synth();
    const json = template.toJSON();
    expect(Object.keys(json.Parameters ?? {})).not.toContain('ShardCount');
    expect(json.Outputs.ShardCount.Value).toBe('4');
    expect(json.Outputs.ShardCount.Description).toContain('re-synthesizing');
  });

  test('a nonsensical shard count is rejected at synthesis', () => {
    expect(() => synth('0')).toThrow(/positive integer/);
    expect(() => synth('banana')).toThrow(/positive integer/);
  });
});
