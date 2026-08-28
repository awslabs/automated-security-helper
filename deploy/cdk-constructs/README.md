# ASH CDK constructs

CDK Pipelines constructs for running an [Automated Security Helper](https://github.com/awslabs/automated-security-helper)
(ASH) scan as part of a pipeline. One construct, `ASHScanStep`, adds a security
scan to a `CodePipeline` and optionally fans the scan out across parallel
CodeBuild actions.

## Not published anywhere

This package is **consumable only from a local build**. It is not on npm, PyPI,
NuGet, Maven, or any other registry, and nothing in this repository publishes it.
Distribution is a separate decision that has not been made, so:

- `package.json` sets `"private": true`, which makes `npm publish` refuse to run.
- No publish step is wired into CI.
- There is no `.npmrc` and no registry credential anywhere in the package.

The package name and the per-language target names (`ash_cdk_constructs`,
`io.github.awslabs.ash.cdk`, `Awslabs.Ash.Cdk`, `ashcdk`) are provisional. They
are declared so the package is publish-*ready* and so `jsii` can validate the
API against every target language, not because those coordinates have been
claimed.

## Requirements

`aws-cdk-lib >= 2.267.0` and `constructs >= 10.8.1`, both peer dependencies, so
your app supplies them. The `aws-cdk-lib` floor is deliberately higher than the
`>=2.257.0` this repository's `pyproject.toml` uses for cdk-nag: 2.267.0 is the
oldest release with no known advisories against it or its bundled dependencies,
and a floor that starts at a version with a published advisory is a poor default
for a security tool. The development dependency is pinned to exactly the floor so
the package is always compiled against the oldest version it claims to support.

To use it today, build it and depend on the directory:

```console
cd deploy/cdk-constructs
npm ci
npm run build
```

```jsonc
// in your app's package.json
"dependencies": {
  "ash-cdk-constructs": "file:../path/to/deploy/cdk-constructs"
}
```

## There is no ASH container image

ASH publishes no container image to any public registry, and will not, for
licensing reasons. So this construct never references a prebuilt `ash` image.
It defaults to a generic AWS-managed CodeBuild image and installs ASH into it.

If you want a warm image, build one yourself from the `Dockerfile` at the root of
this repository, host it in a registry you control, and point the construct at
it:

```ts
new ASHScanStep('SecurityScan', {
  input: source,
  buildImage: codebuild.LinuxBuildImage.fromEcrRepository(myRepo, 'latest'),
  installMode: ASHInstallMode.PREINSTALLED,
});
```

## Usage

```ts
import { CodePipeline, CodePipelineSource, ShellStep } from 'aws-cdk-lib/pipelines';
import { ASHScanStep, ASHSeverityThreshold } from 'ash-cdk-constructs';

const source = CodePipelineSource.gitHub('my-org/my-repo', 'main');

const pipeline = new CodePipeline(this, 'Pipeline', {
  synth: new ShellStep('Synth', {
    input: source,
    commands: ['npm ci', 'npx cdk synth'],
  }),
});

pipeline.addWave('Security', {
  pre: [
    new ASHScanStep('SecurityScan', {
      input: source,
      severityThreshold: ASHSeverityThreshold.MEDIUM,
    }),
  ],
});
```

That produces one CodeBuild action that scans the source and fails the stage if
it finds anything at or above the threshold.

### Sharding

Raise `shardCount` to split the scanners across parallel actions:

```ts
new ASHScanStep('SecurityScan', {
  input: source,
  shardCount: 4,
});
```

`shardCount: 4` produces five actions: four shards that run in parallel, and one
merge action that runs after them.

| `shardCount` | Actions | Which action decides pass/fail |
| --- | --- | --- |
| `1` (default) | `SecurityScan` | the scan itself |
| `n > 1` | `SecurityScanShard0` … `SecurityScanShard{n-1}`, then `SecurityScanMerge` | the merge action |

### Why shards cannot fail the build

This is the part of the design worth understanding before changing anything.

A shard runs only its slice of the scanner list. A shard that finds nothing exits
0 regardless of what the other shards found, so a shard's exit code describes a
subset of the repository and not the repository. Two things follow:

- A pipeline that gated on shard exit codes would pass whenever each individual
  slice happened to be clean, which is not the same as the codebase being clean.
- A shard that failed fast would stop the merge from ever running, leaving the
  pipeline to judge the codebase on partial results.

So the split is not configurable. Shards always run with
`--no-fail-on-findings`; the merge action always exists when `shardCount > 1`;
the merge action always runs at a later run order than every shard; and
`extraScanArguments` rejects `--shard-index`, `--shard-count`,
`--fail-on-findings` and `--no-fail-on-findings` so the escape hatch cannot be
used to move the verdict.

Because the merge action's exit code *is* the pipeline's verdict, `ash merge`
must exit non-zero when the merged findings breach the configured threshold.

Each shard also writes to its own output directory (`<outputDirectory>/shard-N`).
ASH clears its output directory before scanning, so shards sharing a directory
would delete each other's results.

## Generated buildspecs

Three buildspec files in this directory are generated from the same code the
construct renders its CodeBuild projects from, so a non-CDK consumer and a CDK
consumer run the same commands:

| File | Purpose | Fails on findings |
| --- | --- | --- |
| `buildspec.yml` | full unsharded scan | yes |
| `buildspec-shard.yml` | one shard; set `ASH_SHARD_INDEX` and `ASH_SHARD_COUNT` | no, by design |
| `buildspec-merge.yml` | merge; set `ASH_SHARD_RESULTS` to the shard directories | yes |

Regenerate them with:

```console
cd deploy/cdk-constructs && npm ci && npm run generate:buildspec
```

Verify them without rewriting anything — this is what a CI drift gate should run:

```console
cd deploy/cdk-constructs && npm ci && npm run check:buildspec
```

Both scripts compile before they generate, so either one works straight after a
bare `npm ci` with no separate build step. That matters for a drift gate: the
generator lives in compiled output, so a script that assumed `lib/` already
existed would fail with `MODULE_NOT_FOUND` and produce no file at all.

`check:buildspec` byte-compares each committed file against a fresh render and
exits non-zero on any difference. It compares bytes rather than parsed YAML on
purpose: a gate that compares parsed documents passes when someone has
reformatted or re-commented the committed file by hand, which is exactly the
drift it is supposed to catch.

Generation is deterministic. It never reads the clock, the hostname, the
filesystem or the local Python version, key order is insertion order rather than
hash order, and line endings are hard-coded to LF so the gate does not fail on
Windows for a file nobody edited.

## API

`ASHScanStep(id, props)` extends `pipelines.Step` and implements
`pipelines.ICodePipelineActionFactory`.

| Prop | Type | Default | Notes |
| --- | --- | --- | --- |
| `input` | `IFileSetProducer` | required | the file set to scan |
| `shardCount` | `number` | `1` | `1`–`50`; above 1 adds the merge action |
| `installMode` | `ASHInstallMode` | `PIP` | `PIP`, `UVX`, `PREINSTALLED` |
| `version` | `string` | pinned release tag | a git ref: tag, branch or commit |
| `sourceRepository` | `string` | upstream ASH repo | `https://` only |
| `severityThreshold` | `ASHSeverityThreshold` | `LOW` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `outputDirectory` | `string` | `.ash/ash_output` | |
| `buildImage` | `IBuildImage` | `LinuxBuildImage.STANDARD_7_0` | |
| `computeType` | `ComputeType` | `SMALL` | |
| `environmentVariables` | `map<string, string>` | none | |
| `extraScanArguments` | `string[]` | none | verdict and shard flags rejected |
| `rolePolicyStatements` | `PolicyStatement[]` | none | added to each project role |

`CRITICAL` and `HIGH` are equivalent: SARIF does not distinguish the two levels,
so ASH treats them as one.

`severityThreshold` is applied to whichever action owns the verdict: the scan
itself when unsharded, and the merge action when sharded. It is deliberately not
passed to shards. On `ash scan` that option changes only that scan's exit code,
and a shard's exit code is discarded by design, so a floor passed to a shard would
look like it was set while having no effect on anything.

### Triaging a failed merge

`ash merge` refuses results whose `metadata.shard` provenance is missing, which is
how it distinguishes one shard of several from a whole unsharded scan. Provenance
is recorded only when a scan runs with both `--shard-index` and `--shard-count`,
and it is skipped when the scan registered no scanners at all. So a merge action
failing with "no shard provenance found" usually means the fault is upstream in a
shard, not in the merge: either a shard ran `ash scan` without both flags, or a
shard's container registered zero scanners, for instance because a scanner plugin
failed to load. The merge action is where it surfaces, not where it broke.

Setting `shardCount` higher than the number of enabled scanners is wasteful rather
than broken. The surplus shards are assigned no scanners, still record provenance
and still merge; they just cost a CodeBuild start each. That was measured at 50
shards over a 5-scanner tree — 45 empty assignments, all 50 stamped, merged
findings identical to one unsharded scan — and `ash merge` carries a regression
test at that same ceiling, so it is a supported configuration rather than one that
happens to work.

`version` is a git ref, not a distribution version, because ASH is installed from
its repository. It defaults to a pinned release tag, so two runs of the same
pipeline definition scan with the same ASH; pointing it at a branch gives that up.

## How ASH gets installed

Every install mode fetches ASH from its git repository. None installs by
distribution name, and that is deliberate:

- ASH is **not published to PyPI**. The name `automated-security-helper` on PyPI
  is an unrelated single-release placeholder package with no connection to this
  project. Installing it would succeed, leave no `ash` on `PATH` so every build
  would fail at the scan step, and pull a third party's code into the container
  running your security scan.
- `aws-automated-security-helper` and `awslabs-automated-security-helper` do not
  exist on PyPI at all.

So the install is what this repository documents for CI:

```console
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
```

If ASH is ever published to PyPI under a name the project controls, installing by
name becomes preferable and a mode for it is worth adding. Until then there isn't
one, and a name-based install should not be introduced on the assumption that it
might get published later.

In the generated buildspecs the ref comes from an `ASH_VERSION` environment
variable defaulting to the pinned tag, so a consumer can scan with a different
ASH release by overriding one variable rather than editing a generated file:

```console
aws codebuild start-build --project-name my-scan \
  --environment-variables-override name=ASH_VERSION,value=v3.6.0,type=PLAINTEXT
```

## Development

```console
npm ci
npm run build      # runs jsii; a jsii violation in an exported signature fails here
npm test
```

Everything under `src/private/` is internal and deliberately not exported from
`src/index.ts`. jsii models only classes, interfaces and enums, so the free
functions there could not be part of the API even if that were desirable; keeping
them out means command rendering and buildspec generation can change without
breaking a generated Python, Java, .NET or Go package.

`jsii` generates and owns `tsconfig.json`, so it is not committed. Tests compile
against the committed `tsconfig.dev.json`, whose compiler settings match what
jsii emits so a test cannot pass under looser rules than the library builds with.
