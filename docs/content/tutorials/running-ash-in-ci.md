# Running ASH in CI

This guide explains how to integrate ASH v3 into various CI/CD platforms.

## Continuous Integration (CI) Execution

ASH supports running in CI environments as an executable container (e.g., via `docker run`) as well as via Container Job mechanisms, depending on CI platform support.

### Building ASH Container Images for CI Usage

Building ASH images for use in CI platforms requires targeting the `ci` stage of the `Dockerfile`:

```bash
# Via ash CLI
ash build-image --build-target ci

# Via docker or other OCI CLI
docker build --tag automated-security-helper:ci --target ci .
```

## Distributed Scanning Across CI Executors

One scan can be split across several CI executors and recombined afterwards. Each executor runs one shard:

```bash
ash scan --shard-index 0 --shard-count 4
```

Both options are required together. A shard is only meaningful as "index of count", so `--shard-index` on its own would scan part of the repository and report it as a whole scan. Indices are zero-based, so a four-way split uses 0, 1, 2 and 3. The environment variables `ASH_SHARD_INDEX` and `ASH_SHARD_COUNT` are equivalent to the two options, which is convenient on platforms that already hand you the index as an environment variable.

Executors never talk to each other. Each one works out its own slice from the shard index, the shard count and the scanner set, so there is no lock, no shared state and no ordering between shards.

A separate command recombines the shard results:

```bash
ash merge --results <file-or-directory> --results <file-or-directory> \
  --output-dir .ash/merged --output-formats sarif,markdown
```

`--results` is repeatable and accepts either an `ash_aggregated_results.json` file or a directory containing one, because CI artifact downloads land as directories.

### What Sharding Splits, and What That Costs

Sharding partitions the **scanner** set, not the file set. Scanners are handed a directory and most of them walk it themselves, so a file-level split would be honored by some scanners and ignored by the rest — and because merging does not deduplicate, every shard's semgrep findings would then appear once per shard. Partitioning the scanner set is honored by every scanner instead, without any scanner knowing that sharding exists.

That choice has consequences worth knowing before you pick a shard count:

1. **There is a ceiling at the number of scanners.** Today that is ten built-in scanners (bandit, cdk-nag, cfn-nag, checkov, detect-secrets, grype, npm-audit, opengrep, semgrep, syft) plus any scanner plugins you have added. A shard count above the number of scanners leaves the surplus shards with nothing to run. They still start, produce a valid empty report and merge correctly, so this is wasteful rather than wrong.
2. **Balance is by scanner count, not scanner cost.** Scanners are dealt round-robin over a sorted list, so shard sizes differ by at most one. Their runtimes do not: a shard holding semgrep finishes long after a shard holding syft.
3. **One slow scanner still sets the wall clock.** semgrep and checkov dominate ASH's runtime, so separating those two onto different executors is where most of the improvement comes from. Total time cannot fall below the slowest single scanner, and beyond roughly four shards there is very little left to win.

### The Merge Owns the Verdict

!!! warning
    A shard that finds nothing exits 0. Per-shard success does **not** mean the scan passed — it means that shard's scanners had nothing to report. A pipeline that gates on shard exit codes reports a clean scan whenever the findings happen to land on shards it is not looking at.

    Gate on the exit code of `ash merge`. It is the only step that has seen the whole scan.

The shape that follows from this is the same on every platform:

1. Shards run with `--no-fail-on-findings`, so a red shard means something operationally broke rather than "this shard found something".
2. Every shard uploads its `ash_aggregated_results.json` as an artifact.
3. The collect job runs only if every shard job succeeded, downloads all the shard artifacts and runs `ash merge` over them.
4. The collect job's exit code is the pipeline's verdict.

`ash merge` refuses to merge results that do not reconstruct exactly one whole scan. A missing shard index, a repeated index, and shards that disagree about the total count are all hard errors rather than a quietly short merge, because a report missing whole scanners reads exactly like a clean one. So the collect step fails loudly when a shard job did not upload its artifact. That is the intended behavior — do not work around it by letting the collect step run on whatever artifacts happen to be present.

!!! note
    ASH publishes no container image to any public registry, so there is no prebuilt `ash` image for these examples to pull. Install ASH on each executor as the single-job examples do, or build the image inside your own organization and push it to a registry you control.

## GitHub Actions

### Basic Integration

```yaml
name: ASH Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - name: Run ASH scan
        run: ash --mode local
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: ash-results
          path: .ash/ash_output
```

### Using Container Mode

```yaml
name: ASH Security Scan (Container)

on:
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - name: Run ASH scan
        run: ash --mode container
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: ash-results
          path: .ash/ash_output
```

### GitHub Advanced Security (Code Scanning)

ASH includes a dedicated reporter (`github-ghas`) that produces a SARIF file optimized for GitHub Advanced Security. It ensures findings display with proper severity levels (Critical/High/Medium/Low) instead of raw "Error" labels, and is significantly smaller than the standard SARIF output.

```yaml
name: ASH Security Scan with GitHub Advanced Security

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write  # Required for uploading SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git
      - name: Run ASH scan
        run: ash --mode local --no-fail-on-findings
      - name: Upload to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: .ash/ash_output/reports/ash.ghas.sarif
          category: ash-security-scan
```

!!! note
    Use `--no-fail-on-findings` to ensure the upload step runs even when findings are detected. The `if: always()` condition ensures the SARIF upload happens regardless of the scan exit code.

!!! tip
    The `ash.ghas.sarif` file is generated by default alongside all other reports. If you only need the GHAS report, you can disable other reporters in your `.ash/.ash.yaml` configuration.

### Adding Scan Results to PR Comments

```yaml
name: ASH Security Scan with PR Comments

on:
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - name: Run ASH scan
        run: ash --mode local
      - name: Add PR comment
        uses: actions/github-script@v6
        if: always()
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const fs = require('fs');
            const reportPath = '.ash/ash_output/reports/ash.summary.md';

            if (fs.existsSync(reportPath)) {
              const reportContent = fs.readFileSync(reportPath, 'utf8');
              const issueNumber = context.issue.number;

              github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: issueNumber,
                body: reportContent
              });
            }
```

### Distributed Scanning (Execute and Collect)

`strategy.matrix` fans the shards out, and `actions/upload-artifact` / `actions/download-artifact` carry their results to the collect job. `needs: scan-shard` waits for every matrix job, so the collect job cannot start on a partial set of artifacts.

```yaml
name: ASH Distributed Security Scan

on:
  pull_request:
    branches: [ main ]

permissions:
  contents: read

jobs:
  scan-shard:
    runs-on: ubuntu-latest
    strategy:
      # Let every shard report. Otherwise the first shard to fail cancels its
      # siblings and you lose the other shards' diagnostics.
      fail-fast: false
      matrix:
        shard: [0, 1, 2, 3]
    steps:
      - uses: actions/checkout@v7
      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: '3.12'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - name: Run ASH shard ${{ matrix.shard }}
        # --no-fail-on-findings: this shard's exit code is not the verdict.
        run: |
          ash scan --mode local --no-fail-on-findings \
            --shard-index ${{ matrix.shard }} \
            --shard-count 4
      - name: Upload shard results
        uses: actions/upload-artifact@v7
        with:
          # upload-artifact v4 and later reject two jobs uploading the same
          # artifact name, so the shard index has to be part of it.
          name: ash-shard-${{ matrix.shard }}
          path: .ash/ash_output/ash_aggregated_results.json
          if-no-files-found: error

  collect:
    needs: scan-shard
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: '3.12'
      - name: Install ASH
        run: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - name: Download shard results
        uses: actions/download-artifact@v8
        with:
          path: shards
          pattern: ash-shard-*
      - name: Merge shard results
        # This step is the gate. ash merge fails if the shards do not
        # reconstruct one whole scan, then applies the findings verdict.
        run: |
          args=""
          for dir in shards/*/; do
            args="$args --results $dir"
          done
          ash merge $args --output-dir .ash/merged --output-formats sarif,markdown
      - name: Upload merged results
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: ash-merged-results
          path: .ash/merged
```

Leaving `merge-multiple` off the download step is deliberate: each artifact then extracts into its own directory under `shards/`, which is what the loop iterates over. With `merge-multiple: true` all four shards would extract into the same directory and overwrite each other's `ash_aggregated_results.json`.

The shard upload step has no `if: always()`, so a shard whose scan crashed uploads nothing, its job goes red, and the collect job is skipped rather than merging three shards out of four.

## GitLab CI

### Basic Integration

```yaml
ash-scan:
  image: python:3.10
  script:
    - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
    - ash --mode local
  artifacts:
    paths:
      - .ash/ash_output
```

### Using Container Mode

```yaml
ash-scan-container:
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  script:
    - apk add --no-cache python3 py3-pip git
    - pip3 install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
    - ash --mode container
  artifacts:
    paths:
      - .ash/ash_output
```

### Gitlab Security Dashboard

According to Gitlab [documentation](https://docs.gitlab.com/user/application_security/sast/#understanding-the-results),
if any of the jobs in a pipeline fails, the results will **not** be visible in the Security Dashboard.

> A pipeline consists of multiple jobs, including SAST and DAST scanning. If any job fails to finish for any reason,
> the security dashboard does not show SAST scanner output. For example, if the SAST job finishes but the DAST
> job fails, the security dashboard does not show SAST results. On failure, the analyzer outputs an exit code.

If you want to see the results of ASH in Gitlab's Security Dashboard, you must pass the `--no-fail-on-findings` to ASH.

Example using local mode:

```yaml
ash-scan:
  image: python:3.10
  script:
    - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
    - ash --mode local --no-fail-on-findings
  artifacts:
    paths:
      - .ash/ash_output
```

### Distributed Scanning (Execute and Collect)

`parallel` fans the shards out. One conversion is needed: GitLab numbers parallel jobs from 1, so a `parallel: 4` job appears as `ash-scan-shard 1/4` through `ash-scan-shard 4/4` and `CI_NODE_INDEX` carries that number, while ASH shard indices are zero-based. Passing `CI_NODE_INDEX` through unchanged would ask for shard 4 of 4, which ASH rejects because indices must satisfy `0 <= index < count`. The mistake is loud rather than silent, but it is still a mistake — subtract one.

```yaml
stages:
  - scan
  - collect

ash-scan-shard:
  stage: scan
  image: python:3.12
  parallel: 4
  script:
    - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
    # GitLab's CI_NODE_INDEX runs 1..CI_NODE_TOTAL; ASH's shard index is zero-based.
    - export ASH_SHARD_INDEX="$((CI_NODE_INDEX - 1))"
    - export ASH_SHARD_COUNT="$CI_NODE_TOTAL"
    - ash scan --mode local --no-fail-on-findings
    # A job that uses `needs` on a parallel job downloads the artifacts of every
    # parallel instance into one workspace, and artifacts sharing a path
    # overwrite each other. Each shard therefore needs its own directory.
    - mkdir -p "shards/shard-$ASH_SHARD_INDEX"
    - cp .ash/ash_output/ash_aggregated_results.json "shards/shard-$ASH_SHARD_INDEX/"
  artifacts:
    paths:
      - shards/

ash-merge:
  stage: collect
  image: python:3.12
  needs:
    - job: ash-scan-shard
      artifacts: true
  script:
    - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
    # This step is the gate. ash merge fails if the shards do not reconstruct
    # one whole scan, then applies the findings verdict.
    - |
      args=""
      for dir in shards/shard-*/; do
        args="$args --results $dir"
      done
      ash merge $args --output-dir .ash/merged --output-formats sarif,markdown
  artifacts:
    when: always
    paths:
      - .ash/merged
```

`needs` pointing at a `parallel` job depends on all of its instances, not one, so `ash-merge` starts only after all four shards have succeeded.

The Security Dashboard caveat above applies to the merge job as well: a failing job hides SAST results for the whole pipeline, and the merge job is the one that fails on findings.

## AWS CodeBuild

### Basic Integration

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.10
    commands:
      - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0

  build:
    commands:
      - ash --mode local

artifacts:
  files:
    - .ash/ash_output/**/*
```

### Using Container Mode

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.10
    commands:
      - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0

  pre_build:
    commands:
      - nohup /usr/local/bin/dockerd --host=unix:///var/run/docker.sock --host=tcp://127.0.0.1:2375 --storage-driver=overlay2 &
      - timeout 15 sh -c "until docker info; do echo .; sleep 1; done"

  build:
    commands:
      - ash --mode container

artifacts:
  files:
    - .ash/ash_output/**/*
```

### Distributed Scanning (Execute and Collect)

CodeBuild [batch builds](https://docs.aws.amazon.com/codebuild/latest/userguide/batch-build.html) are the fan-out mechanism. Use `batch/build-graph` rather than `batch/build-matrix`: only build-graph tasks accept `depend-on`, so a matrix batch has no way to express "merge after the shards". The matrix form is shown at the end of this section for pipelines that collect in a later stage.

Batch tasks do not share a workspace, so the shard results travel through S3. Set `ASH_SHARD_BUCKET` as a project-level environment variable naming a bucket the build role can read and write, so that every task in the batch sees the same value.

```yaml
version: 0.2

batch:
  # Let every shard finish so you get all of their logs. The merge task is
  # still the gate: if a shard never wrote its results, ash merge refuses.
  fast-fail: false
  build-graph:
    - identifier: shard0
      env:
        variables:
          ASH_SHARD_INDEX: "0"
    - identifier: shard1
      env:
        variables:
          ASH_SHARD_INDEX: "1"
    - identifier: shard2
      env:
        variables:
          ASH_SHARD_INDEX: "2"
    - identifier: shard3
      env:
        variables:
          ASH_SHARD_INDEX: "3"
    - identifier: merge
      buildspec: buildspec-ash-merge.yml
      depend-on:
        - shard0
        - shard1
        - shard2
        - shard3

env:
  variables:
    ASH_SHARD_COUNT: "4"

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0

  build:
    commands:
      # ASH_SHARD_INDEX comes from the batch task, ASH_SHARD_COUNT from env above.
      - ash scan --mode local --no-fail-on-findings
      # Deliberately in `build` and not `post_build`: if the scan fails, nothing
      # is uploaded, and the merge task fails on the missing shard index.
      - aws s3 cp .ash/ash_output/ash_aggregated_results.json "s3://${ASH_SHARD_BUCKET}/${CODEBUILD_RESOLVED_SOURCE_VERSION}/shard-${ASH_SHARD_INDEX}/ash_aggregated_results.json"
```

The `merge` task's `buildspec-ash-merge.yml`:

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0

  build:
    commands:
      # This step is the gate. ash merge fails the batch if any shard's results
      # are missing, then applies the findings verdict.
      - |
        aws s3 cp --recursive "s3://${ASH_SHARD_BUCKET}/${CODEBUILD_RESOLVED_SOURCE_VERSION}/" shards/
        args=""
        for dir in shards/shard-*/; do
          args="$args --results $dir"
        done
        ash merge $args --output-dir .ash/merged --output-formats sarif,markdown

artifacts:
  files:
    - .ash/merged/**/*
```

`CODEBUILD_RESOLVED_SOURCE_VERSION` is the commit, and every task in the batch resolves it to the same value — that is what lets the merge task find the shards without being told where they are. It is not unique per batch, though. Re-running the batch on the same commit overwrites each shard's object in place, and `ash merge` verifies coverage rather than freshness, so a shard that fails on the re-run can leave the previous run's object in place for the merge to read. If you re-run batches, add a per-run value to the prefix from an environment variable override supplied when the batch is started.

The fan-out half written as a build matrix, where CodeBuild creates one build per value of `ASH_SHARD_INDEX`:

```yaml
version: 0.2

batch:
  build-matrix:
    static:
      ignore-failure: false
    dynamic:
      env:
        variables:
          ASH_SHARD_INDEX:
            - "0"
            - "1"
            - "2"
            - "3"

env:
  variables:
    ASH_SHARD_COUNT: "4"

phases:
  install:
    runtime-versions:
      python: 3.12
    commands:
      - pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0

  build:
    commands:
      - ash scan --mode local --no-fail-on-findings
      - aws s3 cp .ash/ash_output/ash_aggregated_results.json "s3://${ASH_SHARD_BUCKET}/${CODEBUILD_RESOLVED_SOURCE_VERSION}/shard-${ASH_SHARD_INDEX}/ash_aggregated_results.json"
```

Whatever runs `ash merge` after that matrix, whether a later CodePipeline stage or a separate project, still owns the verdict and still has to fail the pipeline on its own exit code.

## Jenkins

### Jenkinsfile (Declarative Pipeline)

```groovy
pipeline {
    agent {
        docker {
            image 'python:3.10'
        }
    }
    stages {
        stage('Install ASH') {
            steps {
                sh 'pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
            }
        }
        stage('Run ASH Scan') {
            steps {
                sh 'ash --mode local'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: '.ash/ash_output/**/*', allowEmptyArchive: true
        }
    }
}
```

### Using Container Mode

```groovy
pipeline {
    agent {
        docker {
            image 'docker:20.10.16'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }
    stages {
        stage('Install ASH') {
            steps {
                sh 'apk add --no-cache python3 py3-pip git'
                sh 'pip3 install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
            }
        }
        stage('Run ASH Scan') {
            steps {
                sh 'ash --mode container'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: '.ash/ash_output/**/*', allowEmptyArchive: true
        }
    }
}
```

### Distributed Scanning (Execute and Collect)

Declarative `parallel` runs the shards as sibling stages. Each branch declares its own `agent`, which gives it its own workspace and its own checkout, so the shards cannot overwrite each other's output directory. `stash` carries each shard's results to the merge stage.

```groovy
pipeline {
    agent none
    environment {
        ASH_SHARD_COUNT = '4'
    }
    stages {
        stage('Scan Shards') {
            parallel {
                stage('Shard 0') {
                    agent { docker { image 'python:3.12' } }
                    environment { ASH_SHARD_INDEX = '0' }
                    steps {
                        sh 'pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
                        sh 'ash scan --mode local --no-fail-on-findings'
                        sh 'mkdir -p shards/shard-$ASH_SHARD_INDEX && cp .ash/ash_output/ash_aggregated_results.json shards/shard-$ASH_SHARD_INDEX/'
                        stash name: 'ash-shard-0', includes: 'shards/shard-0/**'
                    }
                }
                stage('Shard 1') {
                    agent { docker { image 'python:3.12' } }
                    environment { ASH_SHARD_INDEX = '1' }
                    steps {
                        sh 'pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
                        sh 'ash scan --mode local --no-fail-on-findings'
                        sh 'mkdir -p shards/shard-$ASH_SHARD_INDEX && cp .ash/ash_output/ash_aggregated_results.json shards/shard-$ASH_SHARD_INDEX/'
                        stash name: 'ash-shard-1', includes: 'shards/shard-1/**'
                    }
                }
                stage('Shard 2') {
                    agent { docker { image 'python:3.12' } }
                    environment { ASH_SHARD_INDEX = '2' }
                    steps {
                        sh 'pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
                        sh 'ash scan --mode local --no-fail-on-findings'
                        sh 'mkdir -p shards/shard-$ASH_SHARD_INDEX && cp .ash/ash_output/ash_aggregated_results.json shards/shard-$ASH_SHARD_INDEX/'
                        stash name: 'ash-shard-2', includes: 'shards/shard-2/**'
                    }
                }
                stage('Shard 3') {
                    agent { docker { image 'python:3.12' } }
                    environment { ASH_SHARD_INDEX = '3' }
                    steps {
                        sh 'pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
                        sh 'ash scan --mode local --no-fail-on-findings'
                        sh 'mkdir -p shards/shard-$ASH_SHARD_INDEX && cp .ash/ash_output/ash_aggregated_results.json shards/shard-$ASH_SHARD_INDEX/'
                        stash name: 'ash-shard-3', includes: 'shards/shard-3/**'
                    }
                }
            }
        }
        stage('Merge Shard Results') {
            agent { docker { image 'python:3.12' } }
            steps {
                sh 'pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0'
                unstash 'ash-shard-0'
                unstash 'ash-shard-1'
                unstash 'ash-shard-2'
                unstash 'ash-shard-3'
                // This step is the gate. ash merge fails the build if the shards
                // do not reconstruct one whole scan, then applies the verdict.
                sh '''
                    args=""
                    for dir in shards/shard-*/; do
                      args="$args --results $dir"
                    done
                    ash merge $args --output-dir .ash/merged --output-formats sarif,markdown
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: '.ash/merged/**/*', allowEmptyArchive: true
                }
            }
        }
    }
}
```

Two properties are worth relying on here. `stash` raises an error when it finds no files, because its `allowEmpty` parameter defaults to false — so a shard that produced no results file fails its own branch instead of passing an empty stash along. And `Merge Shard Results` is a later stage, so it does not run at all unless every parallel branch succeeded; the merge is never handed a partial set.

Add `failFast true` to the `Scan Shards` stage if you would rather the first failing shard abort the rest. Leaving it off gets you every shard's log.

`stash` is designed for small files, which an `ash_aggregated_results.json` normally is. If your results files are large, archive them to external storage from each branch and download them in the merge stage instead.

## CircleCI

### Basic Integration

```yaml
version: 2.1
jobs:
  scan:
    docker:
      - image: cimg/python:3.10
    steps:
      - checkout
      - run:
          name: Install ASH
          command: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - run:
          name: Run ASH scan
          command: ash --mode local
      - store_artifacts:
          path: .ash/ash_output
          destination: ash-results

workflows:
  version: 2
  scan-workflow:
    jobs:
      - scan
```

### Using Container Mode

```yaml
version: 2.1
jobs:
  scan:
    machine:
      image: ubuntu-2204:current
    steps:
      - checkout
      - run:
          name: Install ASH
          command: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - run:
          name: Run ASH scan
          command: ash --mode container
      - store_artifacts:
          path: .ash/ash_output
          destination: ash-results

workflows:
  version: 2
  scan-workflow:
    jobs:
      - scan
```

### Distributed Scanning (Execute and Collect)

`parallelism` runs one job across several containers. `CIRCLE_NODE_INDEX` ranges from 0 to `CIRCLE_NODE_TOTAL - 1`, which is the convention ASH already uses, so the two map across with no arithmetic — unlike GitLab, whose `CI_NODE_INDEX` starts at 1. The workspace carries the shard results to the collect job.

```yaml
version: 2.1
jobs:
  scan-shard:
    docker:
      - image: cimg/python:3.12
    parallelism: 4
    steps:
      - checkout
      - run:
          name: Install ASH
          command: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - run:
          name: Run ASH shard
          # --no-fail-on-findings: this container's exit code is not the verdict.
          command: |
            ash scan --mode local --no-fail-on-findings \
              --shard-index "$CIRCLE_NODE_INDEX" \
              --shard-count "$CIRCLE_NODE_TOTAL"
            mkdir -p "shards/shard-$CIRCLE_NODE_INDEX"
            cp .ash/ash_output/ash_aggregated_results.json "shards/shard-$CIRCLE_NODE_INDEX/"
      - persist_to_workspace:
          # Each container writes its own shard-N directory, so the four
          # containers never persist the same path.
          root: .
          paths:
            - shards

  merge-shards:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - attach_workspace:
          at: .
      - run:
          name: Install ASH
          command: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.7.0
      - run:
          name: Merge shard results
          # This step is the gate. ash merge fails if the shards do not
          # reconstruct one whole scan, then applies the findings verdict.
          command: |
            args=""
            for dir in shards/shard-*/; do
              args="$args --results $dir"
            done
            ash merge $args --output-dir .ash/merged --output-formats sarif,markdown
      - store_artifacts:
          path: .ash/merged
          destination: ash-merged-results

workflows:
  version: 2
  ash-distributed:
    jobs:
      - scan-shard
      - merge-shards:
          requires:
            - scan-shard
```

`requires` waits for every container of `scan-shard`, so `merge-shards` starts only once all four have succeeded.

## Best Practices for CI Integration

> **Tip**: The CI examples in this guide use pinned versions (`@v3.7.0`) for reproducibility. You can also use the `v3` floating tag (`@v3`) to always get the latest stable v3.x release, though pinned versions are recommended for CI/CD pipelines.

1. **Fail builds on critical findings**:
   ```bash
   ash --mode local --fail-on-findings
   ```

2. **Use specific scanners for faster CI runs**:
   ```bash
   ash --mode local --scanners bandit,semgrep,detect-secrets
   ```

3. **Generate CI-friendly reports**:
   ```bash
   ash --mode local --output-formats sarif,markdown,json
   ```

4. **Cache container images** to speed up builds:
   ```yaml
   # GitHub Actions example
   - name: Cache ASH container
     uses: actions/cache@v3
     with:
       path: /var/lib/docker
       key: ${{ runner.os }}-ash-container
   ```

5. **Set severity thresholds** appropriate for your CI pipeline:
   ```bash
   ash --config-overrides 'global_settings.severity_threshold=HIGH'
   ```

## ASH Execution Environment Viability

If you are unsure whether ASH will run in your CI environment, the primary requirement is the ability to run Linux containers for container mode. For local mode, you only need Python 3.10+.

For container mode, ensure your CI environment:
1. Has a container runtime installed (Docker, Podman, etc.)
2. Has permissions to run containers
3. Has sufficient disk space for container images

For local mode, ensure your CI environment:
1. Has Python 3.10+ installed
2. Has permissions to install Python packages
