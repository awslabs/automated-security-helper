# Roll out ASH across repositories

This tutorial is for a security or platform team that runs ASH for many repositories. By
the end you have an ASH image in your own registry, one operator config that every scan
uses and no repository can change, a plan for keeping vulnerability databases current, and
results going where your team reads them.

## Before you start

You need ASH installed ([Install ASH](../how-to/install.md)), docker or another container
runtime, and a registry you can push to. Steps 2 and 3 run on any machine with ASH, and
step 3 creates a small repository to test the gate on.

## 1. Build the image and push it to your registry

ASH publishes no prebuilt image. Build one from `v3.7.0`, name it for your registry,
and push it:

<!-- doctest: illustrative reason="needs a container runtime, network access, and a registry" -->
```bash
export ASH_IMAGE_NAME=registry.example.com/security/ash:3.7.0
ash build-image --no-run --oci-runner docker --ash-revision-to-install v3.7.0 \
  --container-uid 1001 --container-gid 1001
docker push "$ASH_IMAGE_NAME"
```

You should see `Building image registry.example.com/security/ash:3.7.0`, a few minutes
of build output, and then the push. `--oci-runner docker` builds with the runtime you push
with; without it, ASH uses finch when finch is installed. The image holds every scanner
tool and runs as a non-root user with the UID and GID you passed; use the ones your CI
jobs run as. If the build host sets `CI`, ASH builds the root image instead; see
[Root and non-root images](../how-to/run-in-a-container.md#build-target).

## 2. Write the operator config

The operator config is the one file whose settings apply to every scan. Keep it outside
the directories you scan and outside every git checkout, including a home directory or
`/etc` kept in git, where only your team can change it. Do not keep it in an operations
repository: ASH treats a config file inside any git checkout as written by a repository,
even when you name it with `--config`, and ignores the settings in it that only an
operator may make, such as plugin packages, reporter destinations, and sandbox grants. It
logs that only to `ash.log`. This tutorial uses `$HOME/ash-operator/ash.yaml`; on shared
runners, a path such as `/etc/ash/ash.yaml` is a better choice.

<!-- doctest: run fixture=empty -->
```bash
OPERATOR_CONFIG="$HOME/ash-operator/ash.yaml"
mkdir -p "$(dirname "$OPERATOR_CONFIG")"
cat > "$OPERATOR_CONFIG" <<'EOF'
fail_on_findings: true
fail_on_incomplete_scanners: true
content_db_staleness: fail
global_settings:
  severity_threshold: MEDIUM
EOF
if git -C "$(dirname "$OPERATOR_CONFIG")" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "The operator config is inside a git checkout; move it." >&2
  exit 1
fi
```

The last three lines check where the file is: `git rev-parse` must fail there. The four
settings are the gate: fail on findings at MEDIUM or above, fail when a scanner was
MISSING or ended in ERROR, and fail when a vulnerability database or offline ruleset is
past its age bound. They are also ASH's defaults, and writing them down still matters: with
this file in use, ASH does not read a repository's config file, so the repository cannot
change them. Add your organization's suppressions, scanner options, and reporters to the
same file; [Configure ASH](../how-to/configure.md) shows how.

## 3. Check that a repository cannot change the gate

Create a repository with one hardcoded password in it:

```bash
mkdir ash-gate-demo
cd ash-gate-demo
git init --quiet
printf 'DATABASE_PASSWORD = "correct-horse-battery-staple-1234"\n' > app.py
```

Scan it with the operator config:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --config "$OPERATOR_CONFIG" --scanners detect-secrets
```

`--scanners detect-secrets` keeps the check fast: detect-secrets ships with ASH, so it
needs no other tools. The scan ends with
`ERROR (2) Exiting due to 1 actionable findings found in ASH scan`, and
`.ash/ash_output/ash.log` starts with `Using config file specified at:` and your file's
path.

Now give the repository a config file that turns the gate off, and scan without your
config:

<!-- doctest: run expect-exit=0 -->
```bash
mkdir -p .ash
printf 'fail_on_findings: false\n' > .ash/.ash.yaml
ash scan --scanners detect-secrets
```

`ash.log` now starts with `Using config file found at:` and the repository's file, and the
scan exits 0 although the finding is still there. Scan again with your config:

<!-- doctest: run expect-exit=2 -->
```bash
ash scan --config "$OPERATOR_CONFIG" --scanners detect-secrets
```

The scan exits 2 again, because ASH read only your file.

In a scan of one directory, when you pass `--config` or set `ASH_CONFIG`, ASH does not read
the repository's config file at all, so a repository cannot turn off the gate, raise the
threshold, disable scanners, or add suppressions through it. In workspace mode, `--config`
is only the default for projects that have no config of their own; give your settings
there with `--config-overrides`.

The repository can still affect results in other ways:

- Inline `ash-ignore` comments, which ASH honors and marks `(ASH inline)` in the SARIF
  report.
- The scanners' own inline suppressions, such as bandit's `# nosec` and detect-secrets'
  `# pragma: allowlist secret`. To have bandit report `# nosec` lines too, set
  `scanners.bandit.options.ignore_nosec: true` in your file.
- Its `.gitignore` and `.ignore` files, which decide which files ASH scans, committed files
  included.
- The tool config files some scanners read from the repository, such as bandit's `.bandit`.

When you let ASH read a repository's config file instead, that file can change the
verdict, but it cannot load ASH's plugin packages that send data off the machine, choose
reporter destinations or credentials, grant sandbox access, or set the scanner options
that name a program to run or a tool config that can load code.
[Configuration trust model](../concepts/trust-model.md) has the complete rules.

## 4. Run the scan in CI

In CI, run ASH inside your image, mount the repository and the operator config, and point
`ASH_CONFIG` at the config:

<!-- doctest: illustrative reason="needs a container runtime and the image from step 1" -->
```bash
test -f /etc/ash/ash.yaml
mkdir -p "$PWD/../ash-results"
docker run --rm \
  --mount type=bind,source="$PWD",destination=/src,readonly \
  --mount type=bind,source="$PWD/../ash-results",destination=/out \
  --mount type=bind,source=/etc/ash/ash.yaml,destination=/etc/ash/ash.yaml,readonly \
  --env ASH_CONFIG=/etc/ash/ash.yaml \
  registry.example.com/security/ash:3.7.0 \
  ash scan --source-dir /src --output-dir /out
```

The `test -f` line is there because a missing config file is not an error: ASH logs
`Configuration file not found` and scans with the defaults. The repository is mounted
read-only, and the results go to a directory outside it. The job fails with exit code 2
on findings and 1 on an incomplete scan; [Exit codes](../reference/exit-codes.md) lists
them all.

Run ASH inside the image rather than with `ash scan --mode container`: container mode does
not pass your `--config` file into the container, so the scan there would not use it
([Mounts and network](../how-to/run-in-a-container.md#mounts)). The CI guides show the same
setup for each service: [Run ASH in GitHub Actions](../how-to/ci/github-actions.md),
[Run ASH in GitLab CI](../how-to/ci/gitlab-ci.md), and
[Run ASH in Jenkins, CodeBuild, Azure Pipelines, and other CI systems](../how-to/ci/other-ci.md).

## 5. Plan content database refresh

grype and trivy check code against vulnerability databases, and ASH fails a scan when a
database is past its age bound. An image that scans online refreshes the trivy database
during each scan, and grype updates its own database, so the hosts need outbound access to
the databases' download sites. An offline image carries the databases it downloaded at
build time. trivy's bound is the shortest, a day, and it counts from when the database
was built upstream, which is before your image build, so an offline image fails trivy
scans less than a day after its build.

Rebuild the image on a schedule, with `--force` so the build does not reuse cached layers
that hold the old databases and tools:

<!-- doctest: illustrative reason="needs a container runtime, network access, and a registry" -->
```bash
ash build-image --no-run --force --oci-runner docker --ash-revision-to-install v3.7.0 \
  --container-uid 1001 --container-gid 1001
docker push "$ASH_IMAGE_NAME"
```

If the rebuild runs in a CI job, run it as
`env -u CI -u IsCI -u ISCI -u CODEBUILD_BUILD_ID ash build-image ...`, or ASH builds the
root image. Rebuild offline images that scan with trivy more than once a day, and online
images at least weekly, so the scanner tools get their fixes. Keep
`content_db_staleness: fail` in the operator config; a repository cannot relax it while
you pass `--config`. [Run ASH offline](../how-to/run-offline.md) covers air-gapped hosts,
and [Content databases](../concepts/content-databases.md) lists every bound.

## 6. Send findings where your team reads them

Every scan writes its reports to `reports/` in the output directory. Send each to the
place your team works:

- GitHub code scanning: upload `ash.ghas.sarif` ([Export reports](../how-to/export-reports.md#github)).
- GitLab security dashboards: publish `ash.gl-sast-report.json` as a SAST report from a
  job that succeeds, because GitLab ingests security findings only from successful jobs
  ([Run ASH in GitLab CI](../how-to/ci/gitlab-ci.md)).
- A central store or SIEM: copy a findings file, such as `ash.ocsf.json` or `ash.sarif`,
  with your own tooling:

    <!-- doctest: illustrative reason="needs AWS credentials and a bucket" -->
    ```bash
    aws s3 cp ../ash-results/reports/ash.ocsf.json \
      "s3://example-security-scan-results/$REPOSITORY_NAME/$(date -u +%Y%m%dT%H%M%SZ).ocsf.json"
    ```

- AWS services: ASH's AWS reporters are loaded by the operator only. The S3 and CloudWatch
  Logs reporters send the scan summary and configuration, not individual findings; read
  [AWS reporters](../plugins/aws.md) for what each one sends before you turn it on.

Next, set the threshold and failure rules for your organization in
[Set the gate](../how-to/set-the-gate.md).
