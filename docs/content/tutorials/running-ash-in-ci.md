## Continuous Integration (CI) Execution

ASH supports running in CI environments as an executable container (e.g. via `docker run`) as well as via Container Job mechanisms, depending on CI platform support.

### Building ASH Container Images for CI Usage

Building ASH images for use in CI platforms (or other orchestration platforms that may require elevated access within the container) requires targeting the `ci` stage of the `Dockerfile`. This can be done via one of the following methods from the root of the ASH repository:

_via `ash` CLI_

```sh
ash --no-run --build-target ci
```

_via `docker` or other OCI CLI_

```sh
docker build --tag automated-security-helper:ci --target ci .
```

### Examples

Within the CI folder, there are multiple examples of running ASH scans in various CI platforms. All examples include the following:

* ASH repository is cloned from GitHub alongside the repository to be scanned.
* ASH repository directory is added to `$PATH` so that `ash` is available to call directly.
* `ash` is called to invoke the scan, which performs the following steps:
    1. Creates the `ash_output` directory if it does not already exist
    2. Builds the ASH container image
    3. Runs the ASH scan using the built container image
    4. Generates the results in the `ash_output` directory
* Once `ash` is complete, uploads `ash_output` directory as a build artifact.

These examples are meant to show simple implementations that will enable quick integration of ASH
into an application or infrastructure CI pipeline.

---

Current examples provided by subfolder name:

<!-- * Azure Pipelines (`azure-pipelines.yml`)
    * Example file shows how to run an ASH scan using Azure Pipelines [ContainerJobs](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/container-phases?view=azure-devops). -->
* GitHub Actions (`.github/workflows/run-ash.yml`)
    * Job `containerjob`: Example shows how to run ASH with the ASH image itself used for the job execution. This aligns with the `ContainerJob` approach from Azure Pipelines and presents the `ash` script as a callable in PATH.
    * Job `dockerrun`: Example shows how to run an ASH scan using generic `docker run` invocation (seen below)
* GitLab CI (`.gitlab-ci.yml`)
    * Example file shows how to use the ASH image as the runner image in a GitLab CI job
<!-- * Jenkins (`Jenkinsfile`)
    * Example file shows a scripted pipeline that runs an ASH scan using `docker run` with ASH as a containerized executable. -->

### ASH Execution Environment Viability

If you are unsure whether ASH will run in your CI environment or not, the primary requirement is the ability to run Linux containers. This is typically true for most CI platforms, but self-hosted CI agents and enterprise security rules may restrict that ability. If you are unsure whether the CI platform you are using will support it, you can walk through the following flowchart for guidance:

![ASH Execution Environment Viability diagram PNG](CI/ASH%20Execution%20Environment%20Viability.png)
