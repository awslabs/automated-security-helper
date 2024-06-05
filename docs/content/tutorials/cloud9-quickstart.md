# Cloud9 Quickstart Guide

Follow the instruction in the [quickstart page](/quickstart/README.md) to deploy an AWS Cloud9 Environment with ASH pre-installed.

## Using `ash` with `pre-commit`

The `ash` tool can be used interactively on a workstation or run using the [`pre-commit`](https://pre-commit.com/) command.
If `pre-commit` is used to run `ash`, then the `pre-commit` processing takes care of installing
a copy of the `ash` git repository and setting up to run the `ash` program from that installed
repository.  Using `pre-commit` still requires usage of WSL 2 when running on Windows.

Using `ash` as a [`pre-commit`](https://pre-commit.com/) hook enables development teams to use the `ash` tool
in two ways.  First, developers can use `ash` as a part of their local development process on whatever
development workstation or environment they are using.  Second, `ash` can be run in a build automation stage
by running `pre-commit run --hook-stage manual ash` in build automation stage.
When using `pre-commit`, run the `pre-commit` commands while in a folder/directory within the git repository that is
configured with `pre-commit` hooks.

Refer to the [pre-commit-hooks](https://github.com/awslabs/automated-security-helper/blob/main/.pre-commit-hooks.yaml) file for information about the `pre-commit`
hook itself.

To configure a git repository to use the `ash` hook, start with the following `pre-commit-config` configuration:

```yaml
  - repo: https://github.com/awslabs/automated-security-helper.git
    rev: 'v1.3.3' # update with the latest tagged version in the repository
    hooks:
    - id: ash
      name: scan files using ash
      stages: [ manual ]
      # uncomment the line below if using "finch" on MacOS
      # args: [ "-f" ]
```

Once the `.pre-commit-config.yaml` file is updated, the `ash` tool can be run using the following command:

```bash
pre-commit run --hook-stage manual ash
```

Results from the run of the `ash` tool can be found in the `aggregated_results.txt` file
the `--output-dir` folder/directory.

When ASH converts CloudFormation files into CDK and runs cdk-nag on them,
the output of the cdk-nag check results are preserved in a 'ash_cf2cdk_output'
folder/directory under `--output-dir` after the ASH scan is run.

This folder/directory is in addition to the `aggregated_results.txt` file found in `--output-dir`.
