# ASH

- [ASH; The *A*utomated *S*ecurity *H*elper](#ash-the-automated-security-helper)
- [Description](#description)
- [Supported frameworks](#supported-frameworks)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Getting Started - Linux or MacOS](#getting-started---linux-or-macos)
  - [Getting Started - Windows](#getting-started---windows)
  - [Cloud9 Quickstart Guide](#cloud9-quickstart-guide)
- [Using `ash` with `pre-commit`](#using-ash-with-pre-commit)
- [Examples](#examples)
- [Synopsis](#synopsis)
- [FAQ](#faq)
- [Feedback](#feedback)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## ASH; The *A*utomated *S*ecurity *H*elper

## Description

The security helper tool was created to help you reduce the probability of a security violation in a new code, infrastructure or IAM configuration
by providing a fast and easy tool to conduct  preliminary security check as early as possible within your development process.

- It is not a replacement of a human review nor standards enforced by your team/customer.
- It uses light, open source tools to maintain its flexibility and ability to run from anywhere.
- ASH is cloning and running different open-source tools, such as: git-secrets, bandit, Semgrep, Grype, Syft, nbconvert, npm-audit, checkov, cdk-nag and cfn-nag. Please review the tools [LICENSE](license) before usage.

## Supported frameworks

The security helper supports the following vectors:

* Code
  * Git
    * **[git-secrets](https://github.com/awslabs/git-secrets)** - Find api keys, passwords, AWS keys in the code
  * Python
    * **[bandit](https://github.com/PyCQA/bandit)** - finds common security issues in Python code.
    * **[Semgrep](https://github.com/returntocorp/semgrep)** - finds common security issues in Python code.
    * **[Grype](https://github.com/anchore/grype)** - finds vulnerabilities scanner for Python code.
    * **[Syft](https://github.com/anchore/syft)** - generating a Software Bill of Materials (SBOM) for Python code.
  * Jupyter Notebook
    * **[nbconvert](https://nbconvert.readthedocs.io/en/latest/)** - converts Jupyter Notebook (ipynb) files into Python executables. Code scan with Bandit.
  * JavaScript; NodeJS
    * **[npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)** - checks for vulnerabilities in Javascript and NodeJS.
    * **[Semgrep](https://github.com/returntocorp/semgrep)** - finds common security issues in JavaScript code.
    * **[Grype](https://github.com/anchore/grype)** - finds vulnerabilities scanner for Javascript and NodeJS.
    * **[Syft](https://github.com/anchore/syft)** - generating a Software Bill of Materials (SBOM) for Javascript and NodeJS.
  * Go
    * **[Semgrep](https://github.com/returntocorp/semgrep)** - finds common security issues in Golang code.
    * **[Grype](https://github.com/anchore/grype)** - finds vulnerabilities scanner for Golang.
    * **[Syft](https://github.com/anchore/syft)** - generating a Software Bill of Materials (SBOM) for Golang.
  * C#
    * **[Semgrep](https://github.com/returntocorp/semgrep)** - finds common security issues in C# code.
  * Bash
    * **[Semgrep](https://github.com/returntocorp/semgrep)** - finds common security issues in Bash code.
  * Java
    * **[Semgrep](https://github.com/returntocorp/semgrep)** - finds common security issues in Java code.
    * **[Grype](https://github.com/anchore/grype)** - finds vulnerabilities scanner for Java.
    * **[Syft](https://github.com/anchore/syft)** - generating a Software Bill of Materials (SBOM) for Java.
* Infrastructure
  * Terraform; Cloudformation
    * **[checkov](https://github.com/bridgecrewio/checkov)**
    * **[cfn_nag](https://github.com/stelligent/cfn_nag)**
    * **[cdk-nag](https://github.com/cdklabs/cdk-nag)** (via import of rendered CloudFormation templates into a custom CDK project with the [AWS Solutions NagPack](https://github.com/cdklabs/cdk-nag/blob/main/RULES.md#aws-solutions) enabled)
  * Dockerfile
    * **[checkov](https://github.com/bridgecrewio/checkov)**

## Prerequisites

To start using `ash` please make sure to install and configure the following:

- Tools installed to run Linux containers, such as [Finch](https://github.com/runfinch/finch), [Rancher Desktop](https://rancherdesktop.io/), [Podman Desktop](https://podman-desktop.io/), or [Docker Desktop](https://docs.docker.com/get-docker/).
  - This can be any command-line interface (CLI) + container engine combination; there is nothing in ASH that requires a specific container runtime.
  - If on Windows, you will also likely need Windows Subsystem for Linux (WSL) installed as a prerequisite for the listed container engine tools. Please see the specific instructions for the tool of choice regarding Windows-specific prerequisites.

## Getting Started

### Getting Started - Linux or MacOS

Clone the git repository into a folder.  For example:

```bash
# Set up some variables
REPO_DIR="${HOME}"/Documents/repos/reference
REPO_NAME=automated-security-helper

# Create a folder to hold reference git repositories
mkdir -p ${REPO_DIR}

# Clone the repository into the reference area
git clone https://github.com/awslabs/automated-security-helper "${REPO_DIR}/${REPO_NAME}"

# Set the repo path in your shell for easier access
#
# Add this (and the variable settings above) to
# your ~/.bashrc, ~/.bash_profile, ~/.zshrc, or similar
# start-up scripts so that the ash tool is in your PATH
# after re-starting or starting a new shell.
#
export PATH="${PATH}:${REPO_DIR}/${REPO_NAME}"

# Execute the ash tool
ash --version
```

### Getting Started - Windows

**ASH** uses containers, `bash` shell scripts, and multiple background processes running in parallel to run the multiple
source code security scanning tools that it uses.  Because of this, running `ash` from either a `PowerShell` or `cmd`
shell on Windows is not possible.  Furthermore, due to reliance on running containers, usually with Docker Desktop
when running on Windows, there is an implicit dependency on having installed, configured, and operational a
Windows Subsystem for Linux (WSL) 2 environment on the Windows machine where `ash` will be run.

To use `ash` on Windows:

- Install, configure, and test the [WSL 2 environment on Windows](https://learn.microsoft.com/en-us/windows/wsl/install)
- Install, configure, and test [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/), using the WSL 2 environment
- Use the [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/install) program and open a command-line window to interact with the WSL 2 environment
- Install and/or update the `git` client in the WSL 2 environment.  This should be pre-installed, but you may need to update the version
  using the `apt-get update` command.

Once the WSL2 command-line window is open, follow the steps above in [Getting Started - Linux or MacOS](#getting-started---linux-or-macos)
to install and run `ash` in WSL 2 on the Windows machine.

To run `ash`, open a Windows Terminal shell into the WSL 2 environment and use that command-line shell to run the `ash` command.

**Note**: when working this way, be sure to `git clone` any git repositories to be scanned into the WSL 2 filesystem.
Results are un-predictable if repositories or file sub-trees in the Windows filesystem are scanned using `ash`
that is running in the WSL 2 environment.

**Tip**: If you are using Microsoft VSCode for development, it is possible to configure a "remote" connection
[using VSCode into the WSL2 environment](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-vscode).
By doing this, you can host your git repositories in WSL 2 and still
work with them as you have in the past when they were in the Windows filesystem of your Windows machine.

### Cloud9 Quickstart Guide

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

Refer to the [pre-commit-hooks](./.pre-commit-hooks.yaml) file for information about the `pre-commit`
hook itself.

To configure a git repository to use the `ash` hook, start with the following `pre-commit-config` configuration:

```yaml
  - repo: git@github.com:awslabs/automated-security-helper.git
    rev: '1.1.0-e-01Dec2023' # update with the latest tagged version in the repository
    hooks:
    - id: ash
      name: scan files using ash
      stages: [ manual ]
      # uncomment the line below if using "finch" on MacOS
      # args: [ "-f" ]
```

Once the `.pre-commit-hooks.yaml` file is updated, the `ash` tool can be run using the following command:

```bash
pre-commit run --hook-stage manual ash
```

Results from the run of the `ash` tool can be found in the `aggregated_results.txt` file
the `--output-dir` folder/directory.

When ASH converts CloudFormation files into CDK and runs cdk-nag on them,
the output of the cdk-nag check results are preserved in a 'ash_cf2cdk_output'
folder/directory under `--output-dir` after the ASH scan is run.  This folder/directory is
in addition to the `aggregated_results.txt` file found in `--output-dir`.

## Examples

```bash
# Getting help
ash -h

# Scan a directory
ash --source-dir /my/remote/files

# Save the final report to a different directory
ash --output-dir /my/remote/files

# Force rebuild the entire framework to obtain latests changes and up-to-date database
ash --force

# Force run scan for Python code
ash --source-dir . --ext py

* All commands can be used together.
```

## Synopsis

```text
$ ash --help
NAME:
    ash
SYNOPSIS:
    ash [OPTIONS] --source-dir /path/to/dir --output-dir /path/to/dir
OPTIONS:
    --source-dir                    Path to the directory containing the code/files you wish to scan. Defaults to $(pwd)
    --output-dir                    Path to the directory that will contain the report of the scans. Defaults to $(pwd)

    --format                        Output format of the aggregated_results file segments.
                                    Options: text, json
                                    Default: text

    --build-target                  Specify the target stage of the ASH image to build.
                                    Options: non-root, ci
                                    Default: non-root

    --offline                       Build ASH for offline execution.
                                    Default: false

    --offline-semgrep-rulesets      Specify Semgrep rulesets for use in ASH offline mode.
                                    Default: p/ci

    --no-build                      Skip rebuild of the ASH container image, run a scan only.
                                    Requires an existing ASH image to be present in the image cache.
    --no-run                        Skip running a scan with ASH, build a new ASH container image only.
                                    Useful when needing to build an ASH image for publishing to a private image registry.

    --no-cleanup                    Don't cleanup the work directory where temp reports are stored during scans.
    --ext | -extension              Force a file extension to scan. Defaults to identify files automatically.

    -c    | --no-color              Don't print colorized output.
    -s    | --single-process        Run ash scanners serially rather than as separate, parallel sub-processes.
    -o    | --oci-runner            Use the specified OCI runner instead of docker to run the containerized tools.
    -p    | --preserve-report       Add timestamp to the final report file to avoid overwriting it after multiple executions.

    -d    | --debug                 Print ASH debug log information where applicable.
    -q    | --quiet                 Don't print verbose text about the build process.
    -v    | --version               Prints version number.

INFO:
    For more information, please visit https://github.com/awslabs/automated-security-helper
```

## FAQ

- Q: How to run `ash` on a Windows machine

  A: ASH on a windows machine

  - Install a Windows Subsystem for Linux (WSL) 2 environment with a [Ubuntu distribution](https://docs.microsoft.com/en-us/windows/wsl/install). Be sure to use the WSL 2.
  - Install Docker Desktop for windows and activate the [integration the WSL 2](https://docs.docker.com/desktop/windows/wsl/)
  - Clone this git repo from a windows terminal via VPN (while in vpn it'll not connect to the repo directly from Ubuntu WSL 2).
  - Execute the helper tool from the folder downloaded in the previous step from the Ubuntu WSL.

- Q: How to run `ash` in a Continuous Integration/Continuous Deployment (CI/CD) pipline?

  A: Check the [ASH Pipeline solution](https://github.com/aws-samples/automated-security-helper-pipeline)

- Q: How to run `ash` with [finch](https://aws.amazon.com/blogs/opensource/introducing-finch-an-open-source-client-for-container-development/)
  or another Open Container Initiative (OCI) compatible tool.

  A: You can configure the OCI compatible tool to use with by using the environment variable `ASH_OCI_RUNNER`

- Q: How to exclude files from scanning.

  A: `ash` will scan all the files in the folder specified in `--source-dir`, or the current directory if invoked without parameters. If the folder is a git repository,
  then `ash` will use the exclusions in your `.gitignore` configuration file. If you want to exclude any specific folder, it **must** be added to your git ignore list before invoking `ash`.

- Q: `ash` reports there are not files to scan or you see a message stating `warning: You appear to have cloned an empty repository.`

  A: Ensure you're running ASH inside the folder you intend to scan or using the `--source-dir` parameter. If the folder where the files reside is part of a git repository, ensure the files are added (committed) before running ASH.

- Q: How to run `ash` in an environment without internet connectivity/with an airgap?

  A: From your environment which does have internet connectivity, build the ASH image using `--offline` and `--offline-semgrep-rulesets` to specify what resources to package into the image.  Environment variable `$ASH_IMAGE_NAME` controls the name of the image.  After building, push to your container repository of choice which will be available within the airgapped environment.  When you go to execute ASH in your offline environment, passing `--no-build` to `ash` alongside `--offline` and `--offline-semgrep-rulesets` will use your offline image and skip the build.  Specify `$ASH_IMAGE_NAME` to override ASH's container image to the previously-built image available within your airgapped environment.

## Feedback

Create an issue [here](https://github.com/awslabs/automated-security-helper/issues).

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md#contributing-guidelines) for information on how to contribute to this project.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the Apache 2.0 License. See the LICENSE file.
