# Frequently Asked Questions

<!-- TOC -->
- [How can I run `ash` on a Windows machine?](#how-can-i-run-ash-on-a-windows-machine)
- [How can I run `ash` in a CI/CD pipline?](#how-can-i-run-ash-in-a-cicd-pipline)
- [How can I run `ash` with finch or another OCI compatible tool?](#how-can-i-run-ash-with-finch-or-another-oci-compatible-tool)
<!-- /TOC -->

## How can I run `ash` on a Windows machine?

1. Install a Windows Subsystem for Linux (WSL) with an [Ubuntu distribution](https://docs.microsoft.com/en-us/windows/wsl/install). Be sure to use the WSL2.
2. Install Docker Desktop for windows and activate the [the WSL integration](https://docs.docker.com/desktop/windows/wsl/)
3. Clone this git repo from a windows terminal via VPN (while in vpn it'll not connect to the repo directly from Ubuntu WSL).
4. Execute the helper tool from the folder downloaded in the previous step from the Ubuntu WSL.

## How can I run `ash` in a CI/CD pipline?

For CDK Pipeline, please refer to the [ASH Pipeline solution](https://github.com/aws-samples/automated-security-helper-pipeline) available on GitHub.

For additional CI pipeline support, please refer to the [Running ASH in CI](./tutorials/running-ash-in-ci.md) page on this site.

## How can I run `ash` with [finch](https://aws.amazon.com/blogs/opensource/introducing-finch-an-open-source-client-for-container-development/) or another OCI compatible tool?

You can configure the OCI compatible tool to use with by using the environment variable `OCI_RUNNER`

## Can I use a Bandit configuration file when `ash` runs?

Yes, `ash` will use a bandit configuration file if it is placed at the root of your project directory. It must be named `.bandit`, `bandit.yaml`, or `bandit.toml`. Configuration files must be formatted properly according to the [Bandit documentation](https://bandit.readthedocs.io/en/latest/config.html).

> Note: paths excluded in a Bandit configuration file must begin with a `/` because `ash` uses an absolute path when calling `bandit`.