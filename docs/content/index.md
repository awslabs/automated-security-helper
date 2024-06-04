# ASH

- [ASH; The *A*utomated *S*ecurity *H*elper](#ash-the-automated-security-helper)
- [Description](#description)
  - [ASH change advisory](#ash-change-advisory)
- [Getting started with ASH](#getting-started-with-ash)
- [Supported frameworks](#supported-frameworks)
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

### ASH change advisory

We are currently working on a re-architecture of ASH targeting a single-container architecture as well as documentation to go along with it.

## Getting started with ASH

For details on using ASH, please see the relevant guides below:

* [Running ASH Locally](./tutorials/running-ash-locally.md)
* [Running ASH in CI](./tutorials/running-ash-in-ci.md)
* [Cloud9 Quickstart](./tutorials/cloud9-quickstart.md)

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
NAME:
        ash
SYNOPSIS:
        ash [OPTIONS] --source-dir /path/to/dir --output-dir /path/to/dir
OPTIONS:
        -v | --version           Prints version number.

        -p | --preserve-report   Add timestamp to the final report file to avoid overwriting it after multiple executions.
        --source-dir             Path to the directory containing the code/files you wish to scan. Defaults to $(pwd)
        --output-dir             Path to the directory that will contain the report of the scans. Defaults to $(pwd)
        --ext | -extension       Force a file extension to scan. Defaults to identify files automatically.
        --force                  Rebuild the Docker images of the scanning tools, to make sure software is up-to-date.
        --no-cleanup             Don't cleanup the work directory where temp reports are stored during scans.
        --debug                  Print ASH debug log information where applicable.
        -q | --quiet             Don't print verbose text about the build process.
        -c | --no-color          Don't print colorized output.
        -s | --single-process    Run ash scanners serially rather than as separate, parallel sub-processes.
        -o | --oci-runner        Use the specified OCI runner instead of docker to run the containerized tools.

For more information please visit https://github.com/awslabs/automated-security-helper
```

## FAQ
Please see the [FAQs](./faq.md) page.

## Feedback

Create an issue [here](https://github.com/awslabs/automated-security-helper/issues).

## Contributing

Please see the [Contributing](./contributing.md) page.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the Apache 2.0 License. See the LICENSE file.