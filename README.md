# ASH
  * [Description](#description)
  * [Supported frameworks](#supported-frameworks)
  * [Prerequisites](#prerequisites)
  * [Installing ash](#installing-ash)
    + [Examples](#examples)
    + [Synopsis](#synopsis) 
  + [FAQ](#faq)
  
## ASH; The *A*utomated *S*ecurity *H*elper
## Description
The security helper tool was created to help you reduce the probability of a security violation in a new code, infrastructure or IAM configuration 
by providing a fast and easy tool to conduct preliminary security check as early as possible within your development process. 

* It is not a replacement of a human review nor standards.
* It uses light, open source tools to maintain its flexibility and ability to run from anywhere.

## Supported frameworks
The security helper supports the following vectors:

* Code
    * Git
        * **[git-secrets](https://github.com/awslabs/git-secrets)** - Find api keys, passwords, AWS keys in the code
    * Python
        * **[bandit](https://github.com/PyCQA/bandit)** - finds common security issues in Python code.
        * **[Grype](https://github.com/anchore/grype)** - finds vulnerabilities scanner for Python code.
        * **[Syft](https://github.com/anchore/grype)** - generating a Software Bill of Materials (SBOM) for Python code.
    * Jupyter Notebook
        * **[nbconvert](https://nbconvert.readthedocs.io/en/latest/)** - converts Jupyter Notebook (ipynb) files into Python executables. Code scan with Bandit.
    * JavaScript; NodeJS
        * **[npm-audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)** - checks for vulnerabilities in Javascript and NodeJS.
        * **[Grype](https://github.com/anchore/grype)** - finds vulnerabilities scanner for Javascript and NodeJS.
        * **[Syft](https://github.com/anchore/grype)** - generating a Software Bill of Materials (SBOM) for Javascript and NodeJS.
* Infrastructure
    * Teraform; Cloudformation
        *   **[checkov](https://github.com/bridgecrewio/checkov)**
        *   **[cfn_nag](https://github.com/stelligent/cfn_nag)** with custom rules
        *   **[cdk-nag](https://github.com/cdklabs/cdk-nag)** transforming Cloudformation to CDK, and run cdk-nag


## Prerequisites
To start using `ash` please make sure to install and configure the following:
* Install Docker. You can refer to this [installation guide](https://docs.docker.com/get-docker/)

## Installing ash
```
# Clone the repo
git clone URL/Automated-Security-Helper /DESTINATION/DIR

# Set the repo path in your shell for easier access
export PATH=$PATH:/DESTINATION/DIR

# Execute the helper tool
ash
```

### Examples
```
# Getting help
ash -h

# Scan a directory
ash --source-dir /my/remote/files

# Save the final report to a different directory
ash --output-dir /my/remote/files

# Force rebuild the entire framework to obtain latests changes and up-to-date database
ash --force

* All commands can be used together.
```

### Synopsis
```
NAME:
        ash
SYNOPSIS:
        ash [OPTIONS] --source-dir /path/to/dir --output-dir /path/to/dir
OPTIONS:
        -p | --preserve-report   Add timestamp to the final report file to avoid overriding it after multiple executions
        --source-dir             Path to the directory containing the code/files you wish to scan. Defaults to $(pwd)
        --output-dir             Path to the directory that will contain the report of the scans. Defaults to $(pwd)
        --force                  Rebuild the Docker images of the scanning tools, to make sure software is up-to-date.
         -q | --quiet            Don't print verbose text about the build process.

```

## FAQ
* Q: How to run `ash` on a Windows machine  
  A: ASH on a windows machine
  - Install a Windows Subsystem for Linux (WSL) with an [Ubuntu distribution](https://docs.microsoft.com/en-us/windows/wsl/install). Be sure to use the WSL 2.
  - Install Docker Desktop for windows and activate the [integration the WSL](https://docs.docker.com/desktop/windows/wsl/)
  - Clone this git repository.
  - Execute the helper tool from the folder downloaded in the previous step from the Ubuntu WSL.
  
## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This library is licensed under the Apache 2.0 License. See the LICENSE file.
