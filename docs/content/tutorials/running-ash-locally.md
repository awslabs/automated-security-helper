# Running ASH Locally

Please see the [Prerequisites](../docs/prerequisites.md) page to ensure your local workspace is configured as needed before continuing.

At a high-level, you need the ability to run `linux/amd64` containers in order to use ASH.

## Linux or MacOS

Clone the git repository into a folder.  For example:

``` sh
# Set up some variables
REPO_DIR="${HOME}"/Documents/repos/reference
REPO_NAME=automated-security-helper

# Create a folder to hold reference git repositories
mkdir -p ${REPO_DIR}

# Clone the repository into the reference area
git clone https://github.com/awslabs/automated-security-helper.git "${REPO_DIR}/${REPO_NAME}"

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

## Windows

**ASH** uses containers, `bash` shell scripts, and multiple background processes running in parallel to run the multiple
source code security scanning tools that it uses.  Because of this, running `ash` from either a `PowerShell` or `cmd`
shell on Windows is not possible.  Furthermore, due to reliance on running containers, usually with Docker Desktop
when running on Windows, there is an implicit dependency on having installed, configured, and operational a WSL2
(Windows System for Linux) environment on the Windows machine where `ash` will be run.

To use `ash` on Windows:

* Install, configure, and test the [WSL 2 environment on Windows](https://learn.microsoft.com/en-us/windows/wsl/install)
* Install, configure, and test [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/), using the WSL 2 environment
* Use the [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/install) program and open a command-line window to interact with the WSL 2 environment
* Install and/or update the `git` client in the WSL 2 environment.  This should be pre-installed, but you may need to update the version
  using the `apt-get update` command.

Once the WSL2 command-line window is open, follow the steps above in [Getting Started - Linux or MacOS](#getting-started---linux-or-macos)
to install and run `ash` in WSL2 on the Windows machine.

To run `ash`, open a Windows Terminal shell into the WSL 2 environment and use that command-line shell to run the `ash` command.

**Note**: when working this way, be sure to `git clone` any git repositories to be scanned into the WSL2 filesystem.
Results are un-predictable if repositories or file sub-trees in the Windows filesystem are scanned using `ash`
that is running in the WSL2 environment.

**Tip**: If you are using Microsoft VSCode for development, it is possible to configure a "remote" connection
[using VSCode into the WSL2 environment](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-vscode).
By doing this, you can host your git repositories in WSL2 and still
work with them as you have in the past when they were in the Windows filesystem of your Windows machine.
