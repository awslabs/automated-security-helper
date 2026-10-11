# Automated Security Helper

ASH runs a set of open-source security scanners over a directory and combines what they
find into one set of reports and one exit code. You can run it on your machine, in CI, in
a container you build, or from an AI coding agent over MCP.

## What ASH does

- It runs 16 built-in scanners that check source code, secrets, infrastructure as code,
  dependencies, and GitHub Actions workflows, plus community scanners when you load them.
  See the [scanners reference](reference/scanners.md).
- It reads one config file for every scanner: which scanners run, the severity that fails
  a scan, the paths to ignore, and suppressions, each with a required reason and an
  optional expiration date. See [Configure ASH](how-to/configure.md).
- It merges the scanners' results and writes reports from them: SARIF, HTML, Markdown,
  JUnit XML, CSV, CycloneDX, OCSF, GitLab formats, and more. See
  [Read scan results](how-to/read-results.md).
- It returns one exit code. By default a scan fails on findings at MEDIUM severity or
  above. It also fails when a selected scanner could not run or ended in an error, and
  when a vulnerability database or offline ruleset is past its age bound. See
  [Set the gate](how-to/set-the-gate.md).
- For large codebases it can scan only changed files, split a scan into shards and merge
  them, and scan every project in a workspace. See
  [Scale to large repositories](how-to/scale-large-repos.md).
- For code you do not trust it has an opt-in scanner sandbox, rules that limit what a
  repository's own config file may change, and an offline mode. See
  [Scanning untrusted code](concepts/scanning-untrusted-code.md).

## What ASH does not do

- It does not deduplicate findings. When two scanners report the same problem, the results
  hold two findings, and a suppression written for one scanner's rule does not cover the
  other's. See [How ASH works](concepts/how-ash-works.md#findings-are-merged-not-deduplicated).
- It scans files in a directory. It does not scan built container images, running
  containers, or cloud accounts.
- It is not published on PyPI. Install it from GitHub; a package named
  `automated-security-helper` on PyPI belongs to someone else. See
  [Install ASH](how-to/install.md).
- It publishes no container image. `ash build-image` builds one on your machine. See
  [Run ASH in a container](how-to/run-in-a-container.md).
- It does not sandbox scanners unless you turn the sandbox on. A default local scan runs
  every scanner with your environment, your home directory, and your network. See
  [Scanner sandbox](concepts/sandbox.md).
- It does not run offline by default. Scanners download rules and vulnerability
  databases, and some send data to their own services. See
  [what leaves the machine during a scan](concepts/scanning-untrusted-code.md#what-leaves-the-machine-during-a-scan).
- It does not replace a security review of your code.

## Where to start

- To scan code on your own machine, start with [Run your first scan](getting-started/local.md).
- To add ASH as a check to a CI pipeline, start with
  [Add ASH to a GitHub Actions pipeline](getting-started/ci.md).
- To run ASH for many repositories with one policy, start with
  [Roll out ASH across repositories](getting-started/platform-teams.md).
- To let an AI coding agent or IDE run scans, start with
  [Connect an AI agent to ASH](getting-started/agents.md).
- To look up a command, config key, scanner option, or environment variable, go to the
  [reference](reference/index.md).
- To add your own scanner, reporter, or converter, read [Plugins](plugins/index.md).

[Getting started](getting-started/index.md) compares the four paths and what each needs.
