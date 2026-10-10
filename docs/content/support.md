# Get help

## Ask a question or report a bug

Questions, bug reports, and feature requests all go to
[GitHub issues](https://github.com/awslabs/automated-security-helper/issues). Search the
open and closed issues first, then
[open a new issue](https://github.com/awslabs/automated-security-helper/issues/new/choose)
with the bug report or feature request form.

For a bug, include:

- the output of `ash --version`, and how you installed ASH
- your operating system, and the mode you ran in (local, container, precommit, or nix)
- the exact command, and the console output from its first line
- what you expected to happen

ASH's reports can contain secret values that the scanners found, copied from your code,
and the reports and the log show paths on your machine. Do not attach them to an issue.
Paste only the lines that show the problem, with any secrets removed.

[Troubleshoot](how-to/troubleshoot.md) covers common problems by symptom, and the
[FAQ](faq.md) has short answers to the questions people ask most.

## Report a security issue

If you find a security issue in ASH itself, do not report it in a public GitHub issue.
Email aws-security@amazon.com, as
[SECURITY.md](https://github.com/awslabs/automated-security-helper/blob/main/SECURITY.md)
describes. Include a description of the issue and its impact, the steps to reproduce it,
and the ASH versions affected.

SECURITY.md also says what is in scope. A false positive from a scanner is not a security
issue: suppress it in your config, as [Suppress a finding](how-to/suppress-findings.md)
shows. A bug in a scanner that ASH runs, such as semgrep or cfn-lint, belongs with that
scanner's project.

Security fixes go to the 3.x releases. ASH 2.x is no longer supported.
