# Contributing guidelines

Contribute a fix, a new capability, clearer documentation, or a better interface.
Start with the path that fits your change.

| I want to… | Start here |
| --- | --- |
| Report a bug or propose a feature | [GitHub issues](https://github.com/awslabs/automated-security-helper/issues) |
| Set up the project and run checks | [Development guide](DEVELOPMENT.md) |
| Change the website, TUI, or a report | [Interface design](docs/content/developer-guide/interface-design.md) and [preview workflow](docs/ui-tests/README.md) |
| Change onboarding or installation text | Edit the corresponding `.md.template`, then generate its `.md` file |
| Add an integration | [Plugin development](docs/content/plugins/write-a-scanner.md) or [editor integrations](ash-agent-plugins/README.md) |
| Report a security concern | [Security issue notifications](#security-issue-notifications) |

## Reporting bugs and feature requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used (`ash --version` prints it)
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

## Contributing via pull requests

Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the `main` branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Create a branch in your fork for the change.
3. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code,
   it will be hard for us to focus on your change.
4. Ensure local tests pass: `uv sync`, then `uv run pytest`, or `uv run pytest <path>` for part of the suite.
   [DEVELOPMENT.md](DEVELOPMENT.md#testing) has the commands for the optional extras, the integration tests,
   and running the suite with the coverage threshold the way CI does.
5. Commit to your fork using clear commit messages.
6. Send us a pull request, answering any default questions in the pull request interface.
7. Pay attention to any automated continuous integration (CI) failures reported in the pull request, and stay involved in the conversation.

For an interface change, include a representative screenshot or text preview and
record the checks you ran. Review the affected themes, widths, keyboard paths,
and empty/error states. Intentional snapshot changes follow the
[snapshot policy](DEVELOPMENT.md#snapshot-tests).

GitHub provides additional documentation on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).

The [contributor guide](docs/content/contributing/index.md) explains the commit message rules, what CI checks, and
which checks a pull request needs to merge.

## Set up and run the tests

You need git, [uv](https://docs.astral.sh/uv/getting-started/installation/), and Python 3.10 to 3.14. From a clone of your
fork:

<!-- doctest: illustrative reason="installs packages from the network and runs the full test suite" -->
```bash
uv sync --extra cdk --extra symbols
uv run pytest
uv run pytest tests/unit/config
```

The first command installs ASH, its development tools, and both optional extras into `.venv`. The second runs the whole
suite, and the third runs part of it. Neither measures coverage: CI shards the unit tests eight ways, and its
`unit-coverage` job applies an 80% threshold to the combined coverage of each operating system family at Python 3.12.
[Test your change](docs/content/contributing/testing.md#measure-coverage) shows how to run the whole suite with the same
options and threshold. For integration and snapshot tests, see [Test your change](docs/content/contributing/testing.md);
for documentation changes, see [Test the documentation](docs/content/contributing/documentation.md).

## Finding contributions to work on

Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.

## Code of conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
<opensource-codeofconduct@amazon.com> with any additional questions or comments.

## Security issue notifications

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do not create a public GitHub issue.

[SECURITY.md](SECURITY.md) lists the supported versions, what to include in a report, and what is in scope.

## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.

We may ask you to sign a [Contributor License Agreement (CLA)](http://en.wikipedia.org/wiki/Contributor_License_Agreement) for larger changes.
