# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.

## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used (`ash --version` prints it)
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

## Contributing via Pull Requests

Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the `main` branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Create a branch in your fork for the change.
3. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code,
   it will be hard for us to focus on your change.
4. Ensure local tests pass (see below).
5. Commit to your fork using [Conventional Commits](https://www.conventionalcommits.org/) messages, such as
   `fix(sandbox): keep the scanner cache writable`.
6. Send us a pull request with a title in the same format, answering any default questions in the pull request interface.
7. Pay attention to any automated continuous integration (CI) failures reported in the pull request, and stay involved in the conversation.

GitHub provides additional documentation on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).

The [contributor guide](docs/content/contributing/index.md) explains the commit message rules, what CI checks, and
which checks a pull request needs to merge.

## Set up and run the tests

You need git, [uv](https://docs.astral.sh/uv/getting-started/installation/) and Python 3.10 to 3.14. From a clone of your
fork:

<!-- doctest: illustrative reason="installs packages from the network and runs the full test suite" -->
```bash
uv sync --extra cdk --extra symbols
uv run pytest
uv run pytest tests/unit/config --no-cov
```

The first command installs ASH, its development tools and both optional extras into `.venv`. The second runs the whole
suite with its 80% coverage threshold. A run of part of the suite needs `pytest --no-cov`, as in the third command,
because the threshold applies to every run. For integration and snapshot tests, see [Test your change](docs/content/contributing/testing.md);
for documentation changes, see [Testing the documentation](docs/content/contributing/documentation.md).

## Finding contributions to work on

Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
<opensource-codeofconduct@amazon.com> with any additional questions or comments.

## Security issue notifications

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.

[SECURITY.md](SECURITY.md) lists the supported versions, what to include in a report, and what is in scope.

## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.

We may ask you to sign a [Contributor License Agreement (CLA)](http://en.wikipedia.org/wiki/Contributor_License_Agreement) for larger changes.
