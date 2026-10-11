# Development

The development guide is part of the documentation site, under Contributing:

- [Contribute to ASH](docs/content/contributing/index.md): set up a development checkout, the project layout, running
  ASH from your checkout, pull requests, commit messages, what CI runs, code style, and the pre-commit hooks.
- [Test your change](docs/content/contributing/testing.md): the unit, integration, and snapshot tests, the rules the
  suite enforces on new tests, and testing an MCP change locally.
- [Test the documentation](docs/content/contributing/documentation.md): how the docs are checked and how to mark
  a code block.
- [Releases and versions](docs/content/contributing/releases.md): versions, the changelog, cutting a release, tags, and
  the version-pinned pages.

The short version, from a git clone:

<!-- doctest: illustrative reason="installs packages from the network and runs the full test suite" -->
```bash
uv sync --extra cdk --extra symbols
uv run pytest
```

## Snapshot tests

Moved to [Snapshot tests](docs/content/contributing/testing.md#snapshot-tests).

## Release line

Moved to [The release line](docs/content/contributing/releases.md#the-release-line).

## Release App setup

Moved to [The release App](docs/content/contributing/releases.md#the-release-app).
