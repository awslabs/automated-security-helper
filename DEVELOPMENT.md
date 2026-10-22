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

## Interface changes

The [design system](docs/content/developer-guide/interface-design.md) covers the
website, terminal, TUI, and human reports. The [surface review](docs/content/developer-guide/high-end-design-review.md)
records the navigation architecture, motion vocabulary, and platform decisions.

Follow the [preview workflow](docs/ui-tests/README.md) to generate representative
reports and terminal screens, build the documentation, run browser checks, and
inspect the gallery. Review the affected theme, width, keyboard, empty, and
error states. The generated GitHub comment preview approximates GitHub's native
renderer.

Edit versioned content in its `.md.template` and regenerate the output with
`uv run python scripts/version_template_manager.py generate`. Editor and agent
content has its own canonical source in
`ash-agent-plugins/agentic-coding/transpiler/_base/`.

Refresh the README's report and terminal images with `npm run capture -- --readme`
in `docs/ui-tests`. Rebuild the local MIT animation module with `npm run vendor:motion`
after changing its pinned dependency.

## Devfile environments

`devfile.yaml` defines `install`, `build`, and `test` commands for IDEs that read
devfiles (see [Devfile environments](docs/content/contributing/index.md#devfile-environments)).
To run them by hand, for example when the IDE integration fails:

<!-- doctest: illustrative reason="installs uv and packages from the network" -->
```bash
# install
curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR="$HOME/.local/bin" sh && export PATH="$HOME/.local/bin:$PATH" && uv sync

# build
export PATH="$HOME/.local/bin:$PATH" && uv build

# test
export PATH="$HOME/.local/bin:$PATH" && uv run pytest
```

## Snapshot tests

Moved to [Snapshot tests](docs/content/contributing/testing.md#snapshot-tests).

## Release line

Moved to [The release line](docs/content/contributing/releases.md#the-release-line).

## Release App setup

Moved to [The release App](docs/content/contributing/releases.md#the-release-app).
