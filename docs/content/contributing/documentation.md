# Testing the documentation

Every command, config file, environment variable, link and page in these docs is
checked against the code. A docs change that names an option ASH does not have, a
config key ASH ignores, or a page that no longer exists fails CI. This page explains
how the checks decide what a code block is, how to mark a block that cannot be checked
the usual way, how to run the checks yourself, and what each failure means.

There are three layers:

- Static checks, in the `lint` job. They read every markdown file in the repository
  and compare it with the code: the CLI, the config models, the environment variables
  ASH reads, the navigation and the link targets. They also check the docs URLs and
  paths that ASH's own source names. They run in about ten seconds.
- The docs-example runner, in the `integration-test` job. It runs every runnable
  shell and Python block, page by page, and fails when a block exits with the wrong
  code.
- The site build, in the "Build documentation" job. It runs `mkdocs build --strict`
  with link and anchor validation, and without network access.

## How blocks are classified

A fenced code block is checked according to its language. A fence with no language is
an error, because a command in it would escape every check. Use `text` for output
samples.

| Language | Unmarked, it is | Checked |
|----------|-----------------|---------|
| `bash`, `sh`, `shell`, `console` | `run` | executed by the runner; every `ash` line parsed |
| `zsh`, `fish`, `powershell`, `pwsh`, `ps1`, `cmd`, `bat` | an error | must be marked `illustrative` |
| `yaml`, `yml`, `json`, `jsonc`, `toml` | `config kind=ash` | parsed, and validated as an ASH config |
| `python`, `py` | `run` | executed by the runner; must parse; imports must resolve |
| `dockerfile` | not executed | `ash` in `RUN`, `CMD` and `ENTRYPOINT` lines parsed |
| anything else (`text`, `mermaid`, `diff`, ...) | not executed | nothing |

In a `console` block, only the lines that start with a `$` prompt (and their
continuation lines) are commands. Everything else is output.

## Markers

A marker is an HTML comment on the line directly above the opening fence. It does not
render on the site.

````markdown
<!-- doctest: illustrative reason="pulls the container image" -->
```bash
docker pull public.ecr.aws/aws-samples/automated-security-helper:latest
```
````

A blank line between the marker and the fence is an error, as is a marker with no
block after it, so a marker cannot end up governing a different block after an edit.
Values with spaces go in double quotes. Unknown modes and keys are errors.

### Shell and Python blocks

`run` is the default. Use the marker only to change how the block runs.

| Marker | Meaning |
|--------|---------|
| `<!-- doctest: run expect-exit=2 -->` | the block must exit with code 2 |
| `<!-- doctest: run expect-exit=nonzero -->` | the block must fail |
| `<!-- doctest: run expect-exit=any -->` | the exit code is not checked |
| `<!-- doctest: run timeout=300 -->` | allow 300 seconds instead of 60 |
| `<!-- doctest: run env="ASH_OFFLINE=YES,LANG=C" -->` | set these variables for this block only |
| `<!-- doctest: run fixture=empty -->` | start a new session in another fixture project |
| `<!-- doctest: run fresh -->` | start a new session in the default fixture |
| `<!-- doctest: illustrative reason="needs AWS credentials" -->` | do not run the block |

`illustrative` needs a reason a reader would accept, such as "needs Docker", "installs
from the network", "needs AWS credentials", "Windows only" or "runs in CI". "TODO",
"TBD" and "n/a" are rejected. An illustrative block is still checked statically: its
`ash` lines must parse, and a Python block must still parse and import.

The runner treats a page as one session, the way a reader follows a tutorial:

- Blocks run in order, in one copy of a fixture project. The default fixture is
  `sample-project`, a small git repository with a hardcoded password that
  detect-secrets reports without network access. Fixtures live in
  [`tests/test_data/docs_fixtures`](https://github.com/awslabs/automated-security-helper/tree/main/tests/test_data/docs_fixtures).
- Files, the working directory and shell variables carry from one shell block to the
  next. Shell blocks run under `set -e`, so a block stops at its first failing command.
- A Python block runs in a fresh interpreter in the session's directory and
  environment. It cannot change the session.
- HOME is private to the session, `ash` is the one in the project's virtual
  environment, and the network is unreachable: proxies point at a port that refuses
  connections, and uv, pip and npm run offline. A block that needs the network must be
  `illustrative`.

This block runs in CI. The default fixture has one finding, so the scan exits with 2:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

### Config blocks

An unmarked config block must be a complete ASH config. Mark any other file with its
kind.

| Marker | The block is |
|--------|--------------|
| `<!-- doctest: config kind=ash-fragment at=scanners.bandit -->` | the value of one key of an ASH config |
| `<!-- doctest: config kind=pyproject -->` | a `pyproject.toml` whose `[tool.ash]` table is an ASH config |
| `<!-- doctest: config kind=ash-invalid reason="severity is uppercase" -->` | a config ASH must reject |
| `<!-- doctest: config kind=github-actions -->` | a GitHub Actions workflow |
| `<!-- doctest: config kind=gitlab-ci -->` | a GitLab CI file |
| `<!-- doctest: config kind=buildspec -->` | an AWS CodeBuild buildspec |
| `<!-- doctest: config kind=azure-pipelines -->` | an Azure Pipelines file |
| `<!-- doctest: config kind=jenkins -->` | a YAML Jenkins definition |
| `<!-- doctest: config kind=docker-compose -->` | a Compose file |
| `<!-- doctest: config kind=pre-commit -->` | a `.pre-commit-config.yaml` |
| `<!-- doctest: config kind=mcp-client -->` | an MCP client configuration |
| `<!-- doctest: config kind=ash-output -->` | a sample of ASH output |
| `<!-- doctest: config kind=other reason="an IAM policy" -->` | any other file |

Every kind must parse in its language. ASH configs are read with ASH's own reader and
validated by its models, and any key ASH would accept and never read is an error: most
plugin models accept unknown keys without complaint, so a misspelled option would
otherwise do nothing at all. Commands in the `run`, `script` and `commands` keys of CI
files, and the command of an MCP server entry, get the same checks as a shell block.
A `pre-commit` block must use hook ids that
[`.pre-commit-hooks.yaml`](https://github.com/awslabs/automated-security-helper/blob/main/.pre-commit-hooks.yaml)
defines.

### Option tables

A table that documents options or config keys (its first header cell is Option, Key,
Field, Setting or Argument, or it has a Default column) carries a marker naming the
section it documents, on the line directly above its header row:

````markdown
<!-- doctest: options of=scanners.bandit -->
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `confidence_level` | string | `all` | Lowest confidence bandit reports |
````

Every row's first code span must be a key of that section, and its Default cell must
state the default the code has. A table that looks like an options table and has no
marker is an error, so a new table cannot skip the check. Tables headed Variable or
Environment variable are checked as environment variables instead.

| `of=` | The rows are |
|-------|--------------|
| `scanners.bandit`, `reporters.sarif`, `converters.archive` | that plugin's options (the same as adding `.options`) |
| `scanners.*` | the keys every scanner entry has (`name`, `enabled`, `options`) |
| `config` | the top-level keys of an ASH config |
| `global_settings`, `sandbox`, `global_settings.suppressions`, ... | the keys under that config path; a path through a list means one item of it |
| `workspace-policy`, `workspace-policy.workspace`, ... | keys of the workspace policy file |
| `cli`, `cli.scan`, `cli.config.get`, ... | the options and arguments of that `ash` command |

A Default cell is one of:

- a value in one code span, read as YAML: `` `true` ``, `` `1800` ``, `` `[]` ``,
  `` `null` ``, `` `ash-scan` ``, or `` `">=1.7.0,<2.0.0"` `` for a string that YAML would
  read as something else. A path under the repository or home directory starts
  `<repository>/` or `~/`;
- ``from `ENV_NAME`, else `VALUE` `` (one or more `from` parts) for a default ASH reads
  from the environment; `VALUE` is the default when the variable is unset;
- `` `VALUE` on Linux and macOS; `VALUE` on Windows `` for a default that depends on the
  platform;
- one of the phrases `required`, `see the section` (the key is a nested section),
  `computed at run time` or `depends on the platform`, and for `ash` options `off`,
  `on` or `not set`.

A bare word such as `true` or `None` is read the same way; anything else is reported.

### Commands, options and variables in prose

An inline code span that starts with `ash`, or with a wrapper that runs it (`uvx`,
`pipx run`, `uv run`, `docker run`), is checked like a command. A span that is only an
option must be an option of some `ash` command, so write another program's option with
the program: `pytest --run-integration`, not the bare option.

Every `ASH_*` name anywhere on a page must be a variable ASH reads. So must every name
in the first column of a table headed "Variable" or "Environment variable". Write a
family as `ASH_MCP_*`; at least one variable ASH reads must start with the prefix.

An inline code span that is a dotted config path starting with a top-level config key
(`scanners.bandit.options.severity_threshold`, `global_settings.suppressions`,
`sandbox.mode`, also with a value after it, as in `scanners.bandit.enabled=false`) must
resolve in ASH's config models, community plugins included when this ASH has them. Use
`*` or `<name>` for a plugin name that is not fixed: `scanners.<name>.enabled`.

One kind of read is not in the read set: a config value written as `${NAME}`, which
ASH's config loader resolves for any name its rule allows (every `ASH_*` name, and a few
AWS ones). A name that one of the page's ASH config blocks references that way counts as
read everywhere on the page, so the page can set the variable its own config uses.

### Links and pages

- A relative link must reach an existing file, and its `#anchor` an existing heading
  or `id`. On site pages, anchors are computed the way mkdocs computes them; in files
  GitHub renders (`README.md`, `CONTRIBUTING.md`), the way GitHub does.
- A page under `docs/content` may only link to files under `docs/content`, because
  mkdocs cannot publish anything else. Link to other repository files with their
  GitHub URL, `https://github.com/awslabs/automated-security-helper/blob/main/<path>`;
  the path must exist.
- Every page is reachable from a `.nav.yml`, or matches a pattern in `not_in_nav` in
  `mkdocs.yml` with a comment saying why. A `.nav.yml` entry may be a page, a
  directory (which then uses its own `.nav.yml`, or lists everything in it), or a glob
  such as `docs/plugins/community/*.md`. The check runs awesome-nav's own resolver, so
  a glob means what it means in the build, including that it only picks up pages no
  other entry already took. A glob that matches nothing is an error. A glob with
  options is written `- glob: "<pattern>"` with at least one option beside it; on its
  own, `- glob: "<pattern>"` is a titled link to a page named by the pattern.
- When you move or rename a page, add the old path to
  [`docs/redirects.yml`](https://github.com/awslabs/automated-security-helper/blob/main/docs/redirects.yml).
  The site build writes a page at the old URL that forwards readers to the new one,
  keeping the `#anchor` they followed, so that anchor must exist on the new page.

### Docs links in the ASH source

ASH itself names docs pages: help text and error messages point at the site, `ash
get-genai-guide` fetches a docs file from GitHub by path, and some messages name a
heading. The static checks read every string in the package source (docstrings
excepted) and require that:

- a URL on the site reaches a page, directly or through a redirect, and its `#anchor`
  exists on the page it ends at;
- a raw or blob GitHub URL to a docs file names a file that exists. A redirect does not
  help here, because fetching the file does not follow it; when a page moves, the code
  must change too;
- a GitHub URL to any other repository file names a file that exists;
- a docs path (`docs/content/...md`) exists, and a heading the text quotes beside it
  (`'Some heading' in docs/content/page.md`) is a heading on that page.

An f-string is read with each placeholder replaced by the constant it names. A URL
whose path depends on anything else cannot be checked, and is reported as such.

## Running the checks locally

Run these from a checkout of the repository.

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
# Every static check, as the lint job runs them
uv run python scripts/verify_docs_freshness.py

# The examples of one page, through the runner
uv run pytest tests/integration/docs/test_docs_examples.py --run-integration -n 0 -k getting-started

# The site, as the docs job builds it
uv run mkdocs build --clean --strict
```

The expression in `pytest -k getting-started` selects pages by path, so it runs every
page whose path contains `getting-started`. To check that the runner and the checks
themselves still catch what they should:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run pytest tests/unit/test_docs_checks_can_fail.py tests/unit/test_docs_freshness_gate_can_fail.py
uv run pytest tests/integration/docs/test_docs_runner_can_fail.py --run-integration -n 0
```

### Checking docs against another checkout's code

Docs written for code that is not on main yet are checked against a checkout that has
it, while the pages stay in their own checkout. Run the checks with the code
checkout's interpreter and name the docs checkout. Every ASH import, the CLI, the
config models and the environment variables come from the interpreter's ASH; every
page, the nav, `mkdocs.yml`, the redirect map and the fixtures come from the docs
checkout. Both commands print which package and which docs root they used.

<!-- doctest: illustrative reason="needs two checkouts of this repository" -->
```bash
CODE=../code-checkout
DOCS=$PWD

"$CODE/.venv/bin/python" "$DOCS/scripts/verify_docs_freshness.py" --docs-root "$DOCS"

"$CODE/.venv/bin/pytest" "$DOCS/tests/integration/docs" --run-integration -n 0 --docs-root "$DOCS"
```

Use the code checkout's `pytest` rather than `python -m pytest` from the docs
checkout: `python -m` puts the current directory first on the import path, and the
docs checkout's copy of the package would then be the one imported.

## What a failure means

Each static finding is one line: the file and line, the check in brackets, and the
problem. Runner failures name the page, the line of the block, the command, the exit
code and the end of the output.

### markers

| Message contains | Fix |
|------------------|-----|
| has no language | name the language; use `text` for output |
| cannot run in the docs job | mark the Windows, zsh or fish block `illustrative` with a reason |
| a blank line separates this marker | delete the blank line under the marker |
| not directly followed by a fenced code block | move the marker to the line above its fence, or delete it |
| unknown mode, is not a key of | use a mode and key from the tables above |
| needs reason=, is a placeholder | say why the block cannot run |
| names no directory | use a fixture from `tests/test_data/docs_fixtures` |
| never closed | close the fence; everything after it was read as code |

### cli

| Message contains | Fix |
|------------------|-----|
| is not an option of | the option does not exist on that command; the message suggests the nearest one |
| has no subcommand | the command does not exist; check the spelling, or an option's value that reads as a command |
| is a flag and takes no value | drop the `=value` |
| needs a value | give the option a value |
| takes no positional arguments | pass the path with an option such as the source-directory option |
| is not an option of any ash command | another program's option: put the program in the code span |
| placeholder | a run block cannot contain `<placeholder>`; use a real value or mark it `illustrative` |
| `no __main__` | that module cannot be run with `python -m` |
| names no action, has no input | a GitHub Actions `uses:` of this repository names a path or input that does not exist |

### env

The name is not one ASH reads. Check the spelling against the
[environment variable reference](../docs/cli-reference.md), or delete it if the
variable was removed. If ASH builds the name at runtime, the finding says how many
lookups could not be resolved; make the lookup a literal or a module constant.

### config

| Message contains | Fix |
|------------------|-----|
| is not a field of ... ASH accepts it and never reads it | the key does nothing; use the field the model declares |
| ships no scanner (or reporter, converter) named | the plugin is not built in; load it with `ash_plugin_modules` in the same block, or mark the block `config kind=other` |
| this is not an ASH config | mark the block with its kind |
| does not parse | fix the syntax; JSON with comments is `jsonc` |
| ASH accepts this one | an `ash-invalid` block validated; make it fail for the reason it states |
| any other text | the model's own validation error, with the path of the key |

### python

`does not parse` gives the line of the syntax error. `no such module` and `has no
name` mean an import does not resolve in the project's environment: the module was
renamed or removed, or the block needs an extra that is not installed.

### options

| Message contains | Fix |
|------------------|-----|
| documents options or keys but names no section | add `<!-- doctest: options of=<section> -->` above the table |
| is not a key of | the row names an option the section does not have; the message suggests the nearest |
| default says ..., but the default is | the code's default changed; state the one in the message |
| says required, but the default is / but the key is required | the key does (or does not) have a default |
| is not a value or a recognized phrase | write the default in one code span |
| has no key, ships no scanner named | a dotted config path in a code span does not exist |
| needs of= / an options marker goes on the line directly above a table | fix the marker |

### code-links

| Message contains | Fix |
|------------------|-----|
| no page on the site serves this URL | a page the code links to moved; add a redirect, or change the URL in the code |
| has no anchor | the heading the URL points at was renamed; restore the heading or change the URL |
| does not exist in the docs | the docs file the code names moved or was removed; change the code |
| a fetch of the file does not follow it | the code fetches a docs file that moved; change the path in the code |
| that page has no such heading | the code quotes a heading that was renamed |
| is built at runtime | the URL's path is not a constant; write it as a literal so it can be checked |

### links, nav, redirects and site

| Message contains | Fix |
|------------------|-----|
| does not exist | fix the path |
| has no heading or anchor | fix the anchor; heading ids change when a heading is reworded |
| mkdocs cannot serve | link to the GitHub URL the message gives |
| links to a directory | link to the page in it |
| no page on the site serves this URL | the page moved; update the link or add a redirect |
| no reader can reach it | add the page to a `.nav.yml`, or to `not_in_nav` with a reason |
| doesn't match any files or directories | a nav entry or glob reaches no page that is not already listed elsewhere |
| nav entry ... names no page | a titled nav entry points at a page that does not exist |
| still exists, which is not a page, itself redirected | fix the entry in `docs/redirects.yml` |
| must be 'warn', does not pass --strict, hooks does not list | `mkdocs.yml` or the docs workflow lost a strict-build setting; restore it |

## Adding a generated reference page

A reference page that restates the code (a list of options, variables, scanners or
tools) is generated, never written by hand. To add one:

1. Write `scripts/generate_<name>.py`. It renders the page from the code (the click
   tree, a pydantic model, the plugin registry) and writes it. Run as
   `generate_<name>.py --check`, it writes nothing, compares what it would write with
   the committed file, prints a diff and exits non-zero if they differ.
   [`scripts/generate_reporter_docs.py`](https://github.com/awslabs/automated-security-helper/blob/main/scripts/generate_reporter_docs.py)
   is a complete example, including generated regions inside a hand-written page.
2. Start the page with a banner naming the generator and the command that regenerates
   it, so a reader who wants to change it knows not to edit it.
3. Add a freshness test to
   [`tests/unit/test_generated_docs_freshness.py`](https://github.com/awslabs/automated-security-helper/blob/main/tests/unit/test_generated_docs_freshness.py)
   that runs `generate_<name>.py --check`, so the unit suite fails when the code
   changes and the page does not.
4. Add the page to `.nav.yml`. The static checks then cover it like any other page.

The implementation of all of this is in
[`scripts/docs_checks.py`](https://github.com/awslabs/automated-security-helper/blob/main/scripts/docs_checks.py)
and
[`tests/integration/docs/docs_runner.py`](https://github.com/awslabs/automated-security-helper/blob/main/tests/integration/docs/docs_runner.py).
Page paths the checks depend on are constants at the top of `docs_checks.py`.
