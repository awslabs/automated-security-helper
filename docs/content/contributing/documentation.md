# Test the documentation

Every command, config file, environment variable, link, and page in these docs is
checked against the code. A docs change that names an option ASH does not have, a
config key ASH ignores, or a page that no longer exists fails CI. This page explains
how the checks decide what a code block is, how to mark a block that cannot be checked
the usual way, how to run the checks yourself, and what each failure means.

There are three layers:

- Static checks, in the `lint` job. They read every Markdown file in the repository
  and compare it with the code: the CLI, the config models, the environment variables
  ASH reads, the navigation, and the link targets. They also check the docs URLs and
  paths that ASH's own source names. They run in about ten seconds.
- The docs-example runner, in the `integration-test` job. It runs every runnable
  shell and Python block, page by page, and fails when a block exits with the wrong
  code.
- The site build, in the `build-docs` job. It runs `mkdocs build --strict` with link
  and anchor validation, then publishes the site as versions to a throwaway branch with
  the network blocked, and checks what readers of each version would see (see
  [Versioned docs](#versioned-docs)).

All three jobs are in the Unified CI workflow and run on every pull request and merge
queue entry. The `required-checks` gate depends on each of them, so a failure in any
layer blocks the merge. The "Docs Deploy" workflow, `ash-repo-docs.yml`, only publishes
the site, after a push to `main` and when someone runs it by hand on a release tag.

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
| `dockerfile` | not executed | `ash` in `RUN`, `CMD`, and `ENTRYPOINT` lines parsed |
| `groovy` | an error | must be marked `config kind=jenkinsfile` (see [CI pipelines](#ci-pipelines)); `ash` in its `sh` steps parsed |
| `jenkinsfile`, `Jenkinsfile` | an error, marked or not | nothing; fence a Jenkinsfile as `groovy` |
| anything else (`text`, `mermaid`, `diff`, ...) | not executed | nothing |

In a `console` block, only the lines that start with a `$` prompt (and their
continuation lines) are commands. Everything else is output.

## Markers

A marker is an HTML comment on the line directly above the opening fence. It does not
render on the site.

````markdown
<!-- doctest: illustrative reason="needs Docker" -->
```bash
ash --mode container --source-dir .
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
| `<!-- doctest: run expect-exit=nonzero -->` | the block must fail, with a code other than 126 or 127 (a command not executable or not found) |
| `<!-- doctest: run expect-exit=any -->` | the exit code is not checked, so an [output sample](#output-samples) must directly follow the block |
| `<!-- doctest: run timeout=300 -->` | allow 300 seconds instead of 60 |
| `<!-- doctest: run env="ASH_OFFLINE=YES,LANG=C" -->` | set these variables for this block only |
| `<!-- doctest: run fixture=empty -->` | start a new session in another fixture project |
| `<!-- doctest: run fresh -->` | start a new session in the default fixture |
| `<!-- doctest: illustrative reason="needs AWS credentials" -->` | do not run the block |

`illustrative` needs a reason a reader would accept, such as "needs Docker", "installs
from the network", "needs AWS credentials", "Windows only", or "runs in CI". "TODO",
"TBD", and "n/a" are rejected, and so is a reason that names no cause, such as "example"
or "illustrative example only". An illustrative block is still checked statically: its
`ash` lines must parse, and a Python block must still parse and import.

The runner treats a page as one session, the way a reader follows a tutorial:

- Blocks run in order, in one copy of a fixture project. The default fixture is
  `sample-project`, a small git repository with a hardcoded password that
  detect-secrets reports without network access. Fixtures live in
  [`tests/test_data/docs_fixtures`](https://github.com/awslabs/automated-security-helper/tree/main/tests/test_data/docs_fixtures).
- Files, the working directory, and shell variables carry from one shell block to the
  next. Shell blocks run under `set -e`, so a block stops at its first failing command.
- A Python block runs in a fresh interpreter in the session's directory and
  environment, with that directory on its import path. It cannot change the session,
  except through `save-as` (below).
- `HOME` is private to the session, `ash` is the one in the project's virtual
  environment, and downloads fail at once: every proxy variable points at a port that
  refuses connections, and uv, pip, and npm run offline. A block that needs the network
  must be `illustrative`. This is not a sandbox: a program that ignores the proxy
  variables can still connect, and blocks run as you, so run the examples only on docs
  you trust.

This block runs in CI. The default fixture has one finding, so the scan exits with 2:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

### Output samples

A `text` block marked `output` directly after a block the runner runs is a sample of
that block's output. Prose may sit between the two:

````markdown
```bash
ls .ash/ash_output/reports
```

The scan wrote one report:

<!-- doctest: output -->
```text
ash.sarif
```
````

The runner compares the sample with what the block printed, stdout and stderr
together, whatever exit code the block expects. The CLI check does not read the
sample's `ash` lines as commands. Both texts are normalized first:

- ANSI escape codes are removed, and Rich's box-drawing characters become spaces, so a
  table row reads as its cells;
- durations (`46ms`, `1.23s`, `3 seconds`), clock times (`0:00:03`), and timestamps
  (`2026-10-11T12:00:01Z`) become `<time>`;
- the session's project directory reads as `.`, with the paths under it relative, and
  its `HOME` as `~`;
- each run of whitespace becomes one space, and blank lines are dropped.

Then every line of the sample, other than a line that is only `...`, must appear in a
line of the output, in order, starting and ending at word boundaries. `...` inside a
line stands for any text there, so `detect-secrets ... PASSED` matches a table row. The
output is rendered 100 columns wide, the way Rich lays out a table in the runner.

A block marked `output` anywhere else is an error: as the first block on a page, after
an `illustrative` block, after a block that is only saved, after a config block, or
after another sample. Nothing printed it there, so the marker would only hide its `ash`
lines from the CLI check. `tests/unit/test_docs_corpus_census.py` counts the samples the
runner compares, so a sample it stops comparing fails the unit suite.

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
| `<!-- doctest: config kind=jenkinsfile -->` | a declarative `Jenkinsfile`, on a `groovy` block |
| `<!-- doctest: config kind=circleci -->` | a CircleCI `config.yml` |
| `<!-- doctest: config kind=docker-compose -->` | a Compose file |
| `<!-- doctest: config kind=pre-commit -->` | a `.pre-commit-config.yaml` |
| `<!-- doctest: config kind=mcp-client -->` | an MCP client configuration |
| `<!-- doctest: config kind=ash-output model=automated_security_helper.models.asharp_model.AshAggregatedResults.scanner_results -->` | part of a file ASH writes; `model=` names its output model as `<module>.<Model>`, then any fields below it |
| `<!-- doctest: config kind=mcp-response of=mcp.run_ash_scan -->` | an example of an MCP tool's response, in a `json` block or a `text` block with placeholders |
| `<!-- doctest: config kind=other reason="an IAM policy" -->` | any other file |

Every kind must parse in its language. ASH configs are read with ASH's own reader and
validated by its models, which refuse an option a plugin does not declare. Any key ASH
would accept and never read is an error too: a scan ignores an unknown top-level key, so
a reader who copied one would see it do nothing. Commands in the `run`, `command`,
`script`, and `commands` keys of CI files, in the `sh` steps of a Jenkinsfile, and the
command of an MCP server entry, get the same checks as a shell block. A `pre-commit`
block must use hook IDs that
[`.pre-commit-hooks.yaml`](https://github.com/awslabs/automated-security-helper/blob/main/.pre-commit-hooks.yaml)
defines. An `mcp-response` example must be one response the tool named by `of` returns:
every key it shows, nested ones included where the code spells the value out, must be a
key of one dict the tool's return statements build. A key written as a placeholder,
such as `"<scanner_name>"`, stands for any key.

An `ash-output` block is validated against the model `model=` names, which must be one
of ASH's own. Every key the block shows must be a field the model declares, even where
the model accepts extra keys, because a renamed key in a sample is a key ASH does not
write. SARIF's property bags are the exception: they take any key.

### Saving a block as a file

A tutorial often shows a file and then a command that uses it. With `save-as=<path>`,
the runner writes the block, exactly as shown, to that path in the page's project
before the blocks after it run. Missing directories are created. `save-as` works on
any block: Python, shell, config, Dockerfile, or text.

````markdown
<!-- doctest: save-as=my_plugins/greeting.py -->
```python
def hello():
    return "hi"
```

```python
from my_plugins.greeting import hello

print(hello())
```
````

| Marker | What the runner does |
|--------|----------------------|
| `<!-- doctest: save-as=my_plugins/greeting.py -->` | saves the block and does not run it |
| `<!-- doctest: run save-as=tools/check.py -->` | saves the block, then runs it; a Python block runs from the saved file, so `__file__` is that path |
| `<!-- doctest: config kind=github-actions save-as=.github/workflows/ash.yml -->` | saves the block, which is still validated as its kind |
| `<!-- doctest: save-as=.ash/.ash.yaml -->` on a YAML block | saves the block, which is still validated as a complete ASH config |

The path is relative to the root of the page's fixture project, whatever directory
earlier blocks changed to. An absolute path, a path containing `..`, and a path that
goes through a symbolic link are refused, and the block fails; the static check
reports the first two before CI runs. A marker without a mode may carry nothing but
`save-as`. An `illustrative` block is never run or saved, so `illustrative` with
`save-as` is an error: use a marker without a mode to save a block that must not run,
such as a PowerShell script.

The python check knows which modules a page saves. `save-as=my_plugins/scanner.py`
makes `my_plugins` and `my_plugins.scanner` importable by every Python block of the
page, a name imported from a saved module must be defined in it, and a relative
import in a saved package resolves within that package.

### CI pipelines

A block of kind `github-actions`, `gitlab-ci`, `buildspec`, `jenkinsfile`, or `circleci`
is a pipeline, which the Docs CI Runners workflow runs under its CI system's own runner
(see [Run the CI examples with their runners](#run-the-ci-examples-with-their-runners)).
Its marker says how:

| Marker | The block is |
|--------|--------------|
| `<!-- doctest: config kind=github-actions -->` | a complete pipeline; its runner runs it, and ASH must exit 2 in it |
| `<!-- doctest: config kind=github-actions save-as=.github/workflows/ash.yml -->` | a complete pipeline that later blocks on the page may extend; it still runs on its own |
| `<!-- doctest: config kind=github-actions extends=.github/workflows/ash.yml -->` | a fragment, run merged into the pipeline that the nearest block above it saved at that path |
| `<!-- doctest: config kind=gitlab-ci extends=.gitlab-ci.yml event=merge_request -->` | a pipeline run for the event it names |
| `<!-- doctest: config kind=circleci runner=none reason="uses a private orb" -->` | a pipeline no runner runs; the static checks still read it |

The keys follow these rules:

- `extends=` is valid on `github-actions` and `gitlab-ci` blocks, the kinds with a merge
  rule. It must name a block above it on the page, saved with `save-as=` at that path,
  of the same kind, and a fragment cannot also carry `save-as=`.
- `event=` takes `pull_request` or `push` on a `github-actions` block, and `push` or
  `merge_request` on a `gitlab-ci` block; the other kinds take no event. Without it, a
  GitHub workflow runs for `pull_request` when its `on:` lists that event, and for
  `push` otherwise, and a GitLab pipeline runs for `push`.
- `runner=` takes only `none`, and then needs a `reason=` that follows the
  `illustrative` rules. `reason=` goes with `runner=none` only.
- `azure-pipelines` blocks and YAML `jenkins` blocks have no runner. They take none of
  these keys and get the static checks only.
- A `groovy` block must be marked `config kind=jenkinsfile`, with `runner=none` and a
  reason when no runner can run it. An unmarked `groovy` block, or one marked only with
  `save-as=`, is an error, so a Jenkinsfile cannot drop out of the runs. So is a block
  fenced `jenkinsfile` or `Jenkinsfile`, whatever its marker: fence it as `groovy`.

A fragment is merged into the pipeline it extends by its kind's rule:

- `gitlab-ci`: as GitLab merges an included file, with the fragment as the including
  file. Mappings merge at any depth and the fragment's value wins; anything else, such
  as a `script:` or `rules:` list, is replaced by the fragment's.
- `github-actions`, a mapping of jobs: the jobs are added to the saved workflow, and a
  job with the ID of a saved one replaces it whole.
- `github-actions`, a list of steps: a named step replaces the saved job's step with
  the same `name`, and an unnamed one the step that uses the same action, whatever its
  `@` ref. A step with no counterpart goes right before the next fragment step that
  replaces one, or right after the last replaced step.

The static checks merge each fragment the same way and report one that does not merge,
such as a list of steps none of which replaces a saved step, or one whose steps match
steps in more than one job. Whether a block scans only the changed files is read from
the pipeline, not the marker: an `ash` command with `--changed-files-only`, or a call
of `run-ash-security-scan.yml` with its `changed-files-only` input set to `true`.
`tests/unit/test_docs_ci_runner_census.py` compares the blocks each runner leg runs
with an exact list, and checks that every CI block is run by a leg, marked
`runner=none`, or of a kind with no runner, so a block that stops running fails the
unit suite.

### Option tables

A table that documents options, keys, or parameters carries a marker naming the section
it documents, on the line directly above its header row:

````markdown
<!-- doctest: options of=scanners.bandit -->
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `confidence_level` | string | `all` | Lowest confidence bandit reports |
````

Every row's first code span must be a key of that section, and its Default cell must
state the default the code has. A column headed Defaults to, If not passed, If not set,
or If unset is a Default column too. Any other column whose header says it holds
defaults is an error, because nothing compares it.

A table without a marker is an error, so a new table cannot skip the check, when both
of these hold:

- its first header cell is Option, Key, Field, Setting, Argument, Param, Parameter, or
  Prop, or it has a column of defaults;
- most of its rows name a key: of the ASH config model, of an `ash` command, of an MCP
  tool, or of a section in the code tree (a Python function's parameters, a Terraform
  module's variables, an action's or workflow's inputs, the Dockerfile's build
  arguments, a CloudFormation template's parameters, or a TypeScript interface's
  properties). A name close to a key counts, so a table of misspelled keys still needs
  its marker.

A table of other things, such as a list of defenses that are on or off by default,
needs no marker. A table headed Variable or Environment variable whose rows are mostly
upper-case names is checked as environment variables instead: each name must be one ASH
reads, and each Default cell must say what the
[environment variable reference](../reference/environment-variables.md) says.

A row can name several keys when its first cell is only a list of code spans
(`` `quiet`, `simple`, and `debug` ``). Its Default cell then holds one value for all of
them, or one code span per key in the same order (`` `False`, `"origin/main"` ``). A
key written with a value (`` `--build-target ci` ``) is checked as the key alone.

Add `complete` to the marker when the table lists every key of its section, as in
`<!-- doctest: options of=scanners complete -->` above a table of every scanner ASH
ships. Each key of the section that no row names is then an error. `--help`, a hidden option, and the options ASH reads from every
scanner need no row.

| `of=` | The rows are |
|-------|--------------|
| `scanners.bandit`, `reporters.sarif`, `converters.archive` | that plugin's options (the same as adding `.options`) |
| `scanners.*` | the keys every scanner entry has (`name`, `enabled`, `options`) |
| `scanners`, `reporters`, `converters` | the plugins of that section, by name, built-in and community ones; a column headed Enabled by default or On by default is compared with each plugin's `enabled` default |
| `config` | the top-level keys of an ASH config |
| `global_settings`, `sandbox`, `global_settings.suppressions`, ... | the keys under that config path; a path through a list means one item of it |
| `workspace-policy`, `workspace-policy.workspace`, ... | keys of the workspace policy file |
| `cli`, `cli.scan`, `cli.config.get`, ... | the options and arguments of that `ash` command |
| `mcp.run_ash_scan`, ... | the parameters of that MCP tool, from the input schema the server lists |
| `python.automated_security_helper.interactions.run_ash_scan.run_ash_scan` | the parameters of a Python function, a class's `__init__` (`python.<module>.<Class>`) or a method (`python.<module>.<Class>.<method>`), read from the source without importing it |
| `dockerfile` | the build arguments of the shipped `Dockerfile`, with the defaults its `ARG` lines give |
| `cloudformation:deploy/cdk/templates` | the Parameters of one CloudFormation template, or of every template in a directory |
| `github-inputs:.github/workflows/run-ash-security-scan.yml` | the inputs of a GitHub Action (its `action.yml` or the directory holding one) or of a workflow (`workflow_call` and `workflow_dispatch`) |
| `typescript:deploy/cdk-constructs/src/ash-scan-step.ts:ASHScanStepProps` | the properties of a TypeScript interface; one without `?` is required, and the default is its JSDoc `@default` (an `@default - words` default is prose and is not compared) |
| `terraform:deploy/terraform/modules/fargate` | the variables of a Terraform module: every `variable` block in the directory's `.tf` files; one without a default is required, and one whose default is not a literal has no default to compare |

Python, Dockerfile, CloudFormation, GitHub, TypeScript, and Terraform sections are read from the code tree, the
checkout of the installed ASH (see [Check docs against another checkout's
code](#check-docs-against-another-checkouts-code)).

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
  `computed at run time`, or `depends on the platform`, and for `ash` options `off`,
  `on`, or `not set`. `empty` means an empty string or list. A phrase may be set in
  emphasis (`*required*`).

A bare word such as `true` or `None` is read the same way; anything else is reported.

Defaults of a `python.` section are read as Python, not YAML: write `` `None` ``,
`` `False` ``, `` `"low"` ``, or `` `ExecutionStrategy.PARALLEL` ``. A literal is compared
by value and anything else by its source text, and a string may also be written without
quotes (`` `t3.medium` ``). Dockerfile, CloudFormation, GitHub, and TypeScript defaults
are compared as written, so `` `NO` `` is the string NO, not false. A default that is a
member of an enum or class may be written by the member alone: `` `PIP` `` for
`ASHInstallMode.PIP`, `` `PARALLEL` `` for `ExecutionStrategy.PARALLEL`.

### Commands, options, and variables in prose

An inline code span that starts with `ash`, or with a wrapper that runs it (`uvx`,
`pipx run`, `uv run`, `docker run`), is checked like a command. A span that is only an
option must be an option of some `ash` command, so write another program's option with
the program: `pytest --run-integration`, not the bare option. On a generated reference
page, a row a plugin's code wrote names the program even for an option ASH also has,
because there a bare `--config` could be either. That covers the rows of a plugin's
options table and the environment variables whose purpose is quoted from a plugin
module. Write `zizmor --config`, and `ash --config` for ASH's own.

Every `ASH_*` name anywhere on a page must be a variable ASH reads. So must every name
in the first column of a table headed "Variable" or "Environment variable". Write a
family as `ASH_MCP_*`; at least one variable ASH reads must start with the prefix.

An inline code span that is a dotted config path starting with a top-level config key
(`scanners.bandit.options.severity_threshold`, `global_settings.suppressions`,
`sandbox.mode`, also with a value after it, as in `scanners.bandit.enabled=false`) must
resolve in ASH's config models, community plugins included when this ASH has them. Use
`*` or `<name>` for a plugin name that is not fixed: `scanners.<name>.enabled`.

Two more kinds of name are accepted. A build argument, declared with `ARG` in the
Dockerfile ASH ships or passed by ASH as `--build-arg NAME=...` (as it passes the
image name to a custom Containerfile), is documented like any variable. A variable
only the test suite reads or CI sets (in `tests/`, or in an `env:` block under
`.github/`) is accepted on contributor pages (the pages under
`docs/content/contributing/`, the repository's `CONTRIBUTING.md`, and its
`DEVELOPMENT.md`) and reported anywhere else, because a user cannot use it. Running
the checks with `scripts/verify_docs_freshness.py --verbose` prints which of these
sets each accepted name matched.

One kind of read is not in the read set: a config value that starts with a reference
such as `${NAME:default}` or `${NAME}`, which ASH's config loader replaces with the
environment variable for any name its rule allows (every `ASH_*` name, and three AWS
ones). When the variable is not set, `${NAME:default}` becomes `default`, and a scan
refuses a config whose `${NAME}` has no default, with exit 3. A name that one of the
page's ASH config blocks references either way counts as read everywhere on the page,
so the page can set the variable its own config uses.

### File and scanner names

An inline code span that names a file `ash.<name>`, alone or at the end of a path, or
`reports/<name>`, must name a file ASH writes. That is the report of a registered
reporter (`ash.<extension>`), a file a reporter's code writes beside its report (the S3
reporter's `reports/s3-report.json`), a file name a reporter's options default to, a
file name held by a constant in ASH's package whose name says it is one (ending in
`_FILE`, `_FILES`, `_FILENAME`, and the like), or a file the repository ships
(`Formula/ash.rb`). The report of a reporter a Python block on the
same page declares counts on that page. So does the report of a plugin package in this
repository, such as the example plugin package, on a page in the package's project
directory or a page that names the package. A placeholder, as in
`reports/ash.<extension>`, is not checked.

In a table, every item of a column headed Scanner, Scanners, Built-in scanners,
Community plugins, or Community scanners must be one scanner ASH ships, built in or a
community plugin as the header says. A note in parentheses after a name is ignored. Any other item of several
words is an error, because nothing can check it: write
`semgrep, opengrep (as far as their rules cover the language)`, and put longer notes in
another column.

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

## Run the checks locally

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

`verify_docs_freshness.py` prints PASS or FAIL for each check, with the findings under
each failing one, and exits 1 when any check fails. A check that raises did not run:
it prints ERROR with the error, and the script exits 2. Several checks list files with
git, so run the script in a git checkout rather than an extracted copy of one. The
expression in
`pytest -k getting-started` selects pages by path, so it runs every
page whose path contains `getting-started`. To check that the runner and the checks
themselves still catch what they should:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run pytest tests/unit/test_docs_checks_can_fail.py tests/unit/test_docs_freshness_gate_can_fail.py
uv run pytest tests/integration/docs/test_docs_runner_can_fail.py --run-integration -n 0
```

### Check docs against another checkout's code

Docs written for code that is not on main yet are checked against a checkout that has
it, while the pages stay in their own checkout. Run the checks with the code
checkout's interpreter and name the docs checkout. Every ASH import, the CLI, the
config models, and the environment variables come from the interpreter's ASH; every
page, the nav, `mkdocs.yml`, the redirect map, and the fixtures come from the docs
checkout. Both commands print which package and which docs root they used.

<!-- doctest: illustrative reason="needs two checkouts of this repository" -->
```bash
CODE=../code-checkout
DOCS=$PWD

"$CODE/.venv/bin/python" "$DOCS/scripts/verify_docs_freshness.py" --docs-root "$DOCS"

"$CODE/.venv/bin/pytest" "$DOCS/tests/integration/docs" --run-integration -n 0 --docs-root="$DOCS"
```

Use the code checkout's `pytest` rather than `python -m pytest` from the docs
checkout: `python -m` puts the current directory first on the import path, and the
docs checkout's copy of the package would then be the one imported. Pass the option to
pytest as one word, `pytest --docs-root=<checkout>`: pytest reads a separate value as
a test path before the option is registered, and when the tests and the docs come from
different checkouts it then loads both checkouts' `tests/conftest.py` and stops with
"option names {'--run-slow'} already added".

The reference page generators take the same two checkouts: each documents the ASH its
interpreter imports, and compares its page in the docs checkout with what it generates
(`generate_cli_docs.py --docs-root "$DOCS" --check`). Run them from any directory; each
prints the package it documents.

<!-- doctest: illustrative reason="needs two checkouts of this repository" -->
```bash
CODE=../code-checkout
DOCS=$PWD

for page in cli_docs config_reference converter_reference env_var_reference \
    mcp_tool_reference reporter_docs scanner_reference; do
  "$CODE/.venv/bin/python" "$DOCS/scripts/generate_$page.py" --docs-root "$DOCS" --check
done
```

Without the check option, each rewrites its page instead. The MCP tools generator also
writes the agent plugins' tool reference, so after rewriting it, copy that into every
plugin from the docs checkout:

<!-- doctest: illustrative reason="needs a checkout of this repository" -->
```bash
cd "$DOCS/ash-agent-plugins"
uv run --project agentic-coding/transpiler agentic-plugins build
```

A generator's run is offline and leaves the home directory alone: uv and pip may not
reach an index, every proxy variable points at a local port that refuses connections,
and uv's and the XDG cache, data, and config directories are temporary ones that are
removed when it exits. Building the scanner plugins asks each tool for its version, and
online that used to install the tools into the home directory.

## Run the CI examples with their runners

The pipelines on the CI pages also run, each under its CI system's own local runner, in
the Docs CI Runners workflow,
[`ash-docs-ci-runners.yml`](https://github.com/awslabs/automated-security-helper/blob/main/.github/workflows/ash-docs-ci-runners.yml).
It runs on a pull request that changes a path its `paths` filter lists, such as a CI
page or its template, the harness and its pins, the fixture, or the install, scan, and
report code the runs check. It also runs from the Actions tab, for every leg, or the legs
of the runner its `legs` input names. A required check that does not run blocks the
merge, so this path-filtered workflow is not a required check, and `required-checks`,
which stands for the jobs of the "ASH - Unified CI" workflow, does not cover it.

Each leg of its matrix is one runner on one page, and runs every block of that page the
runner can run:

| Kind | Runner | Legs |
|------|--------|------|
| `github-actions` | nektos/act, which runs each job on the hosted runner itself | `act`, one for each page whose GitHub Actions blocks it runs |
| `gitlab-ci` | gitlab-ci-local, which runs each job in its `image:` | `gitlab-ci-local` |
| `jenkinsfile` | Jenkinsfile Runner | `jenkinsfile-runner-lts`, on the LTS core of Jenkins pinned in `runners.toml`, and `jenkinsfile-runner-bundled`, on the core the Jenkinsfile Runner release is built against |
| `buildspec` | the AWS CodeBuild local agent | `codebuild-agent` |
| `circleci` | the CircleCI CLI: `circleci config validate` and `circleci config process`, then `circleci local execute` | `circleci` |
| `azure-pipelines`, YAML `jenkins` | none; these blocks get the static checks only | none |

The core that Jenkinsfile Runner's release is built against is past its upstream support
period. Its leg runs only on a GitHub-hosted runner's throwaway VM, with no listener and
no credentials.

### How a run is set up

Each block a leg runs is one test of `tests/integration/docs/test_docs_ci_runners.py`,
from the census in `scripts/docs_checks.py`. For each one:

- The block, merged into the pipeline it extends if it is a fragment, is committed as
  the pipeline file of a new git repository made from the default fixture,
  `sample-project`, with a bare repository holding `main` as its `origin`. For a pull
  request or merge request event, a branch adds one commit with `changed.py`, whose one
  finding is a `subprocess.call` with `shell=True` (bandit B602).
- The leg checks out the pull request's head commit, not the merge commit (on a
  dispatch, the commit it was dispatched on), and builds its wheel. In the block's
  install line, the release becomes that wheel, which gitlab-ci-local and
  `circleci local execute` mount into the job's container. The CodeBuild agent cannot
  mount it, and a wheel in the source would be scanned, so there the install line names
  the head commit, which pip installs with git. A call of ASH's reusable workflows
  becomes a call of the pull request's own copy in the fixture, with `ash-version` set
  to the head commit. A GitLab job on ASH's own image,
  `registry.example.com/security/automated-security-helper:ci`, runs on the image the
  run builds under that name from the checkout's `Dockerfile` (the `ci` target).
- Each rewrite is an exact replacement, or an insertion at a place read from the
  pipeline (its parsed YAML, or a Jenkinsfile's `sh` script), whose count is recorded.
  A block the rewrites cannot follow fails its test: one with none of the install forms
  they know, or one that could still get ASH from somewhere else, such as another
  install of Python packages, another reference to ASH's repository, or an image of ASH
  the run does not build. So an edit to an install line cannot quietly test the
  release. The install checks read the pipeline's commands as written, so a command
  assembled at run time from variables is not seen.
- After each install, the rewrite adds a command that prints the installed
  distribution's `direct_url.json`. In a job on the image the run builds, it adds one
  right before the first command that runs ASH, which prints from inside the image a
  one-line record of the installed ASH: its version, its `direct_url.json` if it has
  one, the number of its package files and one SHA256 of their paths and SHA256s, and
  the SHA256 of its `METADATA` and `entry_points.txt`. The fixture's copy of
  `run-ash-security-scan.yml` gets one counted step, right after its one
  `uvx --reinstall` step (the scan), that prints the record of the ASH the scan ran,
  even when the scan failed; the repository's own workflow is not changed.
- Each runner starts with an environment built from nothing: a new, empty home
  directory, a `PATH` of the directory that holds the runner, then a fixed system
  `PATH`, `LANG`, the tool download cache of its pytest session (the runs and the
  controls each have their own), and only the variables that runner needs. An `ash`
  that records that it ran is first on the test process's own `PATH`, and the session
  fails if any pipeline reached it.
- Each launch has a time limit, the matrix row's `launch_timeout`. While the runner
  runs, the test process is the child subreaper of what it starts, so a process whose
  parent ends stays below the test process, and the runner's environment holds a
  marker of that launch's own, which the processes it starts inherit unless they clear
  their environment. When the runner ends, or runs out of time, the processes in its
  process group, those the launch started below the test process, and those whose
  environment holds the marker get SIGTERM, and those still running after a short
  grace SIGKILL. Then the containers the Docker daemon gained while the runner ran are
  removed, before the next block runs. If any of them is left, the test fails. A
  process that another service starts for the run, and that gets neither the marker
  nor a new container, is not found.
- Each Jenkins home stays in pytest's work directory, outside the output directory the
  workflow uploads; only the build's log, `build.xml`, JUnit record, and archive are
  copied out.
- The runners and tools are pinned by SHA256 and the images by digest, in
  `tests/integration/docs/ci_runners/runners.toml` and the Jenkins plugin lists beside
  it, and every image the leg pulls is checked against those digests and the images the
  run builds.

### What a run checks

Every runnable block expects ASH to exit 2 on the fixture's findings. A test passes only
when its run shows all of these:

- the runner's own result: the jobs that gate on findings fail under act,
  gitlab-ci-local exits non-zero and the exit code its gate job reads is 2, the build
  fails under Jenkinsfile Runner and `circleci local execute`, and the BUILD phase
  fails under the CodeBuild agent;
- ASH's verdict line in the log, such as
  `ERROR (2) Exiting due to 3 actionable findings found in ASH scan`, with the count the
  fixture plants: two findings in `app.py`, one more in `changed.py` on a pull request
  or merge request branch, and only that one for a scan of the changed files;
- the reports where the page says the pipeline keeps them: act's artifact store, the
  GitLab job's artifacts, the Jenkins build's archive and JUnit record, the CodeBuild
  agent's artifact and report directories, and for CircleCI a copy that the rewrite
  adds as the job's last step, because `circleci local execute` discards the project
  directory when the job ends;
- the actionable findings by file in `ash_aggregated_results.json`;
- under act, what the stubs recorded: the SARIF file each upload was given (on the
  sharded example only the last upload's, which must be the SARIF the merge step
  wrote), the check run the reusable scan workflow publishes, with one failed test per
  actionable finding, and, for a pull request, its comment; and each step that stops
  workflow commands printing its resume token;
- which ASH ran. Each printed `direct_url.json` must name the wheel the leg built, with
  its SHA256, or the head commit of the base repository, one for each print in each run
  of its job, and the wheel file must still have that SHA256 after the run. No line of
  the log may show ASH downloaded from a package index: a `pypi.org` or
  `files.pythonhosted.org` URL that names it, a `Downloading` line for it, or uv's
  `+ automated-security-helper==` line for a copy that came from neither a file nor a
  git URL. The job on the image the run builds is checked by its own record instead:
  its version, its package files (less bytecode and the revision file that each build
  writes for itself), its `METADATA`, and its entry points must match those of the
  wheel built from the same checkout, a `direct_url.json` in it must name a local file
  with that wheel's name, and the runner's log must name the image the run built, as
  its build recorded it.

After the runs, `tests/integration/docs/ci_runners/check_junit.py` checks that the leg
ran one test for each block the census gives it, and skipped none. The negative
controls in `tests/integration/docs/test_docs_ci_runners_can_fail.py` run the first
block of each leg, page, and install mechanism, the wheel or a git commit, with an
install that cannot succeed: a wheel path that does not exist, or a commit no
repository has. In each, the job's script must start, a line it prints must name the
broken input with the installer's refusal of it, and the run must fail with no verdict
line, so a pipeline that fails for another reason is not taken for one that ran the
ASH under test. The job on the image the run builds installs nothing, so it has no
control. One more control checks that the outer `ash` never ran, and
`check_junit.py --controls` checks that every control ran.

The runs start containers that are given the Docker socket, as the CodeBuild agent and
`circleci local execute` do, so the tests refuse to run anywhere but a GitHub-hosted
runner unless `DOCTEST_CI_RUNNERS_ANYWHERE=1` is set. The refusal is an error, not a
skip. Set the variable only on a machine you can throw away, whose Docker daemon
nothing else uses: each launch removes every container the daemon gained while it
ran. A launch also needs Linux's child subreaper and `/proc`, and is refused before it
starts on a host without them. Unless pytest is started with `pytest --run-ci-runners`,
it deselects these tests, so the unit and integration jobs never run them. Listing the
tests starts no runner, and shows which blocks each leg runs:

<!-- doctest: illustrative reason="runs in a checkout of this repository" -->
```bash
uv run pytest tests/integration/docs/test_docs_ci_runners.py --run-integration --run-ci-runners --collect-only -q -n 0
```

### What the runs do not check

- Job permissions and GitHub's services. act gets no token, and the actions that write
  to GitHub (code scanning uploads, pull request comments, and check runs) are replaced
  by stubs that record what they were given.
- What GitLab, GitHub, and CodeBuild do with the reports, such as GitLab's merge request
  widget or a CodeBuild report group. The runs read the files the jobs keep.
- Other Jenkins agents. The Jenkinsfile runs on Jenkinsfile Runner's built-in node,
  which an init hook labels `linux`, on the hosted runner itself.
- Other CodeBuild images and container mode. The agent runs the pinned
  `aws/codebuild/amazonlinux-x86_64-standard:5.0` build image, and is given neither the
  host's AWS credentials nor privileged mode.
- CircleCI's cache and its uploads. The runs check nothing about `restore_cache`,
  `save_cache`, `store_test_results`, or `store_artifacts`.

## Versioned docs

The site is published as versions with [mike](https://github.com/jimporter/mike). Each
version is a directory of the `gh-pages` branch, and `versions.json` at the root of the
branch lists them for the version selector in the site header.

- Every push to `main` publishes the version `main`, titled "main (unreleased)". Its
  pages say that they describe unreleased code, and link to the latest release. Its
  [version-pinned pages](releases.md#version-pinned-pages) are built from their
  templates with `main` for the version, so their install commands install `main`
  (`@main`, `git clone --branch main`, `rev: main`), and the notice says so. Where a
  template needs the release number itself, as in a sample of `ash --version` output,
  it writes `{{RELEASE}}`, which stays the current release number. The static checks
  report `{{RELEASE}}` written as the ref of an install command anywhere but a table
  row or a `text` block, so the `main` version cannot install a release.
- Running the docs workflow by hand on a release tag `vX.Y.Z` publishes the version `X.Y.Z` (see
  [Releases and versions](releases.md#the-documentation-site)). The newest release also
  gets the `latest` alias. `latest/` is a full copy of it rather than a redirect, and
  every version names its `latest/` page as the canonical one for search engines. A
  patch release for an older line is published without moving `latest`.
- A page of a release that is not the latest shows a notice saying so, with a link to
  the latest release.
- Any other tag, such as the floating `v3` or a prerelease, publishes nothing.

The deploy also manages the root of the branch. The root `index.html` redirects to
`latest/`, or to `main/` until a release has been published, and every page path of
that version has a redirect at the root that keeps the `#anchor`. So
`/how-to/install/#install-from-main` still works, and so does an old page path that
`docs/redirects.yml` maps, through the redirect the build writes for it. Everything
else at the root is removed on each deploy, except `.nojekyll`, `CNAME`, and
`versions.json`. To keep another file there, add it to `ROOT_KEEP` in
[`scripts/docs_versions.py`](https://github.com/awslabs/automated-security-helper/blob/main/scripts/docs_versions.py).

That script does all of the publishing. The workflows never run `mkdocs gh-deploy`,
which replaces the whole branch with one unversioned build and so would delete every
version; the site check in the lint job fails if one does. `strict: true` in
`mkdocs.yml` makes every build strict, including the ones mike runs. To preview a page
that still has warnings, use `mkdocs serve --no-strict`.

### Previewing the versions

`mkdocs serve` shows one version. To see the version selector and the notices,
publish to a local branch and serve that. Unless it is told to push, the deploy only
commits to the branch it is given, and a branch other than `gh-pages` keeps the
preview apart from the real site:

<!-- doctest: illustrative reason="runs in a checkout of this repository and starts a server" -->
```bash
uv run python scripts/docs_versions.py deploy --ref refs/tags/v0.0.1 --branch docs-preview
uv run python scripts/docs_versions.py deploy --ref refs/heads/main --branch docs-preview
uv run mike serve --branch docs-preview   # http://localhost:8000/, stop with Ctrl+C
git branch -D docs-preview
```

The ref only names the version: both commands publish the docs in your working tree.

### What the versions check does

The `build-docs` job runs `uv run python scripts/docs_versions.py check`. It
publishes 0.0.1, then 0.0.0, then `main` to a throwaway branch of the checkout, with
every proxy pointing at a port that refuses connections, so a build that needs the
network fails. Before publishing it puts stand-ins for an unversioned site at the root
of the branch: a stylesheet, a sitemap, a page no version has, and an old page from
`docs/redirects.yml`. The check fails unless:

- `mike list` and `versions.json` show the three versions, with `latest` on 0.0.1 only,
  because 0.0.0 is older;
- every page of every version configures the version selector and loads the theme
  script that reads `versions.json`;
- every page of a release carries the outdated notice, every page of `main` carries the
  unreleased one, and no page carries the other;
- `latest/` is a copy of 0.0.1, and the other versions name `latest/` as canonical;
- the version-pinned pages of each release pin that release and no other. On `main`,
  outside tables and `text` blocks, they pin no release, and every install-command form
  that a page uses in 0.0.1 names `main` on that page, from `@main` to
  `refs/heads/main`. The committed pages pin the current version, which is neither 0.0.1
  nor 0.0.0, so this fails unless every build rendered the pages from their templates;
- the root redirects every page of `latest/`, the old page redirects to its place under
  `latest/`, and the stand-ins are gone.

It deletes the branch afterwards and never pushes. It prints how many versions, pages,
and redirects it checked. `tests/unit/test_docs_versions.py` plants each defect the
check exists for (a missing setting in `mkdocs.yml`, a template without the notices,
aliases that are not copies, a root left unversioned, an older release that takes
`latest`, pinned pages left as committed) on a small site, and requires the check to
report it.

## What a failure means

Each static finding is one line: the file and line, the check in brackets, and the
problem. Runner failures name the page, the line of the block, the command, the exit
code, and the end of the output. A refused `save-as` reports `save-as refused` and the
reason instead of an exit code. An output sample that does not match reports the first
sample line the output lacks, as `'<line>' is not in the output of the block at line
<N>`, with the end of the output.

### `markers`

| Message contains | Fix |
|------------------|-----|
| has no language | name the language; use `text` for output |
| cannot run in the docs job | mark the Windows, zsh, or fish block `illustrative` with a reason |
| a blank line separates this marker | delete the blank line under the marker |
| not directly followed by a fenced code block | move the marker to the line above its fence, or delete it |
| unknown mode, is not a key of | use a mode and key from the tables above |
| needs reason=, is a placeholder | say why the block cannot run |
| names no directory | use a fixture from `tests/test_data/docs_fixtures` |
| is not a relative path, leaves the page's project | give `save-as` a path inside the project, without `..` |
| never saves it | drop `illustrative` to save the block without running it, or drop `save-as` |
| may only carry save-as | name a mode for the other keys |
| never closed | close the fence; everything after it was read as code |
| marked output but follows no run block | put the sample directly after the block whose output it shows, or drop the marker |
| expect-exit=any checks nothing about the block | give the exit code the block ends with, or put an output sample directly after it |
| config kind=ash-output needs model= | name the output model the block is part of |
| drops out of the runner census, a groovy block takes config kind=jenkinsfile | mark the `groovy` block `config kind=jenkinsfile`, with `runner=none` and a reason when no runner can run it; fence a `jenkinsfile` block as `groovy` first |
| config kind=jenkinsfile is a groovy block | fence a declarative Jenkinsfile as `groovy`; mark a YAML Jenkins definition `config kind=jenkins` |
| has no runner, has no merge rule, takes no event=, is not an event of | use the key only on a kind that takes it (see [CI pipelines](#ci-pipelines)) |
| names no earlier block on this page saved with, can extend only a block of its own kind, cannot also be saved | point `extends=` at a block above it, of its own kind, saved with `save-as=` at that path |
| runner= takes only none, runner=none needs reason=, reason= goes with runner=none | mark a block no runner can run `runner=none reason="..."`, and give `reason=` only there |

### `cli`

| Message contains | Fix |
|------------------|-----|
| is not an option of | the option does not exist on that command; the message suggests the nearest one |
| has no subcommand | the command does not exist; check the spelling, or an option's value that reads as a command |
| is a flag and takes no value | drop the `=value` |
| needs a value | give the option a value |
| takes no positional arguments | pass the path with an option such as the source-directory option |
| is not an option of any ash command | another program's option: put the program in the code span |
| a plugin's code wrote this row | put the program in the span, or write `ash --config` for ASH's own; the page is generated, so change the text in the plugin's code |
| placeholder | a run block cannot contain `<placeholder>`; use a real value or mark it `illustrative` |
| `no __main__` | that module cannot be run with `python -m` |
| names no action, has no input | a GitHub Actions `uses:` of this repository names a path or input that does not exist |

### `env`

`is read only by the test suite or CI` means the name is real but only contributors
can use it: move it to a contributor page. Otherwise the name is not one ASH reads,
nor a build argument. Check the spelling against the
[environment variable reference](../reference/environment-variables.md), or delete it if the
variable was removed. If ASH builds the name at runtime, the finding says how many
lookups could not be resolved; make the lookup a literal or a module constant.

### `config`

| Message contains | Fix |
|------------------|-----|
| is not a field of ... ASH accepts it and never reads it | the key does nothing; use the field the model declares |
| ships no scanner (or reporter, converter) named | the plugin is not built in; load it with `ash_plugin_modules` in the same block, or mark the block `config kind=other` |
| this is not an ASH config | mark the block with its kind |
| does not parse | fix the syntax; JSON with comments is `jsonc` |
| ASH accepts this one | an `ash-invalid` block validated; make it fail for the reason it states |
| no step of the fragment replaces, more than one job, no longer parses | the fragment does not merge into the pipeline it extends; see the merge rules in [CI pipelines](#ci-pipelines) |
| any other text | the model's own validation error, with the path of the key |

### `python`

`does not parse` gives the line of the syntax error. `no such module` and `has no
name` mean an import does not resolve in the project's environment: the module was
renamed or removed, or the block needs an extra that is not installed. When the module
is one the page saves, `has no name ... the page saves` means the saved block does not
define that name, and `no such module` means no block saves it. `cannot run outside a
package` and `goes above the top-level package` are relative imports with no package
to resolve in: save the block inside one with `save-as=<package>/<module>.py`.

### `options`

| Message contains | Fix |
|------------------|-----|
| documents options or keys but names no section | add `<!-- doctest: options of=<section> -->` above the table |
| is not a key of | the row names an option the section does not have; the message suggests the nearest |
| says ..., but the default is | the code's default changed; state the one in the message |
| says required, but the default is / but the key is required | the key does (or does not) have a default |
| is not a value or a recognized phrase | write the default in one code span, and move any explanation to another column |
| the MCP server has no tool, defines no function or class, no module, is not in the code tree, declares no inputs | the `of=` names nothing in the code; the message says which part |
| has no key, ships no scanner named | a dotted config path in a code span does not exist |
| needs of= / an options marker goes on the line directly above a table | fix the marker |
| that no row names; the marker says the table is complete | add a row for the key, or drop `complete` |
| states defaults, but it is not compared | head the column Default, or Enabled by default for whether each plugin is on |

### `files`

| Message contains | Fix |
|------------------|-----|
| which no reporter ASH registers writes | the file name is misspelled or the reporter's extension changed; the message suggests the nearest name |
| ASH writes no reports/ | name a report or a file a reporter writes beside it; a plugin example's report only on a page that documents the plugin |

### `scanners`

| Message contains | Fix |
|------------------|-----|
| is not a scanner ASH ships | fix the name; the message suggests the nearest one |
| is a community plugin, not a built-in scanner (or the reverse) | move the name to the column for its kind |
| is not one scanner name | list scanner names in the column, with any note in parentheses |

### `code-links`

| Message contains | Fix |
|------------------|-----|
| no page on the site serves this URL | a page the code links to moved; add a redirect, or change the URL in the code |
| has no anchor | the heading the URL points at was renamed; restore the heading or change the URL |
| does not exist in the docs | the docs file the code names moved or was removed; change the code |
| a fetch of the file does not follow it | the code fetches a docs file that moved; change the path in the code |
| that page has no such heading | the code quotes a heading that was renamed |
| is built at runtime | the URL's path is not a constant; write it as a literal so it can be checked |

### `links`, `nav`, `redirects`, and `site`

| Message contains | Fix |
|------------------|-----|
| does not exist | fix the path |
| has no heading or anchor | fix the anchor; heading IDs change when a heading is reworded |
| mkdocs cannot serve | link to the GitHub URL the message gives |
| links to a directory | link to the page in it |
| no page on the site serves this URL | the page moved; update the link or add a redirect |
| no reader can reach it | add the page to a `.nav.yml`, or to `not_in_nav` with a reason |
| doesn't match any files or directories | a nav entry or glob reaches no page that is not already listed elsewhere |
| nav entry ... names no page | a titled nav entry points at a page that does not exist |
| still exists, which is not a page, itself redirected | fix the entry in `docs/redirects.yml` |
| must be 'warn', does not pass --strict, hooks does not list | `mkdocs.yml` or the `build-docs` job lost a strict-build setting; restore it |
| the versioned site needs, the mike plugin is not listed | `mkdocs.yml` lost a setting the [versioned site](#versioned-docs) depends on; restore it |
| replaces the whole gh-pages branch | a workflow runs `mkdocs gh-deploy`; publish with `scripts/docs_versions.py deploy` instead |
| scripts/docs_versions.py deploy (or check) is not run, does not start | the docs workflow lost the step that publishes the versions, or the `build-docs` job lost the step that checks them |
| the workflow that builds the docs does not exist, the docs workflow does not exist | `ash-unified-ci.yml` or `ash-repo-docs.yml` was renamed or removed; the checks read the build from the first and the deploy from the second |

### `templates`

| Message contains | Fix |
|------------------|-----|
| is the ref of an install command | a template writes `{{RELEASE}}` where a command names the ASH it installs; use `v{{VERSION}}` there, or move the release number to a table or a `text` sample (see [Version-pinned pages](releases.md#version-pinned-pages)) |
| nothing was checked | the template manager lists no target with a template |

## Add a generated reference page

A reference page that restates the code (a list of options, variables, scanners, or
tools) is generated, never written by hand. To add one:

1. Write `scripts/generate_<name>.py`. It renders the page from the code (the click
   tree, a pydantic model, or the plugin registry) and writes it under
   `docs/content/reference/`. Run as `generate_<name>.py --check`, it writes nothing,
   compares what it would write with the committed file, prints a diff, and exits
   non-zero if they differ.
   [`scripts/generate_reporter_docs.py`](https://github.com/awslabs/automated-security-helper/blob/main/scripts/generate_reporter_docs.py)
   is a complete example: it writes the whole page, accepts
   `generate_reporter_docs.py --check --docs-root <dir>`, and keeps its hand-written
   columns in a table, `REPORTER_DOCS`, that it requires to cover every registered
   reporter.
2. Start the page with a banner that says `Generated by scripts/generate_<name>.py` and
   gives the command that regenerates it, `uv run python scripts/generate_<name>.py`,
   so a reader who wants to change it knows not to edit it.
3. Add the script and its page to `REFERENCE_PAGES` in
   [`tests/unit/test_generated_docs_freshness.py`](https://github.com/awslabs/automated-security-helper/blob/main/tests/unit/test_generated_docs_freshness.py).
   That one entry runs `generate_<name>.py --check` in the unit suite, so the suite fails
   when the code changes and the page does not, and checks the banner in the page's
   first 600 characters.
4. Add the page to `GOLDEN` in
   [`.github/scripts/check-snapshot-trailers.py`](https://github.com/awslabs/automated-security-helper/blob/main/.github/scripts/check-snapshot-trailers.py),
   so a commit that changes it needs a `Snapshot-Update:` trailer.
5. Add the page to `.nav.yml`. The static checks then cover it like any other page.

The implementation of all of this is in
[`scripts/docs_checks.py`](https://github.com/awslabs/automated-security-helper/blob/main/scripts/docs_checks.py)
and
[`tests/integration/docs/docs_runner.py`](https://github.com/awslabs/automated-security-helper/blob/main/tests/integration/docs/docs_runner.py).
Page paths the checks depend on are constants at the top of `docs_checks.py`.
