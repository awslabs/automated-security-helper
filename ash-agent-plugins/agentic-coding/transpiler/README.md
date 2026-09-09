# Transpiler

Single source of truth (`_base/`) → one plugin package per registered backend.
See the [directory README](../../README.md) for the platform table and the
architecture.

## Run

```sh
# From the ash-agent-plugins/ directory:
uv run --project agentic-coding/transpiler agentic-plugins build   # regenerate all outputs
uv run --project agentic-coding/transpiler agentic-plugins check   # exit 1 on drift or validation failure
```

`build` and `check` report how many backends they covered rather than assuming a
number; `agentic-plugins formats` lists them with the format each one emits.
`agentic-plugins --help` covers the rest (`setup`, `release`, `smoke-test`,
`cli-tools`, `matrix`).

## Develop

```sh
uv sync --project agentic-coding/transpiler --extra test
uv run --project agentic-coding/transpiler --extra test pytest agentic-coding/transpiler/tests/
```

Add a platform by writing a backend module under
`agentic-coding/transpiler/transpiler/backends/<name>/`; `@register_backend`
picks it up on import.

## Dependencies

`jinja2`, `pydantic`, `pyyaml`, `jsonschema`, `python-frontmatter`, `click`.
Stdlib otherwise. Python 3.11+. The `refresh` extra adds
`datamodel-code-generator`, needed only by `refresh-schemas` and
`generate-models`; the `test` extra adds `pytest`.
