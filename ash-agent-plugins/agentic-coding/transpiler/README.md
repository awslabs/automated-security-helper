# Transpiler

Single-source-of-truth → 14 platform plugin packages. See the [repo root README](../README.md) for the full picture.

## Run

```sh
# From the repo root:
uv run --project transpiler transpiler/transpile.py            # regenerate all outputs
uv run --project transpiler transpiler/transpile.py --check    # exit 1 if outputs differ
```

## Develop

```sh
cd transpiler
uv sync                          # create .venv, install jinja2
uv run python transpile.py
```

## Dependencies

Only `jinja2`. Stdlib otherwise. Python 3.11+.
