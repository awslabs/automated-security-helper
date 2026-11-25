# Captured CredSweeper 1.19.7 output

`positive.json` and `negative.json` are the reports a real CredSweeper run wrote
(PyPI release 1.19.7, resolved from ASH's `>=1.19.6,<2.0.0` constraint, CPython 3.12.15,
linux/x86_64, run through `uv tool run`). The unit tests serve them from a fake
subprocess, so they run on every platform without the tool.

Argv, from the root of each input (the working directory ASH uses):

```text
credsweeper --path=. --save-json=<file> --no-stdout --no-color --no-progress \
  --hashed --no-error
```

The positive input was a directory of three files: `app.py` (two lines that look like an
AWS secret key assignment and a password assignment, plus a harmless third line),
`cfg.yml` (one `api_key:` line) and `clean.py` (one `print`). The tool reported one
credential, the password at `app.py` line 2; the AWS-shaped line and the `api_key` line
were not reported, so one capture holds one finding. With `--hashed` the report's `line`,
`variable` and `value` fields are SHA-256 digests of the fabricated text, not the text. The
tool wrote the keys in the order rule, severity, confidence, ml_probability and
`line_data_list`; the repository's pretty-format-json hook rewrote both files with sorted keys and
2-space indents, and changed no value.

The negative input was a directory with only `clean.py`; the tool exits 0 and writes an empty
array (the four bytes `[\n\n]`, which the hook rewrote to `[]`). A run over an empty directory exits 0 and writes no file at all,
which ASH treats as a failed scan (see the scanner's module header). Exit status was 0 for
all three runs, as `--no-error` makes it.

Facts the captures show and the scanner relies on:

- `path` is `./app.py`, relative to the working directory with a leading `./`; the
  converter strips it.
- `severity` is the rule's own rating (`high` for Password) and `confidence`
  (`moderate`) is the model's; ASH rates by `confidence`.
- `line_data_list[].value_start` / `value_end` are character offsets in the line, kept even
  when hashed; ASH does not write them into the SARIF region.
