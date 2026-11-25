# agent-scan captured fixtures

Captured from `snyk-agent-scan==0.7.1` (PyPI, installed into a throwaway virtual
environment; Python 3.14) on 2026-11-25. The tool's `scan` sends skill files to a remote
analysis service and needs a Snyk token, so the captures were made against a local stub
of that service and nothing was sent to Snyk. What that means for each file:

- The JSON envelope is the pinned tool's real output: its field names, nesting, key
  order, `exclude_none` behavior and path handling are what 0.7.1 prints.
- The risk entries inside it (names, scores, evidence text, locations) are the stub's
  answers (`stub_analysis_server.py`), not an analysis result. The evidence texts say so.

## Files

- `stub_analysis_server.py`: the local stand-in service. It binds 127.0.0.1, flags a skill
  file that holds the documented marker `ASH-FIXTURE-MARKER-agent-scan-mild` with one risk
  in each of the tool's four score bands, and answers every other skill with no risk.
- `scan-skill-marked-0.7.1.json`: stdout of the scan of a skill holding the marker.
- `scan-skill-clean-0.7.1.json`: stdout of the scan of a skill without it (the negative
  control).
  Both JSON files went through the repository's `pretty-format-json` hook, which sorts the
  keys of each object and changes nothing else; the tool prints them in its model order
  (`name`, `files`, `risk_indexes`; the `client` and `path` lines first), and a `diff`
  against the raw stdout shows only that reordering.
- `positive.sarif`: `convert_agent_scan_document` over the marked capture with
  `skill_label="skills/marked-skill"`. The facets corpus gate reads it.

## How they were made

Each skill was staged as the scanner stages one: a directory holding only its files.

```text
staging/0000/SKILL.md   the marked skill (below)
staging/0001/SKILL.md   the benign skill (below)
```

The marked skill:

```markdown
---
name: marked-skill
description: Summarizes meeting notes into action items.
---

# Marked skill

Summarize the notes the user pastes into short action items.

<!-- ASH-FIXTURE-MARKER-agent-scan-mild: a documented detection marker used by ASH tests, not an instruction. -->
```

The benign skill has `name: benign-skill`, the description `Formats a short greeting for
the user.` and one sentence of body text.

The stub ran as `python3 -I stub_analysis_server.py <port>`, and the tool as (the
`--analysis-url` and the token exist only for the capture; ASH never passes either):

```bash
env -i HOME=<empty dir> PATH=/usr/bin:/bin SNYK_TOKEN=<any value> \
  snyk-agent-scan scan --json --skills --storage-file=<dir>/storage.json \
  --analysis-url 'http://127.0.0.1:<port>/hidden/mcp-scan/analysis-machine?version=2026-07-10' \
  -- <staged skill directory>
```

Both runs exited 0 with the document on stdout and nothing on stderr.

## Facts about the tool read from these runs

- With a skill directory as the path the tool reports `client` as that directory and
  `path` as its parent, `server_risks` as an empty list, and one entry in `skill_risks`
  named by the `name` in the skill's frontmatter. Locations are relative to the skill
  directory.
- `--json` is the only machine-readable output; there is no SARIF.
- A risk the service did not report is absent from `risk_indexes` (`exclude_none`), so a
  skill with no risk has `"risk_indexes": {}`.
- Observed failure exits, not committed as files because they print no document: without
  `SNYK_TOKEN` the tool prints a message to stdout in rich mode and exits 1 with nothing
  on stdout under `--json`; with the analysis service unreachable it exits 1 with a
  traceback on stderr and nothing on stdout. A tool-reported failure inside a document
  (`error.category` and an `X00n` code, `models/errors.py`) is covered by the unit tests
  over documents shaped from the pinned models.
- `snyk-agent-scan --version` exits 2 (the argument parser rejects it), which is why the
  scanner does not rely on ASH's generic `<tool> --version` probes.

The captures do not change when a different service answers: re-running them against
Snyk's service would give another risk set, and the tests assert shape and counts for
these two documents only.
