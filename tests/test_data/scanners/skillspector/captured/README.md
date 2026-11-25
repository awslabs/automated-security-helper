# SkillSpector captured fixtures

Inputs are the two skills under `../fixture_repo/`:

- `benign/SKILL.md`: a plain note-formatting skill.
- `seeded/SKILL.md`: the same skill plus one documented detection marker (an
  HTML comment carrying the instruction-override phrase behind an
  `ASH-TEST-MARKER` label) and one fetch-and-run line aimed at a host under
  `.invalid`. Nothing in it is attack content. The unit tests build both strings
  themselves and assert the committed files equal them.

Captures, from `skillspector==2.13.7` installed with `uv pip install` into a
scratch venv (CPython 3.14), run with `env -i` and an empty HOME, over copies of
the two skills at `/tmp/skillspector-capture/<name>`:

```text
skillspector scan /tmp/skillspector-capture/seeded --no-llm --format sarif --output seeded.sarif
skillspector scan /tmp/skillspector-capture/benign --no-llm --format sarif --output benign.sarif
```

- `skillspector-2.13.7-seeded.sarif`: exit status 1 (the risk score is above
  SkillSpector's threshold). Five results: `P1` and `P2` on the marker line, two
  `YR4` YARA matches (lines 3 and 10) and `SC2` on the fetch line, all
  `severity: HIGH`, SARIF `error`. Unedited. `properties.findingId` is random
  per run, so a re-capture is not byte-equal; the tests assert shape, rules and
  lines for this capture only.
- `skillspector-2.13.7-benign.sarif`: exit status 0, no results, the negative
  control. Unedited.
- `positive.sarif`: `convert_skillspector_sarif` over the seeded capture with
  `skill_rel=""`. The facets corpus gate reads it.

Facts the scanner relies on, each read from these runs or from the 2.13.7
package:

- The same scan inside an empty network namespace (`unshare -rn`) produced the
  same findings, so `--no-llm` needs no network.
- A report written inside the scanned skill directory is scanned by the next run
  (`.ash/ash_output/...` results appeared in a second run), which is why the
  scanner passes `--exclude=<output dir>/**` when ASH's output directory is inside
  the skill. That run reads `isComplete: false` with one notification naming the
  excluded file.
- Exit status: 0 and 1 are scan results, 2 is every error (`skillspector/cli.py`).
