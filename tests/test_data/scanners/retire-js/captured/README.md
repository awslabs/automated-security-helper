# retire.js captured output

Real output of retire 6.1.1 (`npm install retire@6.1.1`, Node v22.23.3) on a Linux host.

| File | What was scanned | Exit | Notes |
|---|---|---|---|
| `positive.json` | a tree holding `static/jquery-1.6.1.min.js` (a one-line jQuery 1.6.1 banner and stub) and `app/package.json` naming `lodash` 4.17.4 | 13 | Captured 2026-11-25. Seven jQuery vulnerabilities found by file name. lodash 4.17.4 in `package.json` is not reported. |
| `negative.json` | a tree holding only `app/package.json` naming `lodash` 4.17.4 (`--path=app`) | 0 | Captured 2026-11-25. Empty `data`: retire.js 6.1.1 does not read `package.json`, so a vulnerable dependency named there is no finding. |
| `ignores.json` | a tree holding `static/jquery-1.6.1.min.js`, a copy under `.ash/ash_output/scanners/`, a copy under `.ash/ash_output_other/`, and a planted `.retireignore` (`static`) and `.retireignore.json` (`[{"component": "jquery", ...}]`) | 13 | Captured 2026-11-26 with the argv the scanner builds, from a working directory outside the tree: `--outputformat=json --outputpath=<file> --exitwith=13 --nocache --ignorefile=<file> --path=<tree>`, the ignore file holding `[{"path": "<tree>/.ash/ash_output/", "justification": "..."}]`. The `.ash/ash_output` copy is not reported, the `.ash/ash_output_other` copy is, and the planted files are not read. |
| `positive.sarif` | `positive.json` converted by `convert_retire_report` | n/a | Written by the adapter, not by the tool. A test regenerates it and fails when the converter and the file disagree. |

`positive.json` and `negative.json` were captured with `--path=.` from the scanned directory and `--ignorefile` naming a file that holds `[]`; the report's `file` entries are absolute either way.

The same day as `ignores.json`, two control runs without `--ignorefile` and with `--path=.` showed the planted files do hide findings when retire.js reads them: the `.retireignore` naming `static` left only the output-directory copy in the report, and the `.retireignore.json` naming jquery emptied it (exit 0).

Edits to the captured JSON: the absolute path of the scratch directory in `data[].file` was replaced by `/scan/src/` so the file holds no host path, and the repository's JSON formatter re-indented the files. Nothing else was changed.

To recapture: install retire 6.1.1 in a scratch directory, build the trees above, run the argv shown, and replace the path prefix the same way. A different retire version needs its own pin in `RETIRE_VERSION` and a re-read of the field names.
