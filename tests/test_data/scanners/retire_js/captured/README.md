# retire.js captured output

Real output of retire 6.1.1 (`npm install retire@6.1.1`, Node v22.23.3), captured
2026-11-25 on a Linux desk. The scanner ran with the argv ASH builds
(`--outputformat=json --outputpath=<file> --exitwith=13 --nocache
--ignorefile=<file containing []> --path=.`) from the scanned directory.

| File | What was scanned | Exit | Notes |
|---|---|---|---|
| `positive.json` | a tree holding `static/jquery-1.6.1.min.js` (a one-line jQuery 1.6.1 banner and stub) and `app/package.json` naming `lodash` 4.17.4 | 13 | Seven jQuery vulnerabilities found by file name. lodash 4.17.4 in `package.json` is not reported. |
| `negative.json` | a tree holding only `app/package.json` naming `lodash` 4.17.4 (`--path=app`) | 0 | Empty `data`: retire.js 6.1.1 does not read `package.json`, so a vulnerable dependency named there is no finding. |
| `retire_js-6.1.1.sarif` | `positive.json` converted by `convert_retire_report` | n/a | Written by the adapter, not by the tool. A test regenerates it and fails when the converter and the file disagree. |

Edits to the captured JSON: the absolute lane path in `data[].file` was replaced by
`/scan/src/` so the file holds no host path, and the repository's JSON formatter
re-indented the files. Nothing else was changed.

To recapture: install retire 6.1.1 in a scratch directory, build the two trees above,
run the argv shown, and replace the path prefix the same way. A different retire
version needs its own pin in `RETIRE_VERSION` and a re-read of the field names.
