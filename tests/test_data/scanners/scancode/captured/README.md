# ScanCode captured reports

Real `scancode --json` output, captured 2026-11-25 on a Linux x86_64 desktop with
scancode-toolkit 32.5.0 installed by `uv tool install --python 3.12
'scancode-toolkit==32.5.0' --with 'pluggy<1.7'`.

Command (one run per directory, the directory path as the last argument):

```text
scancode --license --json=<file> --quiet -- <dir>
```

Both runs exited 0.

- `positive.json`: the input directory `pos/` held `LICENSE` (the MIT License text plus a
  warranty disclaimer line) and `src/app.py` (a one-line `SPDX-License-Identifier:
  Apache-2.0` comment and `print(1)`). ScanCode reported three MIT and
  warranty-disclaimer matches in `pos/LICENSE` and one Apache-2.0 match in
  `pos/src/app.py`.
- `negative.json`: the input directory `neg/` held `src/app.py` with only `print(1)`. No
  detections.

Edits to the raw output: the lane path was replaced with `<lane>` in the header options,
and the header's timestamps and duration were replaced with `<ts>` and `0`. Nothing else
was changed.

Notes from the capture:

- Paths begin with the name of the directory ScanCode was given (`pos/LICENSE`), which the
  converter strips.
- With `pluggy` 1.7.0 in the install, every `scancode` command exits 1 at import
  (`ValueError: did not find any 'pre_scan' hooks`), so the scanner installs with
  `--with pluggy<1.7`.
