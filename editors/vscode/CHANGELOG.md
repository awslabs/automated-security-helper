# Changelog

## 3.7.0

First release. Runs the `ash` CLI over the open workspace folder and reports its
SARIF findings in the Problems panel.

- `ASH: Scan workspace` and `ASH: Clear findings` commands.
- `ash.executablePath`, `ash.outputDirectory` and `ash.extraArguments` settings.
- A startup check that the configured executable really is ASH, for hosts where a
  bare `ash` resolves to MSYS2's Almquist shell.

The version tracks ASH's own, because the extension is released alongside it and a
user reporting a problem needs one number to name.
