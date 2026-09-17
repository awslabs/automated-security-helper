# Changelog

The headings here are not version numbers, and that is deliberate. `cz bump`
rewrites `package.json`'s `version` so the extension tracks ASH's release, but it
does not and should not rewrite this file: a changelog gains a section per release
rather than having its newest section renamed. A version-numbered heading would sit
one release behind `package.json` from the first bump onward and read as drift.

## Initial release

Runs the `ash` CLI over the open workspace folder and reports its SARIF findings in
the Problems panel.

- `ASH: Scan workspace` and `ASH: Clear findings` commands.
- `ash.executablePath`, `ash.outputDirectory` and `ash.extraArguments` settings.
- A check that the configured executable really is ASH before every scan, for hosts
  where a bare `ash` resolves to MSYS2's Almquist shell instead.
- No runtime dependencies, and a check over the built `.vsix` that fails if it ever
  carries anything but this extension's own output.
