# skillcheck (community plugin)

Scans the target's AI agent skills (`SKILL.md` files and `.skill` packages) with
Mondoo's [skillcheck](https://github.com/mondoohq/skillcheck).

## Enabling it

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_skillcheck_plugins
```

## Installing skillcheck

ASH does not install it. Download the release archive for your platform from the
[releases page](https://github.com/mondoohq/skillcheck/releases) (the plugin was
measured against `v0.4.0`), check it against the release's `checksums.txt`, and put
`skillcheck` on `PATH`.

## What it reports

* A skill the Mondoo AI Agent Security database reports as a risk, at the database's
  severity.
* A skill that fails an Agent Skills specification check, rated MEDIUM or lower
  because it is lint.

## Network

The tool looks up the SHA-256 of each skill in the Mondoo database over the network
(hashes only, never content). It fails open, so a run without the lookup reads as
clean; an `offline` scan therefore skips the scanner. The tool runs with an empty
home directory so it never reads the machine's agent directories.
