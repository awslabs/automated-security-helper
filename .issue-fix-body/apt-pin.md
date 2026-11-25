# Container build: retired ca-certificates pin (#824)

Already fixed on `main`; no code change in this PR. This section records the
verification so the issue can close with a traceable record.

The failing pin the issue reports (`ca-certificates=20250419~deb12u1`, retired
by a Debian bookworm point release) is gone from `main`. Both install stages of
the `Dockerfile` now pin `ca-certificates=20*deb12u*`, an apt version glob that
follows bookworm point releases instead of retiring at each one. The history,
in order:

1. The exact pin was first moved by hand off the retired `deb12u1` to the
   then-current `deb12u2` — the direct cure for the build failure in the issue.
2. #1052 replaced the exact pin with the version glob in both stages, so the
   next point release cannot break `apt-get install` the same way, and taught
   the weekly pin checker (`scripts/check_pinned_tool_versions.py`,
   `_judge_apt_pin`) to judge a glob: `current`, `outdated` when a newer
   version falls outside it, `unavailable` when nothing matches.
3. #1070 unquoted the glob so the CI download guard parses the install line.

The comment above the first install documents the policy. The other apt pins
the issue's `apt-cache policy` table lists (`python3-venv`, `git`, `curl`,
`tree`) stay exact by design; when one of them retires, the weekly pin checker
now reports it instead of the break surfacing as a failed container build.

Closes #824.
