## Betterleaks CI parity (container leg, nix entry, sandbox parity)

Follow-ups from the Betterleaks plugin PR: the community-plugin container validation leg that hadolint and GuardDog already have, and a flake.nix entry.

### What changed

- `.github/scripts/community-scanner-legs.py` reads the community modules the image ships (the Dockerfile's `ASH_COMMUNITY_PLUGIN_MODULES`, all copies must agree) and the scanner names each plugin declares in `ASH_SCANNERS` (the name comes from the scanner's own config class). It reads nothing about where a plugin was published or which registry serves it, so the same legs cover any plugin the image lists. Bad metadata (no list, disagreeing copies, a module with no scanner, an unimportable module) exits 2 so a leg cannot pass with nothing to check.
- `validate-container`: the built-image scan loads its community modules from that script instead of two hardcoded flags, the participation list takes its community names from it, and a new "Scan with the image's betterleaks" step requires betterleaks to run and report a token assembled at run time (never written in the file). The fixture is a GitHub token shape: a quoted AWS access key id was measured on the pinned betterleaks 1.10.1 to produce no finding, so it was not used.
- `validate-nix`: the scan loads the betterleaks module and requires it in the flake-supplied list.
- `flake.nix`: `pkgs.betterleaks`. nixpkgs at the locked revision ships 1.8.1, older than the 1.10.1 pin used by the image and `ash dependencies install`; the entry carries a comment recording that and what to compare after a `flake.lock` bump.
- Sandbox parity (`ash-unified-ci.yml`): betterleaks is installed, its module is in the parity config, and it is in `--require`.

### Verification

- Desk (dev-dsk-d14420e2, Python 3.12.15, `-n 8`): 27-file CI-structure family 853 passed / 0 failed at the branch tip; against origin/main (tip 84771d0aa4f) the new test file's seven structural rows fail red and nothing else differs (failing-id delta 0).
- Betterleaks 1.10.1 on the desk flags the github-pat fixture (exit 2) and `ash scan --scanners betterleaks` reports it as FAILED with 1 finding.
- ruff check and format via the locked pre-commit hooks pass; conflict-marker scan reads 0 on every touched file with a planted control reading 1.

### Not done, and why

- The container, nix and sandbox-parity legs themselves run only in GitHub Actions and were not run here; the first CI run is their measurement. In particular the nix leg's use of nixpkgs 1.8.1 is unmeasured against the scanner.
- The repository self-scan config (`.ash/.ash_community_plugins.yaml`) is unchanged: betterleaks over this tree reports 61 findings (generic-api-key, generic-credential-uri, generic-password, generic-username, mostly test fixtures), so adding the module there needs a suppression pass of its own.
