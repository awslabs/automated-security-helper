{
  description =
    "Pinned scanner toolchain for the Automated Security Helper (Linux and macOS)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  # Deliberately no flake-utils input. `nixpkgs.lib.genAttrs` covers the whole of what
  # eachDefaultSystem would give us here, and every extra flake input is another thing to
  # pin, audit and explain in a repository whose subject is supply-chain scanning.

  outputs = { self, nixpkgs }:
    let
      # Windows is absent on purpose and is not an oversight. Native Windows Nix has no
      # fixed-output derivations -- the mechanism by which any of these tools would be
      # fetched -- and no build sandbox, so it cannot supply a toolchain at all. Windows
      # users go through WSL2, which is served by the Linux systems below.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      pkgsFor = system: import nixpkgs {
        inherit system;

        # checkov depends on `ecdsa`, which nixpkgs marks insecure for CVE-2024-23342: a
        # Minerva-style timing side channel on P-256. Without this, checkov does not merely
        # warn, it refuses to EVALUATE, and the scanner goes MISSING with a message that
        # reads like a fresh advisory.
        #
        # Permitting it is deliberate, and on a security tool the exposure deserves stating
        # rather than waving through. Three facts decide it:
        #
        #   1. There is no fixed version to move to, now or later. The advisory lists
        #      affected versions as ">= 0" with no patched release, and upstream's position
        #      is that side-channel attacks are out of scope with no planned fix. Waiting
        #      for a bump is not a strategy; there will never be one.
        #   2. The CVE affects signing, key generation and ECDH. Signature VERIFICATION is
        #      explicitly unaffected. checkov is a static IaC analyzer -- a scan reads and
        #      evaluates templates.
        #   3. The attack needs an attacker able to time repeated signing operations
        #      against a long-lived key. A one-shot static scan offers neither.
        #
        # Keyed on the package NAME via allowInsecurePredicate rather than on an exact
        # "python3.14-ecdsa-0.19.2" string in permittedInsecurePackages. That string embeds
        # both the python minor version and the ecdsa version, so any nixpkgs bump to
        # either stops it matching and checkov breaks again. The predicate keeps the same
        # narrow scope -- only ecdsa, nothing else -- while surviving those bumps.
        config.allowInsecurePredicate = pkg: nixpkgs.lib.getName pkg == "ecdsa";
      };

      opengrepFor = system:
        (pkgsFor system).callPackage ./nix/opengrep.nix { inherit systems; };

      # The scanners ASH invokes as external executables.
      #
      # cdk-nag is deliberately absent: its scanner sets self.command = "python" and runs
      # from ASH's own environment, so there is no binary for Nix to supply. Listing it
      # would imply a dependency that does not exist.
      #
      # npm-audit is likewise not a package -- it is a subcommand of npm, which is why
      # nodejs appears instead.
      scannersFor = system:
        let pkgs = pkgsFor system;
        in [
          pkgs.bandit
          pkgs.cfn-nag
          pkgs.checkov
          pkgs.detect-secrets
          pkgs.grype
          pkgs.nodejs # provides `npm audit`
          pkgs.semgrep
          pkgs.syft
          pkgs.trivy # community-mode scanner set
          (opengrepFor system)
        ];
    in
    {
      packages = forAllSystems (system:
        let pkgs = pkgsFor system;
        in {
          opengrep = opengrepFor system;

          # Every scanner in one store path, so CI can realize the whole toolchain with a
          # single build and cache it as one unit.
          ash-scanners = pkgs.buildEnv {
            name = "ash-scanners-${system}";
            paths = scannersFor system;
          };

          default = self.packages.${system}.ash-scanners;
        });

      devShells = forAllSystems (system:
        let pkgs = pkgsFor system;
        in {
          default = pkgs.mkShell {
            name = "ash-scanners";
            # curl is not a scanner; the shellHook below uses it to seed the semgrep and
            # opengrep rule caches. It is listed explicitly rather than assumed present,
            # because a shell that silently depends on a host binary is the same class of
            # problem this mode exists to fix.
            packages = scannersFor system ++ [ pkgs.curl ];

            # ASH itself is intentionally NOT in this shell. The shell's job is to supply
            # the external scanner binaries; ASH comes from the ambient environment (uv,
            # pipx or a venv), exactly as it comes from the image in container mode. Since
            # `nix develop` prepends its packages to the inherited PATH rather than
            # replacing it, an `ash` on the caller's PATH stays reachable inside.
            shellHook = ''
              # Tells ASH's scanners not to install tools this shell already provides.
              # Thirteen scanners prefer `uv tool install` when uv is present, and
              # utils/uv_tool_runner.py skips installation in offline mode, so this is the
              # switch that makes them use the pinned binaries instead of fetching their
              # own and shadowing them. Accepted values are YES, TRUE or 1
              # (core/constants.py:is_offline_mode).
              export ASH_OFFLINE=YES

              # MUST be unset, and this is not a tidiness measure.
              #
              # Four of the scanners here (bandit, checkov, detect-secrets, semgrep) are
              # Python packages, so nixpkgs' Python setup hook appends their entire
              # dependency closure's site-packages to PYTHONPATH -- roughly 170 store
              # paths, including its own pydantic and pydantic-core built against
              # python3.14. ASH runs from its own environment on a different interpreter,
              # and inherits that PYTHONPATH, so those take precedence over the ones ASH
              # installed. The extension modules are ABI-incompatible across interpreter
              # versions, and the inner scan dies before it can start with:
              #
              #   ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'
              #
              # Unsetting it is safe because nixpkgs wraps Python applications with their
              # import paths baked into the executable rather than read from the
              # environment. Measured after unsetting: all four scanners still report
              # their versions, and ASH imports cleanly.
              unset PYTHONPATH

              # Three scanners need DATA that no flake can pin, and ASH_OFFLINE above stops
              # them fetching it themselves. The flag is still right -- it is what keeps
              # scanners from installing tools that shadow the pinned ones -- but it makes
              # seeding these caches this shell's job.
              #
              # Leaving them unseeded does not produce a clean failure. grype starts, finds
              # no database and reports ERROR. semgrep and opengrep refuse to construct at
              # all ("running in offline mode but no rule cache was found"), so they vanish
              # from the report entirely rather than appearing as MISSING -- which is worse,
              # because a reader counting scanner rows sees eight and has no row to ask
              # about. That was measured, not predicted: seeding only grype left both
              # absent.
              #
              # This mirrors what the container image does at build time (see the OFFLINE
              # block in the Dockerfile): update the grype database, then fetch each
              # configured semgrep ruleset and share it with opengrep, which reads the same
              # rule format. A shell has no build step, so it seeds on first entry instead.
              # None of this can live in the flake: the vulnerability database changes daily
              # and the rulesets are fetched from a service, so pinning either would mean
              # shipping stale security data, which is worse than fetching it.
              export GRYPE_DB_CACHE_DIR="''${GRYPE_DB_CACHE_DIR:-$HOME/.cache/ash/grype-db}"
              export SEMGREP_RULES_CACHE_DIR="''${SEMGREP_RULES_CACHE_DIR:-$HOME/.cache/ash/semgrep-rules}"
              export OPENGREP_RULES_CACHE_DIR="''${OPENGREP_RULES_CACHE_DIR:-$HOME/.cache/ash/opengrep-rules}"
              mkdir -p "$GRYPE_DB_CACHE_DIR" "$SEMGREP_RULES_CACHE_DIR" "$OPENGREP_RULES_CACHE_DIR"

              # Announced rather than silent: these are network fetches inside what is
              # otherwise a hermetic shell, and a reader deserves to know they happened.
              if [ -z "$(ls -A "$GRYPE_DB_CACHE_DIR" 2>/dev/null)" ]; then
                echo "ash: seeding grype vulnerability database (one time, needs network)" >&2
                grype db update >/dev/null 2>&1 \
                  || echo "ash: grype database download FAILED; grype will report ERROR" >&2
              fi

              if [ -z "$(ls -A "$SEMGREP_RULES_CACHE_DIR" 2>/dev/null)" ]; then
                echo "ash: seeding semgrep and opengrep rulesets (one time, needs network)" >&2
                # Defaults to p/ci, matching ScanOptions.offline_semgrep_rulesets, so the
                # shell and a default scan agree on which rules are present.
                for ruleset in ''${ASH_OFFLINE_SEMGREP_RULESETS:-p/ci}; do
                  outfile="$SEMGREP_RULES_CACHE_DIR/$(basename "$ruleset").yml"
                  if curl -sSf "https://semgrep.dev/c/$ruleset" -o "$outfile"; then
                    # opengrep is a semgrep fork and reads the same rule format, which is
                    # why the container copies rather than fetching twice.
                    cp "$outfile" "$OPENGREP_RULES_CACHE_DIR/$(basename "$ruleset").yml"
                  else
                    echo "ash: ruleset $ruleset download FAILED; semgrep and opengrep will not run" >&2
                  fi
                done
              fi
            '';
          };
        });
    };
}
