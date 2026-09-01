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
            packages = scannersFor system;

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
            '';
          };
        });
    };
}
