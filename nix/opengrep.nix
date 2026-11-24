# opengrep, the one scanner ASH needs that nixpkgs does not carry.
#
# There is no pkgs/by-name/op/opengrep and no `pname = "opengrep"` anywhere in the tree;
# its only appearance is advisory prose in another package's removal message.
#
# WHY WRAP THE RELEASE BINARY INSTEAD OF BUILDING THE OCAML SOURCE
#
# Parity, not effort. ASH already downloads exactly this asset at runtime
# (OpengrepScanner.setup_custom_install_commands -> utils/tool_downloads.py), so pinning
# the same artifact makes Nix mode's opengrep byte-identical to what container and local
# mode execute. A from-source build would be a different binary, and the cross-mode
# finding-set comparison that exists to catch flake problems could then diverge for
# reasons unrelated to the flake.
#
# WHAT THE PUBLISHED ASSET IS, FROM v2.0.0 ON
#
# The scanner itself: one native OCaml executable. v2.0.0 removed Python from opengrep
# ("Remove python", upstream #827), so the asset is no longer the self-extracting
# launcher that earlier releases shipped (a ~150 MB tree unpacked into
# $HOME/.cache/opengrep/v<version>/ on first run, with a CPython runtime and an
# `opengrep.bin` entry point). Measured on the v2.0.0 Linux assets, by reading the files
# and never running them: both are statically linked ELF executables with no
# PT_INTERP and no DT_NEEDED entries (`readelf -l` and `readelf -d`), so on Linux there
# is nothing for autoPatchelfHook to patch and no extraction step. The macOS assets are
# Mach-O executables whose only dynamic dependency is libSystem. The old derivation's
# build-time extraction, interpreter patching and `opengrep.bin` layout assertion all
# existed for the launcher and would fail the build on this asset.
#
# Release asset names changed with that rebuild: `opengrep_manylinux_*` became
# `opengrep_linux_*`. Windows now ships as a zip and is not built here.
{ lib
, stdenv
, fetchurl
, systems
}:

let
  version = "2.0.0";

  # Tracks OpengrepScannerConfigOptions.version, NOT the v1.1.5 default in
  # get_opengrep_url's signature -- that fallback is unreachable whenever the config
  # supplies a version, and pinning it would ship a scanner far behind the pin while
  # looking deliberate.
  assets = {
    x86_64-linux = {
      name = "opengrep_linux_x86";
      hash = "sha256-N+k/TaX9BKGMXB/rvdEvfpjfzNTQyc8lk7yyXutGLaA=";
    };
    aarch64-linux = {
      name = "opengrep_linux_aarch64";
      hash = "sha256-Yle2VCOnRLcEry/5vuuPIiwvaSUjavOGtWsDHUwG1tg=";
    };
    x86_64-darwin = {
      name = "opengrep_osx_x86";
      hash = "sha256-UdL5GNeq0K/BQmu0+/VuMvxww//V3beOMufWHlHAKaI=";
    };
    aarch64-darwin = {
      name = "opengrep_osx_arm64";
      hash = "sha256-tRs9g/FlouCTRJe48bCKuxwwQe8g75Ecl+BMs5rxrVU=";
    };
  };

  inherit (stdenv.hostPlatform) system;
  asset = assets.${system} or (throw "opengrep: no pinned asset for ${system}");
in
stdenv.mkDerivation {
  pname = "opengrep";
  inherit version;

  src = fetchurl {
    url = "https://github.com/opengrep/opengrep/releases/download/v${version}/${asset.name}";
    inherit (asset) hash;
  };

  # The asset is a bare executable, not an archive.
  dontUnpack = true;

  # These are someone else's release artifacts. Stripping buys nothing and risks a binary
  # that no longer starts.
  dontStrip = true;

  installPhase = ''
    runHook preInstall

    # Store paths are mode 444; install sets the executable bits on the copy.
    install -Dm755 "$src" "$out/bin/opengrep"

    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck

    # A fresh HOME, so nothing the binary reads or writes under it comes from the build.
    export HOME="$TMPDIR/check-home"
    mkdir -p "$HOME"

    "$out/bin/opengrep" --version

    # --version only starts the binary. A real scan is what loads the rule parser and
    # the matching engine, so without this the check would pass on a package whose
    # analysis half is broken.
    # The rule and target below are scanner FIXTURES, not executed code: the target is a
    # one-line file containing a known-bad `eval` call purely so the rule has something to
    # match. Nothing here interprets it -- opengrep parses it statically. A fixture that
    # triggers no rule would make this check vacuous.
    mkdir -p probe
    cat > probe/rule.yaml <<'RULE'
    rules:
      - id: probe-eval
        pattern: eval(...)
        message: probe matched eval
        languages: [python]
        severity: WARNING
    RULE
    echo 'eval("1")' > probe/target.py

    # The exit status is deliberately ignored. opengrep, like most scanners, exits
    # non-zero when it FINDS something -- and this fixture is built to be found, so a
    # successful check reports failure. Asserting on the JSON instead means the gate is
    # "the engine produced the expected finding" rather than "the process was happy",
    # which is the property actually worth checking.
    "$out/bin/opengrep" scan --quiet --config probe/rule.yaml --json-output=probe/out.json probe/target.py || true
    grep -q 'probe-eval' probe/out.json \
      || { echo "opengrep: engine ran but produced no finding for a known match" >&2; exit 1; }

    runHook postInstallCheck
  '';

  meta = {
    description = "Static analysis engine used by ASH for SAST scanning";
    homepage = "https://github.com/opengrep/opengrep";
    license = lib.licenses.lgpl21Only;
    mainProgram = "opengrep";
    platforms = systems;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
