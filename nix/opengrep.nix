# opengrep, the one scanner ASH needs that nixpkgs does not carry.
#
# There is no pkgs/by-name/op/opengrep and no `pname = "opengrep"` anywhere in the tree;
# its only appearance is advisory prose in another package's removal message.
#
# WHY WRAP THE RELEASE BINARY INSTEAD OF BUILDING THE OCAML SOURCE
#
# Parity, not effort. ASH already downloads exactly this asset at runtime
# (OpengrepScanner.setup_custom_install_commands -> get_opengrep_url in
# utils/download_utils.py), so pinning the same artifact makes Nix mode's opengrep
# byte-identical to what container and local mode execute. A from-source build would be a
# different binary, and the cross-mode finding-set comparison that exists to catch flake
# problems could then diverge for reasons unrelated to the flake.
#
# WHAT THE PUBLISHED ASSET ACTUALLY IS
#
# Not the scanner. It is a self-extracting launcher that unpacks a ~150 MB tree into
# $HOME/.cache/opengrep/v<version>/ on first run: `opengrep.bin` (the entry point),
# `semgrep/bin/opengrep-core` (the OCaml analysis engine), ~60 CPython extension modules,
# and the rule schemas. Shipping the launcher as-is fails twice over: it needs a writable
# HOME on every run, and the payload it extracts is never patched, so on a system without
# /lib64/ld-linux-x86-64.so.2 it dies with "couldn't launch child (exec): No such file or
# directory" -- reported as a scanner failure, not a packaging one.
#
# So the extraction is done once here, at build time, and every ELF in the resulting tree
# is patched. Three properties were measured before relying on them:
#   - `opengrep.bin` runs standalone from the extracted tree, with no launcher.
#   - it runs with that tree READ-ONLY, which is what a store path is.
#   - it runs with a HOME different from the one it was extracted under, so nothing is
#     baked into absolute paths under the build's HOME.
# Without all three this would have needed an FHS environment and a writable cache.
{ lib
, stdenv
, fetchurl
, autoPatchelfHook
, patchelf
, zlib
, gmp
, pcre
, pcre2
, systems
}:

let
  version = "1.15.1";

  # Tracks OpengrepScannerConfigOptions.version, NOT the v1.1.5 default in
  # get_opengrep_url's signature -- that fallback is unreachable whenever the config
  # supplies a version, and pinning it would ship a scanner fourteen minor versions stale
  # while looking deliberate.
  assets = {
    x86_64-linux = {
      name = "opengrep_manylinux_x86";
      hash = "sha256-xPaqse3IEwx6Ruj15SFXY0IHQPuUGY/JMBIVE1o3KQA=";
    };
    aarch64-linux = {
      name = "opengrep_manylinux_aarch64";
      hash = "sha256-CJMtsy9Mv9bjr2vagq2sQXVCddGKkcD+BlGB5qUpG+c=";
    };
    x86_64-darwin = {
      name = "opengrep_osx_x86";
      hash = "sha256-r7LVCKUB46frc9kZrxAvZ2Q1OVVjHuWFbvshT+5eNDI=";
    };
    aarch64-darwin = {
      name = "opengrep_osx_arm64";
      hash = "sha256-qDMyPYfP6H8pJJjQzNwDet+geQXxHy6y3Kf7zIuAPMU=";
    };
  };

  inherit (stdenv.hostPlatform) system;
  asset = assets.${system} or (throw "opengrep: no pinned asset for ${system}");
  isLinux = stdenv.hostPlatform.isLinux;
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

  nativeBuildInputs = lib.optionals isLinux [ autoPatchelfHook patchelf ];

  buildInputs = lib.optionals isLinux [
    stdenv.cc.cc.lib # libstdc++ / libgcc_s
    zlib
    gmp # OCaml zarith, used by opengrep-core
    pcre
    pcre2
  ];

  # These are someone else's release artifacts. Stripping buys nothing and risks a binary
  # that no longer starts.
  dontStrip = true;

  buildPhase = ''
    runHook preBuild

    # Store paths are mode 444, so the launcher has to be copied out before it can run.
    # Executing it straight from the store fails with "Permission denied", which reads
    # like a sandbox or ownership fault rather than a missing +x bit.
    cp "$src" launcher
    # 755, not +x: cp preserves the store's 444, and patchelf below needs WRITE access to
    # rewrite the interpreter. `chmod +x` alone leaves it unwritable and patchelf fails
    # with "open: Permission denied", which looks like a sandbox restriction.
    chmod 755 launcher

    ${lib.optionalString isLinux ''
      # autoPatchelfHook does not run until the fixup phase, so at this point the launcher
      # still asks for /lib64/ld-linux-x86-64.so.2, which does not exist in the sandbox.
      # Point it at the stdenv loader by hand purely so it can perform the extraction.
      patchelf --set-interpreter "$(cat "$NIX_CC/nix-support/dynamic-linker")" launcher
    ''}

    # The launcher unpacks to $HOME/.cache and the sandbox HOME is /homeless-shelter,
    # which does not exist; without this the extraction fails with
    # "failed to open ... for writing".
    export HOME="$TMPDIR/build-home"
    mkdir -p "$HOME"

    # --version is enough to trigger a full extraction, and extraction is the ONLY thing
    # wanted from the launcher here.
    #
    # The failure is expected and tolerated: having unpacked the tree, the launcher execs
    # the extracted opengrep.bin, which has not been patched yet and still asks for
    # /lib64/ld-linux-x86-64.so.2, so it dies with "couldn't launch child (exec): No such
    # file or directory". That is downstream of the work being done and must not fail the
    # build -- but `|| true` on its own would also swallow a genuine extraction failure,
    # which is why the assertion below is the real gate rather than the exit status.
    ./launcher --version || true

    # Extraction happening at all is also the proof that the payload is EMBEDDED rather
    # than downloaded on first run: the build sandbox has no network.
    test -x "$HOME/.cache/opengrep/v${version}/opengrep.bin" \
      || { echo "opengrep: launcher did not produce opengrep.bin; layout changed upstream" >&2; exit 1; }

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p "$out/share" "$out/bin"
    cp -r "$HOME/.cache/opengrep/v${version}" "$out/share/opengrep"
    chmod +x "$out/share/opengrep/opengrep.bin"

    # A symlink rather than a wrapper: the entry point resolves its own real path to find
    # the tree beside it, which is why it runs standalone at all.
    ln -s "$out/share/opengrep/opengrep.bin" "$out/bin/opengrep"

    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck

    # A fresh HOME, deliberately not the one the tree was extracted under, so this fails
    # if anything baked in a build-time absolute path.
    export HOME="$TMPDIR/check-home"
    mkdir -p "$HOME"

    "$out/bin/opengrep" --version

    # --version only exercises the Python entry point. A real scan is what loads
    # opengrep-core, the OCaml engine that does the actual analysis and is by far the
    # largest thing being patched here -- so without this the check would pass on a
    # package whose scanner half is broken.
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
