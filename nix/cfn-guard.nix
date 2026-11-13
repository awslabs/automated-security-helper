# cfn-guard (AWS CloudFormation Guard), a builtin ASH scanner that nixpkgs does not carry.
#
# WHY THE RELEASE BINARY
#
# Parity, as for opengrep (nix/opengrep.nix): `ash dependencies install` and the container
# image install exactly this asset, verified against the same SHA256
# (_DIGESTS in automated_security_helper/utils/tool_downloads.py), so Nix mode runs the
# same bytes as local and container mode. tests/unit/utils/test_pinned_tool_downloads.py
# keeps the hashes below equal to that table.
#
# The linux assets are statically linked (static-pie on x86_64, static on aarch64: no
# interpreter, no NEEDED entries), so nothing needs patching. The rules cfn-guard
# evaluates are not here: the shell seeds the pinned AWS Guard Rules Registry bundle on
# first entry (see the shellHook in flake.nix), the same way it seeds grype's database.
{ lib
, stdenv
, fetchurl
, systems
}:

let
  version = "3.2.1";

  # cfn-guard names its assets without a version; the version is the release tag in the
  # URL, so the hash is the whole pin. Each hash carries detect-secrets' allowlist
  # pragma: a pinned SRI digest of a public release asset is high-entropy by design.
  assets = {
    x86_64-linux = {
      name = "cfn-guard-v3-x86_64-linux-latest";
      hash = "sha256-jGbvsZxj5sK/JrmkG7zy+FuqipN7AdNQlAGU+q9kzx0=";  # pragma: allowlist secret
    };
    aarch64-linux = {
      name = "cfn-guard-v3-aarch64-linux-latest";
      hash = "sha256-zTeAJtrQ+GWSarHRwILi+vgl9/2Iip/mtcFCzfF1wSk=";  # pragma: allowlist secret
    };
    x86_64-darwin = {
      name = "cfn-guard-v3-x86_64-macos-latest";
      hash = "sha256-UInfqgWnZs8RigIFGOYvd+3b1DrPOgtp02sjF1xsb9o=";  # pragma: allowlist secret
    };
    aarch64-darwin = {
      name = "cfn-guard-v3-aarch64-macos-latest";
      hash = "sha256-TB6xDAYXMRWeqvDn29Rl25+kt2e4IYakq0iWccwAt9A=";  # pragma: allowlist secret
    };
  };

  inherit (stdenv.hostPlatform) system;
  asset = assets.${system} or (throw "cfn-guard: no pinned asset for ${system}");
in
stdenv.mkDerivation {
  pname = "cfn-guard";
  inherit version;

  src = fetchurl {
    url = "https://github.com/aws-cloudformation/cloudformation-guard/releases/download/${version}/${asset.name}.tar.gz";
    inherit (asset) hash;
  };

  sourceRoot = asset.name;

  # Someone else's release artifact; stripping buys nothing.
  dontStrip = true;
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 cfn-guard "$out/bin/cfn-guard"
    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    "$out/bin/cfn-guard" --version | grep -F "${version}"
    runHook postInstallCheck
  '';

  meta = {
    description = "Policy-as-code evaluation of CloudFormation templates, used by ASH";
    homepage = "https://github.com/aws-cloudformation/cloudformation-guard";
    license = lib.licenses.asl20;
    mainProgram = "cfn-guard";
    platforms = systems;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
