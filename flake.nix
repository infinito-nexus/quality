{
  description = "quality";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.nixpkgs-stable.url = "github:NixOS/nixpkgs/nixos-26.05";
  outputs = { self, nixpkgs, nixpkgs-stable }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
    # unstable cannot build semgrep (nixpkgs#579107 patchelf abort, and its CLI imports mcp.server.fastmcp, gone in mcp 2); release-26.05 builds it on Hydra
    semgrep = nixpkgs-stable.legacyPackages.${system}.semgrep;
    jscpd = pkgs.stdenv.mkDerivation (finalAttrs: {
      pname = "jscpd";
      version = "5.4.2";
      src = pkgs.fetchurl {
        url = "https://registry.npmjs.org/jscpd-linux-x64-gnu/-/jscpd-linux-x64-gnu-${finalAttrs.version}.tgz";
        hash = "sha512-eAmKLxx+pIOEX4lZ342CCCjL5bvf+a3gdmaaVHXiGIx2Zr3zKkF32YkfuN2sCvCui5I/wnely80XsRvVVFO47Q==";
      };
      nativeBuildInputs = [ pkgs.autoPatchelfHook ];
      buildInputs = [ pkgs.stdenv.cc.cc.lib ];
      installPhase = ''
        runHook preInstall
        install -Dm755 bin/jscpd $out/bin/jscpd
        install -Dm644 LICENSE $out/share/licenses/jscpd/LICENSE
        runHook postInstall
      '';
      meta.license = pkgs.lib.licenses.mit;
    });
    tools = with pkgs; [
      actionlint
      ast-grep
      gitleaks
      hadolint
      jscpd
      osv-scanner
      python3Packages.lizard
      ripgrep
      ruff
      semgrep
      shellcheck
      trivy
    ];
    runner = pkgs.python3.withPackages (ps: [ ps.pathspec ps.pyyaml ]);
    squid = assert pkgs.lib.versions.major pkgs.squid.version == "7"; pkgs.squid;
  in {
    packages.${system} = {
      tools = pkgs.buildEnv { name = "quality-tools"; paths = tools; };
      scan = pkgs.buildEnv {
        name = "quality-scan";
        paths = tools ++ (with pkgs; [ runner bash cacert coreutils git ]);
      };
      proxy = pkgs.buildEnv { name = "quality-proxy"; paths = [ squid ]; };
    };
    devShells.${system}.default = pkgs.mkShell {
      packages = tools ++ [ (pkgs.python3.withPackages (ps: [ ps.pathspec ps.pytest ps.pyyaml ])) ];
    };
  };
}
