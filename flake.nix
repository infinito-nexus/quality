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
    tools = with pkgs; [
      actionlint
      ast-grep
      gitleaks
      hadolint
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
