{
  description = "quality";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs { inherit system; };
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
  in {
    packages.${system}.tools = pkgs.buildEnv { name = "quality-tools"; paths = tools; };
    devShells.${system}.default = pkgs.mkShell {
      packages = tools ++ [ (pkgs.python3.withPackages (ps: [ ps.pathspec ps.pytest ps.pyyaml ])) ];
    };
  };
}
