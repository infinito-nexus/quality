{
  description = "quality";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.nixpkgs-stable.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.jscpd-x86_64-linux = {
    url = "https://registry.npmjs.org/jscpd-linux-x64-gnu/-/jscpd-linux-x64-gnu-5.4.2.tgz";
    flake = false;
  };
  inputs.jscpd-aarch64-linux = {
    url = "https://registry.npmjs.org/jscpd-linux-arm64-gnu/-/jscpd-linux-arm64-gnu-5.4.2.tgz";
    flake = false;
  };
  inputs.grimp-x86_64-linux = {
    url = "https://files.pythonhosted.org/packages/78/0e/bd28e0ab5fd3d356617a9d30aafbb872838be3865299f3af4be3244d51e2/grimp-3.20-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl";
    flake = false;
  };
  inputs.grimp-aarch64-linux = {
    url = "https://files.pythonhosted.org/packages/40/65/9875f637b413ea26ed0c042f0b7528bf1fc7b5abb6cb895581c2f5b5e162/grimp-3.20-cp314-cp314-manylinux2014_aarch64.manylinux_2_17_aarch64.whl";
    flake = false;
  };
  inputs.import-linter = {
    url = "https://files.pythonhosted.org/packages/b6/45/baf897d969b4e19d9e063ffb13bc12346b1af6b36e1774841d16d84cf3cc/import_linter-2.17-py3-none-any.whl";
    flake = false;
  };
  inputs.dependency-cruiser = {
    url = "https://github.com/sverweij/dependency-cruiser/archive/refs/tags/v18.8.0.tar.gz";
    flake = false;
  };
  outputs = { self, nixpkgs, nixpkgs-stable, ... }@inputs:
  let
    lib = nixpkgs.lib;
    systems = [ "x86_64-linux" "aarch64-linux" ];
    proxyFor = pkgs:
    let
      squid = assert lib.versions.major pkgs.squid.version == "7"; pkgs.squid;
    in pkgs.buildEnv { name = "quality-proxy"; paths = [ squid ]; };
    licences = pkg: map (licence: licence.spdxId or licence.fullName) (lib.toList pkg.meta.license);
    pinOf = name: pkg: {
      package = pkg.pname;
      inherit (pkg) version;
      path = lib.getExe' pkg name;
      licences = licences pkg;
    };
    noticeOf = _: pkg: "${pkg.pname} ${pkg.version}: ${lib.concatStringsSep ", " (licences pkg)}";
    perSystem = system:
    let
      pkgs = import nixpkgs { inherit system; };
      python = pkgs.python3;
      semgrep = nixpkgs-stable.legacyPackages.${system}.semgrep;
      jscpd = pkgs.stdenv.mkDerivation {
        pname = "jscpd";
        version = (lib.importJSON "${inputs."jscpd-${system}"}/package.json").version;
        src = inputs."jscpd-${system}";
        nativeBuildInputs = [ pkgs.autoPatchelfHook ];
        buildInputs = [ pkgs.stdenv.cc.cc.lib ];
        installPhase = ''
          runHook preInstall
          install -Dm755 bin/jscpd $out/bin/jscpd
          install -Dm644 LICENSE $out/share/licenses/jscpd/LICENSE
          runHook postInstall
        '';
        meta.license = lib.licenses.mit;
        meta.mainProgram = "jscpd";
      };
      wheelName = input: baseNameOf (lib.importJSON ./flake.lock).nodes.${input}.locked.url;
      wheelOf = input: pkgs.runCommand (wheelName input) { } "cp ${inputs.${input}} $out";
      wheelVersion = input: lib.elemAt (lib.splitString "-" (wheelName input)) 1;
      grimp = assert lib.versions.majorMinor python.version == "3.14"; python.pkgs.buildPythonPackage {
        pname = "grimp";
        version = wheelVersion "grimp-${system}";
        format = "wheel";
        src = wheelOf "grimp-${system}";
        nativeBuildInputs = [ pkgs.autoPatchelfHook ];
        buildInputs = [ pkgs.stdenv.cc.cc.lib ];
        pythonImportsCheck = [ "grimp" ];
        meta.license = lib.licenses.bsd2;
      };
      import-linter = python.pkgs.buildPythonPackage {
        pname = "import-linter";
        version = wheelVersion "import-linter";
        format = "wheel";
        src = wheelOf "import-linter";
        dependencies = [ grimp python.pkgs.click python.pkgs.rich ];
        pythonImportsCheck = [ "importlinter" ];
        meta.license = lib.licenses.bsd2;
        meta.mainProgram = "lint-imports";
      };
      dependency-cruiser = pkgs.buildNpmPackage {
        pname = "dependency-cruiser";
        version = (lib.importJSON "${inputs.dependency-cruiser}/package.json").version;
        src = inputs.dependency-cruiser;
        npmDepsHash = "sha256-8KDeALHVS+XYWtmNjou3OcAZhRHfDRrZw6doabr6hhU=";
        dontNpmBuild = true;
        npmPackFlags = [ "--ignore-scripts" ];
        doInstallCheck = true;
        nativeInstallCheckInputs = [ pkgs.versionCheckHook ];
        meta.license = lib.licenses.mit;
        meta.mainProgram = "depcruise";
      };
      toolPackages = {
        actionlint = pkgs.actionlint;
        ast-grep = pkgs.ast-grep;
        gitleaks = pkgs.gitleaks;
        hadolint = pkgs.hadolint;
        jscpd = jscpd;
        lizard = pkgs.python3Packages.lizard;
        osv-scanner = pkgs.osv-scanner;
        rg = pkgs.ripgrep;
        ruff = pkgs.ruff;
        semgrep = semgrep;
        shellcheck = pkgs.shellcheck;
        trivy = pkgs.trivy;
        lint-imports = import-linter;
        depcruise = dependency-cruiser;
        scancode = pkgs.python3Packages.scancode-toolkit;
      };
      tools = builtins.attrValues toolPackages;
      gitMinimal = pkgs.gitMinimal;
      runtimePackages = { git = gitMinimal; inherit (pkgs) cacert coreutils; python3 = python; inherit (python.pkgs) pathspec pyyaml; };
      runner = pkgs.python3.withPackages (ps: [ ps.pathspec ps.pyyaml ]);
      version = lib.head (builtins.match ''__version__ = "([^"]+)"'' (lib.head (lib.splitString "\n" (builtins.readFile ./src/quality/__init__.py))));
      pins = lib.mapAttrs pinOf (toolPackages // { git = gitMinimal; });
      noticesText = lib.concatLines ([
        "quality ${version}: MIT"
        "The packages below are bundled with the licence nixpkgs declares for each. They come from nixpkgs revision ${nixpkgs.rev}, semgrep from nixpkgs revision ${nixpkgs-stable.rev}, jscpd from its prebuilt release on npm, grimp from its prebuilt wheel on PyPI, one per platform, import-linter from its wheel on PyPI and dependency-cruiser from its release tag on GitHub, as flake.lock pins them."
        "nix build github:NixOS/nixpkgs/<revision>#<attribute>.src fetches the upstream source of a nixpkgs package."
      ] ++ lib.mapAttrsToList noticeOf (toolPackages // runtimePackages // { inherit grimp; }));
      notices = pkgs.writeTextDir "share/doc/quality/NOTICES" noticesText;
      quality = python.pkgs.buildPythonApplication {
        pname = "kvb-quality";
        inherit version;
        pyproject = true;
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./pyproject.toml
            ./README.md
            ./LICENSE
            (lib.fileset.fileFilter (file: file.hasExt "py") ./src)
            (lib.fileset.fileFilter (file: file.hasExt "yml") ./rules)
          ];
        };
        build-system = [ python.pkgs.setuptools python.pkgs.wheel ];
        dependencies = [ python.pkgs.pathspec python.pkgs.pyyaml ];
        makeWrapperArgs = [ "--set" "PATH" (lib.makeBinPath (tools ++ [ gitMinimal pkgs.coreutils ])) ];
        postInstall = ''
          install -Dm444 ${pkgs.writeText "quality-pins.json" (builtins.toJSON pins)} $out/${python.sitePackages}/quality/pins.json
          install -Dm444 ${notices}/share/doc/quality/NOTICES $out/share/doc/quality/NOTICES
        '';
        pythonImportsCheck = [ "quality.cli" ];
        passthru = { inherit pins noticesText; };
        meta.license = lib.licenses.mit;
        meta.mainProgram = "quality";
      };
    in {
      packages = {
        default = quality;
        image = pkgs.dockerTools.buildLayeredImage {
          name = "quality";
          contents = [ pkgs.dockerTools.fakeNss pkgs.dockerTools.caCertificates notices ];
          extraCommands = ''
            mkdir -p src tmp
            chmod 1777 tmp
          '';
          config = {
            Entrypoint = [ (lib.getExe quality) ];
            User = "65534:65534";
            WorkingDir = "/src";
            Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
          };
        };
        tools = pkgs.buildEnv { name = "quality-tools"; paths = tools; };
        scan = pkgs.buildEnv {
          name = "quality-scan";
          paths = tools ++ (with pkgs; [ runner bash cacert coreutils git ]);
        };
        proxy = proxyFor pkgs;
      };
      devShell = pkgs.mkShell {
        packages = tools ++ [ (pkgs.python3.withPackages (ps: [ ps.pathspec ps.pytest ps.pytest-xdist ps.pyyaml ])) ];
      };
    };
    bySystem = lib.genAttrs systems perSystem;
  in {
    lib = { inherit proxyFor; };
    packages = lib.mapAttrs (_: outputs: outputs.packages) bySystem;
    devShells = lib.mapAttrs (_: outputs: { default = outputs.devShell; }) bySystem;
  };
}
