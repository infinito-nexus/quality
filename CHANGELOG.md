# Changelog

## [0.1.1] - 2026-11-25

Changed:

- Hosted scan: the scan image builds on *nixos/nix* 2.36.0

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): requirements

## [0.1.0] - 2026-11-25

Added:

- CLI: *quality check --staged*, *--base* and *--all* gate on new findings
- Rules: file, folder and inline script limits, defaults and clone detection
- Structural: ast-grep rules per language with a comment catalogue and waivers
- Security: gitleaks, hadolint, semgrep, trivy and osv-scanner adapters
- Legal: licence texts, copyright holders and registry licences, legal score
- Architecture: layer and cycle contracts via import-linter and depcruise
- Database: *quality db update* builds the offline vulnerability bundle
- Doctor: *quality doctor* names each missing or broken tool
- Distribution: Nix flake per system, PyPI package and an OCI image
- Hosted scan: *web-app-cst-quality-check* role, web app and egress proxy
- Web: interface in the language of the browser, switchable by *?lang=*
- CI: reusable quality gate workflow for other repositories

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): runner, rules, hosted scan
