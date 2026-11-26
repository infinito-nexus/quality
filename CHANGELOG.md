# Changelog

## [0.3.0] - 2026-11-26

Added:

- Rules: *test.text-presence* flags tests that only check a file holds text
- CLI: *--rule* runs only the named rules; an unknown id exits 2
- Waivers: a *.nocheck* file waives the soft rules it names in its folder

Fixed:

- Hosted scan: the role takes a free subnet and host port

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): requirements

## [0.2.0] - 2026-11-25

Added:

- CI: reusable *tool.yml* runs one bundled tool from the quality flake
- Distribution: every bundled tool is a package of the flake

Changed:

- CI: *quality-ref* is optional; the gate builds the commit it is called at

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): requirements

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
