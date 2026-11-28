# Changelog

## [1.3.0] - 2026-11-28

Added:

- Audit: *kvb-quality-audit* runs a release security audit of a tag range
- Audit: the pinned Cloudflare audit method, checked by sha256 per file
- Audit: *audit.py prepare* plans the range; *attest* writes the verdict
- Audit: MEDUSA findings seed it; traced rejections become waiver rows
- Audit: one attestation per tree with tokens, minutes and coverage

Fixed:

- Packaging: the wheel ships the *quality.image* subpackage again

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): release audit, packaging

## [1.2.0] - 2026-11-27

Added:

- Image: *quality image* scans local images offline, Trivy plus osv-scanner
- Image: *quality image report* gives one row per image, joining mirrors
- Image: rule *security.vulnerable-image*; it never pulls an image
- Database: *quality db update* also fetches Trivy's Java database

Fixed:

- Database: *quality db update* replaces a read-only bundle without an error

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): image scan, database

## [1.1.0] - 2026-11-27

Added:

- Rules: twelve pattern rules from core's generic lints, on added lines
- Rules: *security.workflow-fork-checkout* and *security.sudo-preserve-env*
- Rules: *coding.shell-or-true*, *coding.empty-except*, -latest runners
- Rules: workflow timeouts, syntax directives, codename tags, *timeout*
- Rules: private-use characters, line references, TODO without a link

Changed:

- Rules: *clean.default-value* flags a Dockerfile *ARG* with a real default

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): requirements

## [1.0.0] - 2026-11-26

Breaking:

- Score: *kvb-quality-score* prints one *Metrics:* block, one value per line
- Score: *--table* and the two-line output are gone
- Score: *--legal*, *--legal-blockers* and *--architecture* are required

Added:

- Score: legal and architecture lines; a legal blocker stops the commit
- Score: *--note metric=text* adds a marked note below the block
- Rules: *.quality/comments.yml* declares the directives of a repository
- Rules: *pragmas_allowed* lets declared tool pragmas pass
- Rules: *clean.em-dash* refuses an added em dash in every text kind

Upgrade notes:

- Callers of *score.py* pass the three new flags and read the new block

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): requirements

## [0.4.0] - 2026-11-26

Added:

- Skills: eight kvb-quality analysis skills, among them *kvb-quality-review*
- Install: *make install* sets up the skills and *kvb-quality-python*
- Package: *quality.agent* holds the helpers the skill scripts share
- Review: *exceptions.py* asks to confirm each added Exception comment
- Tests: live Playwright and e2e checks for the hosted scan stack

Fixed:

- Hosted scan: the scan image starts under the core CA trust wrapper

Contributors:

- [Kevin Veen-Birkenbach](https://veen.world): requirements

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
