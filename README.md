# quality

Homepage: https://github.com/infinito-nexus/quality

## Install

`flake.lock` is the only pin source ([requirement 001](docs/requirements/001-language-agnostic-quality-check.md), decision 18). On a host with Nix, install `packages.default`, the runner wrapped with every tool by absolute store path, and call it by absolute path:

```sh
nix profile install github:infinito-nexus/quality/<release-tag>
~/.nix-profile/bin/quality check --staged
```

### Agent skills

The `kvb-quality-*` analysis skills ([requirement 003](docs/requirements/003-analysis-skills-in-quality.md)) install from a checkout:

```sh
make install
```

It mirrors `skills/kvb-quality-*` into `~/.claude/skills`, `~/.agents/skills` and, when `~/.codex` exists, `~/.codex/skills`; installs the checkout into `~/.local/share/kvb-quality/venv`; and writes `~/.local/bin/kvb-quality-python`, the interpreter every skill script starts with.

`kvb-quality-audit` ([requirement 011](docs/requirements/011-release-security-audit.md)) audits the code a release changes and writes one attestation per tree; skills' `kvb-release-cut` runs it before every release. Its `upstream/` folder is Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill), MIT, vendored unchanged at a pinned commit with its licence; see `skills/kvb-quality-audit/README.md`.

## Dev stack

Hosts without Nix, CI and dev stacks use `packages.image` (`nix build .#image`), the OCI image of the same closure, published to ghcr by digest; the digest is in the release notes. A dev stack adds it as a compose service under the profile `tools` and a make target that runs it:

```yaml
services:
  quality:
    image: ghcr.io/infinito-nexus/quality@sha256:<digest>
    profiles: [tools]
    network_mode: none
    read_only: true
    tmpfs: [/tmp]
    user: "65534"
    working_dir: /src
    volumes:
      - .:/src:ro
```

```make
quality-check:
	docker compose --profile tools run --rm quality check --staged
```

`--staged` needs no database. `--base` and `--all` add the deep tier, which reads the bundle of `quality db update`: mount it with `- <db>:/db:ro` and pass `--db /db`. `--rule <id>`, repeatable, runs only the named catalogue rules in any of the three modes, the checks the runner does itself and `.qualityignore.yml` staleness included; the database is then needed only when a named rule is of the deep tier, so `quality check --base origin/main --rule test.text-presence` runs without `--db`, and an id outside the catalogue stops the check with exit 2. `quality db update --licenses <repo>`, repeatable, also stores the registry licences of the exact pins at each named repository's HEAD and in its staging index for `legal.dependency-license`; a pin without an SPDX licence there stays `unchecked`, and an update without `--licenses` keeps the stored licences. Run the service from a main checkout, because a linked worktree's `.git` file points outside `/src`.

## Image scan

`quality image <ref|archive|dir>... [--json]` scans container images with Trivy and osv-scanner, offline, on the bundle of `quality db update` ([requirement 010](docs/requirements/010-image-vulnerability-scan.md)). It writes one `security.vulnerable-image` finding per vulnerable package and image, in the schema of `quality check --json` plus `package`, `installed`, `fixed`, `vulnerabilities`, `engines` and `message`, and exits 1 when an image has a finding or stays unscanned.

- **Local only**: quality never pulls. A reference is exported from the local Docker daemon with `docker save`, once per image id; a `docker save` tar or an OCI layout directory is read as it is. A reference the daemon does not hold is listed as unscanned with the reason `not local`, as is an image an engine could not read, with the engine's first error line.
- **Bundle**: `quality db update` fetches Trivy's vulnerability and Java databases and the osv-scanner databases of every ecosystem in `rules/tools.yml`, the Debian, Alpine and Ubuntu packages included; an image with JAR files stays unscanned on a bundle without the Java database, so update a bundle older than v1.2.0 first.
- **Pull limits stay with the caller**: pull the images first, through a registry mirror or a pull-through cache, so a scan of many images costs no registry quota.

```sh
docker pull mirror.example/library/nginx:1.27
quality image mirror.example/library/nginx:1.27 ./build/app.tar --json > images.json
quality image report images.json ci-images.json
```

`quality image report <json>... [--json]` reduces such reports to one row per image, keyed by the last path segment and the tag, so `registry.example/x/nginx:1.27` and `mirror.example/nginx:1.27` join. A row shows the image, tag, its distinct ids per severity (`C`, `H`, `M`, `L`, `?`), the ids with a fixed-in version over all ids with the two packages that fix the most and their highest fixed-in version, the ids without a fix and the engines; unscanned images follow in their own list. It proposes no fix: bumping, rebuilding and suppressing stay with the caller.

## CI

Another repository calls the reusable workflows by the commit of a release tag. Each workflow builds its tools from the flake at the commit it is called at (`job.workflow_sha`), so that `uses:` line is the only pin, and Dependabot's `github-actions` ecosystem moves it to the next release. `quality.yml` gates the range a pull request or push adds and scans every commit of it for secrets; `tool.yml` runs one tool of the flake, under its package name, over the whole tree:

```yaml
jobs:
  quality:
    uses: infinito-nexus/quality/.github/workflows/quality.yml@<commit> # <release-tag>
  ruff:
    uses: infinito-nexus/quality/.github/workflows/tool.yml@<commit> # <release-tag>
    with:
      tool: ruff
      args: check src tests
```

## Layer contracts

A repository that holds `.quality/architecture.yml` gets the rules `architecture.layer` and `architecture.cycle` ([requirement 005](docs/requirements/005-architecture-score.md), decision 3); each new hit lowers the architecture score by 25. Python runs through `lint-imports` of import-linter, JavaScript through `depcruise` of dependency-cruiser, both bundled like every other tool. Each section is optional, every key inside it is required, and a malformed file stops the check with an error naming the key. `source` is the directory holding the code, `.` for the root, and for JavaScript also the scope of the cycle check; `layers` lists the highest layer first, and no layer may import one above it:

```yaml
python:
  source: src
  packages: [shop]
  layers: [shop.web, shop.domain]
  forbidden:
    - {from: [shop.domain], to: [shop.web]}
javascript:
  source: web
  layers: [web/ui, web/core]
  forbidden: []
```

## Waivers

A comment on the finding's line waives it: `nocheck: <rule> -- <reason>` in any comment syntax, where a group such as `coding` names all its rules. A `.nocheck` file waives rules for its folder and every folder below it, one `# nocheck: <rule> -- <reason>` per line; a line naming nothing in the catalogue is left to the project's own lints, and a catalogue line without a reason stops the check with exit 2. Hard and changed_only rules are waived only in `.qualityignore.yml`, whose `--base` entries come from the base side, so a change cannot waive its own finding there: a `.nocheck` line naming a group waives only its other rules, and one naming nothing else exits 2. `--all` stops on a `.nocheck` or `.qualityignore.yml` entry that waives nothing.

A repository with its own waiver markers declares their spelling in `.quality/comments.yml` ([requirement 007](docs/requirements/007-repo-directive-spellings.md)): `directives` lists groups in the schema of `rules/comments.yml` (`tool`, `spellings`, optional `languages`, `marker`, `tight`, `position`), whose comments `clean.comment` then accepts, and `pragmas_allowed` lists the tool pragmas `clean.tool-pragma` lets through. A declared directive waives nothing; each side of a `--base` check reads its own file, and a malformed one stops the check with exit 2:

```yaml
directives:
  - tool: core lint waivers
    spellings: ['nocheck:\s*[a-z0-9-]+(?:,\s*[a-z0-9-]+)*']
pragmas_allowed: ['noqa:\s*[A-Z]+\d+(?:,\s*[A-Z]+\d+)*']
```

`clean.em-dash` refuses an added em dash in every text kind ([requirement 008](docs/requirements/008-no-em-dash.md)); translation catalogues (`.po`) have no kind and stay out.

## Text presence tests

`test.text-presence` flags a test that reduces a source file to the presence of text, which core's `docs/contributing/actions/testing/regression.md` forbids: parse, render or run the file and assert on the result instead. It flags a test function (Python `test*`, a JavaScript or TypeScript `test` or `it` callback, PHP `test*` or `#[Test]`, Rust `#[test]`, Go `Test*(t *testing.T)`, Java `@Test`, Ruby `test_*` or an `it` block, a shunit2 `test*()` shell function) that reads a file, asserts at least once that the read text contains something, asserts nothing but containment, and neither parses, renders, writes nor runs anything. A test whose containment checks are all negative, such as a policy scan, stays clean, as does one on runtime output or on a fixture it writes itself. For Python the check is a builtin that follows the read text through assignments, slices, splits, regex extracts, comprehensions and line filters, through module constants, class attributes and `setUp`/`setUpClass`, and through helpers of the same file or of other modules of the repository it imports; a lint scan that collects the files missing a text and asserts the list empty counts as a positive check, one that collects the files holding a text as a negative one, also where it first narrows the scan to the files holding a scope text. What production code returns stays clean unless its name says it reads, and a lexer or address parse counts as running code, as does a test helper named for evaluating a condition or an order, such as `holds` or `*_precedes_*`. A YAML, JSON or TOML parse counts only where the condition that produces a finding uses the structure itself, a key, a type, a count bound or a leaf's equality with a value; a containment, regex, `startswith` or `endswith` on a string leaf of the parsed data is text presence, also where parsed structure merely selects or exempts files. A text read from one file and looked for in another is a cross-reference, and text the test plants into a read file, by `+`, `replace`, `re.sub`, a literal line beside it or a `copy.deepcopy` of parsed data, makes its check a different one, as does a comparison with a module of the code under test. The finding sits on the test's first line, so its nocheck goes there: `def test_x():  # nocheck: test.text-presence -- <reason>`.

## Hosted scan

The role `web-app-cst-quality-check` serves the scan as a web page ([requirement 002](docs/requirements/002-hosted-quality-scan.md)).

| Command | What it does |
| --- | --- |
| `make up` | Builds the images and serves the page at <http://localhost:18098/>, or on the port `QUALITY_DEV_PORT` names; `make down` removes the stack and its volumes. Needs a vulnerability bundle at `$QUALITY_DEV_DB/bundle` (default `~/.cache/quality-check/dev-db/bundle`), created once with `quality db update --db <that path>`. An exported `INFINITO_CACHE_PACKAGE_URL` makes the Nix builds use that package cache's `raw-nixos-cache` repository. |
| `make test-service` | Unit tests of the web app and the launcher, in a virtual environment under `.venv/service`. |
| `make test-egress INFINITO_CORE_DIR=<core> EGRESS_RUNTIMES="<runtimes>"` | Egress tests against the stack of `make up`; the step flags run through that core checkout's container wrapper, and every launcher and test-proxy test runs once under each runtime of `EGRESS_RUNTIMES`, such as `"runc sysbox-runc"`, which `docker info` must offer. |
| `make verify-test INFINITO_CORE_DIR=<core>` | Pulls the role into a core checkout with custom-role support and runs core's full test suite, lints included. |
| `make verify-compose INFINITO_CORE_DIR=<core>` | Runs `verify-test` first, then deploys the role with Keycloak through that checkout and runs its Playwright spec. |
| `make verify-playwright INFINITO_CORE_DIR=<core>` | Pulls the role into that checkout again and reruns its Playwright spec against the stack `verify-compose` left running; the scans the deploy skips while the launcher timer is stopped run here. |
| `make test-live INFINITO_CORE_DIR=<core> QUALITY_LIVE_MEMBER=<user> QUALITY_LIVE_MEMBER_PASSWORD_FILE=<file>` | Live tests against the stack `verify-compose` deployed in that checkout: socket, fetch network, state mount, upload limits, rate limits, realm sign-in. |

## Distribution

| Command | What it does |
| --- | --- |
| `make test-distribution` | Builds `packages.default` and `packages.image`, then checks pins, notices, `quality doctor` and the image. |
| `make test-e2e QUALITY_E2E_SKILLS=<repo> QUALITY_E2E_PACKAGE_MANAGER=<repo> QUALITY_E2E_RUNTIME=<runtime>` | Builds both outputs and checks that the host binary and the image, run under that Docker runtime (core's `SANDBOX_RUNTIME`, such as `runsc`), print the same `quality doctor` output and report the same findings on both repositories; needs Docker and the test bundle `make test-integration` fetches. |

## Benchmarks

The speed criteria of [requirement 001](docs/requirements/001-language-agnostic-quality-check.md) and its recall bound on core run apart from `test-unit` and `test-integration`. The core checkout is only read.

| Command | What it does |
| --- | --- |
| `make test-bench QUALITY_CORE_DIR=<core> QUALITY_DB_DIR=<db>` | Times `quality --version` of the built `packages.default` against 0.15 s as the median of 9 runs and its `quality check --all` on core, deep tier included, against 360 s on 20 CPUs, both timings skipped with the measured load as the reason when 50 % or more of the CPUs are busy in the 5 s before or after them, and checks that `clean.default-value` finds every shell, Python and JavaScript default of `tests/bench/default-value-hits.json`, the hits of `defaults.py` of the kvb-code-clean skill on the core commit named there, which `QUALITY_CORE_DIR` must hold. Needs `nix build .#default` of this tree and a fresh bundle of `quality db update`. |

## Author
Kevin Veen-Birkenbach <kevin@veen.world>
