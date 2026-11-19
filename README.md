# quality

Homepage: https://github.com/infinito-nexus/quality

## Install

`flake.lock` is the only pin source ([requirement 001](docs/requirements/001-language-agnostic-quality-check.md), decision 18). On a host with Nix, install `packages.default`, the runner wrapped with every tool by absolute store path, and call it by absolute path:

```sh
nix profile install github:infinito-nexus/quality/<release-tag>
~/.nix-profile/bin/quality check --staged
```

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

`--staged` needs no database. `--base` and `--all` add the deep tier, which reads the bundle of `quality db update`: mount it with `- <db>:/db:ro` and pass `--db /db`. `quality db update --licenses <repo>`, repeatable, also stores the registry licences of the exact pins at each named repository's HEAD and in its staging index for `legal.dependency-license`; a pin without an SPDX licence there stays `unchecked`, and an update without `--licenses` keeps the stored licences. Run the service from a main checkout, because a linked worktree's `.git` file points outside `/src`.

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

## Hosted scan

The role `web-app-cst-quality-check` serves the scan as a web page ([requirement 002](docs/requirements/002-hosted-quality-scan.md)).

| Command | What it does |
| --- | --- |
| `make up` | Builds the images and serves the page at <http://localhost:18098/>, or on the port `QUALITY_DEV_PORT` names; `make down` removes the stack and its volumes. Needs a vulnerability bundle at `$QUALITY_DEV_DB/bundle` (default `~/.cache/quality-check/dev-db/bundle`), created once with `quality db update --db <that path>`. |
| `make test-service` | Unit tests of the web app and the launcher, in a virtual environment under `.venv/service`. |
| `make test-egress INFINITO_CORE_DIR=<core> EGRESS_RUNTIMES="<runtimes>"` | Egress tests against the stack of `make up`; the step flags run through that core checkout's container wrapper, and every launcher and test-proxy test runs once under each runtime of `EGRESS_RUNTIMES`, such as `"runc sysbox-runc"`, which `docker info` must offer. |
| `make verify-test INFINITO_CORE_DIR=<core>` | Pulls the role into a core checkout with custom-role support and runs core's full test suite, lints included. |
| `make verify-compose INFINITO_CORE_DIR=<core>` | Runs `verify-test` first, then deploys the role with Keycloak through that checkout and runs its Playwright spec. |

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
