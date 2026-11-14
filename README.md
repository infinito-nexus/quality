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

`--staged` needs no database. `--base` and `--all` add the deep tier, which reads the bundle of `quality db update`: mount it with `- <db>:/db:ro` and pass `--db /db`. Run the service from a main checkout, because a linked worktree's `.git` file points outside `/src`.

## Hosted scan

The role `web-app-cst-quality-check` serves the scan as a web page ([requirement 002](docs/requirements/002-hosted-quality-scan.md)).

| Command | What it does |
| --- | --- |
| `make up` | Builds the images and serves the page at <http://localhost:18098/>; `make down` removes the stack and its volumes. |
| `make test-service` | Unit tests of the web app and the launcher, in a virtual environment under `.venv/service`. |
| `make test-egress` | Egress tests against the stack of `make up`. |
| `make verify-test INFINITO_CORE_DIR=<core>` | Pulls the role into a core checkout with custom-role support and runs core's full test suite, lints included. |
| `make verify-compose INFINITO_CORE_DIR=<core>` | Runs `verify-test` first, then deploys the role with Keycloak through that checkout and runs its Playwright spec. |

## Benchmarks

The speed criteria of [requirement 001](docs/requirements/001-language-agnostic-quality-check.md) and its recall bound on core run apart from `test-unit` and `test-integration`. The core checkout is only read.

| Command | What it does |
| --- | --- |
| `make test-bench QUALITY_CORE_DIR=<core> QUALITY_DB_DIR=<db> QUALITY_DEFAULTS_SCRIPT=<defaults.py>` | Times `quality --version` of the built `packages.default` against 0.15 s as the median of 9 runs and its `quality check --all` on core, deep tier included, against 120 s on 20 CPUs, both timings skipped with the measured load as the reason when 50 % or more of the CPUs are busy in the 5 s before or after them, and checks that `clean.default-value` finds at least 95 % of the shell, Python and JavaScript defaults that `defaults.py` of the kvb-code-clean skill reports on core. Needs `nix build .#default` of this tree and a fresh bundle of `quality db update`. |

## Author
Kevin Veen-Birkenbach <kevin@veen.world>
