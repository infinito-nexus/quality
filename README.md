# quality

Homepage: https://github.com/infinito-nexus/quality

## Hosted scan

The role `web-app-cst-quality-check` serves the scan as a web page ([requirement 002](docs/requirements/002-hosted-quality-scan.md)).

| Command | What it does |
| --- | --- |
| `make up` | Builds the images and serves the page at <http://localhost:18098/>; `make down` removes the stack and its volumes. |
| `make test-service` | Unit tests of the web app and the launcher, in a virtual environment under `.venv/service`. |
| `make test-egress` | Egress tests against the stack of `make up`. |
| `make verify-test INFINITO_CORE_DIR=<core>` | Pulls the role into a core checkout with custom-role support and runs core's full test suite, lints included. |
| `make verify-compose INFINITO_CORE_DIR=<core>` | Runs `verify-test` first, then deploys the role with Keycloak through that checkout and runs its Playwright spec. |

## Author
Kevin Veen-Birkenbach <kevin@veen.world>
