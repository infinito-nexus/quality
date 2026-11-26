# Quality Check

## Description

Quality Check is a hosted static quality scan. A visitor names a public Git repository, uploads a single file or pastes code, and the server runs the `quality` checker on it and shows the findings on a private report page.

## Overview

The role deploys the web app, an egress proxy, and an idle anchor of the scan image, which keeps core's image prune from removing it; a host-side launcher starts the scan image once per job step. The launcher runs as a systemd timer, takes queued jobs from the web app's spool, and runs fetch, prepare and scan in separate sandboxed containers under the Kata runtime. Only the fetch step reaches the internet, and only through the proxy, which refuses internal and host addresses. Jobs and reports live on a tmpfs mount and expire after `retention_hours`.

## Features

- **Three inputs:** a public repository URL, one uploaded file, or pasted code with a chosen language.
- **Sandboxed steps:** every step runs read-only, without capabilities, with CPU, memory, PID and disk limits from [meta/services.yml](./meta/services.yml).
- **Egress control:** the fetch network has no route of its own; the proxy denies private ranges and, through [templates/site.conf.j2](./templates/site.conf.j2), the host's own addresses.
- **Anonymous access with limits:** a proof-of-work captcha and per-IP, per-host and global hourly limits; `services.quality-check.access.anonymous` turns anonymous submissions off.
- **Optional SSO:** with Keycloak the app signs users in through its own OIDC code flow with S256 PKCE ([templates/keycloak/clients.json.j2](./templates/keycloak/clients.json.j2)); members of the role's RBAC group get larger limits.
- **Private reports:** a report is reachable only through its random link, sent with `no-referrer` and `noindex`.
- **Cached Nix builds:** a source build fetches the Nix closure through the package cache's `raw-nixos-cache` repository when `dev-nix` names one in `services.nix.package_cache`, and from `cache.nixos.org` otherwise.

## Biber coverage

The `biber:` scenario takes the account out of the `member` group that [meta/rbac.yml](./meta/rbac.yml) declares and proves the role by its quota: `registered_per_user_hour` submissions pass and the next one gets 429, while the `administrator:` scenario puts the account into the group and passes one submission more. No assertion names the group or refuses an admin-scoped element, so the scenarios prove the role through its limit rather than through a role-scoped element.

## Further Resources

- [quality repository](https://github.com/infinito-nexus/quality)
