# Core rehearsal

Requirement 001 asks for `quality check --base main` on three core branches before core adopts the check: each run's exit code and new-finding count, and no non-hard legacy finding reported as new.

## Method

- Binary: `quality 0.1.0` built from `e7edfc2` (`nix build .#default`), deep tier with the bundle of `quality db update`, `--threads 14`.
- Command, in the branch's checkout: `quality check --base <base> --json --db <bundle> --threads 14`.
- Checkout: a detached worktree without files (`git worktree add --no-checkout --detach`, then `git read-tree HEAD`), because quality reads the index and the commits, not the work tree.
- Base: `main` is `origin/main` at `d6b4e1ab6a` (2026-11-14). `feature/store-i18n` was merged in `ace84681ff` and deleted, so its run uses that merge's parents: head `246a681f3c`, base `995d9d7461`.
- Legacy check: every non-hard finding is matched against the range. A line finding must stand on a line the range adds; a folder finding on a folder that gained an entry; a size or complexity finding on a function whose value rose; a clone finding on a pair that did not exist at the merge base.

## Results (2026-11-14)

| Branch | Head | Merge base | Changed files | Exit | New findings | Hard | Legacy reported as new | Time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `production` | `0dc8e74f8a` | `2ae42b9ab4` | 499 | 1 | 148 | 0 | 0 | 75 s |
| `feature/iam-profile-rbac` | `677c9c0f29` | `5182a21244` | 4540 | 2 | none | none | none | 758 s |
| `feature/store-i18n` | `246a681f3c` | `995d9d7461` | 6118 | 2 | none | none | none | 406 s |

### production

The 148 new findings: 106 `clean.comment`, 11 `clean.default-value`, 10 `clean.folder-items`, 6 `clean.clones`, 5 `clean.complexity`, 3 `clean.parameters`, 2 `clean.function-length`, 2 `coding.implicit-namespace`, 1 `clean.prefix-groups`, 1 `clean.tool-pragma`, 1 `clean.unused-nocheck`.

17 of them do not stand on a line the range adds; each is new:

- 12 folder findings, each on a folder that gained an entry in the range: `docs/requirements` (44 to 45, `098-showroom.md`), `plugins/lookup` (149 to 150, `role_version.py`, also its prefix group), `roles` (297 to 299), `tests/lint/ansible/roles` (50 to 51), `tests/lint/ansible/roles/meta` (47 to 48), `tests/unit/python/plugins/lookup` (128 to 129), `tests/unit/python/roles` (124 to 126), `tests/unit/python/roles/web-app-nextcloud` (18 to 19), `tests/unit/python/utils/roles` (14 to 15), `utils/roles` (22 to 23).
- 3 function findings whose value rose (lizard on the merge base and the head): `test_declared_docker_service_image_and_version_are_valid` in `tests/integration/infrastructure/docker/test_services_image_version_valid.py` CCN 10 to 11, `_apps` in `tests/unit/python/plugins/lookup/test_sso.py` CCN 11 to 12 and parameters 9 to 10, `_apps` in `tests/unit/python/utils/roles/applications/services/test_sso.py` parameters 7 to 8.
- 2 clone findings on the untouched side of a new pair: `TestPacmanCleanup` in `tests/unit/python/roles/sys-ctl-cln-disc-space/files/shell/test_script.py`, whose partner is `TestApplicationCollectors`, the class the range adds to that file, and `flatten` in `tests/unit/python/roles/web-app-xwiki/test_blobstore_render_order.py`, which the range copies twice into `test_render_stages.py`; at the merge base the helper existed once.

### feature/iam-profile-rbac and feature/store-i18n

Both exited 2 with `gitleaks exceeded its timeout of 300 s and was killed`, so they report no finding. The host ran other agents' jobs at the time: the queue granted the rehearsal at 70.2 % CPU busy, with peaks of 99.9 % and three jobs running beside it. `store-i18n` adds the 575 MB of generated gettext catalogs that also dominate `check --all` on core. Both runs are repeated on a quiet host, below 50 % CPU, the condition requirement 001 sets for its time budgets.
