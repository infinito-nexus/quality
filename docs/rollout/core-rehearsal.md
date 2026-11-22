# Core rehearsal

Requirement 001 asks for `quality check --base main` on three core branches before core adopts the check: each run's exit code and new-finding count, and no non-hard legacy finding reported as new.

## Method

- Binary: `quality 0.1.0` built from `bb76399` (`nix build .#default`), deep tier with the bundle of `quality db update` dated 2026-11-17 (`sha256:edf475d3…`), `--threads 14`.
- Command, in the branch's checkout: `quality check --base <base> --json --db <bundle> --threads 14`.
- Checkout: a shared clone without files (`git clone --shared --no-checkout`, then `git update-ref --no-deref HEAD <head>` and `git read-tree <head>`), because quality reads the index and the commits, not the work tree.
- Base: `main` is `origin/main` at `75bff92dfa` (2026-11-22). `feature/store-i18n` was merged in `ace84681ff` and deleted, so its run uses that merge's parents: head `246a681f3c`, base `995d9d7461`.
- Quiet host: the run started only below 50 % CPU busy over 5 s (`/proc/stat`, the condition of the Speed criteria), and each branch records the load before and after.
- Legacy check: every non-hard finding is matched against the range. A line finding must stand on a line the range adds or in a file the range adds; a folder finding on a folder that gained an entry; a file length finding on a file that grew; a size or complexity finding on a function whose value rose (lizard on the merge base and the head); a clone finding on a pair that did not exist at the merge base.

## Results (2026-11-22)

| Branch | Head | Merge base | Changed files | Exit | New findings | Hard | Legacy reported as new | Time | CPU busy before, after |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `production` | `b7443aa573` | `d06eb3bcbf` | 488 | 1 | 137 | 0 | 0 | 188 s | 12 %, 11 % |
| `feature/iam-profile-rbac` | `b7a4def00b` | `cd61bb82cd` | 6824 | 1 | 8053 | 84 | at least 32 | 1938 s | 11 %, 25 % |
| `feature/store-i18n` | `246a681f3c` | `995d9d7461` | 6538 | 2 | none | none | none | 659 s | 21 %, 12 % |

The run of 2026-11-14 (binary `e7edfc2`) reached the same verdict for `production` and failed on `gitleaks exceeded its timeout of 300 s` for the other two on a busy host; this run repeats all three on a quiet one.

### production

132 of the 137 findings stand on a line or a folder the range adds. The other 5 are new as well:

- 3 function findings whose value rose: `_apps` in `tests/unit/python/plugins/lookup/test_sso.py` CCN 11 to 12 and parameters 9 to 10, `_apps` in `tests/unit/python/utils/roles/applications/services/test_sso.py` parameters 7 to 8.
- 2 clone findings on the untouched side of a new pair: `tests/unit/python/roles/sys-ctl-cln-disc-space/files/shell/test_script.py:46`, whose partner at line 76 the range adds, and `tests/unit/python/roles/web-app-xwiki/test_blobstore_render_order.py:18`, whose partner in `test_render_stages.py:161` the range adds.

### feature/iam-profile-rbac

84 hard findings: 52 `security.secret`, all from the history scan of the range's commits and mostly in test fakes (`_fake_provision.py`, `test_forms.py`, `test_redact.py`), 29 `security.eval-exec`, 2 `security.shell-exec`, 1 `security.tls-disabled`.

Of the 7969 non-hard findings, 7566 stand on a line, file or folder the range adds, and all 143 function findings off an added line belong to 99 functions whose CCN, length or parameter count rose. Open are 227 clone findings off an added line, whose pairs are not yet checked, 1 `security.partial-scan` on `roles/web-app-mini-qr/files/playwright/test-design.js`, not yet checked, and 32 line findings in three groups that stand on a line the merge base already held:

- 4 `legal.foreign-copyright` findings on unchanged lines (`roles/web-app-docs/meta/services.yml:50`, `roles/web-app-joomla/files/joomla-oidc-plugin/plg_system_keycloak/keycloak.xml:6`, `roles/web-app-n8n/files/javascript/hooks.js:28`, `tests/unit/python/utils/i18n/test_catalog.py:130`): the report notes `base side failed, so every finding of that tool counts as new: scancode exceeded its timeout of 600 s and was killed`.
- 10 `clean.comment` findings on lines whose text the file holds as often as at the merge base, for example `scripts/install/wrapper.sh:11` and `:15`, `scripts/lint/wrapper.sh:8`, `scripts/meta/resolve/diff/affected_roles.sh:33` and `:38`, `tests/unit/python/roles/sys-svc-compose/files/test_prune.py:76`. Each file gained another comment finding, and the line's text rose across the repository (one of them from 973 to 1008 occurrences). `new_fingerprint_hits` in `src/quality/gate.py` counts the fingerprint `(rule, source)` repository-wide and the rise per file by `(path, rule, message)`, so it can hand the repository-wide rise to the legacy line and leave the file's new comment unreported.
- 18 line findings whose text the file holds more often than at the merge base, so a new instance exists, are reported on an older instance of the same text: 8 `coding.workflow-lint` (6 in `.github/workflows/cron-update.yml`, 6 to 8 occurrences), 4 `clean.comment`, 4 `security.temp-path`, 2 `clean.default-value`.

### feature/store-i18n

Exit 2 with `scancode exceeded its timeout of 600 s and was killed` on the head side, on a quiet host. The range adds 6538 files, among them the generated gettext catalogs under `locale/`.

## scancode at 1800 s (2026-11-22, evening)

The same two branches again, with `rules/tools.yml` raising the scancode timeout from 600 s to 1800 s and the run held as the only heavy job of the host (`quality-high` in the agent queue):

| Branch | Exit | Findings | Time | CPU busy before, after |
| --- | --- | --- | --- | --- |
| `feature/store-i18n` | 2 | none | 1861 s | 54 %, 51 % |
| `feature/iam-profile-rbac` | 1 | 8049 | 3020 s | 71 %, 14 % |

- `iam-profile-rbac`: the base side no longer fails, and the 4 `legal.foreign-copyright` findings on unchanged lines are gone (5 to 1, 8053 to 8049 findings).
- `store-i18n`: `scancode exceeded its timeout of 1800 s and was killed` on the head side, with `--processes 14`.
- An earlier attempt the same evening on a busy host (59 to 80 % busy, other test jobs beside it) failed on `gitleaks exceeded its timeout of 300 s` for both branches; it counts for neither timeout.

## Open

- The gate hands a fingerprint rise to an older instance of the same text instead of the instance the range adds.
- scancode exceeds 1800 s on the head side of `store-i18n`; its real need on that range is not measured yet.
- `--base` exports and scans every commit of the range for secrets one by one: on `iam-profile-rbac` the per-commit exports ran from 16:07:11 to past 16:18:13, 1038 commits in 11 minutes (about 0.64 s each), so about 13 of the 32 minutes for its 1243 commits; 10 more minutes went to scancode on the base side until its timeout.
