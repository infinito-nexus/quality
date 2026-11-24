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

## Results on `1d01307` (2026-11-24)

The same heads, bases, bundle and `--threads 14`, with the binary built from `1d01307`: its gate also requires the count of a finding's fingerprint and message in its own file to rise (decision 5), and scancode runs under the 1800 s timeout. Each run started only below 50 % CPU busy.

| Branch | Exit | New findings | Hard | Legacy line findings reported as new | Clone findings off an added line | Time | CPU busy before, after |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `production` | 1 | 137 | 0 | 0 | 0 | 87 s | 9 %, 5 % |
| `feature/iam-profile-rbac` | 1 | 8075 | 84 | 0 | 207 | 988 s | 4 %, 4 % |
| `feature/store-i18n` | 1 | 6082 | 101 | 0 | 166 | 1959 s | 5 %, 5 % |

- `production`: the same 137 findings as on 2026-11-22, explained the same way.
- `iam-profile-rbac`: of the 7991 non-hard findings, 7640 stand on a line, file or folder the range adds, and all 143 function findings off an added line belong to 99 functions whose CCN, length or parameter count rose. The 32 line findings of 2026-11-22 on lines the merge base already held are gone. Open: 207 clone findings and 1 `security.partial-scan` on `roles/web-app-mini-qr/files/playwright/test-design.js`.
- `store-i18n`: the head side completes for the first time. 95 of its 101 hard findings are `security.secret` from the history scan, most of them in the generated catalogs under `locale/`, plus 3 `security.eval-exec`, 2 `security.shell-exec` and 1 `security.tls-disabled`. Of the 5981 non-hard findings, 5686 stand on a line, file or folder the range adds, and all 122 function findings off an added line belong to 87 functions whose values rose. The 7 line and folder findings off an added line are caused by the range too: 5 `clean.comment` on `TODO` lines in `scripts/lint/action.sh` and `scripts/tests/deploy/act/workflow.sh`, whose `# Exception:` lines above them the range deleted; 1 `coding.import-order` on the import block of `cli/build/docs/readme/generate.py`, which the range rewrote; 1 `clean.prefix-groups` on `.github/workflows`, which gained `entry-pr-translate.yml` and renamed `call-test-install-make.yml` to `call-test-install.yml`.
- Clone pairs: a jscpd run over the head's code files with the adapter's thresholds names each open clone finding's partners; a pair counts as old when the stripped lines of both fragments stand contiguously in the merge base. `iam-profile-rbac`: 192 of 207 findings have a new pair, 11 only pairs the base already held, 4 match no pair of the head run. `store-i18n`: 149 of 166 new, 15 only old pairs, 2 unmatched. The likely cause of the 26 old pairs: jscpd pairs a fragment with the first copy it meets, so a copy the range adds elsewhere re-pairs two old copies.

## Open

- 26 clone findings whose pairs both stood at the merge base (11 on `iam-profile-rbac`, 15 on `store-i18n`) are legacy reported as new. The operator picked a pair-aware clone gate (2026-11-24): a clone finding is new only when a line of either half is one the range adds. 238 stays open until the rehearsal runs again with it.
- 6 clone findings (4 on `iam-profile-rbac`, 2 on `store-i18n`) match no pair of the head run and are not yet explained.
- The `security.partial-scan` finding on `iam-profile-rbac` does not come from the file: the `1d01307` binary checks `test-design.js` of the head alone in a one-file repository with Semgrep exit 0 and 0 findings, and Semgrep with the repository's JavaScript rules parses it without an error. It depends on the full run, most likely Semgrep's per-file timeout; the rehearsal rerun for 238 shows whether it repeats.
- `--base` exports and scans every commit of the range for secrets one by one: on `iam-profile-rbac` the per-commit exports ran from 16:07:11 to past 16:18:13, 1038 commits in 11 minutes (about 0.64 s each), so about 13 of the 32 minutes for its 1243 commits; 10 more minutes went to scancode on the base side until its timeout.
