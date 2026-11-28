# 011 - Release Security Audit

## User Story

As the maintainer who cuts a release with skills' `kvb-release-cut`, I want a `kvb-quality-audit` skill that audits the code changed since the last release with Cloudflare's security-audit method and hands back one attestation per tree, so that no release ships a confirmed critical or high vulnerability and an unchanged tree is never audited twice.

## Decisions (operator-confirmed 2026-11-27; do not re-litigate)

1. **Own skill in quality**: `skills/kvb-quality-audit/`, the ninth `kvb-quality-*` folder; 003 decision 1 (exactly eight) is amended to nine. Called by skills' `kvb-release-cut` (skills requirement 076). Rejected: a lens inside `kvb-quality-security` (MEDUSA stays the fast per-commit scan; the audit is the slow per-release one).
2. **Pinned upstream, vendored**: `cloudflare/security-audit-skill` (MIT) is vendored under `skills/kvb-quality-audit/upstream/` at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` with its `LICENSE` and a lock file holding the commit and a sha256 per file; attribution in the skill's README and the repository's notice list. Upstream has no tags, so the pin is a commit. Rejected: fetching at run time (network per release, unpinned code).
3. **Range**: newest `vX.Y.Z` tag reachable from HEAD to HEAD; `--range <a>..<b>` overrides. Scope is the changed files plus the trust-boundary neighbours the reconnaissance phase names; a range that changes only Markdown, plain text or images is skipped with the attestation verdict `skipped: docs-only`. Rejected: whole-repository audits per release (cost).
4. **MEDUSA seeds validation**: the MEDUSA findings of the range (from `kvb-check-security`'s per-file cache) enter the validation phase as candidates. A `rejected` verdict with its source trace becomes the `security.py accept` row of that finding; no manual skeptic round. The audit also hunts holes in its own logic and trust handling.
5. **Release block**: a `confirmed` critical or high finding blocks the release (exit 1); `needs_validation` records carry no severity upstream and block by decision 9.
6. **Output outside the tree**: every run writes to the directory `--out` names (`/tmp/...` or a git-ignored directory of the target), never `~/security-audit-skill`; a tracked path is refused. Target code runs only in the upstream's sandbox rules (no network, empty environment, read-only target); without an enforceable sandbox the step is recorded as `needs_validation`, never run.
7. **Cost first**: reuse the attestation of an unchanged tree (same tree id: no run), the MEDUSA per-file cache and the 064 review memory; upstream profile `quick` unless `--profile` says otherwise; an agent budget (`--budget <n>`, required) caps every agent invocation; models per `kvb-org-perform`; phases that run Docker or a test suite go through `queue.py hold`. Every attestation reports tokens and minutes.
8. **Attestation**: `attestation-<tree id>.json` in `--out`: tree id, range, upstream pin, profile, budget used, counts per verdict (`confirmed`, `needs_validation`, `rejected`) and per severity of the confirmed ones, accepted MEDUSA rows, tokens, minutes, and the verdict `pass`, `blocked` or `skipped: docs-only`. `findings.json` must pass upstream's `validate-findings.cjs` and the ledger `validate-coverage-ledger.cjs` before an attestation is written.
9. **needs_validation fails closed**: every `needs_validation` record blocks the release (attestation `blocked`, exit 1) until a later run confirms or rejects it. Rejected: blocking only candidates seeded by a critical or high MEDUSA finding (the audit's own unverified finds would pass), listing only (an unverified hole would ship).

## Approach

```mermaid
flowchart TD
    subgraph P["🧭 0 · Preparation"]
        P1["📋 Requirement 011"] --> P2{"✅ Operator approves?"}
        P2 -- "✏️ corrections" --> P1
    end
    P2 -- "🤖 yes" --> A1
    subgraph A["📦 A · Vendor and scope"]
        A1["📥 Vendor upstream at the pinned commit, lock and attribution"] --> A2["🧮 Range, changed files, docs-only skip, tree reuse"]
        A2 --> A3{"🧪 Lock, range and reuse tests green?"}
        A3 -- "🔴 no: fix" --> A1
    end
    A3 -- "🟢 yes" --> B1
    subgraph B["🔍 B · Audit and attest"]
        B1["🌱 MEDUSA candidates into validation"] --> B2["🤖 Upstream phases within the budget"]
        B2 --> B3["✅ validate-findings and coverage ledger"]
        B3 --> B4["📜 Attestation, acceptance rows, block verdict"]
        B4 --> B5{"🧪 Fixture findings give the right attestation and exit?"}
        B5 -- "🔴 no: fix" --> B1
        B5 -- "🟢 yes" --> BF{"💬 Operator feedback on a real audit of quality v1.1.0..HEAD?"}
        BF -- "✏️ changes" --> B1
    end
    BF -- "👍 fits" --> D1["🏁 Review, commit with operator OK, minor release, tag and command to Skills"]
```

## Acceptance Criteria

### Vendor

- [x] `skills/kvb-quality-audit/upstream/` holds the upstream `skills/security-audit/` files and `LICENSE` at the pinned commit; `lock.json` names the commit and a sha256 per file, and a test fails on any changed byte.
- [x] The skill's README and the repository notice name Cloudflare, the MIT licence and the upstream URL.
- [x] `skills/` holds nine `kvb-quality-*` folders and 003 decision 1 says nine.

### Scope

- [x] Without `--range`, the range is the newest `vX.Y.Z` tag reachable from HEAD to HEAD; with none, the run exits 2 naming `--range`.
- [x] A docs-only range writes the verdict `skipped: docs-only` and starts no agent.
- [x] A second run on the same tree id returns the stored attestation and starts no agent.
- [x] `--out` on a tracked path, or missing, exits 2.

### Audit

- [x] MEDUSA findings of the range appear as validation candidates; a `rejected` one with a source trace produces exactly one `security.py accept` row.
- [x] A `confirmed` critical or high finding makes the attestation `blocked` and the command exit 1; only lower ones give `pass` and exit 0.
- [x] One `needs_validation` record, of any origin, makes the attestation `blocked` and the command exit 1.
- [x] An attestation is written only after `validate-findings.cjs` and `validate-coverage-ledger.cjs` exit 0.
- [x] A coverage ledger whose `reviewed_paths` miss a changed file is refused with exit 2, since the upstream validator accepts an empty ledger: `test_a_ledger_that_skips_a_changed_file_is_refused`.

### Audit hardening (operator checkpoint 2026-11-27: the first real audit of v1.1.0..HEAD found these in audit.py)

- [x] attest derives tree, files, seeds, out and budget from `--repo` and the prepare options and never reads the plan file back: `test_attest_derives_the_plan_and_never_trusts_the_plan_file`.
- [x] A seed or a ledger candidate without a findings record, or a unit still planned or in progress, leaves the audit unfinished (exit 2): `test_a_seed_without_a_record_leaves_the_audit_unfinished`, `test_a_ledger_candidate_without_a_record_leaves_the_audit_unfinished`.
- [x] The seed fingerprint binds rule, path, line and line digest, and a rejection must name the seed's path and line before it becomes an accept row: `test_identical_lines_in_two_files_are_two_seeds`, `test_a_rejection_that_never_names_the_seed_is_refused`.
- [x] A stored attestation is reused only for the same tree, range, upstream and profile, and a range without changes is refused: `test_a_stored_attestation_answers_only_the_same_request`, `test_a_range_without_changes_is_refused`.
- [x] `--out` is created private; an existing one others can write, or a `--medusa` report inside it, is refused: `test_an_out_dir_others_can_write_is_refused`, `test_a_medusa_report_the_agents_can_write_is_refused`.
- [x] `quality image` treats only an absolute or `./`-relative target as a path and refuses a bare target that names a file, so a planted file cannot replace the daemon image (requirement 010 scope, found by the same audit): `test_a_file_named_like_a_ref_never_replaces_the_daemon_image`.
- [x] Agent invocations never exceed `--budget`; the attestation reports the budget used, tokens and minutes.

### Audit hardening, round 2 (operator pick "Fix the 9, then run 3": the second real audit of v1.1.0..HEAD found these)

- [x] Without `--range` the start is the newest `vX.Y.Z` tag on the first-parent line of HEAD, so a tag on a merged side commit never shrinks the range: `test_a_tag_on_a_merged_side_commit_never_moves_the_start`.
- [x] Build inputs, agent instructions, paths under agent directories and deleted files never count as documentation: `test_build_inputs_and_agent_instructions_are_never_docs`, `test_a_deleted_file_is_never_docs`.
- [x] A blocked archived attempt blocks, a candidate of an archived attempt without a record leaves the audit unfinished, and the attestation counts the live unit statuses under `coverage`: `test_an_archived_blocked_attempt_blocks`, `test_an_archived_candidate_without_a_record_leaves_the_audit_unfinished`.
- [x] A blocked audit records no `security.py accept` row: `test_a_blocked_audit_records_no_acceptance`.
- [x] A stored attestation is reused only for the same budget too and only while its run supports its verdict and counts; a planted one is refused: `test_a_planted_pass_attestation_is_refused_on_reuse`, `test_a_planted_docs_only_attestation_is_refused_on_reuse`.
- [x] attest reads `<out>/run-<tree>` and takes no `--run`; every directory above `--out` must belong to root or the caller and be sticky or writable by no one else, where a user namespace that maps no root counts its overflow uid as root: `test_an_out_dir_under_a_directory_others_can_change_is_refused`, `test_only_a_namespace_without_root_trusts_the_overflow_uid`.
- [x] `security.py accept` without `--line` refuses a sha1 that names no line of the file and is not the whole file's: `test_a_sha1_of_no_line_and_not_of_the_file_is_never_accepted`.
- [x] `quality image` leaves an image unscanned when trivy exits 0 after a parse error (requirement 010 scope): `test_a_trivy_parse_error_on_exit_0_leaves_the_image_unscanned`.
- [x] `quality db update` refuses a bundle root that turned into a link or file during the update and never changes the link's target (requirement 010 scope): `test_update_never_opens_a_tree_swapped_in_for_the_bundle`.

### Docs

- [x] The skill's SKILL.md names the command, every option, the attestation schema and the exit codes; README lists the skill.

### Tests

- Unit: lock verification, range resolution, docs-only detection, attestation counts and verdict per fixture `findings.json`, tracked-path refusal.
- Integration: fixture `findings.json` and ledger through the real upstream validators to an attestation; MEDUSA fixture to one acceptance row; same tree reuse without agents.
- E2E: one real audit of quality `v1.1.0..HEAD` at profile `quick` with its attestation, tokens and minutes shown at the operator checkpoint.
- [x] E2E met 2026-11-28 (operator pick "Fits", decision 98d608756a91afba): run 3 audited `v1.2.0..HEAD` on tree 3f412e19, since v1.2.0 shipped during the work; attestation `blocked` with 14 of 20 invocations, 1926203 tokens and 44 minutes, 5 needs_validation and 3 rejected records go to a follow-up requirement.
