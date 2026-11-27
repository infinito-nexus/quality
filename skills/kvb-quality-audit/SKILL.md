---
name: kvb-quality-audit
description: >
  Security audit of the code a release changes, with Cloudflare's
  security-audit method, ending in one attestation per tree. Run before
  every release; kvb-release-cut calls it.
---

The audit follows the vendored upstream skill in `upstream/` (pinned in
`lock.json`); `scripts/audit.py` does everything around it that needs no
judgement. Requirement 011 of the quality repository holds the decisions.

## Steps

1. **MEDUSA first.** With `<start>` the newest `vX.Y.Z` tag reachable from
   HEAD (`git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*'`)
   or the start of the range you were given:
   `security.py --repo <root> --base <start> --json` of `kvb-quality-security`,
   its output saved to a file outside the tracked tree.
2. **Prepare.**

   ```bash
   audit.py prepare --repo <root> --out <dir> --budget <n> --medusa <report> [--range <a>..<b>] [--profile quick|standard|deep]
   ```

   `<dir>` lies in `/tmp` or a git-ignored directory of the target, never
   `~/security-audit-skill`; it is created private, and an existing one must
   be yours and writable by no one else. `<report>` lies outside `<dir>`. A
   range that changes no file is refused. A printed document with a
   `verdict` key is the stored attestation of the same tree, range, upstream
   and profile, or a `skipped: docs-only` one: the audit is done, start no
   agent. Otherwise it printed the plan `<dir>/plan-<tree>.json`, the
   agents' copy; attest never reads it back.
3. **Audit.** Run the upstream `SKILL.md` (path in the plan's `skill`) in full
   audit mode on the plan:
   - scope: a diff between the two refs of `range`, the plan's `files` plus
     the trust-boundary neighbours reconnaissance names, nothing else;
   - profile and `budget`: the plan's; the budget caps every agent
     invocation of every phase;
   - output: `<dir>/run-<tree>`, so `findings.json` and
     `coverage-ledger.json` land there;
   - seeds: every entry of the plan's `seeds` enters candidate validation,
     and its record keeps the seed's `fingerprint`;
   - also hunt holes in this skill's own logic and trust handling;
   - target code runs only under the upstream sandbox rules; without an
     enforceable sandbox the step is a `needs_validation` record;
   - models per `kvb-org-perform`; a phase that runs Docker or a test suite
     goes through `queue.py hold` of `kvb-org-queue`.
4. **Attest.**

   ```bash
   audit.py attest --repo <root> --out <dir> --budget <n> --medusa <report> [--range <a>..<b>] [--profile quick|standard|deep] --run <dir>/run-<tree> --invocations <n> --tokens <n> --minutes <n>
   ```

   With the options of step 2 it derives the plan again from the
   repository. It validates both files with the upstream validators (needs
   `node`) and refuses:
   - a ledger whose `reviewed_paths` miss a changed file;
   - a seed or a ledger `result_fingerprints` entry without a findings
     record;
   - a unit still `planned` or `in_progress`;
   - a rejection whose trace and evidence never name the seed's path and
     line.

   It then records each rejected seed as a `security.py accept` row with the
   verdict's reason and writes `<dir>/attestation-<tree>.json`. A `blocked`
   ledger unit blocks like a `needs_validation` record.

## Attestation

`tree`, `range`, `upstream` (commit), `profile`, `budget`, `invocations`,
`verdicts` (`confirmed`, `needs_validation`, `rejected`), `severities` (of the
confirmed ones: `critical` to `informational`), `accepted` (rule, path, line,
sha1 per recorded seed), `tokens`, `minutes` and `verdict`: `pass`, `blocked`
or `skipped: docs-only`.

## Exit codes

- 0: plan written, `pass` or `skipped: docs-only`.
- 1: `blocked`: a confirmed critical or high finding, any
  `needs_validation` record or any `blocked` ledger unit. The release stops.
- 2: usage, lock, range, budget, ownership, validation or unfinished-audit
  error.
