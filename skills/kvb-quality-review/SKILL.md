---
name: kvb-quality-review
description: >
  Run every measurable Quality check on one change and print one JSON:
  findings, scores, lens versions, skipped lenses. Confirm every added
  Exception comment before a commit.
---

The measurable base of a review. Judgements stay with its callers.

## Call

```bash
${CLAUDE_SKILL_DIR}/scripts/review.py --repo <root> \
  (--base <ref> | --staged | --range <a>..<b> | --all) \
  [--path <file>]... [--db <dir>] [--measure] --json [-- <command...>]
```

- `--range <a>..<b>` reviews the commits from the merge base of `a` and
  `b` up to `b`; a history finding names the commit that added it.
- `--path` is repeatable and limits every lens and score to those files.
- `--measure` needs the command to measure after `--`.

## Lenses

| Lens | Source | Runs |
| --- | --- | --- |
| `quality` | `quality check`, fast tier | always |
| `quality-deep` | `quality check`, deep tier | only with `--db`, never with `--staged` |
| `legal` | `quality check`, rules with a legal weight | with `quality` |
| `architecture` | `quality check`, rules with an architecture weight | with `quality` |
| `security` | `kvb-quality-security` `security.py --json` | needs a base commit and the change in the working tree |
| `performance` | `kvb-quality-performance` `measure.py --json` | only with `--measure` |

`.qualityignore.yml` and folder `.nocheck` apply through `quality check`.
The security, legal and architecture lenses honour the shared
accepted-findings ledger. `security` scans the working tree against the
base and keeps findings in the files the change adds or modifies; a scan
`security.py` cannot score (its exit 4) is skipped with its problem.
`break_risk` and `confidence` are judgements: they stay `null`, and
`skipped` names `kvb-quality-break-risk` and `kvb-quality-confidence`.
`--all` has no base, so `legal` and `architecture` report findings but no
score, and `security` is skipped; so are `security` and `performance` for a
`--range` whose end is not `HEAD`.

## Output

```json
{"findings": [{"lens": "", "rule": "", "severity": "", "path": "", "line": 1,
  "message": "", "commit": null, "tier": "fast", "blob": ""}],
 "scores": {"security": 100, "legal": 100, "architecture": 100,
  "break_risk": null, "confidence": null, "efficiency": null, "speed": null},
 "lenses": {"quality": "quality 0.3.0 rules sha256:..."},
 "ran": ["quality"],
 "skipped": [{"lens": "quality-deep", "reason": ""}]}
```

- `blob`: the file's blob hash at the target (the index for `--staged`
  and `--all`); for a history finding at its commit; for `security` of the
  working tree file it scanned.
- `commit`: the commit of a history finding, else `null`.
- `tier`: `fast` or `deep` for the lenses of `quality check`, else `null`.
- `legal` reads `~<n>` while a licence stayed unchecked.

## Exit codes

- `0`: no finding.
- `1`: findings.
- `2`: usage error (no mode, two modes, an unknown option) or a tool error;
  stderr names the lens.

## Exception comments

Narrative comments are forbidden, `Exception:` ones too: why the code is
shaped this way goes into the commit body. `Exception:` stays a marker for
a real exception only, a concrete trip-wire the code itself cannot show.
Before every commit:

```bash
${CLAUDE_SKILL_DIR}/scripts/exceptions.py --repo <root> --staged
```

It lists every Exception comment the change adds and exits `1` until each
listed line is passed as `--confirm <path>:<line>`. Confirm a line only
after deciding it is a real exception; otherwise delete it. `--base <ref>`
checks the working tree instead; exit `2` is a usage or git error.
