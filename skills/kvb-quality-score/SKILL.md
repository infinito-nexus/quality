---
name: kvb-quality-score
description: >
  Score fix, break, tokens, velocity, security, legal and architecture; run wherever confidence is reported.
---

Run it wherever fix confidence and break risk are reported: every
`kvb-quality-confidence` block, stage summary, fix report and commit block.
Paste its block verbatim; it replaces prose numbers.

```bash
kvb-quality-python ${CLAUDE_SKILL_DIR}/scripts/score.py --fix <0-100> --break <0-100> --efficiency <n|-|new> --speed <n|-> --security <n|~n> --critical <count> --legal <n|~n> --legal-blockers <count> --architecture <n> [--note <metric>=<text>]...
```

| Emoji | Value | Source |
| --- | --- | --- |
| 🎯 | fix confidence | `kvb-quality-confidence` |
| 💥 | break risk | `kvb-quality-break-risk` |
| 💸 | tokens, `--efficiency` | `measure.py` of `kvb-quality-performance` (code) or the skill-token count (skills) |
| ⏱️ | velocity, `--speed` | `measure.py` of `kvb-quality-performance` |
| 🛡️ | security, critical count | `security.py` of `kvb-quality-security`; `~<n>` from a review by hand |
| ⚖️ | legal, blocker count | `legal` and `legal_blockers` of `quality check --staged --json`; `~<n>` with review findings or unchecked dependencies (`kvb-quality-legal`) |
| 🏛️ | architecture | `architecture` of `quality check --staged --json` |
| 💰 | cost:value quotient, `--value` | 💰 line of the skill-token count |
| 🏆 | score | this script |

Emojis and labels come from `labels.json`, one entry per metric key with
its former labels (Cost, Efficiency, Time, Speed); change a label there,
nowhere else.

Tokens and velocity: after over base in percent, over 100 worse. `-` means not
measured or not relevant (skills have no velocity) and counts as
100; it shows as `–`. `new` (changed skill text without a base) counts as 100
in the score, yet still asks. Never invent a value: measure it or pass `-`.

Score = `fix * (100 - break) / 100 * 100 / tokens * 100 / velocity * security / 100 * legal / 100 * architecture / 100`,
capped to 0..100 and rounded.

## Block

`Metrics:`, one line per value, then the gate after a blank line. A value
that needs a word gets one `--note <metric>=<text>` (one line, one per
metric): a marker (¹, ², ...) follows the value, and the notes follow a
`---` line. With nothing to explain there is no `---`. Read `tables.md`
next to this file before using `--commit-table`, `--message-block` or
`--value`.

## Gate

The last line is the verdict, first match wins:

- `🚦 Gate: ⛔ do not commit: <n> critical security finding(s), <n> legal
  blocker(s)` (exit 4): the commit call is not sent, not even on an earlier
  approval. Fix the finding, rescan, score again.
- `🚦 Gate: ⚠️ ask: fix <f> % < 90, ...` or `break <b> % > 5, ...` (exit 1):
  the 90/5 rule fails, which bars PR labels and the split bar, not a commit:
  commit only on the operator's word. Close the gap as the last section of
  `kvb-quality-break-risk` says.
- `🚦 Gate: ⚠️ ask: <causes>` (exit 3), naming each of `tokens <c> % > 100`,
  `velocity <t> % > 100`, `security <n> % < 100`, `legal <n> % < 100` and
  `architecture <n> % < 100`: ask with the block what the cost buys or why
  each finding is acceptable; commit only on a yes, never carried over to
  another commit.
- `🚦 Gate: ✅ 90/5, tokens and velocity <= 100, security, legal and
  architecture 100 %` (exit 0): commit as usual. 90/5 still needs the full
  test gate green on the exact commit.
- Exit 2: usage error, a malformed `labels.json` or a `--commit-table`
  repository git cannot read, with one stderr line and nothing on stdout;
  fix the cause and score again. A critical finding or a legal blocker still
  exits 4 then.

## Journal

Each `--message-block` render appends a row to the score journal the hub's
burndown draws; no gate reads it. Read `journal.md` next to this file
before reading or refilling it.
