---
name: kvb-quality-performance
description: >
  Measure the CPU, RAM and wall-clock time of a code change against its
  base: the values kvb-quality-score takes as --efficiency and --speed.
---

💸 Tokens is the share of the base's CPU and RAM a code change uses: under
100 % it saves, over 100 % it costs more. Paste the script's line, never a
paragraph about it. `<ref>` is the commit the change starts from: `HEAD` for
uncommitted work, the merge base with the default branch for a branch.

## CPU and RAM

```bash
kvb-quality-python ${CLAUDE_SKILL_DIR}/scripts/measure.py --base <ref> -- <command...>
```

Start it in the directory the command expects. It checks `<ref>` out as a
detached worktree under the temporary directory (`$TMPDIR`, else `/tmp`),
runs the command there and in the working tree from the same relative
directory, compares CPU seconds and peak RSS, and removes the worktree. Cost
is the mean of the CPU and the RAM ratio; pass it as `--efficiency` to
`kvb-quality-score`.

- **Runs**: one per tree. Both values at most 100 end it; otherwise 4 more
  per tree, alternating, and the line reports the mean of all 5
  (`mean of 5`).
- **Other load**: CPU busy beyond the command's own above 30 %, or no
  `/proc/stat`, makes the result an estimate: velocity from the CPU-time
  ratio, both values marked `~`, the line ending in `(estimated: other load
  <x> %)`. Pass the numbers without `~`; the exit code holds.
- **Command**: the targeted tests of the change or a CLI call of the
  changed code, runnable on a clean checkout: the base worktree holds no
  untracked build output, virtualenv or dependency directory.
- **Every run** goes in the background, inside the caller's queue for heavy
  jobs where one exists; a wait cancelled there prints no 💸 line.
- Report the run you made; never rerun to pick the best result.

## Velocity

⏱️ Velocity is the share of the base's wall-clock time a change needs,
`⏱️ velocity <p> % (wall <b>→<a> s)` in the same `measure.py` line; pass
it as `--speed` to `kvb-quality-score`. Code without a runnable path
(configuration, templates no command renders) passes `--speed -`, shown as
`–`; say why.

## Exit codes

- `0`: at most 100.
- `3`: over 100: pass the value to `kvb-quality-score`; its gate asks the
  operator before the commit.
- `2`: usage error, or the command failed; the message names the tree, the
  exit code and the last stderr line. Fix the command, then measure.

`--json` prints the same figures as JSON.
