# Commit table and message block

Every layout prints the same block; values, gate and exit code stay:

- `--commit-table <repo>`: `📁 Worktree: <top level>`, `🌿 Branch: <branch>`
  and `📊 Diff stat: <n> files +<a>/-<d>` of the staged change above the
  block. Every commit block is this table; after the commit,
  `--commit <sha>` shows that commit's diff stat and a `🔖 Commit: <sha>`
  line.
- `--message-block`: the block alone, and a row in the score journal.
  Every commit message carries it as its own paragraph right before the
  trailers, passed as one `-m` argument, so the approval prompt and git
  history show the values; git keeps it byte for byte.

On a skill change add `--value <n:n|?>`, the quotient of the 💰 line (`?`
while it has no value): a `💰 Value` line after `🛡️ Security`. It changes
neither score nor gate.
