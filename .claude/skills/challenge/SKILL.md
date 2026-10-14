---
name: challenge
description: Put a plan, design, diff or "it is done" claim in front of the devils-advocate agent and get a verdict with evidence. Use before accepting a design, before committing a behaviour change, and whenever everyone agrees too quickly.
argument-hint: [what to challenge: a plan, a file, a claim; empty = the uncommitted diff]
context: fork
agent: devils-advocate
---

Challenge the following: $ARGUMENTS

If nothing was given, challenge the current uncommitted work: run `git status` and `git diff`, and if the tree is
clean, the latest commit (`git show`). Use the repository at the current working directory and follow your
report format. Run experiments rather than only arguing, and say what you could not check.
