---
name: next
description: Read ROADMAP.md, pick the next actionable item (or the one named), and propose which agents should do what, in which order. Use when asked what to work on next or to start a roadmap item.
argument-hint: [optional roadmap item id, e.g. M1.1]
---

1. Read `ROADMAP.md` and `CLAUDE.md`. Run `git status` and `git log --oneline -5` to see where the tree is.
2. Choose the item: `$ARGUMENTS` if given; otherwise the first unchecked item in the lowest open milestone that is
   not marked "owner decision" and not blocked by an unchecked prerequisite.
3. If the item is an owner decision, say so, summarise the options and the recommendation from the roadmap, and
   ask the owner. Do not start it.
4. Otherwise print a short plan: the outcome to check, the agents to use in order (see `docs/TEAM.md`:
   architect, devils-advocate, test-engineer, implementer, reviewers, compat-runner, docs-keeper), the commands
   that will prove it is done, and the risks. Skip the agents the item does not need.
5. Ask whether to proceed, unless the owner already said to.
