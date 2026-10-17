---
name: ship
description: Pre-commit gate for finished work. Runs verification, the devils-advocate pass, the doc sync and prepares a commit message. Never pushes. Use only when the owner asks to ship or commit.
disable-model-invocation: true
argument-hint: [optional note for the commit message]
---

Run this gate in order and stop at the first failure, reporting it.

1. `git status` and `git diff --stat`: list what would be committed. Flag anything that should not be there
   (scratch files, `settings.local.json`, bytecode).
2. Run the `/verify` skill. A `FAIL` stops the gate. If `proxy.py` or `tests/` changed, `py36` must be `PASS`, or a
   green CI run for this exact commit must be linked; `py36: NOT RUN` alone stops the gate for such a change (hard
   constraint 2 cannot be checked any other way). For other changes `NOT RUN` is stated in the summary.
3. If `proxy.py` changed: ask `security-auditor` to review the diff, and ask `rfc-conformance` too if wire
   behaviour changed. Run both in parallel. Unanswered high-severity findings stop the gate.
4. Run the `/challenge` skill on the diff. Unanswered BLOCKERs stop the gate; MAJOR objections are listed in the
   summary with the answer or the owner's decision.
5. Ask `docs-keeper` to sync README.md / ROADMAP.md with the change and tick the finished roadmap items.
   If steps 3 to 5 changed any file other than Markdown, go back to step 2: what is committed must be what was verified.
6. Show the final `git diff --stat` (and the full diff of anything changed after step 2) and propose a commit message: one imperative sentence without prefix
   (match `git log --oneline`), a body only if the why is not obvious, then the attribution trailer.
   $ARGUMENTS
7. Commit only if the owner confirms. Never push, never `--no-verify`.
