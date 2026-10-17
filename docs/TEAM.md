# The agent team

Nine agents live in `.claude/agents/`. They are different on purpose: the model and the reasoning effort
follow the kind of work, so the expensive models make decisions and the cheap ones run commands.

| Agent | Role | Model | Effort | Can edit | Use it when |
|-------|------|-------|--------|----------|-------------|
| `lead` | Orchestrates a whole session through the workflow below | opus | xhigh | everything (delegates) | `claude --agent lead` to work through the roadmap |
| `architect` | Options, recommendation, test plan, ADR entry | opus | high | nothing | before any change to behaviour or surface |
| `implementer` | Production code in `proxy.py` | sonnet | medium | `proxy.py` | the design is settled and the tests exist |
| `test-engineer` | Tests from the spec; proves they can fail | sonnet | high | `tests/` | new behaviour, regressions, flaky tests |
| `security-auditor` | Attack-surface review with loopback reproductions | opus | high | nothing | parsing, auth, sockets, limits or logging changed |
| `devils-advocate` | The sceptic: best case against a plan, diff or claim | fable | xhigh | nothing | every plan and every "done" before it is accepted |
| `rfc-conformance` | RFC 1928/1929 requirement-by-requirement check | sonnet | medium | nothing | wire behaviour changed |
| `compat-runner` | Runs `make check/strict/py36`, reports facts | haiku | low | nothing | after any change; before "done" |
| `docs-keeper` | Syncs README/ROADMAP/CLAUDE.md numbers and tables | haiku | medium | `*.md` | after any change; before a commit |

Why this mix: the devil's advocate gets the strongest model at high effort because finding what everyone else
missed is the hardest job and the cheapest place to catch a mistake. `compat-runner` and `docs-keeper` execute
commands and copy numbers, which a small model does well and cheaply. The reviewers in between use opus or
sonnet depending on how much judgement the job needs. To change a choice, edit `model:` / `effort:` in the
agent's frontmatter (`sonnet`, `opus`, `haiku`, `fable` or a full model id; `low` to `max`). Not every model
supports every effort level, and a level a model does not support may be ignored or mapped to the nearest one.

## Workflow

```
pick item ─► architect ─► devils-advocate (plan) ─► test-engineer (red) ─► implementer (green)
          └─► security-auditor ┐
              rfc-conformance  ├─ in parallel ─► devils-advocate (diff) ─► compat-runner ─► docs-keeper ─► owner
              (as needed)      ┘
```

- Tests are written from the spec before the implementation, by a different agent than the one who writes the code.
- The devil's advocate sees the plan *and* the diff, max two rounds per item. Whatever is still disputed after
  round two goes to the owner as a short memo, not to a third round.
- Writers run one after another; reviewers run in parallel.
- Anything the README lists under "Not implemented (deliberately)" is an owner decision, never a drive-by change.

## Using it

| You want | Do |
|----------|----|
| Run a whole session as the orchestrator | `claude --agent lead` |
| What should we do next? | `/next` or `/next M1.1` |
| Is everything still green? | `/verify` (runs in `compat-runner`) |
| Attack this plan / diff / claim | `/challenge <what>` (empty = the uncommitted diff) |
| Ready to commit | `/ship` (gate: verify, review, challenge, docs; never pushes) |
| One specialist directly | "Use the security-auditor agent to review the auth path" |

Subagents cannot start other subagents, so orchestration happens in the main session: `lead` when started with
`--agent lead`, otherwise the session you are in. Claude Code loads the files in `.claude/agents/` at session start
(the `/agents` wizard no longer exists); ask Claude which agent types it has, and restart the session after changing
a file there.

## Guard rails (`.claude/settings.json`)

- After every edit of `proxy.py` or `tests/*.py` with the Edit or Write tool, a hook checks that the file compiles
  and runs the static Python 3.6 guards (`tests/test_compat.py`, a few seconds). Failure goes back to the agent that
  made the edit. Edits made through Bash (`sed -i`, heredocs) do not trigger it; `make check` and the pre-commit
  hook catch those later. The static guards cannot prove 3.6 compatibility (an f-string `{x=}` passes them): only
  `make py36` or CI can.
- Before every Bash command, `.claude/hooks/guard_git.py` splits the command line with `shlex` and blocks git
  commits that skip the hooks (`-n` in any short-option group, any abbreviation of `--no-verify`,
  `-c core.hooksPath=...`) and force-pushes (`-f`, `--force*`, `--mirror`, `+refspec`), also inside `sh -c '...'`.
  Glob permission rules alone cannot do this; they missed `git commit -n` and `--force-with-lease`. Its tests run
  in `make check`.
- Allowed without asking: `make` targets, `unittest` runs, read-only git. Asked: `git push`, `git reset --hard`,
  `git clean`, `rm -rf`. Denied by rule: reading `.env`, SSH keys and Claude credentials with the Read tool (a
  `cat` through Bash is asked, not denied).
- `make hooks` makes git run `make check` before every commit (this clone only), on the staged content exported to
  a temporary directory, so unstaged edits cannot make a broken commit pass.
- The "Can edit" column above is enforced by each agent's instructions and tool list, not by a permission rule.
