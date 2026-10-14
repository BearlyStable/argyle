---
name: verify
description: Run the project's full verification (static Python 3.6 guards, the strict full suite, and the Python 3.6 container run when Docker exists) and report exactly what passed, failed or was not run. Use before saying work is done, before a commit, or when asked whether everything still works.
context: fork
agent: compat-runner
---

Verify the repository at the current working directory. Run `make check`, then `make strict`, then `make py36`,
exactly as your instructions describe, and answer in the required report format. Do not fix anything.
$ARGUMENTS
