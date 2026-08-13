#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# Kali Kimi Interface's core is standard-library only; the single test dependency
# is pytest (see .github/workflows/ci.yml). This hook installs it so `pytest`,
# the compileall syntax gate, and the module CLIs work in remote web sessions.
# Idempotent and non-interactive: safe to run on every session start.
set -euo pipefail

# Only run in Claude Code on the web (remote) sessions; a no-op locally.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

python3 -m pip install --quiet --disable-pip-version-check pytest

echo "session-start: pytest ready ($(python3 -m pytest --version 2>&1 | head -1))"
