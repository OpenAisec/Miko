#!/bin/bash
# Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause

# Skill Path Detection Helper for threat-modeling skill
# Usage: SKILL_PATH=$(bash skill_path.sh)
#        python "$SKILL_PATH/scripts/unified_kb_query.py" --stride spoofing

set -euo pipefail

SKILL_NAME="threat-modeling"

# 1. Check $SKILL_PATH (Codex sets this)
if [ -n "${SKILL_PATH:-}" ] && [ -d "${SKILL_PATH}" ]; then
    echo "${SKILL_PATH}"
    exit 0
fi

# 2. Check $CLAUDE_SKILL_DIR (Claude Code sets this)
if [ -n "${CLAUDE_SKILL_DIR:-}" ] && [ -d "${CLAUDE_SKILL_DIR}" ]; then
    echo "${CLAUDE_SKILL_DIR}"
    exit 0
fi

# 3. Check if running from skill directory itself
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/SKILL.md" ]; then
    echo "${SCRIPT_DIR}"
    exit 0
fi

# 4. Probe known install paths (F-09: require SKILL.md presence)
for candidate in \
    "${HOME}/.codex/skills/${SKILL_NAME}" \
    "${HOME}/.claude/skills/${SKILL_NAME}" \
    ".codex/skills/${SKILL_NAME}" \
    ".claude/skills/${SKILL_NAME}"
do
    if [ -d "${candidate}" ] && [ -f "${candidate}/SKILL.md" ]; then
        echo "$(cd "${candidate}" && pwd)"
        exit 0
    fi
done

# Not found
echo "Error: ${SKILL_NAME} skill not found" >&2
echo "Install locations checked:" >&2
echo "  - \$SKILL_PATH (env)" >&2
echo "  - \$CLAUDE_SKILL_DIR (env)" >&2
echo "  - ${SCRIPT_DIR}/ (script location)" >&2
echo "  - ~/.codex/skills/${SKILL_NAME}" >&2
echo "  - ~/.claude/skills/${SKILL_NAME}" >&2
exit 1
