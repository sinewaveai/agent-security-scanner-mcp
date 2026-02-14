#!/usr/bin/env bash
# =============================================================================
# Pre-commit hook: agent-security-scanner-mcp
# =============================================================================
#
# Scans staged changes for security vulnerabilities before allowing a commit.
#
# Behavior:
#   - BLOCKS the commit if any ERROR-severity issues are found
#   - WARNS (but allows) the commit if only WARNING-severity issues are found
#   - Silently passes if no issues are found
#
# Installation:
#
#   Option 1 — Automatic (recommended):
#     npx agent-security-scanner-mcp init-hooks
#
#   Option 2 — Manual:
#     cp templates/pre-commit-hook.sh .git/hooks/pre-commit
#     chmod +x .git/hooks/pre-commit
#
#   Option 3 — Symlink (stays up to date):
#     ln -sf ../../templates/pre-commit-hook.sh .git/hooks/pre-commit
#
# Configuration:
#   Set environment variables to customize behavior:
#
#     SECURITY_SCAN_THRESHOLD   Minimum severity to block: "error" (default),
#                               "warning", or "info"
#     SECURITY_SCAN_SKIP        Set to "1" to bypass the hook entirely
#     SECURITY_SCAN_VERBOSITY   Output detail: "minimal", "compact" (default),
#                               or "full"
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Allow users to skip the hook via environment variable
if [ "${SECURITY_SCAN_SKIP:-0}" = "1" ]; then
  exit 0
fi

THRESHOLD="${SECURITY_SCAN_THRESHOLD:-error}"
VERBOSITY="${SECURITY_SCAN_VERBOSITY:-compact}"

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------

# Verify that npx is available
if ! command -v npx &> /dev/null; then
  echo "[security-scan] WARNING: npx not found. Skipping security scan."
  echo "[security-scan] Install Node.js 18+ to enable pre-commit scanning."
  exit 0
fi

# Verify that python3 is available (needed by the analyzer)
if ! command -v python3 &> /dev/null; then
  echo "[security-scan] WARNING: python3 not found. Skipping security scan."
  echo "[security-scan] Install Python 3 to enable pre-commit scanning."
  exit 0
fi

# ---------------------------------------------------------------------------
# Get staged files
# ---------------------------------------------------------------------------

# Get list of staged files that are added or modified (not deleted)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
  # No staged files to scan
  exit 0
fi

# Filter to only scannable file types
SCANNABLE_FILES=""
for FILE in $STAGED_FILES; do
  case "$FILE" in
    *.py|*.js|*.ts|*.tsx|*.jsx|*.java|*.go|*.rb|*.php|*.rs|*.c|*.cpp|*.cc|*.h|*.hpp|*.cs|*.tf|*.hcl|*.sql)
      SCANNABLE_FILES="$SCANNABLE_FILES $FILE"
      ;;
  esac
done

SCANNABLE_FILES=$(echo "$SCANNABLE_FILES" | xargs)

if [ -z "$SCANNABLE_FILES" ]; then
  # No scannable files in this commit
  exit 0
fi

# ---------------------------------------------------------------------------
# Run the security scan on staged changes
# ---------------------------------------------------------------------------

echo "[security-scan] Scanning staged changes for security vulnerabilities..."

# Create a temporary file for scan output
SCAN_OUTPUT=$(mktemp)
trap 'rm -f "$SCAN_OUTPUT"' EXIT

# Use scan-diff to analyze only the staged changes.
# We compare the index (staged) against HEAD to get exactly what will be committed.
set +e
npx -y agent-security-scanner-mcp scan-diff HEAD \
  --verbosity "$VERBOSITY" > "$SCAN_OUTPUT" 2>&1
SCAN_EXIT=$?
set -e

# ---------------------------------------------------------------------------
# Parse and evaluate results
# ---------------------------------------------------------------------------

# Try to parse the JSON output
if ! python3 -c "import json; json.load(open('$SCAN_OUTPUT'))" 2>/dev/null; then
  # If the output is not valid JSON, it may be an error message
  if [ $SCAN_EXIT -ne 0 ]; then
    echo "[security-scan] WARNING: Scanner returned an error. Allowing commit."
    echo "[security-scan] Output:"
    head -5 "$SCAN_OUTPUT" 2>/dev/null || true
  fi
  exit 0
fi

# Extract counts from the scan results
COUNTS=$(python3 -c "
import json, sys
try:
    data = json.load(open('$SCAN_OUTPUT'))
    total = data.get('issues_count', data.get('total', 0))
    issues = data.get('issues', [])
    error_count = sum(1 for i in issues if i.get('severity', '').upper() == 'ERROR')
    warning_count = sum(1 for i in issues if i.get('severity', '').upper() == 'WARNING')
    info_count = total - error_count - warning_count
    print(f'{total} {error_count} {warning_count} {info_count}')
except Exception:
    print('0 0 0 0')
" 2>/dev/null)

TOTAL=$(echo "$COUNTS" | cut -d' ' -f1)
ERRORS=$(echo "$COUNTS" | cut -d' ' -f2)
WARNINGS=$(echo "$COUNTS" | cut -d' ' -f3)
INFOS=$(echo "$COUNTS" | cut -d' ' -f4)

# No issues: pass silently
if [ "$TOTAL" -eq 0 ]; then
  echo "[security-scan] No security issues found."
  exit 0
fi

# ---------------------------------------------------------------------------
# Display findings
# ---------------------------------------------------------------------------

echo ""
echo "============================================================"
echo "  Security Scan Results"
echo "============================================================"
echo "  Errors:   $ERRORS"
echo "  Warnings: $WARNINGS"
echo "  Info:     $INFOS"
echo "  Total:    $TOTAL"
echo "============================================================"

# Show individual issues (up to 10)
python3 -c "
import json
try:
    data = json.load(open('$SCAN_OUTPUT'))
    issues = data.get('issues', [])
    shown = 0
    for issue in issues[:10]:
        sev = issue.get('severity', '?')
        line = issue.get('line', '?')
        rule = issue.get('ruleId', '?')
        msg = issue.get('message', '')[:80]
        file_path = issue.get('file', issue.get('filePath', ''))
        loc = f'{file_path}:{line}' if file_path else f'line {line}'
        print(f'  [{sev}] {loc} — {rule}: {msg}')
        shown += 1
    if len(issues) > 10:
        print(f'  ... and {len(issues) - 10} more issue(s)')
except Exception:
    pass
" 2>/dev/null

echo ""

# ---------------------------------------------------------------------------
# Decide: block or warn
# ---------------------------------------------------------------------------

BLOCK=0

case "$THRESHOLD" in
  error)
    if [ "$ERRORS" -gt 0 ]; then
      BLOCK=1
    fi
    ;;
  warning)
    if [ "$ERRORS" -gt 0 ] || [ "$WARNINGS" -gt 0 ]; then
      BLOCK=1
    fi
    ;;
  info)
    if [ "$TOTAL" -gt 0 ]; then
      BLOCK=1
    fi
    ;;
esac

if [ "$BLOCK" -eq 1 ]; then
  echo "COMMIT BLOCKED: Security issues at or above '$THRESHOLD' severity were found."
  echo ""
  echo "Options:"
  echo "  1. Fix the issues and try again"
  echo "  2. Skip this check:  SECURITY_SCAN_SKIP=1 git commit ..."
  echo "  3. Lower the threshold:  SECURITY_SCAN_THRESHOLD=error git commit ..."
  echo ""
  exit 1
else
  # Issues found but below threshold — warn and allow
  echo "WARNING: Security issues found, but none at or above '$THRESHOLD' severity."
  echo "Commit will proceed. Consider fixing the warnings above."
  echo ""
  exit 0
fi
