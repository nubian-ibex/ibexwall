#!/bin/sh
# Validates DCO sign-off and Conventional Commit subjects for a commit
# range. Usage: check-commits.sh [<base>] [<head>]
# With no resolvable base (first push / new branch) the whole history is
# checked.
set -eu
base="${1:-}"
head="${2:-HEAD}"

range=$(printf '%s' "$base")
if [ -z "$range" ] || ! git rev-parse --verify -q "${base}^{commit}" >/dev/null 2>&1; then
  root=$(git rev-list --max-parents=0 "$head" | tail -1)
  range="${root}"
fi

fail=0
for commit in $(git rev-list "${range}..${head}"); do
  author_name=$(git log -1 --format='%an' "$commit")
  author_email=$(git log -1 --format='%ae' "$commit")
  subject=$(git log -1 --format='%s' "$commit")
  body=$(git log -1 --format='%b' "$commit")

  # DCO: a Signed-off-by trailer matching the commit author.
  if ! printf '%s\n' "$body" | grep -qF "Signed-off-by: ${author_name} <${author_email}>"; then
    echo "missing DCO sign-off matching author: ${commit} ${subject}"
    fail=1
  fi

  # Conventional Commits subject.
  if ! printf '%s' "$subject" | grep -Eq '^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([^)]+\))?!?: .+'; then
    echo "non-conventional subject: ${commit} ${subject}"
    fail=1
  fi

  if [ "${#subject}" -gt 72 ]; then
    echo "subject longer than 72 chars: ${commit} ${subject}"
    fail=1
  fi
done

exit "$fail"
