#!/usr/bin/env bash
# diffstat.sh: counts of a change for the job summary (spec section 9 job diff-stat, build plan B04). It never fails
# on content: the job passes whatever the change holds.
#
# Usage: diffstat.sh BASE HEAD [--summary FILE]
#   BASE and HEAD are commits or refs of the repository in the current directory (three-dot semantics are not used:
#   the plain BASE..HEAD difference is counted, renames as a delete plus an add). With --summary FILE a markdown
#   table is appended to FILE (the caller passes $GITHUB_STEP_SUMMARY). Counts only: no file name, line or content.
# Output: VERDICT: PASS and a fenced block with files, insertions, deletions and binary-files.
# Failures (exit 64 for bad input, 1 when git cannot produce the diff): VERDICT: FAIL input <what> or
# VERDICT: FAIL diffstat git-diff, each with the remaining steps.
#
# May call: git diff --numstat, git rev-parse (both with stdin from /dev/null), awk (OPS_CI_AWK overrides), printf.
# No network, no ssh.
# Written for bash 3.2 and BSD userland (awk, sed, find, tr). Verified on bash 3.2 and macOS awk only by the planner's Mac run (see the PR); the author could run bash 5.2 with mawk and original-awk only.
set -euo pipefail
export LC_ALL=C   # byte-wise awk, tr, sed, sort: a multibyte character next to a number or a word must not abort awk (macOS)

AWK="${OPS_CI_AWK:-awk}"

input_fail() {
  echo "VERDICT: FAIL input $1"
  echo '```'
  echo "remaining: $2"
  echo '```'
  exit 64
}

base=""
head=""
summary=""
npos=0
while [ $# -gt 0 ]; do
  case "$1" in
    --summary) [ $# -ge 2 ] || input_fail missing-argument "give a file after --summary"; summary=$2; shift 2 ;;
    -*) input_fail unknown-option "use only BASE HEAD and --summary FILE" ;;
    *)
      npos=$((npos + 1))
      if [ "$npos" -eq 1 ]; then base=$1; elif [ "$npos" -eq 2 ]; then head=$1; else input_fail too-many-arguments "pass exactly BASE and HEAD"; fi
      shift ;;
  esac
done
[ "$npos" -eq 2 ] || input_fail missing-argument "pass BASE and HEAD"
git rev-parse --verify --quiet "$base^{commit}" </dev/null >/dev/null 2>&1 || input_fail bad-base "BASE is not a commit of this repository"
git rev-parse --verify --quiet "$head^{commit}" </dev/null >/dev/null 2>&1 || input_fail bad-head "HEAD is not a commit of this repository"

if ! raw=$(git diff --numstat --no-renames "$base" "$head" -- </dev/null 2>/dev/null); then
  echo "VERDICT: FAIL diffstat git-diff"
  echo '```'
  echo "remaining: run in the repository that holds both commits, then re-run diffstat.sh"
  echo '```'
  exit 1
fi

# shellcheck disable=SC2016  # the awk program is single-quoted on purpose
counts=$(printf '%s\n' "$raw" | "$AWK" '
  NF == 0 { next }
  { files++ ; if ($1 == "-") bin++; else { ins += $1; del += $2 } }
  END { printf "%d %d %d %d\n", files, ins, del, bin }')
read -r files ins del bin <<< "$counts"

if [ -n "$summary" ]; then
  {
    {
      echo "### diff-stat"
      echo ""
      echo "| files | insertions | deletions | binary files |"
      echo "|---|---|---|---|"
      echo "| $files | $ins | $del | $bin |"
    } >> "$summary"
  } 2>/dev/null || input_fail summary-unwritable "make the --summary file writable"
fi

echo "VERDICT: PASS"
echo '```'
echo "files: $files"
echo "insertions: $ins"
echo "deletions: $del"
echo "binary-files: $bin"
echo '```'
