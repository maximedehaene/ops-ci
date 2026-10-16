#!/usr/bin/env bash
# check_old_wording.sh: retired-phrasing grep (spec section 9 job old-wording-grep, decision 14, build plan B04).
# Fails when a file holds a phrasing listed in checks/old-wording.txt (one extended regex per line, # comments).
# Matching is case-insensitive. Any run of spaces, tabs, hyphens, underscores, Unicode dashes (U+2010..U+2015,
# U+2212, U+00AD) and no-break spaces counts as one separator, zero-width characters are ignored, and a phrase
# wrapped over two lines is found. Not caught on purpose: words inserted or reordered ("one, live change"),
# other spellings, and phrases built from variables. The list file itself is never scanned.
#
# Usage: check_old_wording.sh [--list FILE] [--exclude PATH]... PATH...
#   PATH is a file or a directory (walked, .git skipped, symlinks not followed). --list defaults to
#   ../checks/old-wording.txt next to this script. --exclude skips that file or directory.
# Exit: 0 PASS, 1 FAIL (a phrasing found, or a fail-closed condition), 64 input error.
# Fail closed: an unreadable or empty list, a list line using a backslash escape other than a leading or trailing \b,
# no file scanned, an unreadable file and an awk error are all FAIL, never PASS.
# Output: the VERDICT line, then a fenced block: counts, "hit: <file>:<line> P<k>" (k = line k of the patterns,
# not the text), and the remaining steps. Paths with a newline are not supported.
#
# May call: awk (OPS_CI_AWK overrides), sed, tr, find, sort, cat, printf, cd, pwd. No network, no git, no ssh.
# Written for bash 3.2 and BSD userland (awk, sed, find, tr). Verified on bash 3.2 and macOS awk only by the planner's Mac run (see the PR); the author could run bash 5.2 with mawk and original-awk only.
set -euo pipefail
export LC_ALL=C   # byte-wise awk, tr, sed, sort: a multibyte character next to a number or a word must not abort awk (macOS)

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AWK="${OPS_CI_AWK:-awk}"
ENGINE="$HERE/lib/old_wording.awk"
LIST="$HERE/../checks/old-wording.txt"

input_fail() {
  echo "VERDICT: FAIL input $1"
  echo '```'
  echo "remaining: $2"
  echo '```'
  exit 64
}
fail() { # fail <name> <remaining> [block lines...]
  local name=$1 rem=$2
  shift 2
  echo "VERDICT: FAIL old-wording $name"
  echo '```'
  while [ $# -gt 0 ]; do echo "$1"; shift; done
  echo "remaining: $rem"
  echo '```'
  exit 1
}
abspath() { # abspath <existing path>: no symlink resolution, enough to compare two names for one file
  local d b
  if [ -d "$1" ]; then (cd "$1" && pwd); return; fi
  d=$(cd "$(dirname "$1")" && pwd) || return 1
  b=$(basename "$1")
  echo "$d/$b"
}

# a relative name gets ./ before it reaches awk, find or dirname: "x=y.md" would be an awk assignment, "-" stdin
dotslash() { case "$1" in /*|./*|../*) printf '%s\n' "$1" ;; *) printf './%s\n' "$1" ;; esac; }
paths=()
excludes=()
while [ $# -gt 0 ]; do
  case "$1" in
    --list) [ $# -ge 2 ] || input_fail missing-argument "give a file after --list"; LIST=$2; shift 2 ;;
    --exclude) [ $# -ge 2 ] || input_fail missing-argument "give a path after --exclude"; excludes+=("$2"); shift 2 ;;
    --) shift; while [ $# -gt 0 ]; do paths+=("$1"); shift; done ;;
    -*) input_fail unknown-option "use only --list FILE, --exclude PATH and paths" ;;
    *) paths+=("$1"); shift ;;
  esac
done
LIST=$(dotslash "$LIST")
[ "${#paths[@]}" -gt 0 ] || input_fail no-paths "pass at least one file or directory"
[ -r "$ENGINE" ] || input_fail engine-missing "restore scripts/lib/old_wording.awk"
[ -f "$LIST" ] && [ -r "$LIST" ] || fail list-unreadable "restore the pattern list or pass --list FILE" "list: unreadable"

# exclusions: the pattern list itself plus --exclude paths (a directory excludes everything under it)
skip=("$(abspath "$LIST")")
if [ "${#excludes[@]}" -gt 0 ]; then
  for e in "${excludes[@]}"; do
    e=$(dotslash "$e")
    [ -e "$e" ] || input_fail exclude-missing "an --exclude path does not exist"
    skip+=("$(abspath "$e")")
  done
fi
is_skipped() { # is_skipped <file>
  local a e
  a=$(abspath "$1")
  for e in "${skip[@]}"; do
    [ "$a" = "$e" ] && return 0
    case "$a" in "$e"/*) return 0 ;; esac
  done
  return 1
}

# collect the files
tmp=$(mktemp "${TMPDIR:-/tmp}/old-wording.XXXXXX")
trap 'rm -f "$tmp" "$tmp.in"' EXIT
for p in "${paths[@]}"; do
  p=$(dotslash "$p")
  if [ -d "$p" ]; then
    find "$p" -name .git -prune -o -type f -print | LC_ALL=C sort >> "$tmp"
  elif [ -f "$p" ]; then
    echo "$p" >> "$tmp"
  else
    fail unreadable "fix the path and re-run" "missing: $p"
  fi
done

# normalise the Unicode look-alikes (bytes; the C locale keeps BSD sed byte-exact), keep line numbers
NBSP=$'\xc2\xa0'; SHY=$'\xc2\xad'; MINUS=$'\xe2\x88\x92'
D0=$'\xe2\x80\x90'; D1=$'\xe2\x80\x91'; D2=$'\xe2\x80\x92'; D3=$'\xe2\x80\x93'; D4=$'\xe2\x80\x94'; D5=$'\xe2\x80\x95'
ZW0=$'\xe2\x80\x8b'; ZW1=$'\xe2\x80\x8c'; ZW2=$'\xe2\x80\x8d'; WJ=$'\xe2\x81\xa0'; BOM=$'\xef\xbb\xbf'
normalise() {
  tr -d '\000' < "$1" | LC_ALL=C sed -e "s/$NBSP/ /g" -e "s/$SHY/-/g" -e "s/$MINUS/-/g" \
    -e "s/$D0/-/g" -e "s/$D1/-/g" -e "s/$D2/-/g" -e "s/$D3/-/g" -e "s/$D4/-/g" -e "s/$D5/-/g" \
    -e "s/$ZW0//g" -e "s/$ZW1//g" -e "s/$ZW2//g" -e "s/$WJ//g" -e "s/$BOM//g"
}

nfiles=0
hits=""
nhits=0
patterns=-1
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if is_skipped "$f"; then continue; fi
  [ -r "$f" ] || fail unreadable "fix the file permissions and re-run" "unreadable: $f"
  nfiles=$((nfiles + 1))
  # one awk run per file: the normalised text is fed through a temp file named like the original for the report
  if ! normalise "$f" > "$tmp.in"; then fail unreadable "fix the file and re-run" "unreadable: $f"; fi
  rc=0
  out=$("$AWK" -v "list=$LIST" -f "$ENGINE" "$LIST" "$tmp.in" </dev/null 2>/dev/null) || rc=$?
  if [ "$rc" -eq 3 ]; then
    fail bad-list "fix the pattern list line named above" "list: line $(printf '%s\n' "$out" | sed -n 's/^BADLIST //p' | sed -n 1p) uses an unsupported escape"
  elif [ "$rc" -ne 0 ]; then
    fail awk-error "check the pattern list syntax and re-run" "awk-error: $f"
  fi
  patterns=$(printf '%s\n' "$out" | sed -n 's/^PATTERNS //p' | sed -n 1p)
  h=$(printf '%s\n' "$out" | sed -n 's/^HIT [^:]*:/hit: /p')
  if [ -n "$h" ]; then
    nhits=$((nhits + $(printf '%s\n' "$h" | wc -l)))
    hits="$hits"$'\n'"$(printf '%s\n' "$h" | sed "s|^hit: |hit: $f:|")"
  fi
done < "$tmp"

[ "$nfiles" -gt 0 ] || fail no-input "pass files that exist and are not the list or excluded" "files: 0"
[ "$patterns" -gt 0 ] 2>/dev/null || fail empty-list "put at least one pattern into the list file" "files: $nfiles" "patterns: 0"

if [ "$nhits" -eq 0 ]; then
  echo "VERDICT: PASS"
  echo '```'
  echo "files: $nfiles"
  echo "patterns: $patterns"
  echo "hits: 0"
  echo '```'
  exit 0
fi
echo "VERDICT: FAIL old-wording retired-phrasing"
echo '```'
echo "files: $nfiles"
echo "patterns: $patterns"
echo "hits: $nhits"
printf '%s\n' "$hits" | sed '/^$/d'
echo "remaining: reword or remove each retired phrasing at the lines above, then re-run check_old_wording.sh"
echo '```'
exit 1
