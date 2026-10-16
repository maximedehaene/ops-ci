#!/usr/bin/env bash
# check_script_rules.sh: the rule-3 grep (ADR-0009, spec section 9 job rule3-grep, build plan B04).
# Fails when a shell script holds a forbidden pattern: sourcing a file, dumping the environment or argv, printing
# unit Environment= lines, journal or docker-inspect output, curl|sh, apt-key, docker group changes, set -x, reading
# secret or key files, luksDump output, nft/iptables flushes (R01..R15, the rules of tests/agent-host/check_forbidden.py),
# loading an env file (R16) and an ssh or git call without stdin from /dev/null (R17). The patterns and what each one
# catches are in scripts/lib/script_rules.awk. Comments are not scanned; heredoc bodies and quoted strings are.
#
# Usage: check_script_rules.sh [--allow-source ARG]... FILE...
#   --allow-source ARG  sourcing exactly ARG (as written, quotes included) is allowed; no | in ARG.
# Exit: 0 PASS, 1 FAIL (rule hits), 64 input error. Output: the VERDICT line, then a fenced block with the file
# count, one "hit: <file>:<line> <rule> <name>" per hit (never the text of the line) and the remaining steps.
# Input errors: VERDICT: FAIL input <what>. A file that cannot be read, no file at all, or an awk error is a FAIL
# (fail closed), never a PASS.
#
# May call: awk (OPS_CI_AWK overrides), sed, sort, cat, printf. No network, no git, no ssh.
# Written for bash 3.2 and BSD userland (awk, sed, find, tr). Verified on bash 3.2 and macOS awk only by the planner's Mac run (see the PR); the author could run bash 5.2 with mawk and original-awk only.
set -euo pipefail
export LC_ALL=C   # byte-wise awk, tr, sed, sort: a multibyte character next to a number or a word must not abort awk (macOS)

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AWK="${OPS_CI_AWK:-awk}"
RULES="$HERE/lib/script_rules.awk"

input_fail() {
  echo "VERDICT: FAIL input $1"
  echo '```'
  echo "remaining: $2"
  echo '```'
  exit 64
}

allow="|"
files=()
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-source)
      [ $# -ge 2 ] || input_fail missing-argument "give an argument after --allow-source"
      case "$2" in *"|"*) input_fail bad-allow-source "remove the | from the --allow-source argument" ;; esac
      allow="$allow$2|"; shift 2 ;;
    --) shift; while [ $# -gt 0 ]; do files+=("$1"); shift; done ;;
    -*) input_fail unknown-option "use only --allow-source ARG and file names" ;;
    *) files+=("$1"); shift ;;
  esac
done
[ "${#files[@]}" -gt 0 ] || input_fail no-files "pass at least one script file"
[ -r "$RULES" ] || input_fail rules-missing "restore scripts/lib/script_rules.awk"

hits=""
nhits=0
unreadable=0
awkfail=0
for f in "${files[@]}"; do
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then
    unreadable=$((unreadable + 1)); hits="$hits"$'\n'"unreadable: $f"; continue
  fi
  # a relative name gets ./ so that awk cannot read "x=y.sh" as an assignment or "-" as standard input
  case "$f" in /*|./*) af=$f ;; *) af=./$f ;; esac
  if out=$(SHOWN="$f" "$AWK" -v "allow=$allow" -f "$RULES" "$af" </dev/null 2>/dev/null); then
    if [ -n "$out" ]; then
      nhits=$((nhits + $(printf '%s\n' "$out" | wc -l)))
      hits="$hits"$'\n'"$(printf '%s\n' "$out" | sed 's/^HIT /hit: /')"
    fi
  else
    awkfail=$((awkfail + 1)); hits="$hits"$'\n'"awk-error: $f"
  fi
done

fails=$((nhits + unreadable + awkfail))
if [ "$fails" -eq 0 ]; then
  echo "VERDICT: PASS"
  echo '```'
  echo "files: ${#files[@]}"
  echo "hits: 0"
  echo '```'
  exit 0
fi

if [ "$nhits" -gt 0 ]; then name=$(printf '%s\n' "$hits" | sed -n 's/^hit: [^ ]* R[0-9]* //p' | sed -n 1p)
elif [ "$unreadable" -gt 0 ]; then name=unreadable
else name=awk-error
fi
echo "VERDICT: FAIL rule3 $name"
echo '```'
echo "files: ${#files[@]}"
echo "hits: $nhits"
echo "unreadable: $unreadable"
echo "awk-errors: $awkfail"
printf '%s\n' "$hits" | sed '/^$/d'
echo "remaining: fix each hit above (R01..R17 are described in scripts/lib/script_rules.awk), then re-run check_script_rules.sh on the same files"
echo '```'
exit 1
