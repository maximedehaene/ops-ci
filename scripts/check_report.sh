#!/usr/bin/env bash
# check_report.sh: report check (spec section 9 job report-check, section 10, build plan B04), and the host/address
# scan of section 10 ("no hostnames, addresses or secrets").
#
# Report mode: check_report.sh [--allow FILE] FILE...
#   per file: the name is YYYY-MM-DD-<slug>.md with a real month and day; no CR characters; the file starts with a
#   front matter block between two "---" lines holding "data-class: operational" and "body-sha256: <64 lowercase
#   hex>" exactly once each (other keys must be "key: value" lines); body-sha256 equals the SHA-256 of everything
#   after the closing "---" line, byte for byte (the rule that docs/standards/skills-and-roles.md follows); and the
#   whole file passes the data rules below.
# Data mode: check_report.sh --data [--allow FILE] FILE...   only the data rules, for any text file (the test row
#   that scans the whole ops-ci-seed/ tree uses this).
# Data rules (scripts/lib/report_data.awk): D01 IPv4 outside the documentation ranges, D02 IPv6, D03 MAC,
#   D04 tailnet names, D05 token and key material, D06 host names with a known TLD not in the allow list.
#   Allow list: ../checks/allowed-domains.txt (one "<domain> | <reason>" per line; a missing reason, a duplicate, an
#   uppercase name or a whole-TLD wildcard makes the list invalid: FAIL allowlist).
# Exit: 0 PASS, 1 FAIL, 64 input error. Output: the VERDICT line, then a fenced block with counts, one
# "check: <file> <name>" per failed check, one "hit: <file>:<line> <rule> <name>" per data hit (never the text),
# and the remaining steps. No file, an unreadable file or an awk error is a FAIL, never a PASS.
#
# May call: awk (OPS_CI_AWK overrides), sed, tail, cat, wc, tr, mktemp, rm, basename, dirname, sha256sum or shasum or openssl
# (the first found), printf. No network, no git, no ssh.
# Written for bash 3.2 and BSD userland (awk, sed, find, tr). Verified on bash 3.2 and macOS awk only by the planner's Mac run (see the PR); the author could run bash 5.2 with mawk and original-awk only.
set -euo pipefail
export LC_ALL=C   # byte-wise awk, tr, sed, sort: a multibyte character next to a number or a word must not abort awk (macOS)

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AWK="${OPS_CI_AWK:-awk}"
DATA="$HERE/lib/report_data.awk"
ALLOW_FILE="$HERE/../checks/allowed-domains.txt"

input_fail() {
  echo "VERDICT: FAIL input $1"
  echo '```'
  echo "remaining: $2"
  echo '```'
  exit 64
}
early_fail() { # early_fail <name> <remaining> [block lines...]
  local name=$1 rem=$2
  shift 2
  echo "VERDICT: FAIL report $name"
  echo '```'
  while [ $# -gt 0 ]; do echo "$1"; shift; done
  echo "remaining: $rem"
  echo '```'
  exit 1
}
sha256_of_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r | cut -d' ' -f1
  else echo "no-sha256-tool"; fi
}

mode=report
files=()
while [ $# -gt 0 ]; do
  case "$1" in
    --data) mode=data; shift ;;
    --allow) [ $# -ge 2 ] || input_fail missing-argument "give a file after --allow"; ALLOW_FILE=$2; shift 2 ;;
    --) shift; while [ $# -gt 0 ]; do files+=("$1"); shift; done ;;
    -*) input_fail unknown-option "use only --data, --allow FILE and file names" ;;
    *) files+=("$1"); shift ;;
  esac
done
[ "${#files[@]}" -gt 0 ] || input_fail no-files "pass at least one file"
# a relative name gets ./ before it reaches awk, tail or basename: "x=y.md" would be an awk assignment, "-" stdin
dotslash() { case "$1" in /*|./*) printf '%s\n' "$1" ;; *) printf './%s\n' "$1" ;; esac; }
[ -r "$DATA" ] || input_fail engine-missing "restore scripts/lib/report_data.awk"
[ -f "$ALLOW_FILE" ] && [ -r "$ALLOW_FILE" ] || early_fail allowlist "restore the allow list or pass --allow FILE" "allowlist: unreadable"

# parse the allow list into |a|b|*.c| ; print "ERR <line>" on a bad line
# shellcheck disable=SC2016  # the awk program is single-quoted on purpose
allow=$("$AWK" '
  /^[ \t]*($|#)/ { next }
  {
    line = $0; sub(/\r$/, "", line)
    i = index(line, "|")
    if (i == 0) { print "ERR " NR; bad = 1; exit }
    d = substr(line, 1, i - 1); r = substr(line, i + 1)
    gsub(/^[ \t]+|[ \t]+$/, "", d); gsub(/^[ \t]+|[ \t]+$/, "", r)
    if (r == "" || d == "") { print "ERR " NR; bad = 1; exit }
    base = d; wild = 0
    if (substr(d, 1, 2) == "*.") { base = substr(d, 3); wild = 1 }
    if (base !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?([.][a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/) { print "ERR " NR; bad = 1; exit }
    if (d in seen) { print "ERR " NR; bad = 1; exit }
    seen[d] = 1
    out = out d "|"
  }
  END { if (!bad) print "|" out }
' "$(dotslash "$ALLOW_FILE")" </dev/null 2>/dev/null) || early_fail allowlist "fix the allow list" "allowlist: awk-error"
case "$allow" in
  ERR*) early_fail allowlist "fix the allow list line named above" "allowlist: line ${allow#ERR } is invalid" ;;
esac
[ -n "$allow" ] || allow="|"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-report.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
DOT1=$'\xe3\x80\x82'; DOT2=$'\xef\xbc\x8e'; DOT3=$'\xef\xbd\xa1'     # U+3002, U+FF0E, U+FF61
checks=""
nchecks=0
hits=""
nhits=0
first=""
addcheck() { # addcheck <file> <name>
  nchecks=$((nchecks + 1))
  checks="$checks"$'\n'"check: $1 $2"
  [ -n "$first" ] || first=$2
}

for f in "${files[@]}"; do
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then addcheck "$f" unreadable; continue; fi
  af=$(dotslash "$f")

  if [ "$mode" = report ]; then
    base=$(basename "$af")
    # shellcheck disable=SC2016
    if ! printf '%s\n' "$base" | "$AWK" '
        { ok = ($0 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[a-z0-9][a-z0-9-]*[.]md$/)
          if (ok) { m = substr($0, 6, 2) + 0; d = substr($0, 9, 2) + 0; if (m < 1 || m > 12 || d < 1 || d > 31) ok = 0 }
          exit ok ? 0 : 1 }'; then
      addcheck "$f" filename
    fi
    if [ "$(tr -d -c '\r' < "$f" | wc -c | tr -d ' ')" != 0 ]; then
      addcheck "$f" cr-in-file
    else
      # shellcheck disable=SC2016
      fm=$("$AWK" '
        NR == 1 { if ($0 != "---") { print "ERR front-matter"; exit } ; next }
        closed { next }
        $0 == "---" { closed = 1; close_line = NR; next }
        $0 ~ /^[ \t]*$/ { next }
        $0 ~ /^[a-z][a-z0-9-]*: / {
          key = $0; sub(/: .*/, "", key); val = $0; sub(/^[^:]*: */, "", val); sub(/[ \t]+$/, "", val)
          if (key == "data-class") { dcn++; dc = val }
          if (key == "body-sha256") { shan++; sha = val }
          next
        }
        { bad = 1 }
        END {
          if (NR == 0) { print "ERR front-matter"; exit }
          if (!closed) { print "ERR front-matter"; exit }
          if (bad) { print "ERR front-matter"; exit }
          if (dcn != 1) { print "ERR data-class"; exit }
          if (dc != "operational") { print "ERR data-class"; exit }
          if (shan != 1) { print "ERR body-sha256-missing-or-duplicated"; exit }
          if (sha !~ /^[0-9a-f]+$/ || length(sha) != 64) { print "ERR body-sha256-format"; exit }
          print "OK " close_line " " sha
        }' "$af" </dev/null) || fm="ERR awk-error"
      case "$fm" in
        ERR*) addcheck "$f" "${fm#ERR }" ;;
        OK*)
          read -r _ close_line want <<< "$fm"
          got=$(tail -n +$((close_line + 1)) "$af" </dev/null | sha256_of_stdin)
          [ "$got" = "$want" ] || addcheck "$f" body-sha256
          ;;
        *) addcheck "$f" front-matter ;;
      esac
    fi
  fi

  # The data scan reads a normalised copy: NUL bytes removed; the ideographic full stop (U+3002), the fullwidth full
  # stop (U+FF0E) and the halfwidth ideographic full stop (U+FF61) turned into "." (look-alike dots in host names).
  # The host rule runs on a second copy where every byte 0x80-0xFF is the letter q, so a host name with a
  # non-ASCII letter ("pi" + a-umlaut, fullwidth letters) stays one host-like token; a top-level label that starts with a letter and contains qq
  # is treated as a non-ASCII (internationalised) label and counts as a host. All other rules read the first copy.
  rc=0
  tr -d '\000' < "$af" | sed -e "s/$DOT1/./g" -e "s/$DOT2/./g" -e "s/$DOT3/./g" > "$tmp/norm" || rc=1
  tr '\200-\377' 'q' < "$tmp/norm" > "$tmp/host" || rc=1
  out1=$(SHOWN="$f" "$AWK" -v "allow=$allow" -v mode=nohost -f "$DATA" "$tmp/norm" </dev/null 2>/dev/null) || rc=1
  out2=$(SHOWN="$f" "$AWK" -v "allow=$allow" -v mode=host -f "$DATA" "$tmp/host" </dev/null 2>/dev/null) || rc=1
  if [ "$rc" -ne 0 ]; then addcheck "$f" awk-error; continue; fi
  out=$(printf '%s\n%s\n' "$out1" "$out2" | sed '/^$/d')
  if [ -n "$out" ]; then
    nhits=$((nhits + $(printf '%s\n' "$out" | wc -l)))
    hits="$hits"$'\n'"$(printf '%s\n' "$out" | sed 's/^HIT /hit: /')"
    [ -n "$first" ] || first=$(printf '%s\n' "$out" | sed -n 's/^HIT [^ ]* D[0-9]* //p' | sed -n 1p)
  fi
done

fails=$((nchecks + nhits))
if [ "$fails" -eq 0 ]; then
  echo "VERDICT: PASS"
  echo '```'
  echo "mode: $mode"
  echo "files: ${#files[@]}"
  echo "hits: 0"
  echo '```'
  exit 0
fi
echo "VERDICT: FAIL report $first"
echo '```'
echo "mode: $mode"
echo "files: ${#files[@]}"
echo "failed-checks: $nchecks"
echo "data-hits: $nhits"
printf '%s\n%s\n' "$checks" "$hits" | sed '/^$/d'
echo "remaining: fix each item above (data rules D01..D06 are in scripts/lib/report_data.awk), then re-run check_report.sh on the same files"
echo '```'
exit 1
