# report_data.awk: the "no hostnames, addresses or secrets" scan of spec section 10, for check_report.sh.
# POSIX awk only (BSD awk): no \b, \d, {n} intervals, lookbehind or gawk functions.
# Variables: mode = "" (all rules), "nohost" (all but D06) or "host" (D06 only; check_report.sh feeds it the copy with
# bytes 0x80-0xFF mapped to q). allow = "|host|*.suffix|" (lower case): domains that may appear. Output: "HIT <file>:<line> <id> <name>",
# never the matched text. Rules (D01..D06 follow tests/agent-host/check_forbidden.py; the allowed set is smaller):
#   D01 ipv4      a dotted quad outside the documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
#                 (private, loopback and CGNAT addresses are real addresses of someone's network and are not allowed)
#   D02 ipv6      a full or compressed IPv6 literal other than 2001:db8::/32, :: and ::1
#   D03 mac       a MAC address (six hex pairs, : or - between)
#   D04 tailnet   a name under the tailnet domain, or a tailnet-<name> label
#   D05 token     token or private key material (tskey-, ghp_/gho_/ghu_/ghs_/ghr_, github_pat_, BEGIN ... PRIVATE KEY,
#                 AKIA/ASIA keys, xox? tokens, sk- keys, sk_live_/sk_test_, AIza keys, JWTs)
#   D06 hostname  a name ending in a known TLD that is not in the allow list (emails count: the part after @)
# Defanged dots (a dot written in brackets or parentheses, or the word dot in brackets) are read as dots. Not detected: single-label host names,
# decimal or hex IP forms, names with a TLD outside the list below, ports.

function hit(ln, id, name,   k) {
    k = ln SUBSEP id
    if (k in seen) return
    seen[k] = 1
    print "HIT " (shown != "" ? shown : FILENAME) ":" ln " " id " " name
}

function isalnum_(c) { return c ~ /^[A-Za-z0-9_]$/ }

function ipv4(s, ln,   rest, off, st, tok, pc, nc, n, parts, i, ok, a, b, c) {
    rest = s; off = 0
    while (match(rest, /[0-9][0-9.]*/)) {
        st = off + RSTART
        tok = substr(rest, RSTART, RLENGTH)
        nc = substr(rest, RSTART + RLENGTH, 1)
        off += RSTART + RLENGTH - 1
        rest = substr(rest, RSTART + RLENGTH)
        pc = (st > 1) ? substr(s, st - 1, 1) : " "
        sub(/[.]+$/, "", tok)
        if (pc ~ /[A-Za-z0-9_:]/ || nc ~ /[A-Za-z0-9_]/) continue
        n = split(tok, parts, ".")
        if (n != 4) continue
        ok = 1
        for (i = 1; i <= 4; i++) if (parts[i] !~ /^[0-9][0-9]?[0-9]?$/ || parts[i] + 0 > 255) ok = 0
        if (!ok) continue
        a = parts[1] + 0; b = parts[2] + 0; c = parts[3] + 0
        if (a == 192 && b == 0 && c == 2) continue
        if (a == 198 && b == 51 && c == 100) continue
        if (a == 203 && b == 0 && c == 113) continue
        hit(ln, "D01", "ipv4")
    }
}

function ipv6(s, ln,   rest, off, st, tok, pc, nc, ncol, ng, groups, i, ok, t, dbl, k, n) {
    rest = s; off = 0
    while (match(rest, /[0-9A-Fa-f:]+/)) {
        st = off + RSTART
        tok = substr(rest, RSTART, RLENGTH)
        nc = substr(rest, RSTART + RLENGTH, 1)
        off += RSTART + RLENGTH - 1
        rest = substr(rest, RSTART + RLENGTH)
        pc = (st > 1) ? substr(s, st - 1, 1) : " "
        if (pc ~ /[A-Za-z0-9_.]/ || nc ~ /[A-Za-z0-9_.]/) continue
        t = tok
        ncol = gsub(/:/, ":", t)
        dbl = index(tok, "::") > 0
        if (ncol < 2 || !(dbl || ncol >= 7)) continue
        if (tok !~ /[0-9A-Fa-f]/) continue
        k = index(tok, "::")
        if (k > 0 && index(substr(tok, k + 2), "::") > 0) continue
        if (substr(tok, 1, 1) == ":" && substr(tok, 2, 1) != ":") continue
        if (substr(tok, length(tok)) == ":" && substr(tok, length(tok) - 1, 1) != ":") continue
        ng = split(tok, groups, ":")
        ok = 1; n = 0
        for (i = 1; i <= ng; i++) {
            if (groups[i] == "") continue
            if (groups[i] !~ /^[0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?$/) ok = 0
            n++
        }
        if (!ok) continue
        if (dbl ? n > 7 : n != 8) continue
        t = tolower(tok)
        if (t == "::1" || t == "::") continue
        if (t ~ /^2001:0?db8(:|$)/) continue
        hit(ln, "D02", "ipv6")
    }
}

function mac(s, ln,   rest, off, st, pc, nc, h, re) {
    h = "[0-9A-Fa-f][0-9A-Fa-f]"
    re = h "[:-]" h "[:-]" h "[:-]" h "[:-]" h "[:-]" h
    rest = s; off = 0
    while (match(rest, re)) {
        st = off + RSTART
        nc = substr(rest, RSTART + RLENGTH, 1)
        off += RSTART + RLENGTH - 1
        rest = substr(rest, RSTART + RLENGTH)
        pc = (st > 1) ? substr(s, st - 1, 1) : " "
        if (pc ~ /[0-9A-Fa-f:]/ || nc ~ /[0-9A-Fa-f:]/) continue
        hit(ln, "D03", "mac")
    }
}

function runlen_ge(s, re, skip, min,   m) {   # a token matching re, with at least min characters after skip
    if (!match(s, re)) return 0
    return RLENGTH - skip >= min
}

function token(s, ln) {
    if (s ~ "tskey-[A-Za-z0-9]") hit(ln, "D05", "token")
    if (runlen_ge(s, "gh[pousr]_[A-Za-z0-9]+", 4, 20)) hit(ln, "D05", "token")
    if (runlen_ge(s, "github_pat_[A-Za-z0-9_]+", 11, 20)) hit(ln, "D05", "token")
    if (s ~ "-----BEGIN [A-Z ]*PRIVATE KEY") hit(ln, "D05", "token")
    if (runlen_ge(s, "(AKIA|ASIA)[0-9A-Z]+", 4, 16)) hit(ln, "D05", "token")
    if (runlen_ge(s, "xox[abprs]-[A-Za-z0-9-]+", 5, 10)) hit(ln, "D05", "token")
    if (runlen_ge(s, "(^|[^A-Za-z0-9_-])sk-[A-Za-z0-9_-]+", 3, 20)) hit(ln, "D05", "token")
    if (runlen_ge(s, "sk_(live|test)_[A-Za-z0-9]+", 8, 10)) hit(ln, "D05", "token")
    if (runlen_ge(s, "AIza[0-9A-Za-z_-]+", 4, 35)) hit(ln, "D05", "token")
    if (s ~ "eyJ[A-Za-z0-9_-]+[.]eyJ[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+") hit(ln, "D05", "token")
}

function allowed(h,   k, list, n, i, e) {
    if (index(allow, "|" h "|") > 0) return 1
    n = split(allow, list, "|")
    for (i = 1; i <= n; i++) {
        e = list[i]
        if (substr(e, 1, 2) == "*." && length(h) > length(e) - 1 && substr(h, length(h) - length(e) + 2) == substr(e, 2)) return 1
    }
    return 0
}

function hostnames(s, ln,   rest, tok, n, labels, tld) {
    # No boundary test on either side: a name after a dot, a hyphen, a wildcard star or an @ sign is still a name
    # (a cookie-style leading dot, a wildcard certificate name, a flag glued to a name, an email domain).
    rest = s
    while (match(rest, /[a-z0-9]([a-z0-9-]*[a-z0-9])?([.][a-z0-9]([a-z0-9-]*[a-z0-9])?)+/)) {
        tok = substr(rest, RSTART, RLENGTH)
        rest = substr(rest, RSTART + RLENGTH)
        n = split(tok, labels, ".")
        tld = labels[n]
        if (!(tld in TLD) && tld !~ /^[a-z][a-z]*qq/ ) continue      # qq = a non-ASCII byte pair mapped by check_report.sh
        if (allowed(tok)) continue
        hit(ln, "D06", "hostname")
    }
}

BEGIN {
    shown = ENVIRON["SHOWN"]          # the file name as the caller wrote it
    n = split("com net org io dev be eu invalid local lan home internal arpa cloud app info co uk nl fr de ai me tv xyz online site biz us ca ch it es lu corp intranet localdomain", t, " ")
    for (i = 1; i <= n; i++) TLD[t[i]] = 1
}

{
    s = $0
    sub(/\r$/, "", s)
    gsub("[[][.][]]", ".", s)
    gsub("[(][.][)]", ".", s)
    gsub("[[][Dd][Oo][Tt][]]", ".", s)
    low = tolower(s)
    if (mode != "host") {
        ipv4(s, FNR)
        ipv6(s, FNR)
        mac(s, FNR)
        if (low ~ "[.]ts[.]" "net([^a-z0-9_]|$)" || low ~ "tailnet-[a-z0-9]+") hit(FNR, "D04", "tailnet")
        token(s, FNR)
    }
    if (mode != "nohost") hostnames(low, FNR)
}
