# script_rules.awk: the rule-3 patterns of ADR-0009 for check_script_rules.sh. POSIX awk only (bash 3.2 era
# userland, BSD awk): no \b, \s, \d, {n} intervals or backreferences; word edges are written out.
# Input: shell scripts. Variable: allow = "|arg1|arg2|" (sourcing these exact arguments is allowed).
# Output: one line per hit, "HIT <file>:<line> <id> <name>", never the text of the line.
# Comments are not code and are not scanned (a comment cannot run); everything else is, including heredoc bodies
# and quoted strings. A line ending in a backslash is joined to the next, so the pattern cannot hide behind it.
# Rule ids R01..R15 follow F01..F15 of tests/agent-host/check_forbidden.py; R16 and R17 are additions.

function hit(ln, id, name,   k) {
    k = FILENAME SUBSEP ln SUBSEP id
    if (k in seen) return
    seen[k] = 1
    print "HIT " (shown != "" ? shown : FILENAME) ":" ln " " id " " name
}

# Lexes one physical line the way bash reads it, starting in quote state q0 ("", "'", "\"" or "$'"):
#   - a backslash outside single quotes escapes the next character (so \' and \" do not open or close a quote, and
#     an escaped blank does not end a word); a backslash that is the last character escapes the newline;
#   - inside single quotes nothing is special; inside "..." and $'...' only the backslash is;
#   - a # that starts a word outside quotes begins a comment (the rest of the line is dropped).
# Results: PL_out = the line without the comment (a trailing escaping backslash is not copied), PL_q = the quote
# state at the end, PL_cont = 1 when the line ends in an escaping backslash (bash joins the next line), PL_cmt = 1
# when a comment was cut, PL_cmtbs = 1 when that comment ends in an odd run of backslashes.
function parse_line(line, q0,   i, n, c, q, out, p, k, bs, escend) {
    n = length(line); q = q0; out = ""; escend = -1
    PL_cont = 0; PL_cmt = 0; PL_cmtbs = 0
    for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (q == "'") { out = out c; if (c == "'") q = ""; continue }
        if (c == "\\") {
            if (i == n) { PL_cont = 1; break }
            out = out c substr(line, i + 1, 1); i++; escend = i; continue
        }
        if (q != "") {
            out = out c
            if ((q == "\"" && c == "\"") || (q == "$'" && c == "'")) q = ""
            continue
        }
        if (c == "'") { q = "'"; out = out c; continue }
        if (c == "\"") { q = "\""; out = out c; continue }
        if (c == "$" && substr(line, i + 1, 1) == "'") { q = "$'"; out = out "$'"; i++; continue }
        if (c == "#" && i - 1 != escend) {
            p = (i == 1) ? " " : substr(line, i - 1, 1)
            if (p == " " || p == "\t" || p == ";" || p == "&" || p == "|" || p == "(" || p == ")") {
                PL_cmt = 1
                k = n; bs = 0
                while (k > i && substr(line, k, 1) == "\\") { bs++; k-- }
                PL_cmtbs = bs % 2
                break
            }
        }
        out = out c
    }
    PL_out = out; PL_q = q
}

# Blanks the inside of single quotes and of $'...' strings, with the same escape rules as parse_line (nothing in them is expanded or run by this line; sh -c and eval strings are
# matched separately on the unmasked line), so "jq '. | if . == null'" or "awk '. ~ x'" is not a source command.
function mask_single(line, q0,   i, n, c, q, out) {
    n = length(line); out = ""; q = q0
    for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (q == "'") { if (c == "'") { q = ""; out = out c } else out = out "x"; continue }
        if (c == "\\") {                                  # an escape: the next character is literal ("\'" opens no string)
            if (i == n) { out = out c; continue }
            i++
            out = out ((q == "$'") ? "xx" : c substr(line, i, 1))
            continue
        }
        if (q == "$'") { if (c == "'") { q = ""; out = out c } else out = out "x"; continue }
        if (q == "\"") { if (c == "\"") q = ""; out = out c; continue }
        if (c == "'") { q = "'"; out = out c; continue }
        if (c == "\"") { q = "\""; out = out c; continue }
        if (c == "$" && substr(line, i + 1, 1) == "'") { q = "$'"; out = out "$'"; i++; continue }
        out = out c
    }
    return out
}

# Python's \b for ASCII, as in tests/agent-host/check_forbidden.py: an occurrence of word with a non-word character
# (or the edge of the line) on both sides. after() is true when such an occurrence is followed by text matching ^re
# (the text starts right after the word, so a regex written for Python's "\bword\b<rest>" is <rest> here).
# bad_occ() is true when such an occurrence is NOT followed by text matching ^okre.
function after(s, word, re,   base, pos, wl, pc, nc) {
    wl = length(word); base = 0
    while ((pos = index(substr(s, base + 1), word)) > 0) {
        pos += base
        pc = (pos > 1) ? substr(s, pos - 1, 1) : ""
        nc = substr(s, pos + wl, 1)
        if (pc !~ /^[A-Za-z0-9_]$/ && nc !~ /^[A-Za-z0-9_]$/ && (re == "" || substr(s, pos + wl) ~ ("^(" re ")"))) return 1
        base = pos
    }
    return 0
}
function bad_occ(s, word, okre,   base, pos, wl, pc, nc) {
    wl = length(word); base = 0
    while ((pos = index(substr(s, base + 1), word)) > 0) {
        pos += base
        pc = (pos > 1) ? substr(s, pos - 1, 1) : ""
        nc = substr(s, pos + wl, 1)
        if (pc !~ /^[A-Za-z0-9_]$/ && nc !~ /^[A-Za-z0-9_]$/ && substr(s, pos + wl) !~ ("^(" okre ")")) return 1
        base = pos
    }
    return 0
}

# True when seg (the text after "ssh ", up to the next ; & or |) has -n as an ssh option. OpenSSH reads options, then
# the host, then options again; the first plain word after the host starts the remote command. A letter that takes
# an argument ends a cluster and, when it is the last letter, consumes the next word ("-on" is -o with the argument n).
# So "ssh -n h cmd" and "ssh h -n cmd" count, "ssh h uname -n" does not: that -n is uname's, ssh still reads stdin.
function ssh_has_n(seg,   n, t, i, j, c, takes, host) {
    takes = "bcDEeFIiJLlmOopQRSWwBP"
    n = split(seg, t, "[ \t]+"); host = 0
    for (i = 1; i <= n; i++) {
        if (t[i] == "") continue
        if (t[i] !~ /^-/) { if (host) return 0; host = 1; continue }
        for (j = 2; j <= length(t[i]); j++) {
            c = substr(t[i], j, 1)
            if (c == "n") return 1
            if (index(takes, c) > 0) { if (j == length(t[i])) i++; break }
        }
    }
    return 0
}

function scan(s, ln, q0,   rest, t, arg, off, st, m, i, seg) {
    sub(/^[ \t]+/, "", s)
    if (s == "") return
    m = mask_single(s, q0)

    # R01 source: sourcing anything not in the allow list, at any command position or inside sh -c / eval.
    rest = m
    while (match(rest, C "(source|[.])[ \t]+[^ \t;&|)]+")) {
        t = substr(rest, RSTART, RLENGTH)
        rest = substr(rest, RSTART + RLENGTH)
        arg = t
        sub(/^.*(source|[.])[ \t]+/, "", arg)
        if (index(allow, "|" arg "|") == 0) hit(ln, "R01", "source")
    }
    if (s ~ "(^|[^A-Za-z0-9_])((ba|z|da|k)?sh[ \t]+-[A-Za-z]*c|eval)[ \t]+[\"']?[ \t]*(source|[.])[ \t]") hit(ln, "R01", "source")

    # R02 env-dump
    if (after(s, "printenv", "")) hit(ln, "R02", "env-dump")
    if (m ~ C "env([ \t]+-[A-Za-z0-9]+)*[ \t]*($|[|;&)])") hit(ln, "R02", "env-dump")
    if (m ~ C "(set|local)[ \t]*($|[|;&)])") hit(ln, "R02", "env-dump")
    if (m ~ C "(export|declare|typeset|readonly)([ \t]+-[A-Za-z]+)*[ \t]*($|[|;&)])") hit(ln, "R02", "env-dump")
    if (m ~ C "(declare|typeset)[ \t]+-[A-Za-z]*p") hit(ln, "R02", "env-dump")
    if (after(s, "compgen", "[ \t]+-v")) hit(ln, "R02", "env-dump")
    if (s ~ "/proc/[^ \t]*/environ") hit(ln, "R02", "env-dump")

    # R03 argv-dump
    if (after(s, "echo", ARGV_DUMP) || after(s, "printf", ARGV_DUMP)) hit(ln, "R03", "argv-dump")
    if (s ~ "BASH_ARGV|/proc/[^ \t]*/cmdline") hit(ln, "R03", "argv-dump")

    # R04 systemctl-show: only "systemctl show -p <name> --value" is allowed (show-environment is not).
    if (after(s, "systemctl", "[ \t]+([^;|&]*[ \t])?show" NW)) {
        if (s !~ "systemctl[ \t]+show[ \t]+-p[ \t]+[^ \t]+[ \t]+--value") hit(ln, "R04", "systemctl-show")
    }

    # R05 docker-inspect
    if (after(s, "docker", "[ \t]+([^;|&]*[ \t])?inspect" NW)) hit(ln, "R05", "docker-inspect")

    # R06 unit-env: unit Environment= lines, systemctl cat, the Environment property.
    if (after(s, "systemctl", "[ \t]+([^;|&]*[ \t])?cat" NW)) hit(ln, "R06", "unit-env")
    if (s ~ "Environment=") hit(ln, "R06", "unit-env")
    if (s ~ "systemctl[^;|]*show[^;|]*-p[ \t]*Environment") hit(ln, "R06", "unit-env")

    # R07 priority: journalctl -p / -pXX / combined short flags containing p / --priority, or PRIORITY=
    if (after(s, "journalctl", "[^|]*([ \t]-[A-Za-z0-9]*p|--priority)")) hit(ln, "R07", "priority")
    if (s ~ "PRIORITY=") hit(ln, "R07", "priority")

    # R08 journal-print: every journalctl on the line must be piped straight into grep -c (count; -vc, -ci and
    # --count too), so a second plain journalctl on the same line is still found.
    if (bad_occ(s, "journalctl", "[^|;]*[|][ \t]*grep[ \t]+(-[A-Za-z]*c[A-Za-z]*|--count)([ \t]|$)")) hit(ln, "R08", "journal-print")

    # R09 curl-sh: a download piped into a shell or interpreter, or run by process substitution / eval.
    if (after(s, "curl", CURL_SH) || after(s, "wget", CURL_SH)) hit(ln, "R09", "curl-sh")
    if (s ~ "((ba|z|da|k)?sh|source|[.])[ \t]+<[(][ \t]*(curl|wget)") hit(ln, "R09", "curl-sh")
    if (s ~ "eval[ \t]+[\"']?[$][(][ \t]*(curl|wget)") hit(ln, "R09", "curl-sh")

    # R10 apt-key
    if (after(s, "apt-key", "")) hit(ln, "R10", "apt-key")

    # R11 docker-group
    if (after(s, "usermod", "[^;|]*(-[A-Za-z]*G|--groups)[ \t=]*[^ \t]*docker")) hit(ln, "R11", "docker-group")
    if (after(s, "gpasswd", "[^;|]*[ \t](-a|--add)[^;|]*docker")) hit(ln, "R11", "docker-group")
    if (after(s, "adduser", "[ \t]+[^ \t]+[ \t]+docker" NW)) hit(ln, "R11", "docker-group")
    if (after(s, "groupmems", "[^;|]*-a")) hit(ln, "R11", "docker-group")

    # R12 trace: set -x in any flag cluster, set -o xtrace, bash/sh -x, xtrace variables.
    if (after(s, "set", "[ \t]+(-[A-Za-z]+[ \t]+)*-[A-Za-z]*x")) hit(ln, "R12", "trace")
    if (after(s, "set", "[ \t]+-o[ \t]+xtrace")) hit(ln, "R12", "trace")
    for (i = 1; i <= nsh; i++) if (after(s, SH[i], "[ \t]+-[A-Za-z]*x")) hit(ln, "R12", "trace")
    if (s ~ "BASH_XTRACEFD|(^|[^A-Za-z0-9_])SHELLOPTS=[^ \t]*xtrace") hit(ln, "R12", "trace")

    # R13 secret-read: a reader command on a secrets, key or header file.
    for (i = 1; i <= nrd; i++) if (after(s, RD[i], "[^|;]*" SECRET)) hit(ln, "R13", "secret-read")
    if (s ~ "[$][(]<[ \t]*[^ \t)]*" SECRET) hit(ln, "R13", "secret-read")

    # R14 luks-dump: only "luksDump --dump-json-metadata ... | jq"; never the volume key.
    if (bad_occ(s, "luksDump", "[ \t]+--dump-json-metadata([^A-Za-z0-9_|][^|]*)?[|][ \t]*jq" NW)) hit(ln, "R14", "luks-dump")
    if (s ~ "--dump-(master|volume)-key") hit(ln, "R14", "luks-dump")

    # R15 flush
    if (s ~ "flush[ \t]+ruleset") hit(ln, "R15", "flush")
    if (after(s, "nft", "[ \t]+flush" NW)) hit(ln, "R15", "flush")
    if (after(s, "iptables", IPT) || after(s, "ip6tables", IPT)) hit(ln, "R15", "flush")

    # R16 env-load: loading an env file into the shell (the dummy.env file is parsed key by key, never loaded).
    if (after(s, "set", "[ \t]+(-[A-Za-z]+[ \t]+)*-[A-Za-z]*a[A-Za-z]*([ \t]|$)") || s ~ "allexport") hit(ln, "R16", "env-load")
    if (m ~ C "(cat|xargs|eval|export|env)[ \t][^|;]*[.]env([^A-Za-z0-9_]|$)") hit(ln, "R16", "env-load")

    # R17 stdin-devnull: an ssh or git call must read stdin from /dev/null. A call on the right of a pipe, with a
    # here-document or here-string, or with ssh -n takes its stdin on purpose and is skipped; the redirect or -n must
    # belong to this call (up to the next ; & or |), unless a group, loop or if is redirected as a whole.
    rest = m; off = 0
    while (match(rest, "(" C WRAP "|[ \t]" WRAPREQ ")([^ \t;&|]*/)?(ssh|git)[ \t]")) {
        st = off + RSTART
        t = substr(rest, RSTART, RLENGTH)
        off += RSTART + RLENGTH - 1
        rest = substr(rest, RSTART + RLENGTH)
        if (substr(t, 1, 1) == "|" && (st == 1 || substr(m, st - 1, 1) != "|")) continue
        seg = rest; sub(/[;&|].*/, "", seg)         # this call only: up to the next ; & or |
        if (seg ~ "<[ \t]*/dev/null" || seg ~ "<<") continue
        if (s ~ "(done|fi|esac|[)}])[ \t]*<[ \t]*/dev/null") continue      # a group or loop redirected as a whole
        if (t ~ /ssh[ \t]$/ && ssh_has_n(seg)) continue
        hit(ln, "R17", "stdin-devnull")
    }
}

BEGIN {
    shown = ENVIRON["SHOWN"]          # the file name as the caller wrote it
    NW = "([^A-Za-z0-9_]|$)"
    ARGV_DUMP = "[^|;]*[$][{]?[@*]"
    CURL_SH = "[^|]*[|][ \t]*(sudo[ \t]+)?((ba|z|da|k)?sh|python[0-9.]*|perl|ruby|node)" NW
    IPT = "[^;|]*([ \t]-[FX]" NW "|--flush)"
    SECRET = "(secrets|[.]pem" NW "|(^|[^A-Za-z0-9_])id_[a-z0-9]+|luks-header|[.]key" NW "|admin[.]pub)"
    nsh = split("bash sh zsh dash ksh", SH, " ")
    nrd = split("cat head tail tac less more nl od xxd strings base64 bat", RD, " ")
    # a wrapper in front of ssh or git (timeout 5 ssh h, nice -n 10 git, env FOO=1 ssh, xargs ssh ...): the call after it
    # is checked like any other; the wrapper's own arguments are options, numbers with a unit, assignments or UPPER words
    WRAPW = "(timeout|nice|env|nohup|command|sudo|time|exec|xargs|stdbuf|ionice|setsid|doas|flock)"
    # an argument of a wrapper: an option, a number with a unit, an assignment (the value may be quoted), an UPPER word,
    # or a variable or quoted word ($cap, "$cap", "${cap}s", 'x'), so that a computed argument does not hide the call
    WARG = "(-[^ \t]*|[0-9][0-9.]*[smhd]?|[A-Za-z_][A-Za-z0-9_]*=(\"[^\"]*\"|'[^']*'|[^ \t]*)|[A-Z]+|[$][^ \t]*|\"[^\"]*\"|'[^']*')"
    WRAP = "(" WRAPW "[ \t]+(" WARG "[ \t]+)*)?"
    WRAPREQ = WRAPW "[ \t]+(" WARG "[ \t]+)*"
    # a command position: line start, after ; & | ( { !, or after a keyword that takes a command
    C = "(^|[;&|({!][ \t]*|(^|[^A-Za-z0-9_./$-])(then|do|else|if|elif|while|until|exec|command|sudo|time|nohup)[ \t]+)"
}

FNR == 1 {
    if ($0 ~ /^#!.*[ \t]-[A-Za-z]*x/) hit(1, "R12", "trace")   # shebang flags are not comments
}

{ LN[FNR] = $0; NLINES = FNR }

# The file is read in two passes that each group continued lines by themselves, because the grouping depends on the
# quote state and the two readings can disagree about where a continued line ends:
#  pass 0: every statement starts outside a quote (right for most files; robust against a stray apostrophe in a
#          here-document or a message);
#  pass 1: the quote state is carried from one statement to the next, which is what bash does. It starts at the first
#          statement that pass 0 left inside a quote (up to there both are identical) and runs to the end of the file:
#          a second divergent region after the two have been back in step must be read in carried state as well.
# Where this lexing might differ from bash's, a further reading is scanned as well and either one can hit:
#  - "\<CR><LF>": bash escapes the CR and does not join; a CRLF script may be read as joined by other tools;
#  - a comment that ends in a backslash after a quote or a backslash ("echo \' # note \"): if the # is not a comment
#    after all, the backslash joins the next line;
#  - a statement that starts inside a quote is also scanned as written, without comment removal.
function pass(carry,   i, raw, hadcr, text, body, join, amb, q, q0, cont, startno, altjoin) {
    q = ""; cont = ""; altjoin = ""; i = 1
    if (carry) { i = DIVI; q = DIVQ }
    for (; i <= NLINES; i++) {
        raw = LN[i]
        hadcr = (raw ~ /\r$/)
        if (hadcr) sub(/\r$/, "", raw)
        if (cont == "") {
            startno = i; q0 = q
            if (raw ~ /^[ \t]*#/ && q == "") { altjoin = ""; continue }      # a comment line never continues
        }
        text = cont raw
        parse_line(text, q0)
        body = PL_out; join = PL_cont
        amb = 0
        if (hadcr && join) { join = 0; amb = 1 }
        else if (!join && PL_cmt && PL_cmtbs && (index(body, "'") || index(body, "\"") || index(body, "`") || index(body, "\\"))) amb = 1
        if (join) { cont = body; continue }
        cont = ""
        scan(body, startno, q0)
        if (altjoin != "") { scan(altjoin body, startno, q0); altjoin = "" }
        if (q0 != "") scan(text, startno, q0)
        if (carry) q = PL_q
        else if (PL_q != "" && !DIVI) { DIVI = i + 1; DIVQ = PL_q }
        if (amb) altjoin = body
    }
    if (cont != "") scan(cont, startno, q0)
}

END {
    pass(0)
    if (DIVI > 0 && DIVI <= NLINES) pass(1)
}
