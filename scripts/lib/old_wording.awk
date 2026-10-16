# old_wording.awk: retired-phrasing scan for check_old_wording.sh. POSIX awk only (BSD awk): no \b in the engine.
# Input 1: the pattern list (variable listfile is read by the first pass); input 2..: the text files.
# Text and patterns are lower-cased. In the text, every run of spaces, tabs, hyphens and underscores is one space
# (the shell wrapper has already turned Unicode dashes and no-break spaces into hyphens and spaces and removed
# zero-width characters), so a list entry that has [ -] between its words also catches other letter case, doubled
# spaces, underscores and mixed separators. A phrase wrapped over two lines is caught too: each line is also
# matched joined to the line before it (list bullets and quote marks at the start of the second line are ignored).
# A list line is one extended regex; \b may stand only at the very start or end of it and means a word edge.
# Output: "PATTERNS <n>" once, then "HIT <file>:<line> P<k>" per hit. A bad list line prints "BADLIST <line>" and
# exits 3.

function norm(s) {
    s = tolower(s)
    gsub(/[-_ \t\r]+/, " ", s)
    sub(/^ /, "", s)
    sub(/ $/, "", s)
    return s
}

function hit(ln, k,   key) {
    key = FILENAME SUBSEP ln SUBSEP k
    if (key in seen) return
    seen[key] = 1
    print "HIT " FILENAME ":" ln " P" k
}

FILENAME == list {
    p = $0
    sub(/\r$/, "", p)
    if (p ~ /^[ \t]*($|#)/) next
    p = tolower(p)
    if (substr(p, 1, 2) == "\\b") p = "(^|[^a-z0-9_])" substr(p, 3)
    if (length(p) >= 2 && substr(p, length(p) - 1) == "\\b") p = substr(p, 1, length(p) - 2) "([^a-z0-9_]|$)"
    if (index(p, "\\") > 0) { print "BADLIST " FNR; exit 3 }
    n++
    re[n] = p
    next
}

FNR == 1 { prev = "" }
FILENAME != list {
    if (!started) { print "PATTERNS " n + 0; started = 1 }
    cur = norm($0)
    c2 = cur
    sub(/^[>*#+ ]+/, "", c2)
    joined = (prev == "") ? "" : prev " " c2
    for (k = 1; k <= n; k++) {
        if (cur ~ re[k]) hit(FNR, k)
        else if (joined != "" && joined ~ re[k] && prev !~ re[k]) hit(FNR, k)
    }
    prev = cur
}

END { if (!started) print "PATTERNS " n + 0 }
