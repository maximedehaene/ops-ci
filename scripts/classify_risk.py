#!/usr/bin/env python3
"""classify_risk.py: risk class of a deploy range D..T (build plan B03; spec §7, ADR-0010).

Run by the Pi to compute the effective risk (the only class any decision uses) and, advisory only, on PRs.

Contract
--------
Usage:
  classify_risk.py --ops-repo DIR --ops-ref L (--service NAME | --repo NAME) --repo-dir DIR
                   --range D..T --first-deploy yes|no --rollback-ci pass|fail|unknown
  classify_risk.py --ops-repo DIR --ops-ref L --validate

Source of services.yaml: always `git show <L>:services.yaml` in the ops checkout at --ops-repo, where L is the
  accepted ops commit (40 hex that must name a commit, not a tree or blob; the Pi passes state/ops-accepted.sha). There is no option to read a working-tree
  file, so the services.yaml of a PR under test (an ops PR adding or changing an entry) is never used.
--first-deploy: decided by the Pi (no state/deployed/<service>.sha), never read from services.yaml.
--rollback-ci: whether scripts/rollback.sh passed in the CI of T, as the Pi read it for gate (b).
--range: exactly two full 40-hex SHAs joined by "..". D must be a strict ancestor of T. Every commit in D..T is
  inspected (paths and changed lines), so a change made and reverted inside the range still counts; a merge
  commit is compared with each of its parents; files are line-scanned as text whatever their attributes.
Git is run without inherited GIT_* variables and with GIT_NO_REPLACE_OBJECTS=1.

Exit codes:
  0   classified: "VERDICT: PASS" and a block holding "risk: LOW|MEDIUM|HIGH". The only case with a risk class.
  3   refused: "VERDICT: FAIL <op> <name>" and a block without any risk class. The Pi must treat 3, and any
      other non-zero code, as "no deploy" plus needs-maxime (B09).
  64  usage: a missing, repeated or unknown option. Nothing is classified.
Refusals (exit 3), each "VERDICT: FAIL <op> <name>":
  services-yaml unreadable|malformed-line <n>|missing-repo <key>|duplicate-key <key>|duplicate-field
    <key>.<field>|unknown-field <key>.<field>|missing-field <key>.<field>|bad-value <key>.<field>|duplicate-repo
    <repo>|none   (the whole file is refused, whatever service is asked for)
  unknown-service <name>, unknown-repo <name>, service-repo-mismatch <name>
  not-deployable <service>   (kind: none: label and settings coverage only, never deployed)
  todo <service>.<field>     (repo or kind of the asked service is TODO)
  input <option>             (a value with the wrong shape)
  ops-ref not-a-commit, range not-ancestor|empty|unreadable, git <op>, internal error
Output: the VERDICT line, then a fenced block of fixed fields, nothing after it (decision 10, ADR-0009). No path,
  diff line, environment value or argv is printed.

Rules (spec §7). Findings only ever raise the class; when a rule cannot be decided it is treated as hit.
  HIGH:   github (a path under .github/), first-deploy, auth (auth, grants, permissions or the registry, by path
          or changed line; also a service whose venv or affects names client-registry), shared-unit and
          shared-container (command rules, below), range-too-large (the range is over the scan cap)
  not LOW (MEDIUM unless HIGH): unit-file, privilege (sudoers, user, group), secret-env (secret or env-name
          change), migration, rollback-not-scripted (no scripts/rollback.sh at T), rollback-ci (not pass),
          multi-service (affects is not empty), unknown-affects (affects holds TODO), unit-restart and
          container-restart (command rules, below)
  hard rule, no override, never LOW: shared (shared: true), shared-resource (venv or affects names a
          shared_resources entry), shared-venv (venv names another service, or another service's venv names
          this one), shared-venv-unknown (this or any other service's venv is TODO)

Command rules (spec §7, "Restarting units and containers"). A changed line (added or removed, any file) is read for
  systemctl, docker, podman, docker-compose and podman-compose commands. Lines are joined over a trailing backslash (no
  space) or comma, and a line that starts with + goes on the line before it (Black layout). Quotes, [ ] and commas are
  dropped, / and = split words (an --option=value stays one word), ; & | ( ) < > and backticks end a command, # starts
  a comment, so sudo, a path, an Exec prefix (- @ + !), a shell wrapper, a here-doc or list-form argv does not hide a
  command. A list-form argv ends at the "]" that closes the outermost "[" opened before the command word and is
  followed by ")" or "}", by "," and a keyword argument (name=) or a closing ) or }; the end of the text is not
  an end (a read window that was cut looks like the end of the line, and a read that did not end counts as cut); a
  "]" followed by anything else ([:], * 1, +, .method, ", [" for another list) does not end it, and with no "[" before
  the command word nothing ends it (over-flag). A word is split on commas and quotes
  first: [d]ocker or docke[r] in a piece is a glob; a piece with a name followed by an index (UNITS[i],
  ${UNITS[$i]}.service, UNITS[i].name) is a name picked at run time and counts as shared. Not read (Known limits in
  spec §7): a tuple or "cmd +=" built on a later line, ( ) around the argv, .__add__([...]) (MEDIUM at most), a dict
  literal indexed at once, " ".join([...]) + "x", shlex.join(...), list([...]) + [...] (LOW or MEDIUM), a quoted index
  key (UNITS["cf"], MEDIUM).
  systemctl: verbs start stop restart reload try-restart reload-or-restart try-reload-or-restart reload-or-try-restart
    force-reload condrestart kill, and enable reenable disable mask preset together with --now. Per unit named: named
    like a shared_resources entry (ignoring - _ . and case, a template instance counts as its template; checked before
    the service's own units); or a glob that fnmatch-matches an entry, the entry plus .service, or the
    entry plus - _ or . and a character; or an index (UNITS[i]); or listed by a shared service or by two services;
    or an entry followed by - _ . and not an own unit -> shared-unit. An exact own unit (no suffix means .service), or
    an instance of an own template -> nothing. Anything else, or no name -> unit-restart. A command not read to its
    end (over the read window) or a line over the command-word cap -> shared-unit.
  containers: docker, podman, docker-compose, podman-compose, "docker compose"; verbs restart stop kill rm down start
    pause unpause, up with --force-recreate, update with --restart (also after "container"). A shared name -> shared-
    container; any other name -> container-restart. Also shared-container: no service name left after the options and
    their values (the whole compose project, or names fed by xargs), --all or -a (for start, -a is --attach and is
    ignored), $( ) in place of a name, a command not read to its end. The first word after --attach, --no-attach and
    --exit-code-from is a compose service name, but it is skipped as an option value (MEDIUM is an estimate: the
    compose documentation does not settle which it is).

Scan cap: the patch text of D..T that is read is capped at MAX_SCAN_BYTES (below). Over it, git is stopped, the lines
  are not scanned and the finding range-too-large (HIGH) is added: a range too big to read is never lower than HIGH.

May call: git (show, cat-file, rev-parse, merge-base, rev-list, log) with stdin from /dev/null, read-only.
Requires python3 >= 3.7 and git. Standard library only.
"""
import fnmatch
import os
import re
import subprocess
import sys

EXIT_OK, EXIT_REFUSED, EXIT_USAGE = 0, 3, 64

HEX40 = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[A-Za-z0-9._-]+$")
UNIT = re.compile(r"^[A-Za-z0-9@._-]+\.(service|timer|socket|path|mount|target)$")
KINDS = ("systemd", "static", "none", "TODO")

# Fields per kind: (required, optional). kind: none carries only repo and kind.
FIELDS = {
    "systemd": ({"repo", "kind", "baseline_sha", "vouched_shas", "expected_deploy_minutes",
                 "expected_rollback_minutes", "units", "affects", "first_deploy_done"}, {"venv", "shared"}),
    "static": ({"repo", "kind", "baseline_sha", "vouched_shas", "expected_deploy_minutes",
                "expected_rollback_minutes", "served_dir", "affects", "first_deploy_done"}, {"shared"}),
    "none": ({"repo", "kind"}, set()),
    "TODO": ({"repo", "kind"}, {"baseline_sha", "vouched_shas", "expected_deploy_minutes",
                                "expected_rollback_minutes", "units", "served_dir", "venv", "affects",
                                "first_deploy_done", "shared"}),
}
ALL_FIELDS = set().union(*[r | o for r, o in FIELDS.values()])

I = re.IGNORECASE
PATH_RULES = [
    ("github", re.compile(r"^\.github/")),
    ("auth", re.compile(r"auth|grant|permission|registry", I)),
    ("unit-file", re.compile(r"\.(service|timer|socket|path|mount|target)$|(^|/)systemd/", I)),
    ("privilege", re.compile(r"(^|/)[^/]*(sudoers|sysusers|polkit)", I)),
    ("secret-env", re.compile(r"(^|/)(\.env|[^/]*\.env|\.env\.[^/]*|env\.example)$|(^|/)[^/]*(secret|credential)", I)),
    ("migration", re.compile(r"(^|/)(migrations?|alembic|schema)(/|$)|\.sql$", I)),
]
LINE_RULES = [
    ("auth", re.compile(r"oauth|authori[sz]|authenticat|\bgrant(s|ed)?\b|registry", I)),
    ("privilege", re.compile(r"\b(useradd|usermod|userdel|groupadd|groupmod|groupdel|gpasswd|adduser|addgroup|visudo|sudoers)\b|^\s*(User|Group|SupplementaryGroups|DynamicUser)\s*=", I)),
    ("secret-env", re.compile(r"os\.environ|getenv|process\.env|\bEnvironment(File)?\s*=|LoadCredential|CREDENTIALS_DIRECTORY|\bsecrets?\b", I)),
    ("migration", re.compile(r"\b(alter|create|drop)\s+(table|index|view)\b|pragma\s+user_version", I)),
]
HIGH = {"github", "first-deploy", "auth", "shared-unit", "shared-container", "range-too-large"}

# The one place the scan cap is set: bytes of `git log -p` output read for D..T (what the line rules scan, deleted
# and added bytes both counted). 16 MiB is under the 20 MB binary that was measured at 4.5 to 7.5 s and about 100 MB
# RSS (no cap: 100 MB took about 35 s and 470 MB), so a capped scan stays near 5 s and 80 MB on that machine; text
# diffs of a deploy are far smaller. Over it the range is HIGH (finding range-too-large), never a lower class.
MAX_SCAN_BYTES = 16 * 1024 * 1024

# Command rule tables (spec §7). Verbs that stop, start, restart or signal a unit; the second group only with --now.
SYSTEMCTL_VERBS = ("start", "stop", "restart", "reload", "try-restart", "reload-or-restart", "try-reload-or-restart",
                   "reload-or-try-restart", "force-reload", "condrestart", "kill")
SYSTEMCTL_NOW_VERBS = ("enable", "reenable", "disable", "mask", "preset")
SYSTEMCTL_VALUE_OPTS = ("-s", "--signal", "--kill-whom", "-H", "--host", "-M", "--machine", "-p", "--property",
                        "-t", "--type", "--state", "-n", "--lines", "-o", "--output", "--kill-value")
CONTAINER_VERBS = ("restart", "stop", "kill", "rm", "down", "up", "start", "pause", "unpause", "update")
# Options before the verb that take a value (docker and compose global options), and per verb the options after it
# that take a value (the number is how many words they take: --scale web=2 is two). A value is never a container.
CONTAINER_GLOBAL_VALUE_OPTS = ("-H", "--host", "-c", "--context", "--config", "-l", "--log-level", "-f", "--file", "-p",
                               "--project-name", "--profile", "--env-file", "--project-directory", "--ansi",
                               "--parallel", "--progress")
_TIME = {"-t": 1, "--time": 1, "--timeout": 1}
_SIG = {"-s": 1, "--signal": 1}
CONTAINER_VERB_VALUE_OPTS = {
    "restart": dict(_TIME, **_SIG), "stop": dict(_TIME, **_SIG), "kill": dict(_SIG),
    "down": dict(_TIME, **{"--rmi": 1}),
    "up": dict(_TIME, **{"--wait-timeout": 1, "--pull": 1, "--scale": 2, "--exit-code-from": 1, "--attach": 1,
                         "--no-attach": 1}),
    "update": {"--restart": 1, "--blkio-weight": 1, "--cpu-period": 1, "--cpu-quota": 1, "--cpu-rt-period": 1,
               "--cpu-rt-runtime": 1, "-c": 1, "--cpu-shares": 1, "--cpus": 1, "--cpuset-cpus": 1,
               "--cpuset-mems": 1, "-m": 1, "--memory": 1, "--memory-reservation": 1, "--memory-swap": 1,
               "--pids-limit": 1},
}
UNIT_SUFFIX = re.compile(r"\.(service|timer|socket|path|mount|target|slice|scope|device|swap|automount)$")
CMD_START = re.compile(r"(?<![A-Za-z0-9_])(?:systemctl|docker|podman)")
CMD_WINDOW = 8192      # characters read after each command word; a longer command is treated as undecidable
CMD_MAX_PER_LINE = 2000


class Refused(Exception):
    def __init__(self, op, name=""):
        Exception.__init__(self, op)
        self.op, self.name = op, name


def emit(verdict, fields):
    out = ["VERDICT: " + verdict, "```"]
    out += ["%s: %s" % (k, v) for k, v in fields]
    out.append("```")
    sys.stdout.write("\n".join(out) + "\n")


# git runs without any inherited GIT_* variable (GIT_DIR, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY, ...) and with
# replace objects ignored, so the repo, objects and history read are exactly the ones named on the command line.
GIT_ENV = dict([(k, v) for k, v in os.environ.items() if not k.startswith("GIT_")] + [("GIT_NO_REPLACE_OBJECTS", "1")])


def git(repo, args, op):
    try:
        p = subprocess.run(["git", "-C", repo, "-c", "core.quotepath=off"] + args, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=GIT_ENV)
    except OSError:
        raise Refused("git", op)
    if p.returncode != 0:
        raise Refused("git", op)
    return p.stdout


def git_capped(repo, args, op, cap):
    """Like git(), but stdout is read in chunks and git is killed once more than `cap` bytes arrived; returns None then."""
    try:
        p = subprocess.Popen(["git", "-C", repo, "-c", "core.quotepath=off"] + args, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=GIT_ENV)
    except OSError:
        raise Refused("git", op)
    chunks, size = [], 0
    try:
        while True:
            chunk = p.stdout.read(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > cap:
                p.kill()
                return None
            chunks.append(chunk)
    finally:
        p.stdout.close()
        rc = p.wait()
    if rc != 0:
        raise Refused("git", op)
    return b"".join(chunks)


# ---- services.yaml: a strict subset of YAML, parsed without a YAML library ----

def strip_comment(rest):
    """Return the value text of `rest` with a trailing comment removed; quotes and flow lists are kept whole."""
    s = rest.strip()
    if not s or s.startswith("#"):
        return ""
    if s[0] in "\"'":
        end = s.find(s[0], 1)
        if end < 0:
            return None
        tail = s[end + 1:].strip()
        return s[:end + 1] if (not tail or tail.startswith("#")) else None
    if s[0] == "[":
        end = s.find("]")
        if end < 0:
            return None
        tail = s[end + 1:].strip()
        return s[:end + 1] if (not tail or tail.startswith("#")) else None
    m = re.search(r"\s#", s)
    return (s[:m.start()] if m else s).strip()


def scalar(v):
    if v is None:
        return None
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    if v[:1] in "{[&*!|>%@`," or ": " in v:
        return None
    return v


def flow_list(v):
    if v is None or not (v.startswith("[") and v.endswith("]")):
        return None
    inner = v[1:-1].strip()
    if not inner:
        return []
    items = [scalar(x.strip()) for x in inner.split(",")]
    return None if any(i is None or i == "" for i in items) else items


def parse_services(text):
    if text.startswith("\ufeff"):
        text = text[1:]
    shared_resources, services, order = None, {}, []
    section, key, seen_services = None, None, False
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw[:-1] if raw.endswith("\r") else raw
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line[:len(line) - len(line.lstrip())]:
            raise Refused("services-yaml", "malformed-line %d" % n)
        if not line.startswith(" "):
            m = re.match(r"^([A-Za-z_]+):(.*)$", line)
            if not m:
                raise Refused("services-yaml", "malformed-line %d" % n)
            top, val = m.group(1), strip_comment(m.group(2))
            if top == "shared_resources":
                if shared_resources is not None:
                    raise Refused("services-yaml", "malformed-line %d" % n)
                shared_resources = flow_list(val)
                if shared_resources is None or not all(NAME.fullmatch(x) for x in shared_resources):
                    raise Refused("services-yaml", "bad-value shared_resources")
                section = None
            elif top == "services" and val == "" and not seen_services:
                seen_services, section, key = True, "services", None
            else:
                raise Refused("services-yaml", "malformed-line %d" % n)
            continue
        if section != "services":
            raise Refused("services-yaml", "malformed-line %d" % n)
        m = re.match(r"^  ([^ #:][^:]*):(.*)$", line)
        if m:
            k, val = m.group(1), strip_comment(m.group(2))
            if not NAME.fullmatch(k) or val != "":
                raise Refused("services-yaml", "malformed-line %d" % n)
            if k in services:
                raise Refused("services-yaml", "duplicate-key " + k)
            services[k], key = {}, k
            order.append(k)
            continue
        m = re.match(r"^    ([a-z_]+):(.*)$", line)
        if not m or key is None:
            raise Refused("services-yaml", "malformed-line %d" % n)
        f, val = m.group(1), strip_comment(m.group(2))
        if f in services[key]:
            raise Refused("services-yaml", "duplicate-field %s.%s" % (key, f))
        if f not in ALL_FIELDS:
            raise Refused("services-yaml", "unknown-field %s.%s" % (key, f))
        if val is None or val == "":
            raise Refused("services-yaml", "bad-value %s.%s" % (key, f))
        services[key][f] = val
    if shared_resources is None:
        raise Refused("services-yaml", "bad-value shared_resources")
    if not services:
        raise Refused("services-yaml", "none")
    validate(services, order, shared_resources)
    return services, order, shared_resources


def validate(services, order, shared):
    repos = {}
    for k in order:
        s = services[k]
        if "repo" not in s:
            raise Refused("services-yaml", "missing-repo " + k)
        bad = lambda f: Refused("services-yaml", "bad-value %s.%s" % (k, f))
        kind = scalar(s.get("kind", ""))
        if kind not in KINDS:
            raise Refused("services-yaml", ("bad-value %s.kind" if "kind" in s else "missing-field %s.kind") % k)
        req, opt = FIELDS[kind]
        for f in sorted(req):
            if f not in s:
                raise Refused("services-yaml", "missing-field %s.%s" % (k, f))
        for f in sorted(s):
            if f not in req | opt:
                raise Refused("services-yaml", "unknown-field %s.%s" % (k, f))
        out = {}
        for f, v in s.items():
            if f in ("units", "vouched_shas", "affects"):
                lst = flow_list(v)
                if lst is None:
                    raise bad(f)
                out[f] = lst
            else:
                sv = scalar(v)
                if sv is None:
                    raise bad(f)
                out[f] = sv
        r = out["repo"]
        if r != "TODO":
            if not NAME.fullmatch(r) or re.fullmatch(r"\.+", r):
                raise bad("repo")
            if r in repos:
                raise Refused("services-yaml", "duplicate-repo " + r)
            repos[r] = k
        for f, v in out.items():
            ok = True
            if f == "baseline_sha":
                ok = v == "TODO" or bool(HEX40.fullmatch(v))
            elif f == "vouched_shas":
                ok = all(HEX40.fullmatch(x) for x in v)
            elif f in ("expected_deploy_minutes", "expected_rollback_minutes"):
                ok = v == "TODO" or (v.isdigit() and 1 <= int(v) <= 240)
            elif f == "units":
                ok = bool(v) and (v == ["TODO"] or all(UNIT.fullmatch(x) for x in v))
            elif f == "served_dir":
                ok = v == "TODO" or (v.startswith("~/") and ".." not in v.split("/") and "\n" not in v)
            elif f in ("first_deploy_done", "shared"):
                ok = v in ("true", "false") or (f == "first_deploy_done" and v == "TODO")
            elif f == "venv":
                ok = v in ("own", "TODO") or (v != k and (v in services or v in shared))
            elif f == "affects":
                ok = v == ["TODO"] or all(x != k and (x in services or x in shared) for x in v)
            if not ok:
                raise bad(f)
        services[k] = out


# ---- range inspection ----

def join_parts(parts):
    return " ".join(parts).replace("\x1f ", "")      # a last \x1f stays: it is whitespace to split() and \s


def changed(repo_dir, d, t):
    """Paths and changed lines over every commit in d..t, not only the net diff: a change made and reverted
    inside the range still counts. -m shows a merge commit against each parent, so a change made in the merge
    itself is seen. --text scans files that attributes (-diff, binary) or content would mark as binary.
    Returns (paths, lines, commands, too_large); commands are the lines with backslash continuations joined; too_large is True when either git output passed MAX_SCAN_BYTES."""
    names = git_capped(repo_dir, ["log", "-m", "--no-renames", "--format=", "--name-only", "-z", "%s..%s" % (d, t)],
                       "log", MAX_SCAN_BYTES)
    raw = None if names is None else git_capped(
        repo_dir, ["log", "-m", "--text", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0",
                   "--format=%x00", "-p", "%s..%s" % (d, t)], "log", MAX_SCAN_BYTES)
    if names is None or raw is None:
        return set(), [], [], True
    paths = set(x.decode("utf-8", "replace").strip("\n") for x in names.split(b"\x00"))
    paths.discard("")
    lines, cmds, in_hunk, parts, sign, done = [], [], False, [], "", False
    for b in raw.split(b"\n"):
        s = b.decode("utf-8", "replace")
        if s.startswith("diff --git ") or s.startswith("\x00") or s.startswith("@@"):
            if parts:
                cmds.append(join_parts(parts))
            in_hunk, parts = s.startswith("@@"), []
        elif in_hunk and s[:1] in ("+", "-"):
            text = s[1:]
            lines.append(text)
            if parts and (sign != s[0] or (done and not text.lstrip().startswith("+"))):
                cmds.append(join_parts(parts))      # a finished command goes on only over a line that starts with + (Black layout)
                parts = []
            t = text.rstrip()
            parts.append(t[:-1] + "\x1f" if t.endswith("\\") else text)   # \x1f: join the next line with no space
            sign = s[0]
            # a command goes on over a trailing backslash, and over a trailing comma (a list of argv words, one a line)
            done = not t.endswith(("\\", ","))
    if parts:
        cmds.append(join_parts(parts))
    return paths, lines, cmds, False


def is_shared_service(k, services, shared):
    s = services[k]
    return (s.get("shared") == "true" or k in shared or bool((set(s.get("affects", [])) | {s.get("venv")}) & set(shared))
            or any(o != k and services[o].get("venv") == k for o in services))


def norm(x):
    return re.sub(r"[-_.]", "", x.lower())


GLOB = re.compile(r"[*?\[]")
INDEXED = re.compile(r"\w\[[^\[\]]+\]")    # UNITS[i], ${UNITS[$i]}.service, UNITS[i].name: a name picked at run time from a collection
GLOB_CLASS = re.compile(r"\w\[[^\[\]\"',\s]+\]|\[[^\[\]\"',\s]+\]\w")    # [d]ocker, docke[r]: not a list of argv


def shared_match(name, shared, exact=False):
    """True when `name` (a unit, container or compose service name) is a shared resource: equal to a shared_resources
    entry (ignoring - _ and .), or starting with <entry>- <entry>_ or <entry>.; a glob, also of a template
    (name@*), is matched against the entries with fnmatch; a name ending in an index (UNITS[i]) is always shared:
    which one is picked is not known."""
    n = name.lower()
    res = [e.lower() for e in shared]
    base = UNIT_SUFFIX.sub("", n)
    if GLOB.search(n):
        pat = base.split("@")[0]       # name@* is matched on name: the entries are plain names
        forms = [c for e in res for c in (e, e + ".service", e + "-x", e + "_x", e + ".x")]   # an entry, or a name starting with it
        return bool(INDEXED.search(n)) or any(fnmatch.fnmatchcase(c, pat) for c in forms)
    head = base.split("@")[0]
    return any(norm(head) == norm(e) or (not exact and head.startswith((e + "-", e + "_", e + "."))) for e in res)


def unit_finding(arg, svc, services, shared):
    """Finding for one unit named after a systemctl verb: shared-unit, unit-restart or None (the service's own)."""
    arg = arg.replace("\\", "")      # in a shell, \c is c
    if GLOB.search(arg):
        return "shared-unit" if shared_match(arg, shared) else "unit-restart"
    u = arg if UNIT_SUFFIX.search(arg) else arg + ".service"
    head = UNIT_SUFFIX.sub("", u)
    suffix = u[len(head):]
    base = head.split("@")[0]
    tmpl = base + "@" + suffix if "@" in head else u        # name@x.service is an instance of name@.service
    if shared_match(u, shared, exact=True):     # before own: a unit named like a shared resource is shared
        return "shared-unit"
    listed = [o for o in services if {u, tmpl} & set(services[o].get("units", []))]
    if len(listed) > 1 or any(o != svc and is_shared_service(o, services, shared) for o in listed):
        return "shared-unit"
    if listed:      # before the owner of the plain name: a unit another service lists is that service's, not an instance of this one
        if svc in listed:
            return None
    elif base + suffix in set(services[svc].get("units", [])):     # an instance of a template whose plain unit is its own
        return None
    return "shared-unit" if shared_match(u, shared) else "unit-restart"


def container_finding(name, shared):
    name = name.replace("\\", "")
    return "shared-container" if shared_match(name, shared) else "container-restart"


LIST_CLOSE = re.compile(r",\s*(\w+\s*=[^=]|[)}])")      # , keyword=... or , ) : the next argument is not another list


def list_end(text, opened):
    """Index of the "]" that ends a list-form argv, or len(text). The list ends at the "]" that brings the depth of the
    `opened` "[" that were open before the command word back to 0 and is followed by ")" or "}", by "," and a keyword
    argument (name=) or a closing ) or }. ][:], ] * 1, ].__add__(, + and ", [" (another list as an argument) go on, as
    does a "]" inside a nested list. The end of the text is not an end: a window that was cut at CMD_WINDOW looks like
    the end of the line, and the caller treats a read that did not end as cut (an over-flag); where the text really ends
    there is nothing more to read. With none open before the command word, nothing ends it (over-flag)."""
    depth = opened
    for i, c in enumerate(text):
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if opened and depth <= 0:
                after = text[i + 1:].lstrip()
                if after[:1] in (")", "}") or LIST_CLOSE.match(after):
                    return i
    return len(text)


def command_tokens(text, opened=0):
    """Tokens of the first command in `text`: ; & | ( ) < > and backticks end a token and a command, quotes, [ ] and
    commas are dropped (so list-form argv reads as words) and the list ends at its closing ] (see list_end), / and =
    split a word (an --option=value stays one word), a # starts a comment; [d]ocker or UNITS[i] inside a piece
    (a word between commas and quotes) is a glob and stays."""
    end = list_end(text, opened)
    t = re.sub(r"(?<!\S)[&0-9]*[<>]+&?[0-9-]*", " ; ", text[:end].replace("`", " ; "))
    t = re.sub(r"[;&|()<>]", " ; ", t)
    out = []
    for raw in t.split():
        if raw == ";" or raw.startswith("#"):
            return out, True
        for piece in re.split(r"[\"',]", raw):
            words = [piece] if GLOB_CLASS.search(piece) else re.sub(r"[\[\]]", " ", piece).split()
            for p in words:
                if p.startswith("-") and "=" in p:
                    out.append(p)
                else:
                    out.extend(x for x in re.split(r"[=/]", p) if x)
    return out, end < len(text)


def systemctl_args(toks):
    """Unit names after the verb of a systemctl command, or None when the verb does not stop, start or signal a unit."""
    verb = [i for i, x in enumerate(toks) if x in SYSTEMCTL_VERBS or (x in SYSTEMCTL_NOW_VERBS and "--now" in toks)]
    if not verb:
        return None
    names, skip = [], False
    for x in toks[verb[0] + 1:]:
        if skip:
            skip = False
        elif x in SYSTEMCTL_VALUE_OPTS:
            skip = True
        elif not x.startswith("-"):
            names.append(x)
    return names


def container_args(toks):
    """(names, bulk) after the verb of a docker/podman/compose command, or None when it is not an acting
    verb (restart, stop, kill, rm, down, start, pause, unpause, up --force-recreate, update --restart). bulk: --all,
    -a, or a $( ) command substitution in place of a name."""
    v, i = None, 0
    while i < len(toks):
        if toks[i] in CONTAINER_GLOBAL_VALUE_OPTS:
            i += 2
            continue
        if toks[i] in CONTAINER_VERBS:
            v = i
            break
        i += 1
    if v is None:
        return None
    verb, rest = toks[v], toks[v + 1:]
    if verb == "up" and not any(x.startswith("--force-recreate") for x in rest):
        return None
    if verb == "update" and not any(x.startswith("--restart") for x in rest):
        return None
    opts = CONTAINER_VERB_VALUE_OPTS.get(verb, {})
    names, bulk, i = [], False, 0
    while i < len(rest):
        x = rest[i]
        i += 1
        if x in opts:
            i += opts[x]
        elif x.startswith("-"):
            # -a is --attach for start: only the other verbs take it for every container
            bulk = bulk or x == "--all" or bool(verb != "start" and re.fullmatch(r"-[A-Za-z]+", x) and "a" in x[1:])
        elif x == "$":
            bulk = True
        else:
            names.append(x)
    return names, bulk


def command_findings(line, svc, services, shared):
    """Findings for every systemctl, docker, podman or compose command on one changed line (header: command rules)."""
    found, n = set(), 0
    for m in CMD_START.finditer(line):
        n += 1
        if n > CMD_MAX_PER_LINE:
            found.add("shared-unit")        # words that were not read could name anything
            break
        exe = m.group(0)
        window = line[m.start():m.start() + CMD_WINDOW]
        before = line[:m.start()]
        toks, ended = command_tokens(window, max(0, before.count("[") - before.count("]")))
        cut = not ended and m.start() + CMD_WINDOW < len(line)
        if exe == "systemctl":
            names = systemctl_args(toks[1:])
            if names is None:
                continue
            if cut:
                found.add("shared-unit")    # the rest of the command was not read
            if not names:
                found.add("unit-restart")
            for a in names:
                f = unit_finding(a, svc, services, shared)
                if f:
                    found.add(f)
        else:
            r = container_args(toks[1:])
            if r is None:
                continue
            names, bulk = r
            if cut or bulk or not names:        # no name: the whole compose project, or names fed by xargs or stdin
                found.add("shared-container")
            for a in names:
                found.add(container_finding(a, shared))
    return found


def classify(args, services, shared):
    svc, repo = args.get("--service"), args.get("--repo")
    for opt, v in (("service", svc), ("repo", repo)):
        if v is not None and not NAME.fullmatch(v):
            raise Refused("input", opt)
    if svc is not None and svc not in services:
        raise Refused("unknown-service", svc)
    if repo is not None:
        hit = [k for k in services if services[k]["repo"] == repo and repo != "TODO"]
        if not hit:
            raise Refused("unknown-repo", repo)
        if svc is not None and hit[0] != svc:
            raise Refused("service-repo-mismatch", svc)
        svc = hit[0]
    s = services[svc]
    if s["kind"] == "none":
        raise Refused("not-deployable", svc)
    for f in ("repo", "kind"):
        if s[f] == "TODO":
            raise Refused("todo", "%s.%s" % (svc, f))

    rng = args["--range"]
    m = re.fullmatch(r"([0-9a-f]{40})\.\.([0-9a-f]{40})", rng)
    if not m:
        raise Refused("input", "range")
    d, t = m.group(1), m.group(2)
    first, rb = args["--first-deploy"], args["--rollback-ci"]
    if first not in ("yes", "no"):
        raise Refused("input", "first-deploy")
    if rb not in ("pass", "fail", "unknown"):
        raise Refused("input", "rollback-ci")
    rd = args["--repo-dir"]
    for x in (d, t):
        try:
            git(rd, ["cat-file", "-e", x + "^{commit}"], "cat-file")
        except Refused:
            raise Refused("range", "unreadable")
    if d == t:
        raise Refused("range", "empty")
    try:
        git(rd, ["merge-base", "--is-ancestor", d, t], "merge-base")
    except Refused:
        raise Refused("range", "not-ancestor")
    commits = int(git(rd, ["rev-list", "--count", "%s..%s" % (d, t)], "rev-list").strip() or b"0")

    paths, lines, cmds, too_large = changed(rd, d, t)
    found = set(["range-too-large"] if too_large else [])
    units = set(s.get("units", [])) - {"TODO"}
    for p in paths:
        for name, rx in PATH_RULES:
            if rx.search(p):
                found.add(name)
        if p.rsplit("/", 1)[-1] in units:
            found.add("unit-file")
    for ln in lines:
        for name, rx in LINE_RULES:
            if rx.search(ln):
                found.add(name)
    for ln in cmds:
        found |= command_findings(ln, svc, services, shared)
    if first == "yes":
        found.add("first-deploy")
    try:
        git(rd, ["cat-file", "-e", t + ":scripts/rollback.sh"], "cat-file")
    except Refused:
        found.add("rollback-not-scripted")
    if rb != "pass":
        found.add("rollback-ci")

    affects, venv = s.get("affects", []), s.get("venv")
    if affects == ["TODO"]:
        found.add("unknown-affects")
    elif affects:
        found.add("multi-service")
    if s.get("shared") == "true":
        found.add("shared")
    named = set(affects) | ({venv} if venv else set())
    if named & set(shared):
        found.add("shared-resource")
    if "client-registry" in named:
        found.add("auth")
    if venv and venv not in ("own", "TODO") and venv in services:
        found.add("shared-venv")
    if any(o != svc and services[o].get("venv") == svc for o in services):
        found.add("shared-venv")
    if venv == "TODO" or any(services[o].get("venv") == "TODO" for o in services):
        found.add("shared-venv-unknown")

    risk = "HIGH" if found & HIGH else ("MEDIUM" if found else "LOW")
    return [("mode", "classify"), ("risk", risk), ("service", svc), ("repo", s["repo"]), ("kind", s["kind"]),
            ("range", "%s..%s" % (d, t)), ("commits", commits), ("files", "unknown" if too_large else len(paths)),
            ("first_deploy", first), ("rollback_ci", rb), ("findings", ",".join(sorted(found)) or "none"),
            ("ops_ref", args["--ops-ref"])]


def todo_fields(services, order):
    out = []
    for k in order:
        for f in sorted(services[k]):
            v = services[k][f]
            if v == "TODO" or (isinstance(v, list) and "TODO" in v):
                out.append("%s.%s" % (k, f))
    return out


VALUE_OPTS = ("--ops-repo", "--ops-ref", "--service", "--repo", "--repo-dir", "--range", "--first-deploy",
              "--rollback-ci")


def parse_args(argv):
    args, i = {}, 0
    while i < len(argv):
        a = argv[i]
        if a == "--validate" and a not in args:
            args[a] = True
            i += 1
        elif a in VALUE_OPTS and a not in args and i + 1 < len(argv):
            args[a] = argv[i + 1]
            i += 2
        else:
            return None
    need = {"--ops-repo", "--ops-ref"}
    if "--validate" in args:
        return args if set(args) == need | {"--validate"} else None
    need |= {"--repo-dir", "--range", "--first-deploy", "--rollback-ci"}
    if not need <= set(args) or not ({"--service", "--repo"} & set(args)):
        return None
    return args


def main(argv):
    args = parse_args(argv)
    if args is None:
        sys.stderr.write(__doc__.split("Exit codes:")[0])
        emit("FAIL usage", [("mode", "usage"), ("exit", EXIT_USAGE)])
        return EXIT_USAGE
    mode = "validate" if "--validate" in args else "classify"
    ref = args["--ops-ref"]
    try:
        if not HEX40.fullmatch(ref):
            raise Refused("input", "ops-ref")
        try:
            git(args["--ops-repo"], ["cat-file", "-e", ref + "^{commit}"], "cat-file")
        except Refused:
            raise Refused("ops-ref", "not-a-commit")
        try:
            text = git(args["--ops-repo"], ["show", ref + ":services.yaml"], "show").decode("utf-8")
        except (Refused, UnicodeDecodeError):
            raise Refused("services-yaml", "unreadable")
        services, order, shared = parse_services(text)
        if mode == "validate":
            todo = todo_fields(services, order)
            emit("PASS", [("mode", mode), ("services", len(order)), ("todo_fields", len(todo))]
                 + [("todo", x) for x in todo] + [("ops_ref", ref)])
            return EXIT_OK
        emit("PASS", classify(args, services, shared))
        return EXIT_OK
    except Refused as e:
        emit(("FAIL %s %s" % (e.op, e.name)).rstrip(), [("mode", mode), ("refused", e.op), ("exit", EXIT_REFUSED)])
        return EXIT_REFUSED
    except Exception:  # fail closed: any unexpected error is a refusal, never a class
        emit("FAIL internal error", [("mode", mode), ("refused", "internal"), ("exit", EXIT_REFUSED)])
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
