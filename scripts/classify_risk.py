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
          or changed line; also a service whose venv or affects names client-registry)
  not LOW (MEDIUM unless HIGH): unit-file, privilege (sudoers, user, group), secret-env (secret or env-name
          change), migration, rollback-not-scripted (no scripts/rollback.sh at T), rollback-ci (not pass),
          multi-service (affects is not empty), unknown-affects (affects holds TODO)
  hard rule, no override, never LOW: shared (shared: true), shared-resource (venv or affects names a
          shared_resources entry), shared-venv (venv names another service, or another service's venv names
          this one), shared-venv-unknown (this or any other service's venv is TODO)

May call: git (show, cat-file, rev-parse, merge-base, rev-list, log) with stdin from /dev/null, read-only.
Requires python3 >= 3.7 and git. Standard library only.
"""
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
HIGH = {"github", "first-deploy", "auth"}


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

def changed(repo_dir, d, t):
    """Paths and changed lines over every commit in d..t, not only the net diff: a change made and reverted
    inside the range still counts. -m shows a merge commit against each parent, so a change made in the merge
    itself is seen. --text scans files that attributes (-diff, binary) or content would mark as binary."""
    names = git(repo_dir, ["log", "-m", "--no-renames", "--format=", "--name-only", "-z", "%s..%s" % (d, t)], "log")
    paths = set(x.decode("utf-8", "replace").strip("\n") for x in names.split(b"\x00"))
    paths.discard("")
    raw = git(repo_dir, ["log", "-m", "--text", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0",
                         "--format=%x00", "-p", "%s..%s" % (d, t)], "log")
    lines, in_hunk = [], False
    for b in raw.split(b"\n"):
        s = b.decode("utf-8", "replace")
        if s.startswith("diff --git ") or s.startswith("\x00"):
            in_hunk = False
        elif s.startswith("@@"):
            in_hunk = True
        elif in_hunk and s[:1] in ("+", "-"):
            lines.append(s[1:])
    return paths, lines


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

    paths, lines = changed(rd, d, t)
    found = set()
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
            ("range", "%s..%s" % (d, t)), ("commits", commits), ("files", len(paths)),
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
