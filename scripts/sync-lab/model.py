"""Expected-state model for the sync lab. Fed only by the operations the lab performs, never by CLI
output. State lives in a JSON file. Usage: model.py STATE COMMAND [args...]

  init                          fresh state (devices A, B, C without a package)
  apply WORD...                 apply one operation line (add/edit/rm/attach_add/attach_rm)
  plan STEP R1..R6              derive an operation from the random numbers and the model state, apply it
                                (deliver and round are only printed; the lab applies them with `delivered`)
  sha NAME HEX                  record the plaintext sha256 of attachment NAME
  delivered SRC DST VARIANT OBSERVED SRC_DIRTY DST_DIRTY
                                apply a cloud delivery; prints MISMATCH if the lab's mode differs from the
                                model's version bookkeeping. The dirty flags (0/1) are the lab's byte-level
                                observation. The model tracks unsynced edits itself; lab-dirty with
                                model-clean is accepted (a merge rewrite), lab-clean with model-dirty fails.
                                Model fields are keyed by name: random mode never renames or re-adds a field.
  check A:RAWFILE [B:RAWFILE..] compare raw CLI views with the model and with each other

Merge rules follow 03 §5: per-attribute stamps, per-field stamps with removed_fields markers, tombstone
vs live by deleted_at >= modified_at, attachment union with tombstones. Stamps are the operation order.
Cloud rule: a delivery is a plain overwrite only if the sender holds the cloud's current version, the
receiver has no unsynced edits, or the receiver has no package; else a conflict copy.
"""
import copy
import json
import re
import sys

DEVS = ["A", "B", "C"]


def load(p):
    with open(p) as f:
        return json.load(f)


def save(p, s):
    with open(p, "w") as f:
        json.dump(s, f)


def new_state():
    return {
        "clock": 0,
        "ver": 0,
        "items": {d: None for d in DEVS},
        "base": {d: 0 for d in DEVS},
        "synced": {d: None for d in DEVS},
        "sha": {},
    }


def mk(title, t):
    return {
        "title": [title, t],
        "fav": [False, t],
        "tags": [["login"], t],
        "icon": [None, t],
        "fields": {
            "username": ["u0", t],
            "password": ["p0", t],
            "url": ["http://u0", t],
            "notes": ["n0", t],
        },
        "removed": {},
        "atts": {},
        "att_removed": {},
        "modified": t,
        "deleted": None,
    }


def find(items, title):
    for k, i in items.items():
        if i["deleted"] is None and i["title"][0] == title:
            return k
    raise SystemExit("model: no live item titled %r" % title)


def apply_op(st, w):
    st["clock"] += 1
    t = st["clock"]
    k, d = w[0], w[1]
    if st["items"][d] is None:
        st["items"][d] = {}
    items = st["items"][d]
    if k == "add":
        items[w[2]] = mk(w[2], t)
        return
    it = items[find(items, w[2])]
    if k == "rm":
        it["deleted"] = t
    elif k == "attach_add":
        it["atts"][w[3]] = t
        it["att_removed"].pop(w[3], None)
    elif k == "attach_rm":
        del it["atts"][w[3]]
        it["att_removed"][w[3]] = t
    elif k == "edit":
        args = w[3:]
        untag = [args[i + 1] for i, a in enumerate(args) if a == "--untag"]
        tag = [args[i + 1] for i, a in enumerate(args) if a == "--tag"]
        tags = list(it["tags"][0])
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--title":
                it["title"] = [args[i + 1], t]
            elif a in ("--favorite", "--unfavorite"):
                it["fav"] = [a == "--favorite", t]
            elif a == "--icon":
                it["icon"] = [None if args[i + 1] == "auto" else args[i + 1], t]
            elif a == "--set":
                n, v = args[i + 1].split("=", 1)
                assert n in it["fields"], "model: set on absent field " + n
                it["fields"][n] = [v, t]
            elif a == "--add":
                n, v = args[i + 1].split(":", 1)[1].split("=", 1)
                it["fields"][n] = [v, t]
            elif a == "--rm-field":
                n = args[i + 1]
                del it["fields"][n]
                it["removed"][n] = t
            i += 1 if a in ("--favorite", "--unfavorite") else 2
        if untag or tag:
            tags = [x for x in tags if x not in untag]
            for x in tag:
                if x not in tags:
                    tags.append(x)
            it["tags"] = [tags, t]
    else:
        raise SystemExit("model: unknown op " + k)
    it["modified"] = t


def pick(a, b):
    return a if a[1] >= b[1] else b


def merge_item(o, t):
    od, td = o["deleted"], t["deleted"]
    if od is not None and td is not None:
        return copy.deepcopy(o if od >= td else t)
    if od is not None or td is not None:
        tomb, live = (o, t) if od is not None else (t, o)
        return copy.deepcopy(tomb if tomb["deleted"] >= live["modified"] else live)
    r = {"deleted": None}
    for a in ("title", "fav", "tags", "icon"):
        r[a] = copy.deepcopy(pick(o[a], t[a]))
    fo, ft, ro, rt = o["fields"], t["fields"], o["removed"], t["removed"]
    fields = {}
    for n in set(fo) | set(ft):
        if n in fo and n in ft:
            fields[n] = pick(fo[n], ft[n])
        elif n in ft:
            if not (n in ro and ro[n] >= ft[n][1]):
                fields[n] = ft[n]
        elif not (n in rt and rt[n] >= fo[n][1]):
            fields[n] = fo[n]
    removed = {n: max(ro.get(n, 0), rt.get(n, 0)) for n in set(ro) | set(rt)}
    removed = {n: s for n, s in removed.items() if not (n in fields and fields[n][1] > s)}
    r["fields"] = copy.deepcopy(fields)
    r["removed"] = removed
    ar = {n: max(o["att_removed"].get(n, 0), t["att_removed"].get(n, 0)) for n in set(o["att_removed"]) | set(t["att_removed"])}
    atts = {}
    for n in set(o["atts"]) | set(t["atts"]):
        added = max(o["atts"].get(n, 0), t["atts"].get(n, 0))
        if not (n in ar and ar[n] >= added):
            atts[n] = added
    r["atts"], r["att_removed"] = atts, ar
    r["modified"] = max(o["modified"], t["modified"])
    return r


def merge(ours, theirs):
    out = {}
    for k in set(ours) | set(theirs):
        if k not in ours:
            out[k] = copy.deepcopy(theirs[k])
        elif k not in theirs:
            out[k] = copy.deepcopy(ours[k])
        else:
            out[k] = merge_item(ours[k], theirs[k])
    return out


def delivered(st, src, dst, variant, observed, src_dirty, dst_dirty):
    msgs = []
    ver0 = st["ver"]
    if variant == "drop":
        expected = "dropped"
    else:
        head = st["base"][src] == ver0
        no_pkg = st["items"][dst] is None
        # Unsynced edits are tracked from the model's own operations (items vs what the cloud last
        # gave or took). The lab's byte-level bit may be set when the model's is not (a merge can
        # rewrite a file without changing any item); the reverse means the lab lost track of an edit.
        m_src = st["items"][src] != st["synced"][src]
        m_dst = (not no_pkg) and st["items"][dst] != st["synced"][dst]
        if m_src and not src_dirty:
            msgs.append("MISMATCH dirtiness: %s has edits the model knows of but the lab sees none" % src)
        if m_dst and not dst_dirty:
            msgs.append("MISMATCH dirtiness: %s has edits the model knows of but the lab sees none" % dst)
        src_dirty, dirty = src_dirty or m_src, dst_dirty or m_dst
        if head and src_dirty:
            st["ver"] += 1
            st["base"][src] = st["ver"]
            st["synced"][src] = copy.deepcopy(st["items"][src])
        forced = variant.startswith("forced")
        plain = (not forced) and (no_pkg or (head and not dirty))
        expected = "plain" if plain else "conflict"
        if plain:
            st["items"][dst] = copy.deepcopy(st["items"][src])
            st["base"][dst] = st["base"][src]
            st["synced"][dst] = copy.deepcopy(st["items"][dst])
        else:
            st["items"][dst] = merge(st["items"][dst] or {}, st["items"][src])
            if head:
                st["base"][dst] = st["ver"]
    if expected != observed:
        msgs.append("MISMATCH cloud rule %s->%s (%s): model expects %s, lab did %s" % (src, dst, variant, expected, observed))
    return msgs


def plan(st, step, r):
    d = "A" if r[0] % 2 == 0 else "B"
    o = "B" if d == "A" else "A"
    op = r[1] % 100
    items = st["items"][d] or {}
    live = sorted(k for k, i in items.items() if i["deleted"] is None)
    it = None
    if live and 10 <= op < 71:
        it = items[live[r[2] % len(live)]]
    if op < 10:
        w = ["add", d, "n%d" % step]
    elif op < 85 and it is None and op >= 10 and op < 71:
        return "noop"
    elif op < 18:
        w = ["edit", d, it["title"][0], "--title", "r%d" % step]
    elif op < 24:
        w = ["edit", d, it["title"][0], "--unfavorite" if it["fav"][0] else "--favorite"]
    elif op < 30:
        g = "g%d" % (r[3] % 4)
        w = ["edit", d, it["title"][0], "--untag" if g in it["tags"][0] else "--tag", g]
    elif op < 34:
        ic = "letter:#0000%d" % (10 + r[3] % 90)
        if ic == it["icon"][0]:
            ic = "letter:#0000%d" % (10 + (r[3] + 1) % 90)
        w = ["edit", d, it["title"][0], "--icon", ic]
    elif op < 48:
        names = sorted(it["fields"])
        if not names:
            return "noop"
        n = names[r[3] % len(names)]
        w = ["edit", d, it["title"][0], "--set", "%s=v%d" % (n, step)]
    elif op < 54:
        w = ["edit", d, it["title"][0], "--add", "text:x%d=v%d" % (step, step)]
    elif op < 60:
        names = sorted(it["fields"])
        if not names:
            return "noop"
        w = ["edit", d, it["title"][0], "--rm-field", names[r[3] % len(names)]]
    elif op < 64:
        w = ["rm", d, it["title"][0]]
    elif op < 68:
        w = ["attach_add", d, it["title"][0], "att%d" % step, str(1 + r[3] % 3000)]
    elif op < 71:
        names = sorted(it["atts"])
        if not names:
            return "noop"
        w = ["attach_rm", d, it["title"][0], names[r[3] % len(names)]]
    elif op < 85:
        n = r[3] % 100
        if n < 15:
            v = "drop"
        elif n < 30:
            v = "vault"
        elif n < 45:
            v = "delay:%d" % (r[4] % 40)
        elif n < 60:
            v = "forced:" + ["sibling", "inpackage", "sibling-n", "inpackage-n"][r[4] % 4]
        else:
            v = "plain"
        return " ".join(["deliver", d, o, v])
    else:
        return " ".join(["round", d, o])
    apply_op(st, w)
    return " ".join(w)


def view(items):
    out = []
    live = [i for i in (items or {}).values() if i["deleted"] is None]
    for i in sorted(live, key=lambda i: i["title"][0]):
        out.append("item %s fav=%d tags=%s icon=%s" % (i["title"][0], i["fav"][0], ",".join(i["tags"][0]), i["icon"][0] or "-"))
        for n in sorted(i["fields"]):
            out.append("  f %s=%s" % (n, i["fields"][n][0]))
    return out


def attview(st, items):
    out = []
    live = [i for i in (items or {}).values() if i["deleted"] is None]
    for i in sorted(live, key=lambda i: i["title"][0]):
        for n in sorted(i["atts"]):
            out.append("att %s %s %s" % (i["title"][0], n, st["sha"].get(n, "?")))
    return out


def parse_raw(path):
    secs, cur = [], None
    for line in open(path).read().splitlines():
        if line.startswith("=== "):
            cur = [line[4:], []]
            secs.append(cur)
        elif cur is not None:
            cur[1].append(line)
    return secs


def real(path):
    """Returns (view lines, attachment lines, blob map id->hash, errors)."""
    secs = parse_raw(path)
    errs = [h for h, _ in secs if h.startswith("ERROR")]
    fav = set()
    shas, blobs = {}, {}
    for h, body in secs:
        if h == "fav":
            fav = {l.split()[1] for l in body if len(l.split()) > 1}
        elif h.startswith("sha "):
            _, i, s = h.split()
            shas[i] = s
            if s in ("FAIL", "missing"):
                errs.append(h)
        elif h.startswith("blob "):
            p = h.split()
            blobs[p[1]] = p[2] if len(p) > 2 else "absent"
    entries, atts = [], []
    for h, body in secs:
        if not h.startswith("item "):
            continue
        title = h[5:]
        tags, icon, fields = [], "-", {}
        for l in body:
            m = re.match(r"^tags:\s*(.*)$", l)
            if m:
                tags = [x for x in m.group(1).split(", ") if x]
                continue
            m = re.match(r"^Icon: (\S+) (\S+)$", l)
            if m:
                icon = m.group(1) + ":" + m.group(2)
                continue
            m = re.match(r"^(\S+): (.*)  \(id ([0-9a-f-]{36})\)$", l)
            if m:
                fields[m.group(1)] = m.group(2)
        lines = ["item %s fav=%d tags=%s icon=%s" % (title, title in fav, ",".join(tags), icon)]
        lines += ["  f %s=%s" % (n, fields[n]) for n in sorted(fields)]
        entries.append((title, lines))
        for h2, b2 in secs:
            if h2 == "att " + title:
                for l in b2:
                    p = l.split()
                    if len(p) >= 2:
                        atts.append("att %s %s %s" % (title, p[1], shas.get(p[0], "?")))
    out = []
    for _, lines in sorted(entries):
        out += lines
    return out, sorted(atts), blobs, errs


def check(st, specs):
    problems = []
    views = {}
    for spec in specs:
        d, path = spec.split(":", 1)
        v, a, blobs, errs = real(path)
        for e in errs:
            problems.append("%s: CLI error section '%s'" % (d, e))
        ev = view(st["items"][d])
        ea = attview(st, st["items"][d])
        if v != ev:
            problems.append("%s differs from model:\n   real:  %s\n   model: %s" % (d, " | ".join(v), " | ".join(ev)))
        if a != ea:
            problems.append("%s attachments differ from model:\n   real:  %s\n   model: %s" % (d, " | ".join(a), " | ".join(ea)))
        views[d] = (v, a, blobs)
    ds = list(views)
    for x in ds[1:]:
        if views[x][:2] != views[ds[0]][:2]:
            problems.append("%s and %s differ from each other" % (ds[0], x))
        for i, h in views[x][2].items():
            h0 = views[ds[0]][2].get(i)
            if h0 and h0 != h:
                problems.append("blob %s differs between %s and %s" % (i, ds[0], x))
    for x in ds[1:]:
        if view(st["items"][x]) != view(st["items"][ds[0]]):
            problems.append("MODEL-NONCONVERGED %s vs %s: the model itself did not converge" % (ds[0], x))
    return problems


def main():
    p, cmd, a = sys.argv[1], sys.argv[2], sys.argv[3:]
    if cmd == "init":
        save(p, new_state())
        return 0
    st = load(p)
    rc = 0
    if cmd == "apply":
        apply_op(st, a)
    elif cmd == "plan":
        print(plan(st, int(a[0]), [int(x) for x in a[1:]]))
    elif cmd == "sha":
        st["sha"][a[0]] = a[1]
    elif cmd == "delivered":
        msgs = delivered(st, a[0], a[1], a[2], a[3], a[4] == "1", a[5] == "1")
        print("\n".join(msgs))
    elif cmd == "check":
        probs = check(st, a)
        print("\n".join(probs))
        rc = 1 if probs else 0
    else:
        raise SystemExit("unknown command " + cmd)
    save(p, st)
    return rc


sys.exit(main())
