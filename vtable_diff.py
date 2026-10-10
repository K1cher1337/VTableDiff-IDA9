# -*- coding: utf-8 -*-
"""
VTable Diff - IDA Pro 9.1 plugin

Shows how virtual-table slots moved between two builds of a module.

Workflow
  1. OLD IDB : Edit > Plugins > "VTable Diff: export vtable"   -> old.json
  2. NEW IDB : Edit > Plugins > "VTable Diff: compare with JSON" -> table old_idx -> new_idx
  3. Optional: apply old (user) names to matched new functions, save CSV.

The vtable can be given as: hex address, symbol name (??_7X@@6B@),
or an RTTI class name (e.g. CSource2Client) - works on stripped x64/x86 MSVC binaries.

Install: copy to <IDA>/plugins/ or %APPDATA%/Hex-Rays/IDA Pro/plugins/
"""
import os
import re
import csv
import time
import html
import webbrowser
import json
import struct
import hashlib
import difflib
import collections
import traceback

import ida_idaapi
import ida_kernwin
import ida_bytes
import ida_diskio
import ida_funcs
import ida_ida
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import idautils
import idc

SCHEMA = 1
MAX_INSN = 3000
MAX_ENTRIES = 4096

AUTO_RE = re.compile(
    r"^(sub|loc|off|unk|byte|word|dword|qword|flt|dbl|asc|stru|xmmword|ymmword|"
    r"nullsub|def|locret|jpt|j_sub|j_nullsub)_[0-9A-Fa-f]+$|^unknown_libname_\d+$"
)

STATE = {"last": None}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def ptr_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def rd_ptr(ea):
    return ida_bytes.get_qword(ea) if ptr_size() == 8 else ida_bytes.get_dword(ea)


def is_auto(name):
    return (not name) or bool(AUTO_RE.match(name))


def md5(s):
    return hashlib.md5(s.encode("utf-8", "replace")).hexdigest()


def is_code_ptr(p):
    seg = ida_segment.getseg(p)
    return bool(seg and (seg.perm & ida_segment.SEGPERM_EXEC))


def auto_count(vt):
    ps = ptr_size()
    n = 0
    while n < MAX_ENTRIES:
        ea = vt + n * ps
        if n > 0 and ida_bytes.has_user_name(ida_bytes.get_flags(ea)):
            break
        if not is_code_ptr(rd_ptr(ea)):
            break
        n += 1
    return n


def read_string(ea):
    if not ida_bytes.is_loaded(ea):
        return None
    fl = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(fl):
        return None
    if ida_bytes.is_strlit(fl):
        st = idc.get_str_type(ea)
        if st is None or st == -1:
            st = ida_nalt.STRTYPE_C
        b = ida_bytes.get_strlit_contents(ea, -1, st)
        return b.decode("utf-8", "replace")[:200] if b else None
    b = ida_bytes.get_bytes(ea, 64)
    if b:
        m = re.match(rb"[\x20-\x7e]{5,}", b)
        if m and len(b) > len(m.group(0)) and b[len(m.group(0))] == 0:
            return m.group(0).decode("ascii")
    return None


# --------------------------------------------------------------------------
# function fingerprint
# --------------------------------------------------------------------------
def _analyze_func(ea):
    f = ida_funcs.get_func(ea)
    if f is None:
        ida_funcs.add_func(ea)
        f = ida_funcs.get_func(ea)
    if f is None:
        return None, None

    lo, hi = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    mn, pat = [], []
    strs, calls, consts, disps = set(), set(), set(), set()
    ncalls = 0
    thunk_tgt = None
    insn = ida_ua.insn_t()

    for h in idautils.FuncItems(f.start_ea):
        if len(mn) >= MAX_INSN:
            break
        n = ida_ua.decode_insn(insn, h)
        if n <= 0:
            continue
        m = insn.get_canon_mnem()
        mn.append(m)
        raw = ida_bytes.get_bytes(h, n) or b""
        mask_from = n
        is_call = (m == "call")

        for k in range(8):
            op = insn.ops[k]
            t = op.type
            if t == ida_ua.o_void:
                break
            if t in (ida_ua.o_near, ida_ua.o_far):
                tgt = op.addr
                outside = not (f.start_ea <= tgt < f.end_ea)
                if is_call or outside:
                    ncalls += 1
                    nm = ida_name.get_name(tgt)
                    if not is_auto(nm):
                        calls.add(nm)
                    if m == "jmp" and len(mn) == 1:
                        thunk_tgt = tgt
                if op.offb:
                    mask_from = min(mask_from, op.offb)
            elif t == ida_ua.o_mem:
                tgt = op.addr
                s = read_string(tgt)
                if s:
                    strs.add(s)
                else:
                    nm = ida_name.get_name(tgt)
                    if not is_auto(nm):
                        calls.add("d:" + nm)
                if op.offb:
                    mask_from = min(mask_from, op.offb)
            elif t == ida_ua.o_displ:
                v = op.addr & 0xFFFFFFFF
                if v >= 0x80000000:
                    v -= 1 << 32
                disps.add(v)
            elif t == ida_ua.o_imm:
                v = op.value & 0xFFFFFFFFFFFFFFFF
                if lo <= v < hi:
                    if op.offb:
                        mask_from = min(mask_from, op.offb)
                elif v >= 0x100:
                    consts.add("%X" % v)

        for i, bt in enumerate(raw):
            pat.append("??" if i >= mask_from else "%02X" % bt)

    fp = {
        "start": f.start_ea,
        "size": f.end_ea - f.start_ea,
        "ninsn": len(mn),
        "mnems": " ".join(mn),
        "mnem_hash": md5(" ".join(mn)),
        "phash": md5(" ".join(pat[:6000])),
        "pattern": " ".join(pat[:64]),
        "strings": sorted(strs)[:40],
        "calls": sorted(calls)[:60],
        "consts": sorted(consts)[:60],
        "disps": sorted(disps)[:80],
        "ncalls": ncalls,
        "thunk": False,
    }
    if len(mn) == 1 and thunk_tgt is not None:
        fp["thunk"] = True
        return fp, thunk_tgt
    return fp, None


def analyze_vfunc(ea):
    fp, tgt = _analyze_func(ea)
    depth = 0
    while fp is not None and tgt is not None and depth < 3:
        fp2, tgt2 = _analyze_func(tgt)
        if fp2 is None:
            break
        fp2["thunk"] = True
        fp, tgt = fp2, tgt2
        depth += 1
    return fp


def dump_vtable(vt, count, query=""):
    ps = ptr_size()
    imb = ida_nalt.get_imagebase()
    if count <= 0:
        count = auto_count(vt)
    if count <= 0:
        raise RuntimeError("no code pointers at %X - is this really a vtable?" % vt)

    entries = []
    ida_kernwin.show_wait_box("Analyzing %d slots..." % count)
    try:
        for i in range(count):
            if ida_kernwin.user_cancelled():
                raise RuntimeError("cancelled")
            ida_kernwin.replace_wait_box("Analyzing slot %d / %d" % (i, count))
            ea = rd_ptr(vt + i * ps)
            nm = ida_name.get_name(ea)
            entries.append({
                "idx": i, "off": i * ps, "ea": ea, "rva": ea - imb,
                "name": nm, "auto": is_auto(nm), "fp": analyze_vfunc(ea),
            })
    finally:
        ida_kernwin.hide_wait_box()

    return {
        "schema": SCHEMA,
        "module": ida_nalt.get_root_filename(),
        "imagebase": imb,
        "ptr": ps,
        "query": query,
        "vtable": vt,
        "vtable_name": ida_name.get_name(vt),
        "count": count,
        "entries": entries,
    }


# --------------------------------------------------------------------------
# vtable lookup (address / name / RTTI)
# --------------------------------------------------------------------------
def _scan(needle, align):
    """yield EAs of every aligned occurrence of `needle` in the database"""
    chunk = 0x800000
    seen = set()
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        ea = seg.start_ea
        while ea < seg.end_ea:
            sz = min(chunk, seg.end_ea - ea)
            data = ida_bytes.get_bytes(ea, sz)
            if data:
                pos = data.find(needle)
                while pos != -1:
                    hit = ea + pos
                    if hit % align == 0 and hit not in seen:
                        seen.add(hit)
                        yield hit
                    pos = data.find(needle, pos + 1)
            ea += chunk - 32 if sz == chunk else sz


def rtti_find(cls):
    """x64/x86 MSVC RTTI: class name -> [(vtable, col, offset)]"""
    ps = ptr_size()
    imb = ida_nalt.get_imagebase()
    names = [cls] if cls.startswith(".?A") else [".?AV%s@@" % cls, ".?AU%s@@" % cls]
    out = []
    for nm in names:
        needle = nm.encode() + b"\x00"
        for s in _scan(needle, 1):
            td = s - 2 * ps
            if ps == 8:
                pk = struct.pack("<I", (td - imb) & 0xFFFFFFFF)
            else:
                pk = struct.pack("<I", td)
            for h in _scan(pk, 4):
                col = h - 12
                if not ida_bytes.is_loaded(col):
                    continue
                sig = ida_bytes.get_dword(col)
                if ps == 8:
                    if sig != 1 or ida_bytes.get_dword(col + 20) != ((col - imb) & 0xFFFFFFFF):
                        continue
                    cp = struct.pack("<Q", col)
                else:
                    if sig != 0:
                        continue
                    cp = struct.pack("<I", col)
                off = ida_bytes.get_dword(col + 4)
                for v in _scan(cp, ps):
                    vt = v + ps
                    if is_code_ptr(rd_ptr(vt)):
                        out.append((vt, col, off))
    out.sort(key=lambda x: (x[2] != 0, x[0]))
    return out


def resolve_candidates(text):
    """text -> list of {vt, col, off, how}"""
    text = (text or "").strip()
    if not text:
        return []
    if re.fullmatch(r"(0x)?[0-9A-Fa-f]{5,16}", text):
        ea = int(text, 16)
        if ida_bytes.is_loaded(ea):
            return [{"vt": ea, "col": None, "off": None, "how": "address"}]
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, text)
    if ea != ida_idaapi.BADADDR:
        return [{"vt": ea, "col": None, "off": None, "how": "symbol"}]

    ida_kernwin.show_wait_box("Scanning RTTI for '%s'..." % text)
    try:
        res = rtti_find(text)
    finally:
        ida_kernwin.hide_wait_box()
    if res:
        seen, out = set(), []
        for vt, col, off in res:
            if vt not in seen:
                seen.add(vt)
                out.append({"vt": vt, "col": col, "off": off, "how": "rtti"})
        return out

    out = []
    low = text.lower()
    for ea, nm in idautils.Names():
        dm = ida_name.demangle_name(nm, ida_name.MNG_LONG_FORM) or ""
        if "vftable" in dm and low in dm.lower():
            out.append({"vt": ea, "col": None, "off": None, "how": "name"})
            if len(out) >= 50:
                break
    return out


class PickChooser(ida_kernwin.Choose):
    def __init__(self, title, cands, deflt):
        rtti = any(c["col"] is not None for c in cands)   # this-off / COL exist only for RTTI hits
        cols = [["#", 3], ["VTable", 14], ["Slots", 6]]
        if rtti:
            cols += [["this-off", 8], ["COL", 14]]
        cols += [["Symbol", 44 if not rtti else 30], ["Slot 0", 14]]
        ida_kernwin.Choose.__init__(self, title, cols, flags=ida_kernwin.Choose.CH_MODAL, deflt=deflt)
        self.items = []
        for i, c in enumerate(cands):
            row = [str(i), "0x%X" % c["vt"], str(c["slots"])]
            if rtti:
                row += ["" if c["off"] is None else ("%d%s" % (c["off"], " (main)" if c["off"] == 0 else "")),
                        "" if c["col"] is None else "0x%X" % c["col"]]
            row += [ida_name.get_name(c["vt"]) or "", "%X" % rd_ptr(c["vt"])]
            self.items.append(row)

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]


def pick_vtable(text, hint=None):
    """resolve text to ONE vtable; shows a picker when there are several.
    returns candidate dict (with 'slots') or None"""
    cands = resolve_candidates(text)
    if not cands:
        ida_kernwin.warning("vtable not found: %s" % text)
        return None
    for c in cands:
        c["slots"] = auto_count(c["vt"])
    if len(cands) == 1:
        return cands[0]
    best = 0
    if hint:
        best = min(range(len(cands)),
                   key=lambda k: (cands[k]["off"] not in (0, None), abs(cands[k]["slots"] - hint)))
    title = "Select vtable for '%s' - %d found" % (text, len(cands))
    if hint:
        title += " (old had %d slots)" % hint
    n = PickChooser(title, cands, best).Show(True)
    if n is None or n < 0:
        return None
    return cands[n]


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------
def _prep(e):
    fp = e.get("fp")
    if not fp:
        e["_p"] = None
        return
    e["_p"] = {
        "mn": fp["mnems"].split(),
        "st": set(fp["strings"]),
        "ca": set(fp["calls"]),
        "co": set(fp["consts"]),
        "di": set(fp["disps"]),
    }


def _jacc(x, y):
    if not x and not y:
        return None
    u = len(x | y)
    return len(x & y) / u if u else None


def _seq_sim(a, b):
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    r = min(la, lb) / max(la, lb)
    if r < 0.3:
        return r * 0.5
    if la > 500 or lb > 500:
        inter = sum((collections.Counter(a) & collections.Counter(b)).values())
        return 2.0 * inter / (la + lb)
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    q = sm.quick_ratio()
    if q < 0.4:
        return q * 0.7
    return sm.ratio()


def pair_score(a, b):
    pa, pb = a["_p"], b["_p"]
    if pa is None or pb is None:
        return 0.0
    fa, fb = a["fp"], b["fp"]
    trivial = min(fa["ninsn"], fb["ninsn"]) <= 4
    if fa["phash"] == fb["phash"]:
        return 0.9 if trivial else 1.0

    parts = [(3.0, _seq_sim(pa["mn"], pb["mn"]))]
    for w, k in ((3.0, "st"), (1.5, "ca"), (1.5, "co"), (1.0, "di")):
        j = _jacc(pa[k], pb[k])
        if j is not None:
            parts.append((w, j))
    sa, sb = max(fa["size"], 1), max(fb["size"], 1)
    parts.append((1.0, min(sa, sb) / max(sa, sb)))
    s = sum(w * v for w, v in parts) / sum(w for w, _ in parts)
    if trivial:
        s = min(s, 0.85)
    return s


def _lis(pairs):
    if not pairs:
        return []
    L = [1] * len(pairs)
    P = [-1] * len(pairs)
    for x in range(len(pairs)):
        for y in range(x):
            if pairs[y][1] < pairs[x][1] and L[y] + 1 > L[x]:
                L[x] = L[y] + 1
                P[x] = y
    k = max(range(len(pairs)), key=L.__getitem__)
    out = []
    while k != -1:
        out.append(pairs[k])
        k = P[k]
    return out[::-1]


def _nw(olds, news, S, floor=0.35, gap=0.1):
    a, b = len(olds), len(news)
    D = [[0.0] * (b + 1) for _ in range(a + 1)]
    T = [[0] * (b + 1) for _ in range(a + 1)]
    for i in range(1, a + 1):
        D[i][0] = -gap * i
        T[i][0] = 1
    for j in range(1, b + 1):
        D[0][j] = -gap * j
        T[0][j] = 2
    for i in range(1, a + 1):
        for j in range(1, b + 1):
            best, t = D[i - 1][j] - gap, 1
            v = D[i][j - 1] - gap
            if v > best:
                best, t = v, 2
            s = S[olds[i - 1]][news[j - 1]]
            if s >= floor:
                v = D[i - 1][j - 1] + s
                if v >= best:
                    best, t = v, 3
            D[i][j], T[i][j] = best, t
    out = []
    i, j = a, b
    while i > 0 or j > 0:
        t = T[i][j]
        if t == 3:
            out.append((olds[i - 1], news[j - 1]))
            i -= 1
            j -= 1
        elif t == 1:
            i -= 1
        else:
            j -= 1
    return out[::-1]


def match_vtables(old, new, progress=None):
    n, m = len(old), len(new)
    for e in old:
        _prep(e)
    for e in new:
        _prep(e)

    S = [[0.0] * m for _ in range(n)]
    for i in range(n):
        if progress and not progress(i, n):
            raise RuntimeError("cancelled")
        for j in range(m):
            S[i][j] = pair_score(old[i], new[j])

    matches = {}   # old_idx -> (new_idx, score, how)
    used = set()

    # 1) unique high-confidence anchors
    anchors = []
    for i in range(n):
        if not m:
            break
        row = S[i]
        j = max(range(m), key=row.__getitem__)
        s = row[j]
        if s < 0.85:
            continue
        r2 = max((row[k] for k in range(m) if k != j), default=0.0)
        c2 = max((S[k][j] for k in range(n) if k != i), default=0.0)
        if s - r2 >= 0.05 and s - c2 >= 0.05:
            anchors.append((i, j))
    for i, j in anchors:
        matches[i] = (j, S[i][j], "anchor")
        used.add(j)

    # 2) order-preserving alignment inside gaps between monotone anchors
    skel = _lis(sorted(anchors))
    bounds = [(-1, -1)] + skel + [(n, m)]
    for (ai, aj), (bi, bj) in zip(bounds, bounds[1:]):
        olds = [i for i in range(ai + 1, bi) if i not in matches]
        news = [j for j in range(aj + 1, bj) if j not in used]
        if not olds or not news:
            continue
        for i, j in _nw(olds, news, S):
            matches[i] = (j, S[i][j], "aligned")
            used.add(j)

    # 3) positional guess for leftovers when counts agree
    skel = _lis(sorted((i, v[0]) for i, v in matches.items()))
    bounds = [(-1, -1)] + skel + [(n, m)]
    for (ai, aj), (bi, bj) in zip(bounds, bounds[1:]):
        olds = [i for i in range(ai + 1, bi) if i not in matches]
        news = [j for j in range(aj + 1, bj) if j not in used]
        if olds and len(olds) == len(news):
            for i, j in zip(olds, news):
                matches[i] = (j, S[i][j], "guess")
                used.add(j)

    rows = []
    for i in range(n):
        if i in matches:
            j, s, how = matches[i]
            rows.append({"old": i, "new": j, "score": s, "how": how})
        else:
            rows.append({"old": i, "new": None, "score": 0.0, "how": "removed"})
    for j in range(m):
        if j not in used:
            rows.append({"old": None, "new": j, "score": 0.0, "how": "added"})
    return rows


def conf_label(r):
    if r["new"] is None:
        return "REMOVED"
    if r["old"] is None:
        return "NEW"
    if r["how"] == "guess":
        return "guess"
    s = r["score"]
    if s >= 0.97:
        return "exact"
    if s >= 0.80:
        return "high"
    if s >= 0.55:
        return "medium"
    return "low"


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------
class DiffChooser(ida_kernwin.Choose):
    def __init__(self, title, rows, old, new, ps):
        ida_kernwin.Choose.__init__(
            self, title,
            [["Old", 5], ["Old off", 8], ["New", 5], ["New off", 8], ["Shift", 6],
             ["Score", 6], ["Status", 9], ["Old name", 28], ["New func", 18]],
            flags=0,
        )
        self.rows = rows
        self.items = []
        self.attrs = []
        for r in rows:
            o = old[r["old"]] if r["old"] is not None else None
            nw = new[r["new"]] if r["new"] is not None else None
            lab = conf_label(r)
            shift = "" if (o is None or nw is None) else "%+d" % (r["new"] - r["old"])
            self.items.append([
                "" if o is None else str(r["old"]),
                "" if o is None else "0x%X" % (r["old"] * ps),
                "" if nw is None else str(r["new"]),
                "" if nw is None else "0x%X" % (r["new"] * ps),
                shift,
                "" if (o is None or nw is None) else "%.2f" % r["score"],
                lab,
                "" if o is None else (o["name"] or ""),
                "" if nw is None else "%X" % nw["ea"],
            ])
            col = {"REMOVED": 0xA0A0FF, "NEW": 0xA0FFA0, "guess": 0x80FFFF, "low": 0x80FFFF}.get(lab, -1)
            self.attrs.append(col)
        self.new = new

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetLineAttr(self, n):
        c = self.attrs[n]
        return [c, 0] if c != -1 else None

    def OnSelectLine(self, n):
        r = self.rows[n]
        if r["new"] is not None:
            ida_kernwin.jumpto(self.new[r["new"]]["ea"])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)


def shift_ranges(rows):
    m = sorted((r for r in rows if r["old"] is not None and r["new"] is not None),
               key=lambda r: r["old"])
    out = []
    start = prev = cur = None
    for r in m:
        sh = r["new"] - r["old"]
        if cur is None or sh != cur or r["old"] != prev + 1:
            if cur is not None:
                out.append((start, prev, cur))
            start, cur = r["old"], sh
        prev = r["old"]
    if cur is not None:
        out.append((start, prev, cur))
    return out


class RangesChooser(ida_kernwin.Choose):
    def __init__(self, ranges, ps):
        ida_kernwin.Choose.__init__(
            self, "VTable Diff: shift ranges",
            [["Old slots", 12], ["Old offsets", 16], ["Shift", 7], ["Shift bytes", 11], ["New slots", 12]],
            flags=0,
        )
        self.items = [
            ["%d..%d" % (a, b), "0x%X..0x%X" % (a * ps, b * ps), "%+d" % s, "%+d" % (s * ps),
             "%d..%d" % (a + s, b + s)]
            for a, b, s in ranges
        ]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]


def _safe(x):
    return re.sub(r"[^\w.-]+", "_", str(x)).strip("_.")


def idb_stem():
    """(name of the IDB without extension, its directory)"""
    p = idc.get_idb_path() or ""
    n = os.path.splitext(os.path.basename(p))[0]
    if not n:
        n = os.path.splitext(ida_nalt.get_root_filename() or "")[0]
    return _safe(n) or "idb", os.path.dirname(p)


def class_label(query, vt):
    """short class name for file names: from the query, else from the vtable symbol"""
    q = (query or "").strip()
    if q.startswith(".?A") and "@@" in q:
        q = q[4:q.index("@@")]
    if not q or re.fullmatch(r"(0x)?[0-9A-Fa-f]{5,16}", q):
        nm = ida_name.get_name(vt) or ""
        m = re.match(r"^\?\?_7(.+?)@@6B", nm)
        q = m.group(1) if m else ("vt_%X" % vt)
    return _safe(q) or ("vt_%X" % vt)


def _cfg_file():
    try:
        d = ida_diskio.get_user_idadir()
    except Exception:
        d = os.path.expanduser("~")
    return os.path.join(d, "vtable_diff_settings.json")


def cfg_get(key):
    try:
        with open(_cfg_file(), "r", encoding="utf-8") as f:
            return json.load(f).get(key)
    except Exception:
        return None


def cfg_set(key, value):
    try:
        try:
            with open(_cfg_file(), "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        data[key] = value
        with open(_cfg_file(), "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def remember_dir(ext, path):
    if path:
        cfg_set("dir_" + ext, os.path.dirname(os.path.abspath(path)))


def start_dir(ext):
    """last folder used for this file type, else the folder of the IDB"""
    d = cfg_get("dir_" + ext)
    if d and os.path.isdir(d):
        return d
    return idb_stem()[1]


def default_path(ext, cls):
    name = "%s_%s.%s" % (idb_stem()[0], cls, ext)
    folder = start_dir(ext)
    return os.path.join(folder, name) if folder else name


def default_query():
    ea = ida_kernwin.get_screen_ea()
    nm = ida_name.get_name(ea)
    return nm if nm and not is_auto(nm) else "0x%X" % ea


def do_export():
    q = ida_kernwin.ask_str(default_query(), 0, "VTable: address / symbol / RTTI class name")
    if not q:
        return
    c = pick_vtable(q)
    if c is None:
        return
    auto = c["slots"]
    cnt = ida_kernwin.ask_long(auto, "Detected %d slots at 0x%X.\nSlots count to export:" % (auto, c["vt"]))
    if cnt is None:
        return
    if cnt <= 0:
        cnt = auto
    data = dump_vtable(c["vt"], cnt, q)
    cls = class_label(q, c["vt"])
    data["cls"] = cls
    path = ida_kernwin.ask_file(True, default_path("json", cls), "Save vtable dump")
    if not path:
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    remember_dir("json", path)
    print("[vtdiff] exported %d slots (vtable 0x%X) -> %s" % (data["count"], c["vt"], path))
    print("[vtdiff] GitHub: https://github.com/K1cher1337/VTableDiff-IDA_9.1_Plugin")


def do_compare():
    sd = start_dir("json")
    path = ida_kernwin.ask_file(False, os.path.join(sd, "*.json") if sd else "*.json", "Load OLD vtable dump")
    if not path:
        return
    remember_dir("json", path)
    with open(path, "r", encoding="utf-8") as f:
        old_data = json.load(f)
    old = old_data["entries"]
    hint = len(old)
    q = ida_kernwin.ask_str(old_data.get("query", ""), 0,
                            "NEW vtable (old had %d slots):\naddress / symbol / RTTI class name" % hint)
    if not q:
        return
    c = pick_vtable(q, hint)
    if c is None:
        return
    auto = c["slots"]
    cnt = ida_kernwin.ask_long(auto, "Detected %d slots at 0x%X (old had %d).\nSlots count to use:" %
                               (auto, c["vt"], hint))
    if cnt is None:
        return
    if cnt <= 0:
        cnt = auto
    new_data = dump_vtable(c["vt"], cnt, q)
    new = new_data["entries"]

    ida_kernwin.show_wait_box("Matching %d x %d..." % (len(old), len(new)))
    try:
        def prog(i, n):
            ida_kernwin.replace_wait_box("Matching row %d / %d" % (i, n))
            return not ida_kernwin.user_cancelled()
        rows = match_vtables(old, new, prog)
    finally:
        ida_kernwin.hide_wait_box()

    ps = new_data["ptr"]
    STATE["last"] = {
        "rows": rows, "old": old, "new": new, "ps": ps,
        "meta": {
            "old_module": old_data.get("module"), "new_module": new_data.get("module"),
            "old_vt": old_data.get("vtable"), "new_vt": new_data.get("vtable"),
            "old_vt_name": old_data.get("vtable_name"), "new_vt_name": new_data.get("vtable_name"),
            "query": q,
            "cls": (class_label(q, c["vt"]) if not re.fullmatch(r"(0x)?[0-9A-Fa-f]{5,16}", q.strip())
                    else (old_data.get("cls") or class_label(q, c["vt"]))),
        },
    }

    matched = sum(1 for r in rows if r["old"] is not None and r["new"] is not None)
    removed = sum(1 for r in rows if r["new"] is None)
    added = sum(1 for r in rows if r["old"] is None)
    weak = sum(1 for r in rows if conf_label(r) in ("low", "guess"))
    nranges = len(shift_ranges(rows))
    print("[vtdiff] %d -> %d slots: %d matched (%d weak), %d removed, %d new, %d shift ranges" %
          (len(old), len(new), matched, weak, removed, added, nranges))
    print("[vtdiff] GitHub: https://github.com/K1cher1337/VTableDiff-IDA_9.1_Plugin")

    choose_output()


def do_ranges():
    st = STATE["last"]
    if not st:
        ida_kernwin.warning("Run a comparison first")
        return
    ch = RangesChooser(shift_ranges(st["rows"]), st["ps"])
    ch.Show()
    STATE["ranges"] = ch


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
 --bg:#0a0e13;--bg2:#0f151c;--panel:#131a22;--panel2:#18212b;--line:#232f3d;--line2:#2e3d4f;
 --text:#e6edf4;--mut:#8696a8;--acc:#6ea8fe;--ch:150px;
 --exact:#34d399;--high:#4cc9f0;--medium:#a78bfa;--low:#fbbf24;--guess:#fb923c;--removed:#f87171;--new:#f472b6;
}
*{box-sizing:border-box}
html{color-scheme:dark}
body{margin:0;background:radial-gradient(1200px 500px at 20% -10%,#14202e 0%,var(--bg) 60%);background-attachment:fixed;color:var(--text);
 font:14px/1.45 -apple-system,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;min-height:100vh}
.mono{font-family:ui-monospace,"Cascadia Code","SF Mono",Consolas,Menlo,monospace}
.mut{color:var(--mut)}
.wrap{max-width:1560px;margin:0 auto;padding:26px 24px 60px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:18px}
h1{margin:0;font-size:26px;letter-spacing:-.02em}
h1 span{font-weight:400;font-size:18px}
.sub{margin-top:6px;color:var(--mut);font-size:13px}
.sub b{color:var(--text);font-weight:600}
.hr{display:flex;align-items:center;gap:14px}
.gen{font-size:12px;color:var(--mut)}
.lang{display:inline-flex;border:1px solid var(--line2);border-radius:9px;overflow:hidden;background:var(--panel)}
.lang button{background:transparent;border:0;color:var(--mut);padding:6px 12px;font-size:12.5px;font-weight:700;cursor:pointer;letter-spacing:.04em}
.lang button:hover{color:var(--text)}
.lang button.on{background:var(--acc);color:#0a0e13}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:16px}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.card .v{font-size:26px;font-weight:700;letter-spacing:-.02em}
.card .l{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.card.acc .v{color:var(--c)}
.map{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:16px}
.maphead{font-size:12px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.strip{display:flex;flex-wrap:wrap;gap:3px}
.strip i{display:block;width:12px;height:12px;border-radius:3px;background:var(--c);opacity:.9;cursor:pointer;transition:transform .08s}
.strip i:hover{transform:scale(1.5);opacity:1}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:12px;color:var(--mut)}
.legend span:before{content:"";display:inline-block;width:9px;height:9px;border-radius:2px;background:var(--c);margin-right:6px}
.controls{position:sticky;top:0;z-index:30;background:rgba(10,14,19,.94);backdrop-filter:blur(8px);
 border:1px solid var(--line);border-radius:12px;padding:10px 12px;margin-bottom:12px;display:flex;flex-direction:column;gap:10px}
.crow{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.search{flex:1 1 360px;position:relative}
.search input{width:100%;background:var(--bg2);border:1px solid var(--line2);color:var(--text);border-radius:10px;
 padding:10px 38px 10px 14px;font-size:14px;outline:none}
.search input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(110,168,254,.18)}
.search kbd{position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:11px;color:var(--mut);
 border:1px solid var(--line2);border-radius:5px;padding:1px 6px}
.chip,.btn{background:var(--panel2);border:1px solid var(--line2);color:var(--text);border-radius:999px;padding:5px 12px;
 font-size:12.5px;cursor:pointer;user-select:none;transition:background .1s,border-color .1s;font-family:inherit}
.btn{border-radius:8px}
.chip:hover,.btn:hover{border-color:var(--acc)}
.btn.on{border-color:var(--acc);background:rgba(110,168,254,.15);color:var(--acc)}
.chip.on{background:color-mix(in srgb,var(--c,var(--acc)) 20%,transparent);border-color:var(--c,var(--acc));color:var(--c,var(--acc))}
.chip .n{opacity:.7;margin-left:6px}
.cnt{margin-left:auto;font-size:12.5px;color:var(--mut)}
.hint{font-size:11.5px;color:var(--mut)}
.hint code{background:var(--bg2);border:1px solid var(--line);border-radius:4px;padding:0 5px;color:#c9d6e4}
.main{display:grid;grid-template-columns:minmax(0,1fr) 270px;gap:14px;align-items:start}
/* NOTE: overflow:clip (not hidden) - hidden would make this box the sticky scroll container and break the sticky header */
.tablebox{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:clip;scroll-margin-top:calc(var(--ch) + 12px)}
table{width:100%;border-collapse:separate;border-spacing:0}
thead th{position:sticky;top:var(--ch);z-index:10;background:var(--panel2);text-align:left;font-size:11.5px;
 text-transform:uppercase;letter-spacing:.06em;color:var(--mut);padding:10px 10px;border-bottom:1px solid var(--line2);
 cursor:pointer;white-space:nowrap}
thead th:hover{color:var(--text)}
thead th.sorted{color:var(--acc)}
thead th .ar{margin-left:4px;font-size:10px}
tbody td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
tr.row{cursor:pointer}
tr.row td:first-child{border-left:3px solid var(--c)}
tr.row:hover td{background:var(--panel2)}
tr.row.open td{background:var(--panel2)}
tr.row.same td.num,tr.row.same td.fncell{opacity:.72}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.fn{display:flex;flex-direction:column;gap:1px;min-width:0}
.nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:360px}
.nm.auto{color:#aab6c4;font-weight:500}
.ea{font-size:11.5px;color:var(--mut)}
.b{--c:var(--mut);display:inline-block;padding:2px 9px;border-radius:999px;font-size:11.5px;font-weight:600;color:var(--c);
 background:color-mix(in srgb,var(--c) 15%,transparent);border:1px solid color-mix(in srgb,var(--c) 40%,transparent);white-space:nowrap}
.st-exact{--c:var(--exact)}.st-high{--c:var(--high)}.st-medium{--c:var(--medium)}.st-low{--c:var(--low)}
.st-guess{--c:var(--guess)}.st-removed{--c:var(--removed)}.st-new{--c:var(--new)}
.sh{font-weight:700;padding:1px 8px;border-radius:6px;font-variant-numeric:tabular-nums}
.sh.pos{color:#fbbf24;background:rgba(251,191,36,.12)}
.sh.neg{color:#60a5fa;background:rgba(96,165,250,.12)}
.sh0{color:var(--mut)}
.sc{position:relative;width:74px;height:18px;background:var(--bg2);border-radius:5px;overflow:hidden;border:1px solid var(--line)}
.sc i{position:absolute;left:0;top:0;bottom:0;background:color-mix(in srgb,var(--c) 45%,transparent)}
.sc span{position:relative;display:block;text-align:center;font-size:11px;line-height:16px;font-variant-numeric:tabular-nums}
mark{background:rgba(110,168,254,.35);color:#fff;border-radius:3px;padding:0 1px}
tr.det td{background:var(--bg2);padding:14px 16px 16px;border-left:3px solid var(--c);border-bottom:1px solid var(--line)}
.dg{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.dbox{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px;min-width:0}
.dbox h4{margin:0 0 8px;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
.kv{display:grid;grid-template-columns:100px minmax(0,1fr);gap:3px 10px;font-size:13px}
.kv div:nth-child(odd){color:var(--mut)}
.kv div:nth-child(even){overflow-wrap:anywhere}
.pat{font-size:11.5px;word-break:break-all;color:#c4d2e2;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;margin-top:6px}
.strs{display:flex;flex-wrap:wrap;gap:5px}
.strs span{font-size:11.5px;background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:1px 7px;color:#c4d2e2;max-width:100%;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mini{margin-left:8px;font-size:11px;background:transparent;border:1px solid var(--line2);color:var(--mut);border-radius:5px;padding:0 6px;cursor:pointer;font-family:inherit}
.mini:hover{color:var(--text);border-color:var(--acc)}
.side{position:sticky;top:calc(var(--ch) + 12px);display:flex;flex-direction:column;gap:12px;max-height:calc(100vh - var(--ch) - 24px);overflow:auto}
.sbox{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px}
.sbox h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
.rg{display:flex;justify-content:space-between;align-items:center;width:100%;text-align:left;background:var(--bg2);
 border:1px solid var(--line);color:var(--text);border-radius:8px;padding:7px 10px;margin-bottom:6px;cursor:pointer;font-size:12.5px;font-family:inherit}
.rg:hover{border-color:var(--acc)}
.rg.on{border-color:var(--acc);background:rgba(110,168,254,.12)}
.pills{display:flex;flex-wrap:wrap;gap:5px}
.pill{background:var(--bg2);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:2px 8px;font-size:12px;cursor:pointer}
.pill:hover{border-color:var(--acc)}
.empty{display:none;padding:40px;text-align:center;color:var(--mut)}
footer{margin-top:22px;font-size:12px;color:var(--mut);text-align:center}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(20px);background:#1f2b38;border:1px solid var(--acc);
 color:var(--text);padding:8px 16px;border-radius:10px;opacity:0;pointer-events:none;transition:all .18s;z-index:99;font-size:13px}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(max-width:1100px){.main{grid-template-columns:1fr}.side{position:static;max-height:none}}
@media(max-width:800px){.hide-s{display:none}.nm{max-width:170px}}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#2a3748;border-radius:6px}
</style></head><body>
<div class="wrap">
 <header>
  <div><h1>VTable Diff <span class="mut" data-i18n="report"></span></h1><div class="sub" id="sub"></div></div>
  <div class="hr"><div class="gen mono" id="gen"></div>
   <div class="lang" id="lang"><button data-l="en">EN</button><button data-l="ru">RU</button></div></div>
 </header>
 <section class="cards" id="cards"></section>
 <section class="map"><div class="maphead mut" data-i18n="map_head"></div>
  <div class="strip" id="strip"></div><div class="legend" id="legend"></div></section>
 <div class="controls" id="controls">
  <div class="crow">
   <div class="search"><input id="q" type="text" autocomplete="off" spellcheck="false" data-i18n-ph="ph"><kbd>/</kbd></div>
   <button class="btn" id="bMoved" data-i18n="b_moved"></button>
   <button class="btn" id="bCsv" data-i18n="b_csv"></button>
   <button class="btn" id="bDl" data-i18n="b_dl"></button>
   <button class="btn" id="bMap" data-i18n="b_map"></button>
  </div>
  <div class="crow"><div class="crow" id="chips"></div><div class="cnt" id="cnt"></div></div>
  <div class="hint" data-i18n-html="hint"></div>
 </div>
 <div class="main">
  <div class="tablebox" id="tablebox">
   <table id="tbl"><thead><tr>
    <th data-k="o" data-i18n="th_o"></th><th data-k="oo" class="hide-s" data-i18n="th_oo"></th><th data-k="on" data-i18n="th_on"></th>
    <th data-k="st" data-i18n="th_st"></th><th data-k="sh" data-i18n="th_sh"></th>
    <th data-k="n" data-i18n="th_n"></th><th data-k="no" class="hide-s" data-i18n="th_no"></th><th data-k="nn" data-i18n="th_nn"></th>
    <th data-k="sc" data-i18n="th_sc"></th></tr></thead><tbody id="tb"></tbody></table>
   <div class="empty" id="empty" data-i18n="empty"></div>
  </div>
  <aside class="side" id="side"></aside>
 </div>
 <footer data-i18n="footer"></footer>
</div>
<div id="toast"></div>
<script id="data" type="application/json">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent);
const rows=D.rows;
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const reEsc=s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');

/* ------------------------------ i18n ------------------------------ */
const I18N={
 en:{report:'report',
  c_old:'Old slots',c_new:'New slots',c_matched:'Matched',c_moved:'Moved',c_weak:'Weak',c_removed:'Removed',c_added:'New only',
  map_head:'Slot map \u00b7 one cell per slot, click to jump',
  ph:'Search: name, address, status\u2026   o:12  n:14  s:+2',
  b_moved:'Moved only',b_csv:'Copy CSV',b_dl:'Download CSV',b_map:'Copy map',
  hint:'Syntax: <code>o:12</code> old index \u00b7 <code>n:14</code> new index \u00b7 <code>s:+2</code> exact shift \u00b7 several words = all must match \u00b7 <code>/</code> focus \u00b7 <code>Esc</code> reset \u00b7 click a row for details',
  th_o:'Old #',th_oo:'Old off',th_on:'Old function',th_st:'Status',th_sh:'Shift',th_n:'New #',th_no:'New off',th_nn:'New function',th_sc:'Score',
  empty:'No slots match the current filter.',footer:'Generated by the VTable Diff IDA plugin',
  all:'All',showing:'Showing {0} of {1}',range_txt:'range old {0}',
  sd_ranges:'Shift ranges',sd_none:'no matched slots',sd_old:'old {0}',sd_clear:'Clear range',
  sd_removed:'Removed (old slots)',sd_added:'New slots (no old match)',sd_check:'Check manually',
  d_old:'Old build',d_new:'New build',d_idx:'Index',d_name:'Name',d_size:'Size',d_bytes:'bytes',d_insns:'Insns',d_match:'Match',
  d_thunk:'thunk resolved',d_strs:'Strings referenced',d_sold:'old',d_snew:'new',d_none:'none',
  d_pat:'New pattern (operands masked)',d_copy:'copy',d_copyea:'copy EA',d_copyrva:'copy RVA',
  t_copied:'Copied',t_dl:'Downloaded',t_fail:'Copy failed',
  tip_old:'old #{0}',tip_new:'new #{0}',tip_added:'added',tip_removed:'removed',
  gen_ptr:'{0}-bit pointers',slots:'slots',
  st_exact:'exact',st_high:'high',st_medium:'medium',st_low:'low',st_guess:'guess',st_REMOVED:'REMOVED',st_NEW:'NEW',
  how_anchor:'anchor',how_aligned:'aligned',how_guess:'positional guess',how_removed:'removed',how_added:'added'},
 ru:{report:'\u043e\u0442\u0447\u0451\u0442',
  c_old:'\u0421\u043b\u043e\u0442\u043e\u0432 (\u0441\u0442\u0430\u0440\u044b\u0439)',c_new:'\u0421\u043b\u043e\u0442\u043e\u0432 (\u043d\u043e\u0432\u044b\u0439)',c_matched:'\u0421\u043e\u043f\u043e\u0441\u0442\u0430\u0432\u043b\u0435\u043d\u043e',c_moved:'\u0421\u0434\u0432\u0438\u043d\u0443\u043b\u043e\u0441\u044c',c_weak:'\u0421\u043b\u0430\u0431\u044b\u0435',c_removed:'\u0423\u0434\u0430\u043b\u0435\u043d\u043e',c_added:'\u0422\u043e\u043b\u044c\u043a\u043e \u043d\u043e\u0432\u044b\u0435',
  map_head:'\u041a\u0430\u0440\u0442\u0430 \u0441\u043b\u043e\u0442\u043e\u0432 \u00b7 \u043e\u0434\u043d\u0430 \u043f\u043b\u0438\u0442\u043a\u0430 \u043d\u0430 \u0441\u043b\u043e\u0442, \u043a\u043b\u0438\u043a \u2014 \u043f\u0435\u0440\u0435\u0439\u0442\u0438 \u043a \u0441\u0442\u0440\u043e\u043a\u0435',
  ph:'\u041f\u043e\u0438\u0441\u043a: \u0438\u043c\u044f, \u0430\u0434\u0440\u0435\u0441, \u0441\u0442\u0430\u0442\u0443\u0441\u2026   o:12  n:14  s:+2',
  b_moved:'\u0422\u043e\u043b\u044c\u043a\u043e \u0441\u0434\u0432\u0438\u043d\u0443\u0442\u044b\u0435',b_csv:'\u041a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c CSV',b_dl:'\u0421\u043a\u0430\u0447\u0430\u0442\u044c CSV',b_map:'\u041a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u043a\u0430\u0440\u0442\u0443',
  hint:'\u0421\u0438\u043d\u0442\u0430\u043a\u0441\u0438\u0441: <code>o:12</code> \u0441\u0442\u0430\u0440\u044b\u0439 \u0438\u043d\u0434\u0435\u043a\u0441 \u00b7 <code>n:14</code> \u043d\u043e\u0432\u044b\u0439 \u0438\u043d\u0434\u0435\u043a\u0441 \u00b7 <code>s:+2</code> \u0442\u043e\u0447\u043d\u044b\u0439 \u0441\u0434\u0432\u0438\u0433 \u00b7 \u043d\u0435\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u0441\u043b\u043e\u0432 \u2014 \u0434\u043e\u043b\u0436\u043d\u044b \u0441\u043e\u0432\u043f\u0430\u0441\u0442\u044c \u0432\u0441\u0435 \u00b7 <code>/</code> \u0432 \u043f\u043e\u0438\u0441\u043a \u00b7 <code>Esc</code> \u0441\u0431\u0440\u043e\u0441 \u00b7 \u043a\u043b\u0438\u043a \u043f\u043e \u0441\u0442\u0440\u043e\u043a\u0435 \u2014 \u0434\u0435\u0442\u0430\u043b\u0438',
  th_o:'\u0421\u0442\u0430\u0440\u044b\u0439 \u2116',th_oo:'\u041e\u0444\u0441\u0435\u0442 (\u0441\u0442.)',th_on:'\u0421\u0442\u0430\u0440\u0430\u044f \u0444\u0443\u043d\u043a\u0446\u0438\u044f',th_st:'\u0421\u0442\u0430\u0442\u0443\u0441',th_sh:'\u0421\u0434\u0432\u0438\u0433',th_n:'\u041d\u043e\u0432\u044b\u0439 \u2116',th_no:'\u041e\u0444\u0441\u0435\u0442 (\u043d\u043e\u0432.)',th_nn:'\u041d\u043e\u0432\u0430\u044f \u0444\u0443\u043d\u043a\u0446\u0438\u044f',th_sc:'\u041f\u043e\u0445\u043e\u0436\u0435\u0441\u0442\u044c',
  empty:'\u041d\u0435\u0442 \u0441\u043b\u043e\u0442\u043e\u0432, \u043f\u043e\u0434\u0445\u043e\u0434\u044f\u0449\u0438\u0445 \u043f\u043e\u0434 \u0444\u0438\u043b\u044c\u0442\u0440.',footer:'\u0421\u043e\u0437\u0434\u0430\u043d\u043e \u043f\u043b\u0430\u0433\u0438\u043d\u043e\u043c VTable Diff \u0434\u043b\u044f IDA',
  all:'\u0412\u0441\u0435',showing:'\u041f\u043e\u043a\u0430\u0437\u0430\u043d\u043e {0} \u0438\u0437 {1}',range_txt:'\u0434\u0438\u0430\u043f\u0430\u0437\u043e\u043d \u0441\u0442\u0430\u0440\u044b\u0445 {0}',
  sd_ranges:'\u0414\u0438\u0430\u043f\u0430\u0437\u043e\u043d\u044b \u0441\u0434\u0432\u0438\u0433\u0430',sd_none:'\u043d\u0435\u0442 \u0441\u043e\u043f\u043e\u0441\u0442\u0430\u0432\u043b\u0435\u043d\u043d\u044b\u0445 \u0441\u043b\u043e\u0442\u043e\u0432',sd_old:'\u0441\u0442\u0430\u0440\u044b\u0435 {0}',sd_clear:'\u0421\u0431\u0440\u043e\u0441\u0438\u0442\u044c \u0434\u0438\u0430\u043f\u0430\u0437\u043e\u043d',
  sd_removed:'\u0423\u0434\u0430\u043b\u0435\u043d\u043e (\u0441\u0442\u0430\u0440\u044b\u0435 \u0441\u043b\u043e\u0442\u044b)',sd_added:'\u041d\u043e\u0432\u044b\u0435 \u0441\u043b\u043e\u0442\u044b (\u0431\u0435\u0437 \u0441\u0442\u0430\u0440\u043e\u0433\u043e \u0430\u043d\u0430\u043b\u043e\u0433\u0430)',sd_check:'\u041f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u0432\u0440\u0443\u0447\u043d\u0443\u044e',
  d_old:'\u0421\u0442\u0430\u0440\u0430\u044f \u0441\u0431\u043e\u0440\u043a\u0430',d_new:'\u041d\u043e\u0432\u0430\u044f \u0441\u0431\u043e\u0440\u043a\u0430',d_idx:'\u0418\u043d\u0434\u0435\u043a\u0441',d_name:'\u0418\u043c\u044f',d_size:'\u0420\u0430\u0437\u043c\u0435\u0440',d_bytes:'\u0431\u0430\u0439\u0442',d_insns:'\u0418\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u0439',d_match:'\u041c\u0435\u0442\u043e\u0434',
  d_thunk:'\u0440\u0430\u0441\u043a\u0440\u044b\u0442 thunk',d_strs:'\u0421\u0442\u0440\u043e\u043a\u0438, \u043d\u0430 \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u0435\u0441\u0442\u044c \u0441\u0441\u044b\u043b\u043a\u0438',d_sold:'\u0441\u0442\u0430\u0440\u0430\u044f',d_snew:'\u043d\u043e\u0432\u0430\u044f',d_none:'\u043d\u0435\u0442',
  d_pat:'\u041f\u0430\u0442\u0442\u0435\u0440\u043d \u043d\u043e\u0432\u043e\u0439 \u0444\u0443\u043d\u043a\u0446\u0438\u0438 (\u043e\u043f\u0435\u0440\u0430\u043d\u0434\u044b \u0437\u0430\u043c\u0430\u0441\u043a\u0438\u0440\u043e\u0432\u0430\u043d\u044b)',d_copy:'\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c',d_copyea:'\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c EA',d_copyrva:'\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c RVA',
  t_copied:'\u0421\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d\u043e',t_dl:'\u0421\u043a\u0430\u0447\u0430\u043d\u043e',t_fail:'\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c',
  tip_old:'\u0441\u0442\u0430\u0440\u044b\u0439 \u2116{0}',tip_new:'\u043d\u043e\u0432\u044b\u0439 \u2116{0}',tip_added:'\u0434\u043e\u0431\u0430\u0432\u043b\u0435\u043d',tip_removed:'\u0443\u0434\u0430\u043b\u0451\u043d',
  gen_ptr:'\u0443\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u0438 {0} \u0431\u0438\u0442',slots:'\u0441\u043b\u043e\u0442\u043e\u0432',
  st_exact:'\u0442\u043e\u0447\u043d\u043e',st_high:'\u0432\u044b\u0441\u043e\u043a\u0430\u044f',st_medium:'\u0441\u0440\u0435\u0434\u043d\u044f\u044f',st_low:'\u043d\u0438\u0437\u043a\u0430\u044f',st_guess:'\u0434\u043e\u0433\u0430\u0434\u043a\u0430',st_REMOVED:'\u0423\u0414\u0410\u041b\u0415\u041d\u041e',st_NEW:'\u041d\u041e\u0412\u041e\u0415',
  how_anchor:'\u044f\u043a\u043e\u0440\u044c',how_aligned:'\u0432\u044b\u0440\u0430\u0432\u043d\u0438\u0432\u0430\u043d\u0438\u0435',how_guess:'\u043f\u043e \u043f\u043e\u0437\u0438\u0446\u0438\u0438',how_removed:'\u0443\u0434\u0430\u043b\u0435\u043d\u043e',how_added:'\u0434\u043e\u0431\u0430\u0432\u043b\u0435\u043d\u043e'}
};
let L='';
try{L=localStorage.getItem('vtd_lang')||''}catch(e){}
if(L!=='ru'&&L!=='en')L=/^ru/i.test(navigator.language||'')?'ru':'en';
function t(k){
 let s=(I18N[L]||{})[k];if(s===undefined)s=I18N.en[k];if(s===undefined)return k;
 for(let i=1;i<arguments.length;i++)s=s.split('{'+(i-1)+'}').join(String(arguments[i]));
 return s;
}
const STS=['exact','high','medium','low','guess','REMOVED','NEW'];
const RANK={};STS.forEach((s,i)=>RANK[s]=i);
const sl=s=>t('st_'+s);
function howLbl(h){const v=(I18N[L]||{})['how_'+h];return v===undefined?h:v}
const hex=v=>v===null||v===undefined?'':'0x'+v.toString(16).toUpperCase();
const S={q:'',sel:new Set(),moved:false,range:null,sort:{k:'o',d:1}};
let hlRe=null;

rows.forEach((r,i)=>{
 r.i=i;
 r._h=[r.on,r.nn,r.oea,r.nea,r.orva,r.nrva,r.st,I18N.ru['st_'+r.st],r.how,r.o===null?'':'#'+r.o,r.n===null?'':'#'+r.n].join(' ').toLowerCase();
});

function toast(m){const e=$('#toast');e.textContent=m;e.classList.add('show');clearTimeout(toast._t);toast._t=setTimeout(()=>e.classList.remove('show'),1400)}
function copy(txt){
 const done=()=>toast(t('t_copied'));
 const fb=()=>{const a=document.createElement('textarea');a.value=txt;a.style.position='fixed';a.style.opacity='0';
  document.body.appendChild(a);a.select();try{document.execCommand('copy');done()}catch(e){toast(t('t_fail'))}a.remove()};
 if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(txt).then(done,fb)}else fb();
}

/* ------------------------------ static parts ------------------------------ */
function applyStatic(){
 document.documentElement.lang=L;
 document.querySelectorAll('[data-i18n]').forEach(e=>e.textContent=t(e.dataset.i18n));
 document.querySelectorAll('[data-i18n-html]').forEach(e=>e.innerHTML=t(e.dataset.i18nHtml));
 document.querySelectorAll('[data-i18n-ph]').forEach(e=>e.placeholder=t(e.dataset.i18nPh));
 document.querySelectorAll('#lang button').forEach(b=>b.classList.toggle('on',b.dataset.l===L));
}
function buildTop(){
 const m=D.meta,st=D.stats;
 $('#sub').innerHTML='<b>'+esc(m.old_module)+'</b> '+esc(m.old_vt_name||m.old_vt)+' <span class="mono">('+st.old+' '+esc(t('slots'))+')</span>'
  +' &rarr; <b>'+esc(m.new_module)+'</b> '+esc(m.new_vt_name||m.new_vt)+' <span class="mono">('+st.new+' '+esc(t('slots'))+')</span>';
 $('#gen').textContent=m.generated+' \u00b7 '+t('gen_ptr',m.ptr*8);
 const cards=[['c_old',st.old,''],['c_new',st.new,''],['c_matched',st.matched,'--exact'],['c_moved',st.moved,'--low'],
  ['c_weak',st.weak,'--guess'],['c_removed',st.removed,'--removed'],['c_added',st.added,'--new']];
 $('#cards').innerHTML=cards.map(c=>'<div class="card'+(c[2]?' acc':'')+'" style="'+(c[2]?'--c:var('+c[2]+')':'')+'"><div class="v">'+c[1]+'</div><div class="l">'+esc(t(c[0]))+'</div></div>').join('');
 $('#legend').innerHTML=STS.map(s=>'<span class="st-'+s.toLowerCase()+'">'+esc(sl(s))+'</span>').join('');
 $('#strip').innerHTML=rows.map(r=>{
  const a=r.o===null?t('tip_added'):t('tip_old',r.o), b=r.n===null?t('tip_removed'):t('tip_new',r.n);
  return '<i class="st-'+r.st.toLowerCase()+'" data-i="'+r.i+'" title="'+esc(a+' \u2192 '+b+(r.sh?' ('+(r.sh>0?'+':'')+r.sh+')':'')+' \u00b7 '+sl(r.st))+'"></i>';
 }).join('');
}
$('#strip').onclick=e=>{const c=e.target.closest('i');if(!c)return;const r=rows[+c.dataset.i];setQ(r.o!==null?'o:'+r.o:'n:'+r.n)};

function buildChips(){
 const cnt={};rows.forEach(r=>cnt[r.st]=(cnt[r.st]||0)+1);
 $('#chips').innerHTML='<span class="chip'+(S.sel.size===0?' on':'')+'" data-s="">'+esc(t('all'))+'<span class="n">'+rows.length+'</span></span>'+
  STS.filter(s=>cnt[s]).map(s=>'<span class="chip st-'+s.toLowerCase()+(S.sel.has(s)?' on':'')+'" data-s="'+s+'">'+esc(sl(s))+'<span class="n">'+cnt[s]+'</span></span>').join('');
}
$('#chips').onclick=e=>{const c=e.target.closest('.chip');if(!c)return;const s=c.dataset.s;
 if(!s)S.sel.clear();else if(S.sel.has(s))S.sel.delete(s);else S.sel.add(s);render()};

function buildSide(){
 let h='<div class="sbox"><h3>'+esc(t('sd_ranges'))+'</h3>';
 if(!D.ranges.length)h+='<div class="mut">'+esc(t('sd_none'))+'</div>';
 D.ranges.forEach((g,i)=>{
  const on=S.range&&S.range.a===g.a&&S.range.b===g.b;
  h+='<button class="rg'+(on?' on':'')+'" data-i="'+i+'"><span class="mono">'+esc(t('sd_old',g.a+(g.a!==g.b?'..'+g.b:'')))+'</span>'+
   '<span class="sh '+(g.s>0?'pos':g.s<0?'neg':'sh0')+'">'+(g.s>0?'+':'')+(g.s===0?'=':g.s)+'</span></button>';
 });
 h+=(S.range?'<button class="btn" id="clr" style="width:100%;margin-top:4px">'+esc(t('sd_clear'))+'</button>':'')+'</div>';
 const rem=rows.filter(r=>r.st==='REMOVED'),add=rows.filter(r=>r.st==='NEW'),weak=rows.filter(r=>r.st==='low'||r.st==='guess');
 if(rem.length)h+='<div class="sbox"><h3>'+esc(t('sd_removed'))+'</h3><div class="pills">'+rem.map(r=>'<span class="pill mono" data-q="o:'+r.o+'">'+r.o+'</span>').join('')+'</div></div>';
 if(add.length)h+='<div class="sbox"><h3>'+esc(t('sd_added'))+'</h3><div class="pills">'+add.map(r=>'<span class="pill mono" data-q="n:'+r.n+'">'+r.n+'</span>').join('')+'</div></div>';
 if(weak.length)h+='<div class="sbox"><h3>'+esc(t('sd_check'))+'</h3><div class="pills">'+weak.map(r=>'<span class="pill mono" data-q="o:'+r.o+'">'+r.o+'\u2192'+r.n+'</span>').join('')+'</div></div>';
 $('#side').innerHTML=h;
}
$('#side').onclick=e=>{
 const g=e.target.closest('.rg');
 if(g){const r=D.ranges[+g.dataset.i];S.range=(S.range&&S.range.a===r.a&&S.range.b===r.b)?null:{a:r.a,b:r.b};render();return}
 if(e.target.id==='clr'){S.range=null;render();return}
 const p=e.target.closest('.pill');if(p)setQ(p.dataset.q);
};

/* ------------------------------ filter / sort ------------------------------ */
function tokens(){return S.q.toLowerCase().split(/\s+/).filter(Boolean)}
function matchTok(r,tk){
 let m;
 if((m=/^o:(\d+)$/.exec(tk)))return r.o===+m[1];
 if((m=/^n:(\d+)$/.exec(tk)))return r.n===+m[1];
 if((m=/^s:([+-]?\d+)$/.exec(tk)))return r.sh===+m[1];
 return r._h.indexOf(tk)>=0;
}
function keyOf(r,k){
 switch(k){
  case 'o':return r.o;case 'n':return r.n;case 'oo':return r.oo;case 'no':return r.no;case 'sh':return r.sh;
  case 'sc':return(r.o===null||r.n===null)?null:r.sc;case 'st':return RANK[r.st];
  case 'on':return r.on?r.on.toLowerCase():null;case 'nn':return r.nn?r.nn.toLowerCase():null;
 }
}
function visible(){
 const T=tokens();
 const v=rows.filter(r=>{
  if(S.sel.size&&!S.sel.has(r.st))return false;
  if(S.moved&&!(r.sh!==null&&r.sh!==0))return false;
  if(S.range&&!(r.o!==null&&r.o>=S.range.a&&r.o<=S.range.b))return false;
  for(const tk of T)if(!matchTok(r,tk))return false;
  return true;
 });
 const k=S.sort.k,d=S.sort.d;
 v.sort((a,b)=>{
  const x=keyOf(a,k),y=keyOf(b,k);
  if(x===null||x===undefined){if(y===null||y===undefined)return a.i-b.i;return 1}
  if(y===null||y===undefined)return -1;
  const c=x<y?-1:x>y?1:0;return c?c*d:a.i-b.i;
 });
 return v;
}

/* ------------------------------ table ------------------------------ */
function hl(s){
 s=String(s==null?'':s);if(!hlRe)return esc(s);
 let out='',last=0,m;hlRe.lastIndex=0;
 while((m=hlRe.exec(s))){if(m[0]===''){hlRe.lastIndex++;continue}
  out+=esc(s.slice(last,m.index))+'<mark>'+esc(m[0])+'</mark>';last=m.index+m[0].length}
 return out+esc(s.slice(last));
}
function fnCell(name,ea,auto){
 if(!ea)return '<span class="mut">\u2014</span>';
 return '<div class="fn"><span class="nm'+(auto?' auto':'')+'" title="'+esc(name)+'">'+hl(name||'?')+'</span><span class="ea mono">'+hl(ea)+'</span></div>';
}
function shCell(r){
 if(r.sh===null)return '<span class="mut">\u2014</span>';
 if(r.sh===0)return '<span class="sh0">=</span>';
 return '<span class="sh '+(r.sh>0?'pos':'neg')+'">'+(r.sh>0?'+':'')+r.sh+'</span>';
}
function kv(a){return '<div class="kv">'+a.map(x=>'<div>'+esc(x[0])+'</div><div class="mono">'+esc(x[1])+'</div>').join('')+'</div>'}
function strs(a){return a&&a.length?'<div class="strs">'+a.map(x=>'<span title="'+esc(x)+'">'+esc(x)+'</span>').join('')+'</div>':'<span class="mut">'+esc(t('d_none'))+'</span>'}
function detail(r){
 const dash='\u2014';
 const o=[[t('d_idx'),r.o===null?dash:r.o+'  ('+hex(r.oo)+')'],[t('d_name'),r.on||dash],['EA',r.oea||dash],['RVA',r.orva||dash],
  [t('d_size'),r.osz==null?dash:r.osz+' '+t('d_bytes')],[t('d_insns'),r.oi==null?dash:r.oi]];
 const n=[[t('d_idx'),r.n===null?dash:r.n+'  ('+hex(r.no)+')'],[t('d_name'),r.nn||dash],['EA',r.nea||dash],['RVA',r.nrva||dash],
  [t('d_size'),r.nsz==null?dash:r.nsz+' '+t('d_bytes')],[t('d_insns'),r.ni==null?dash:r.ni],[t('d_match'),howLbl(r.how)+(r.thunk?' ('+t('d_thunk')+')':'')]];
 return '<tr class="det st-'+r.st.toLowerCase()+'"><td colspan="9"><div class="dg">'+
  '<div class="dbox"><h4>'+esc(t('d_old'))+'</h4>'+kv(o)+'</div>'+
  '<div class="dbox"><h4>'+esc(t('d_new'))+'</h4>'+kv(n)+
   (r.nea?'<div style="margin-top:8px"><button class="mini" data-c="'+esc(r.nea)+'">'+esc(t('d_copyea'))+'</button><button class="mini" data-c="'+esc(r.nrva)+'">'+esc(t('d_copyrva'))+'</button></div>':'')+'</div>'+
  '<div class="dbox"><h4>'+esc(t('d_strs'))+'</h4><div class="mut" style="font-size:11.5px;margin-bottom:4px">'+esc(t('d_sold'))+'</div>'+strs(r.ostr)+
   '<div class="mut" style="font-size:11.5px;margin:8px 0 4px">'+esc(t('d_snew'))+'</div>'+strs(r.nstr)+'</div>'+
  (r.pat?'<div class="dbox" style="grid-column:1/-1"><h4>'+esc(t('d_pat'))+'<button class="mini" data-c="'+esc(r.pat)+'">'+esc(t('d_copy'))+'</button></h4><div class="pat mono">'+esc(r.pat)+'</div></div>':'')+
  '</div></td></tr>';
}
function rowHTML(r){
 const cl='st-'+r.st.toLowerCase();
 const both=r.o!==null&&r.n!==null;
 const same=both&&r.sh===0;
 return '<tr class="row '+cl+(same?' same':'')+(r._open?' open':'')+'" data-i="'+r.i+'">'+
  '<td class="num mono">'+(r.o===null?'<span class="mut">\u2014</span>':hl(String(r.o)))+'</td>'+
  '<td class="num mono mut hide-s">'+(r.oo===null?'':hex(r.oo))+'</td>'+
  '<td class="fncell">'+fnCell(r.on,r.oea,r.oauto)+'</td>'+
  '<td><span class="b '+cl+'">'+esc(sl(r.st))+'</span></td>'+
  '<td class="num">'+shCell(r)+'</td>'+
  '<td class="num mono">'+(r.n===null?'<span class="mut">\u2014</span>':hl(String(r.n)))+'</td>'+
  '<td class="num mono mut hide-s">'+(r.no===null?'':hex(r.no))+'</td>'+
  '<td class="fncell">'+fnCell(r.nn,r.nea,r.nauto)+'</td>'+
  '<td>'+(both?'<div class="sc '+cl+'"><i style="width:'+Math.round(r.sc*100)+'%"></i><span>'+r.sc.toFixed(2)+'</span></div>':'<span class="mut">\u2014</span>')+'</td></tr>'+
  (r._open?detail(r):'');
}
function render(){
 const T=tokens().filter(x=>!/^[ons]:/.test(x));
 hlRe=T.length?new RegExp(T.map(reEsc).join('|'),'gi'):null;
 const v=visible();
 $('#tb').innerHTML=v.map(rowHTML).join('');
 $('#empty').style.display=v.length?'none':'block';
 $('#cnt').textContent=t('showing',v.length,rows.length)+(S.range?'  \u00b7  '+t('range_txt',S.range.a+'..'+S.range.b):'');
 $('#bMoved').classList.toggle('on',S.moved);
 document.querySelectorAll('thead th').forEach(th=>{
  const a=th.querySelector('.ar');if(a)a.remove();
  th.classList.toggle('sorted',th.dataset.k===S.sort.k);
  if(th.dataset.k===S.sort.k){const s=document.createElement('span');s.className='ar';s.textContent=S.sort.d>0?'\u25b2':'\u25bc';th.appendChild(s)}
 });
 buildChips();buildSide();fit();
 window._vis=v;
}
function setQ(v){S.q=v;$('#q').value=v;render();$('#tablebox').scrollIntoView({behavior:'smooth',block:'start'})}

/* ------------------------------ events ------------------------------ */
$('#q').addEventListener('input',e=>{S.q=e.target.value;render()});
$('#tb').addEventListener('click',e=>{
 const c=e.target.closest('[data-c]');if(c){copy(c.dataset.c);return}
 if(e.target.closest('tr.det'))return;
 const tr=e.target.closest('tr.row');if(!tr)return;
 const r=rows[+tr.dataset.i];r._open=!r._open;render();
});
document.querySelectorAll('thead th').forEach(th=>th.addEventListener('click',()=>{
 const k=th.dataset.k;if(S.sort.k===k)S.sort.d=-S.sort.d;else{S.sort.k=k;S.sort.d=1}render()}));
$('#bMoved').onclick=()=>{S.moved=!S.moved;render()};
function csvText(){
 const q=v=>{v=v===null||v===undefined?'':String(v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v};
 const h=['old_idx','old_off','old_name','status','shift','new_idx','new_off','new_name','new_ea','score','how'];
 return [h.join(',')].concat((window._vis||[]).map(r=>[r.o,hex(r.oo),r.on,r.st,r.sh,r.n,hex(r.no),r.nn,r.nea,r.sc,r.how].map(q).join(','))).join('\n');
}
$('#bCsv').onclick=()=>copy(csvText());
$('#bDl').onclick=()=>{const b=new Blob([csvText()],{type:'text/csv'});const a=document.createElement('a');
 a.href=URL.createObjectURL(b);a.download='vtable_diff.csv';document.body.appendChild(a);a.click();a.remove();toast(t('t_dl'))};
$('#bMap').onclick=()=>copy((window._vis||[]).filter(r=>r.o!==null&&r.n!==null)
 .map(r=>r.o+' -> '+r.n+(r.sh?'  ('+(r.sh>0?'+':'')+r.sh+')':'')).join('\n'));
document.addEventListener('keydown',e=>{
 const inp=document.activeElement===$('#q');
 if(e.key==='/'&&!inp){e.preventDefault();$('#q').focus();$('#q').select()}
 else if(e.key==='Escape'){if(S.q||S.range||S.sel.size||S.moved){S.q='';S.range=null;S.sel.clear();S.moved=false;$('#q').value='';render()}$('#q').blur()}
});
document.querySelectorAll('#lang button').forEach(b=>b.addEventListener('click',()=>{
 L=b.dataset.l;try{localStorage.setItem('vtd_lang',L)}catch(e){}
 applyStatic();buildTop();render();
}));
function fit(){document.documentElement.style.setProperty('--ch',($('#controls').offsetHeight)+'px')}
window.addEventListener('resize',fit);
if(window.ResizeObserver)new ResizeObserver(fit).observe($('#controls'));
applyStatic();buildTop();render();
</script></body></html>
"""


def build_report_data(st):
    old, new, ps = st["old"], st["new"], st["ps"]
    meta = dict(st.get("meta") or {})
    meta["ptr"] = ps
    meta["generated"] = time.strftime("%Y-%m-%d %H:%M")
    for k in ("old_vt", "new_vt"):
        if isinstance(meta.get(k), int):
            meta[k] = "0x%X" % meta[k]

    def h(v):
        return "0x%X" % v

    rows = []
    for r in st["rows"]:
        o = old[r["old"]] if r["old"] is not None else None
        n = new[r["new"]] if r["new"] is not None else None
        ofp = (o or {}).get("fp") or {}
        nfp = (n or {}).get("fp") or {}
        rows.append({
            "o": r["old"], "n": r["new"],
            "oo": None if o is None else r["old"] * ps,
            "no": None if n is None else r["new"] * ps,
            "sh": None if (o is None or n is None) else r["new"] - r["old"],
            "sc": round(r["score"], 3), "st": conf_label(r), "how": r["how"],
            "on": o["name"] if o else "", "oauto": bool(o and o.get("auto")),
            "oea": h(o["ea"]) if o else "", "orva": h(o["rva"]) if o else "",
            "nn": n["name"] if n else "", "nauto": bool(n and n.get("auto")),
            "nea": h(n["ea"]) if n else "", "nrva": h(n["rva"]) if n else "",
            "osz": ofp.get("size"), "nsz": nfp.get("size"),
            "oi": ofp.get("ninsn"), "ni": nfp.get("ninsn"),
            "pat": nfp.get("pattern", ""),
            "ostr": (ofp.get("strings") or [])[:8], "nstr": (nfp.get("strings") or [])[:8],
            "thunk": bool(nfp.get("thunk")),
        })
    moved = sum(1 for x in rows if x["sh"] not in (None, 0))
    stats = {
        "old": len(old), "new": len(new),
        "matched": sum(1 for x in rows if x["o"] is not None and x["n"] is not None),
        "moved": moved,
        "weak": sum(1 for x in rows if x["st"] in ("low", "guess")),
        "removed": sum(1 for x in rows if x["n"] is None),
        "added": sum(1 for x in rows if x["o"] is None),
    }
    ranges = [{"a": a, "b": b, "s": s} for a, b, s in shift_ranges(st["rows"])]
    return {"meta": meta, "stats": stats, "rows": rows, "ranges": ranges}


def make_html(st):
    data = build_report_data(st)
    js = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    m = data["meta"]
    title = "VTable Diff - %s -> %s" % (m.get("old_module", "?"), m.get("new_module", "?"))
    return HTML_TEMPLATE.replace("__TITLE__", html.escape(title)).replace("__DATA__", js)


def do_html():
    st = STATE["last"]
    if not st:
        ida_kernwin.warning("Run a comparison first")
        return
    meta = st.get("meta") or {}
    path = ida_kernwin.ask_file(True, default_path("html", meta.get("cls") or "report"), "Save HTML report")
    if not path:
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(make_html(st))
    remember_dir("html", path)
    print("[vtdiff] HTML report -> %s" % path)
    try:
        webbrowser.open("file:///" + os.path.abspath(path).replace("\\", "/"))
    except Exception:
        pass
    return True


def show_window(st=None):
    st = st or STATE["last"]
    if not st:
        ida_kernwin.warning("Run a comparison first")
        return
    rows, old, new, ps = st["rows"], st["old"], st["new"], st["ps"]
    matched = sum(1 for r in rows if r["old"] is not None and r["new"] is not None)
    old_title = STATE.get("chooser_title")
    if old_title:
        w = ida_kernwin.find_widget(old_title)
        if w:
            ida_kernwin.close_widget(w, 0)
    title = "VTable Diff: %d -> %d slots (%d matched)" % (len(old), len(new), matched)
    STATE["chooser_title"] = title
    ch = DiffChooser(title, rows, old, new, ps)
    ch.Show()
    STATE["chooser"] = ch


def do_window():
    show_window()


def do_console():
    st = STATE["last"]
    if not st:
        ida_kernwin.warning("Run a comparison first")
        return
    ps, old, new = st["ps"], st["old"], st["new"]
    fmt = "%5s %8s | %5s %8s | %6s %5s %-8s | %-36s %-18s %s"
    L = ["[vtdiff] full diff: %d old -> %d new slots" % (len(old), len(new)),
         fmt % ("old", "off", "new", "off", "shift", "score", "status", "old name", "new ea", "new name")]
    for r in st["rows"]:
        o = old[r["old"]] if r["old"] is not None else None
        n = new[r["new"]] if r["new"] is not None else None
        both = o is not None and n is not None
        L.append(fmt % (
            "" if o is None else r["old"],
            "" if o is None else "0x%X" % (r["old"] * ps),
            "" if n is None else r["new"],
            "" if n is None else "0x%X" % (r["new"] * ps),
            "%+d" % (r["new"] - r["old"]) if both else "",
            "%.2f" % r["score"] if both else "",
            conf_label(r),
            ((o["name"] or "")[:36]) if o else "",
            "0x%X" % n["ea"] if n else "",
            (n["name"] or "") if n else "",
        ))
    L.append("[vtdiff] shift ranges:")
    for a, b, sh in shift_ranges(st["rows"]):
        L.append("   old %d..%d  ->  %+d slots (%+d bytes)" % (a, b, sh, sh * ps))
    L.append("[vtdiff] GitHub: https://github.com/K1cher1337/VTableDiff-IDA_9.1_Plugin")
    print("\n".join(L))


OUT_WINDOW, OUT_HTML, OUT_CONSOLE = 1, 2, 4


def _ask_outputs(n_old, n_new, mask):
    """3 checkboxes -> bitmask, or None if cancelled"""
    class OutForm(ida_kernwin.Form):
        def __init__(self):
            ida_kernwin.Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
VTable Diff - result

Done: %d old / %d new slots. Show the result as:

<IDA window:{cWin}>
<HTML report (save and open in browser):{cHtml}>
<Console (full table):{cCon}>{cGroup}>
""" % (n_old, n_new), {"cGroup": ida_kernwin.Form.ChkGroupControl(("cWin", "cHtml", "cCon"))})

    f = OutForm()
    f.Compile()
    f.cGroup.value = mask
    try:
        if f.Execute() != 1:
            return None
        return int(f.cGroup.value)
    finally:
        f.Free()


def choose_output():
    st = STATE["last"]
    mask = STATE.get("out_mask", OUT_WINDOW | OUT_HTML)
    try:
        res = _ask_outputs(len(st["old"]), len(st["new"]), mask)
    except Exception:
        traceback.print_exc()   # checkbox form failed - fall back to plain buttons
        r = ida_kernwin.ask_buttons(
            "IDA window + HTML", "Console", "IDA window", ida_kernwin.ASKBTN_YES,
            "VTable Diff finished: %d -> %d slots\nHow to show the result?" % (len(st["old"]), len(st["new"])))
        res = {1: OUT_WINDOW | OUT_HTML, 0: OUT_CONSOLE}.get(r, OUT_WINDOW)
    if res is None:
        print("[vtdiff] result kept - reopen it via Edit > Plugins > VTable Diff: ...")
        return
    STATE["out_mask"] = res
    if res & OUT_CONSOLE:
        do_console()
    if res & OUT_WINDOW:
        show_window(st)
    if res & OUT_HTML:
        if not do_html() and not (res & OUT_WINDOW):
            show_window(st)   # saving was cancelled - don't lose the result


def do_apply_names():
    st = STATE["last"]
    if not st:
        ida_kernwin.warning("Run a comparison first")
        return
    todo = []
    for r in st["rows"]:
        if r["old"] is None or r["new"] is None:
            continue
        if r["how"] == "guess" or r["score"] < 0.8:
            continue
        o, nw = st["old"][r["old"]], st["new"][r["new"]]
        if o["auto"] or not o["name"]:
            continue
        if not is_auto(ida_name.get_name(nw["ea"])):
            continue
        todo.append((nw["ea"], o["name"], r["old"], r["new"]))
    if not todo:
        ida_kernwin.info("Nothing to rename (need confident matches with user-defined old names)")
        return
    if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "Rename %d functions in this IDB?" % len(todo)) != 1:
        return
    flags = ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE
    ok = 0
    for ea, nm, oi, ni in todo:
        if ida_name.set_name(ea, nm, flags):
            ok += 1
    print("[vtdiff] renamed %d / %d" % (ok, len(todo)))


def do_save_csv():
    st = STATE["last"]
    if not st:
        ida_kernwin.warning("Run a comparison first")
        return
    path = ida_kernwin.ask_file(True, "*.csv", "Save diff as CSV")
    if not path:
        return
    ps = st["ps"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["old_idx", "old_off", "new_idx", "new_off", "shift", "score", "status",
                    "how", "old_name", "new_ea", "new_name"])
        for r in st["rows"]:
            o = st["old"][r["old"]] if r["old"] is not None else None
            nw = st["new"][r["new"]] if r["new"] is not None else None
            w.writerow([
                "" if o is None else r["old"],
                "" if o is None else "0x%X" % (r["old"] * ps),
                "" if nw is None else r["new"],
                "" if nw is None else "0x%X" % (r["new"] * ps),
                "" if (o is None or nw is None) else r["new"] - r["old"],
                "%.3f" % r["score"], conf_label(r), r["how"],
                "" if o is None else o["name"],
                "" if nw is None else "0x%X" % nw["ea"],
                "" if nw is None else nw["name"],
            ])
    print("[vtdiff] saved", path)


# --------------------------------------------------------------------------
# plugin glue
# --------------------------------------------------------------------------
class _Handler(ida_kernwin.action_handler_t):
    def __init__(self, fn):
        ida_kernwin.action_handler_t.__init__(self)
        self.fn = fn

    def activate(self, ctx):
        try:
            self.fn()
        except Exception as e:
            if str(e) != "cancelled":
                traceback.print_exc()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("vtdiff:export", "VTable Diff: export vtable", do_export),
    ("vtdiff:compare", "VTable Diff: compare with JSON", do_compare),
    ("vtdiff:html", "VTable Diff: export HTML report", do_html),
    ("vtdiff:window", "VTable Diff: show result window", do_window),
    ("vtdiff:console", "VTable Diff: print full diff to console", do_console),
    ("vtdiff:ranges", "VTable Diff: show shift ranges", do_ranges),
    ("vtdiff:apply", "VTable Diff: apply old names", do_apply_names),
    ("vtdiff:csv", "VTable Diff: save last diff as CSV", do_save_csv),
]


class vtdiff_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Track vtable slot shifts between two builds"
    help = "Export vtable from the old IDB, compare in the new IDB"
    wanted_name = "VTable Diff"
    wanted_hotkey = "Ctrl-Alt-V"

    def init(self):
        self._handlers = []
        for name, label, fn in ACTIONS:
            h = _Handler(fn)
            self._handlers.append(h)
            ida_kernwin.register_action(ida_kernwin.action_desc_t(name, label, h, None, label, -1))
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", name, ida_kernwin.SETMENU_APP)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        r = ida_kernwin.ask_buttons("Export", "Compare", "Cancel", ida_kernwin.ASKBTN_YES,
                                    "VTable Diff\nExport: run in OLD idb\nCompare: run in NEW idb")
        try:
            if r == 1:
                do_export()
            elif r == 0:
                do_compare()
        except Exception as e:
            if str(e) != "cancelled":
                traceback.print_exc()

    def term(self):
        for name, _, _ in ACTIONS:
            ida_kernwin.detach_action_from_menu("Edit/Plugins/", name)
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return vtdiff_plugin_t()
