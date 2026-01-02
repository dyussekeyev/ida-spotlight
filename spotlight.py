# SPDX-License-Identifier: Apache-2.0
#
# IDA Spotlight — Function triage for IDA 9.2+ (IDAPython / PySide6)

import sqlite3
import hashlib

import csv
import json
import math
import os
import re
import time
from typing import Optional, Dict, Any, List

import idaapi
import ida_kernwin
import idautils
import ida_funcs
import ida_name
import ida_ua
import ida_lines
import ida_bytes
import idc
import ida_nalt
import ida_segment
import ida_netnode

from PySide6 import QtWidgets, QtCore, QtGui
import shiboken6


# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

from spotlight_shared import (
    load_signals_and_config,
    normalize_name,
    normalize_dll_name,
    build_func_filters,
    is_filtered_func,
    build_common_sections,
    build_common_import_dlls,
    default_kb_db_path,
)

BASE_DIR = os.path.dirname(__file__)
SIGNALS, CFG = load_signals_and_config(BASE_DIR)

FUNC_FILTERS = build_func_filters(CFG)
COMMON_SECTIONS = build_common_sections(CFG)
COMMON_IMPORT_DLLS = build_common_import_dlls(CFG)

CONTEXT_BONUS_FACTOR = float(CFG.get("context_bonus_factor", 0.15))
LIBRARY_SCORE_PENALTY = float(CFG.get("library_score_penalty", 3.0))

LIBRARY_ROW_COLOR = QtGui.QColor(160, 220, 255)


# ----------------------------------------------------------------------
# Spotlight KB (SQLite) config
# ----------------------------------------------------------------------

KB_NODE_NAME = "$ ida_spotlight_kb"


def kb_node():
    return ida_netnode.netnode(KB_NODE_NAME, ida_netnode.NETNODE_CREATE)


def kb_get_setting(key: str, default: str = "") -> str:
    try:
        val = kb_node().get(key)
        if val is None:
            return default
        return val.decode("utf-8")
    except Exception:
        return default


def kb_set_setting(key: str, value: str):
    try:
        kb_node().set(key, value.encode("utf-8"))
    except Exception:
        pass


def kb_db_path() -> str:
    # Stored per-IDB via netnode; empty => default
    p = (kb_get_setting("db_path", "") or "").strip()
    return p if p else default_kb_db_path()


KB_MAX_HITS = 50


class SpotlightContext:
    def __init__(self):
        self.signals: Dict[str, Dict[str, Dict[str, float]]] = {}
        self.categories: List[str] = []
        self.results: Dict[int, Dict[str, Any]] = {}
        self.last_scan_seconds: float = 0.0


CTX = SpotlightContext()
CTX.signals = SIGNALS
CTX.categories = sorted(SIGNALS.keys())


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def qt_alive(obj) -> bool:
    try:
        return obj is not None and shiboken6.isValid(obj)
    except Exception:
        return False


def fmt_ea(ea: int) -> str:
    return f"0x{int(ea):x}"


def safe_regex_search(pattern: str, text: str) -> bool:
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except Exception:
        return False


def sanitize_operand_name(name: str) -> str:
    if not name:
        return ""
    if ":" in name:
        name = name.split(":")[-1]
    return name.strip()


def func_start_from_any_ea(ea: int) -> Optional[int]:
    f = ida_funcs.get_func(int(ea))
    return int(f.start_ea) if f else None


def top_reason_str(res: Dict[str, Any]) -> str:
    reasons = res.get("reasons", [])
    if not reasons:
        return ""
    try:
        top = max(reasons, key=lambda x: float(x.get("weight", 0.0)))
        return top.get("text", "")
    except Exception:
        return ""


def categories_str(res: Dict[str, Any]) -> str:
    cats = [k for k, v in res.get("category_hits", {}).items() if v]
    cats.sort()
    return ", ".join(cats)


def is_code_widget(widget) -> bool:
    try:
        wtype = ida_kernwin.get_widget_type(widget)
        return wtype in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE)
    except Exception:
        return False


def widget_title(widget) -> str:
    try:
        return ida_kernwin.get_widget_title(widget) or ""
    except Exception:
        return ""


def get_qt_parent():
    try:
        w = ida_kernwin.get_current_widget()
        return ida_kernwin.PluginForm.FormToPyQtWidget(w)
    except Exception:
        return None


def _extract_view_letter_from_title(title: str) -> Optional[str]:
    # Expected: "IDA View-A", "Pseudocode-A"
    m = re.match(r"^(IDA View|Pseudocode)-([A-Z])$", (title or "").strip())
    if not m:
        return None
    return m.group(2)


def _paired_view_titles(title: str) -> List[str]:
    letter = _extract_view_letter_from_title(title)
    if not letter:
        return [title]
    return [f"IDA View-{letter}", f"Pseudocode-{letter}"]


def find_code_widget_by_title(title: str):
    try:
        w = ida_kernwin.find_widget(title)
    except Exception:
        w = None
    if w is None:
        return None
    if not is_code_widget(w):
        return None
    return w


# ----------------------------------------------------------------------
# Spotlight KB (SQLite) helpers
# ----------------------------------------------------------------------

def kb_db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(kb_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def kb_db_ready() -> bool:
    p = kb_db_path()
    if not os.path.exists(p):
        return False
    try:
        with kb_db_connect() as c:
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='idb'")
            if c.fetchone() is None:
                return False
            # sanity: new schema tables should exist
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feat_import_func'")
            return c.fetchone() is not None
    except Exception:
        return False


def kb_db_diagnose(path: str) -> str:
    if not path:
        return "database path is empty"

    if not os.path.exists(path):
        return "file does not exist"

    try:
        conn = sqlite3.connect(path)
    except sqlite3.Error as e:
        return f"sqlite open failed: {e}"

    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='idb'"
        )
        if cur.fetchone() is None:
            return "sqlite opened, but Spotlight schema missing (table 'idb')"
    except sqlite3.Error as e:
        return f"schema check failed: {e}"
    finally:
        conn.close()

    return ""  # OK


# ----------------------------------------------------------------------
# Sample profile (for KB correlation)
# ----------------------------------------------------------------------

def _iter_import_items_filtered() -> List[str]:
    # Build "dll_norm!func_norm" list (matching indexer) and filter common imports by default.
    items: List[str] = []
    try:
        qty = ida_nalt.get_import_module_qty()
    except Exception:
        return items

    for i in range(qty):
        dll_raw = ida_nalt.get_import_module_name(i) or ""
        dll_norm = normalize_dll_name(dll_raw)
        if not dll_norm:
            continue
        if dll_norm in COMMON_IMPORT_DLLS:
            continue

        def cb(ea, name, ord_):
            if name:
                fn = normalize_name(str(name))
            elif ord_ is not None:
                fn = normalize_name(f"ord{int(ord_)}")
            else:
                return True
            items.append(f"{dll_norm}!{fn}")
            return True

        try:
            ida_nalt.enum_import_names(i, cb)
        except Exception:
            continue

    return items


def spotlight_import_fingerprint(import_items: List[str]) -> str:
    s = ",".join(sorted(import_items))
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()


def _iter_section_norms_filtered() -> List[str]:
    out: List[str] = []
    try:
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(int(seg_ea))
            if not seg:
                continue
            name_raw = ida_segment.get_segm_name(seg) or ""
            name_norm = normalize_name(name_raw)
            if not name_norm:
                continue
            if name_norm in COMMON_SECTIONS:
                continue
            out.append(name_norm)
    except Exception:
        pass
    return out


def extract_sample_profile_for_kb() -> Dict[str, Any]:
    import_items = _iter_import_items_filtered()
    import_fingerprint = spotlight_import_fingerprint(import_items)

    # For overlap scoring
    dll_norms = sorted({x.split("!", 1)[0] for x in import_items if "!" in x})
    import_func_norms = sorted({x.split("!", 1)[1] for x in import_items if "!" in x})

    section_norms = sorted(set(_iter_section_norms_filtered()))

    return {
        "import_items": import_items,
        "import_fingerprint": import_fingerprint,
        "dll_norms": dll_norms,
        "import_func_norms": import_func_norms,
        "section_norms": section_norms,
    }


# ----------------------------------------------------------------------
# KB queries
# ----------------------------------------------------------------------

def kb_paths_by_import_fingerprint(fp: str) -> List[str]:
    fp = (fp or "").strip()
    if not fp:
        return []
    with kb_db_connect() as c:
        rows = c.execute(
            """
            SELECT path
            FROM idb
            WHERE import_fingerprint = ?
            ORDER BY path
            LIMIT ?
            """,
            (fp, KB_MAX_HITS + 1),
        ).fetchall()
        return [r["path"] for r in rows]


def kb_paths_by_section_norms(section_norms: List[str]) -> List[str]:
    section_norms = [s for s in (section_norms or []) if s]
    if not section_norms:
        return []
    qmarks = ",".join(["?"] * len(section_norms))
    with kb_db_connect() as c:
        rows = c.execute(
            f"""
            SELECT DISTINCT idb.path AS path
            FROM feat_section s
            JOIN idb ON idb.id = s.idb_id
            WHERE s.name_norm IN ({qmarks})
            ORDER BY path
            LIMIT ?
            """,
            (*section_norms, KB_MAX_HITS + 1),
        ).fetchall()
        return [r["path"] for r in rows]


def kb_paths_by_import_func_norms(import_func_norms: List[str]) -> List[str]:
    import_func_norms = [s for s in (import_func_norms or []) if s]
    if not import_func_norms:
        return []
    qmarks = ",".join(["?"] * len(import_func_norms))
    with kb_db_connect() as c:
        rows = c.execute(
            f"""
            SELECT DISTINCT idb.path AS path
            FROM feat_import_func f
            JOIN idb ON idb.id = f.idb_id
            WHERE f.func_norm IN ({qmarks})
            ORDER BY path
            LIMIT ?
            """,
            (*import_func_norms, KB_MAX_HITS + 1),
        ).fetchall()
        return [r["path"] for r in rows]


def kb_paths_for_function_name_raw(name_raw: str) -> List[str]:
    n = (name_raw or "").strip()
    if not n:
        return []
    if is_filtered_func(n, FUNC_FILTERS):
        return []
    nn = normalize_name(n)
    with kb_db_connect() as c:
        rows = c.execute(
            """
            SELECT DISTINCT idb.path AS path
            FROM func
            JOIN idb ON idb.id = func.idb_id
            WHERE func.name_norm = ?
            ORDER BY path
            LIMIT ?
            """,
            (nn, KB_MAX_HITS + 1),
        ).fetchall()
        return [r["path"] for r in rows]


# ----------------------------------------------------------------------
# Extraction
# ----------------------------------------------------------------------

def extract_calls(func_start_ea: int) -> List[str]:
    calls: List[str] = []
    for insn_ea in idautils.FuncItems(int(func_start_ea)):
        if not idaapi.is_call_insn(insn_ea):
            continue

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, insn_ea):
            continue

        try:
            target = int(idc.get_operand_value(insn_ea, 0))
        except Exception:
            target = 0

        name = ida_name.get_name(target) if target else ""
        if not name or name.startswith("?"):
            op = ida_ua.print_operand(insn_ea, 0)
            name = ida_lines.tag_remove(op) if op else ""

        name = sanitize_operand_name(name)
        if name:
            calls.append(name)

    return calls


def extract_strings_by_xrefs(func_start_ea: int) -> List[str]:
    # still used for local scoring
    strings = set()
    f = ida_funcs.get_func(int(func_start_ea))
    if not f:
        return []

    for insn_ea in idautils.FuncItems(int(f.start_ea)):
        try:
            refs = idautils.DataRefsFrom(insn_ea)
        except Exception:
            continue

        for ref in refs:
            try:
                if not ida_bytes.is_strlit(ida_bytes.get_full_flags(ref)):
                    continue
                raw = ida_bytes.get_strlit_contents(ref)
                if raw:
                    strings.add(raw.decode(errors="ignore"))
            except Exception:
                continue

    return list(strings)


# ----------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------

def init_func_result(start_ea: int, name: str, length: int) -> Dict[str, Any]:
    return {
        "ea": int(start_ea),
        "name": name or f"sub_{int(start_ea):x}",
        "length": int(length),

        "is_library": False,

        "base_score": 0.0,
        "context_bonus": 0.0,
        "final_score": 0.0,

        "category_hits": {c: 0 for c in CTX.categories},
        "reasons": [],
    }


def add_reason(res: Dict[str, Any], cat: str, text: str, weight: float):
    res["reasons"].append({"category": cat, "text": text, "weight": float(weight)})


def score_function_base(res: Dict[str, Any], calls: List[str], strings: List[str]):
    for cat, rules in CTX.signals.items():
        fn_map = rules.get("functions", {})
        for call in calls:
            if call in fn_map:
                w = fn_map[call]
                res["base_score"] += w
                res["category_hits"][cat] += 1
                add_reason(res, cat, f"Calls {call}", w)

    for cat, rules in CTX.signals.items():
        str_map = rules.get("strings", {})
        for s in strings:
            for pattern, w in str_map.items():
                if safe_regex_search(pattern, s):
                    res["base_score"] += w
                    res["category_hits"][cat] += 1
                    add_reason(res, cat, f"String matches /{pattern}/", w)

    res["final_score"] = res["base_score"]


def apply_library_penalty(res: Dict[str, Any]):
    if not res.get("is_library"):
        return
    res["base_score"] -= float(LIBRARY_SCORE_PENALTY)
    res["final_score"] -= float(LIBRARY_SCORE_PENALTY)
    add_reason(res, "Library", "Library function penalty", -float(LIBRARY_SCORE_PENALTY))


def apply_context_bonus(results: Dict[int, Dict[str, Any]]):
    base_scores = {ea: r["base_score"] for ea, r in results.items()}

    for ea, r in results.items():
        best_score = 0.0
        best_ea = None

        for insn_ea in idautils.FuncItems(int(ea)):
            if not idaapi.is_call_insn(insn_ea):
                continue

            try:
                tgt = int(idc.get_operand_value(insn_ea, 0))
            except Exception:
                tgt = 0

            callee = ida_funcs.get_func(tgt) if tgt else None
            if not callee:
                continue

            s = base_scores.get(int(callee.start_ea), 0.0)
            if s > best_score:
                best_score = s
                best_ea = int(callee.start_ea)

        if best_score >= 4.0 and best_ea is not None:
            bonus = best_score * float(CONTEXT_BONUS_FACTOR)
            r["context_bonus"] = bonus
            r["final_score"] += bonus
            add_reason(r, "Context", f"Adjacent to {ida_funcs.get_func_name(best_ea)}", bonus)


# ----------------------------------------------------------------------
# Priority tiers / Coloring
# ----------------------------------------------------------------------

def priority_color(priority: str) -> Optional[QtGui.QColor]:
    if priority == "critical":
        return QtGui.QColor(255, 90, 90)
    if priority == "high":
        return QtGui.QColor(255, 170, 70)
    if priority == "medium":
        return QtGui.QColor(255, 235, 120)
    return None


def compute_priority_tiers(rows_sorted: List[Dict[str, Any]]) -> Dict[int, str]:
    tiers: Dict[int, str] = {}
    positives = [
        r for r in rows_sorted
        if float(r.get("final_score", 0.0)) > 0.0 and not r.get("is_library", False)
    ]
    if not positives:
        return tiers

    m = len(positives)
    critical_n = max(1, int(math.ceil(0.10 * m)))
    high_n = max(1, int(math.ceil(0.30 * m)))

    critical_n = min(critical_n, m)
    high_n = min(max(high_n, critical_n), m)

    for i, r in enumerate(positives):
        ea = int(r["ea"])
        if i < critical_n:
            tiers[ea] = "critical"
        elif i < high_n:
            tiers[ea] = "high"
        else:
            tiers[ea] = "medium"

    return tiers


# ----------------------------------------------------------------------
# Inspector rendering
# ----------------------------------------------------------------------

def render_inspector(res: Dict[str, Any], priority_name: Optional[str] = None) -> str:
    lines = []
    lines.append(f"Function: {res.get('name','')}")
    lines.append(f"Start: {fmt_ea(res.get('ea', 0))}")
    lines.append(f"Length: {hex(int(res.get('length', 0)))} ({int(res.get('length', 0))})")
    lines.append(f"Library: {'yes' if res.get('is_library') else 'no'}")
    if priority_name is not None:
        lines.append(f"Priority: {priority_name}")
    lines.append("")
    lines.append(f"Base score: {float(res.get('base_score', 0.0)):.2f}")
    lines.append(f"Context bonus: {float(res.get('context_bonus', 0.0)):.2f}")
    lines.append(f"Final score: {float(res.get('final_score', 0.0)):.2f}")
    lines.append("")
    lines.append("Reasons:")

    reasons = res.get("reasons", [])
    if not reasons:
        lines.append("  (none)")
    else:
        for rr in sorted(reasons, key=lambda x: float(x.get("weight", 0.0)), reverse=True):
            lines.append(f"  - [{rr.get('category','')}] {rr.get('text','')}: {float(rr.get('weight',0.0)):+.2f}")

    return "\n".join(lines)


def render_kb_correlation_block(func_start: int, func_name: str, calls: List[str]) -> str:
    title = "Spotlight KB correlation"
    lines = [title, "-" * len(title)]
    db_path = kb_db_path()
    reason = kb_db_diagnose(db_path)

    if reason:
        lines.append("KB not ready:")
        lines.append(f"- {reason}")
        lines.append(f"Path: {db_path}")
        return "\n".join(lines)


    prof = extract_sample_profile_for_kb()

    # Strong: import_fingerprint
    fp = prof.get("import_fingerprint", "")
    strong_paths = kb_paths_by_import_fingerprint(fp) if fp else []
    if strong_paths:
        lines.append("Strong:")
        lines.append(f"- import_fingerprint match ({len(strong_paths)}):")
        for p in strong_paths[:10]:
            lines.append(f"  - {p}")
        if len(strong_paths) > 10:
            lines.append(f"  ... ({len(strong_paths) - 10} more)")
    else:
        lines.append("Strong:")
        lines.append("- (none)")

    # Medium: overlap by import funcs / sections
    import_func_norms = prof.get("import_func_norms", []) or []
    sec_norms = prof.get("section_norms", []) or []

    imp_paths = kb_paths_by_import_func_norms(import_func_norms[:200]) if import_func_norms else []
    sec_paths = kb_paths_by_section_norms(sec_norms[:100]) if sec_norms else []

    lines.append("")
    lines.append("Medium:")
    if imp_paths:
        lines.append(f"- imported function overlap (any) ({len(imp_paths)}):")
        for p in imp_paths[:10]:
            lines.append(f"  - {p}")
        if len(imp_paths) > 10:
            lines.append(f"  ... ({len(imp_paths) - 10} more)")
    else:
        lines.append("- imported function overlap: (none)")

    if sec_paths:
        lines.append(f"- section name overlap (any) ({len(sec_paths)}):")
        for p in sec_paths[:10]:
            lines.append(f"  - {p}")
        if len(sec_paths) > 10:
            lines.append(f"  ... ({len(sec_paths) - 10} more)")
    else:
        lines.append("- section name overlap: (none)")

    # Function name recall
    lines.append("")
    fn_paths = kb_paths_for_function_name_raw(func_name)
    lines.append(f"Function name recall: {func_name}")
    if fn_paths:
        for p in fn_paths[:10]:
            lines.append(f"- {p}")
        if len(fn_paths) > 10:
            lines.append(f"... ({len(fn_paths) - 10} more)")
    else:
        lines.append("(no matches)")

    # Callee recall
    lines.append("")
    lines.append("Callee recall:")
    callees = []
    seen = set()
    for c in calls:
        cc = (c or "").strip()
        if not cc:
            continue
        if is_filtered_func(cc, FUNC_FILTERS):
            continue
        if cc.lower() in seen:
            continue
        seen.add(cc.lower())
        callees.append(cc)

    if not callees:
        lines.append("(no callees)")
        return "\n".join(lines)

    # Show top N callees; for each show first few matching IDBs
    for callee in callees[:25]:
        paths = kb_paths_for_function_name_raw(callee)
        if not paths:
            continue
        lines.append(f"- {callee}:")
        for p in paths[:5]:
            lines.append(f"  - {p}")
        if len(paths) > 5:
            lines.append(f"  ... ({len(paths) - 5} more)")

    return "\n".join(lines)


# ----------------------------------------------------------------------
# Chunked scanner
# ----------------------------------------------------------------------

class ChunkedScanner(QtCore.QObject):
    progress = QtCore.Signal(int)
    finished = QtCore.Signal(str)

    def __init__(self, chunk_size=100):
        super().__init__()
        self.chunk_size = int(chunk_size)
        self.funcs = list(idautils.Functions())
        self.total = int(len(self.funcs))
        self.idx = 0
        self.results = {}
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.tick)
        self.t0 = 0.0

    def start(self):
        self.idx = 0
        self.results = {}
        self.t0 = time.time()
        self.progress.emit(0)
        self.timer.start(1)

    def tick(self):
        try:
            if self.total <= 0:
                self.timer.stop()
                CTX.results = {}
                CTX.last_scan_seconds = time.time() - self.t0
                self.progress.emit(100)
                self.finished.emit("")
                return

            processed = 0
            while processed < self.chunk_size and self.idx < self.total:
                ea = self.funcs[self.idx]
                self.idx += 1
                processed += 1

                f = ida_funcs.get_func(ea)
                if not f:
                    continue

                start = int(f.start_ea)
                end = int(f.end_ea)
                length = max(0, end - start)
                name = ida_funcs.get_func_name(start) or ida_name.get_name(start) or f"sub_{start:x}"

                res = init_func_result(start, name, length)

                try:
                    flags = idc.get_func_flags(start)
                    if flags & ida_funcs.FUNC_LIB:
                        res["is_library"] = True
                except Exception:
                    pass

                try:
                    calls = extract_calls(start)
                    strs = extract_strings_by_xrefs(start)
                    score_function_base(res, calls, strs)
                    apply_library_penalty(res)
                except Exception as e:
                    add_reason(res, "Error", f"Scan error: {e}", 0.0)

                self.results[start] = res

            if self.idx < self.total:
                pct = int((self.idx * 100) / self.total)
                self.progress.emit(min(pct, 99))
                return

            self.timer.stop()

            try:
                apply_context_bonus(self.results)
            except Exception as e:
                idaapi.msg(f"[IDA Spotlight] Context bonus failed: {e}\n")

            CTX.results = self.results
            CTX.last_scan_seconds = time.time() - self.t0
            self.progress.emit(100)
            self.finished.emit("")

        except Exception as fatal:
            self.timer.stop()
            idaapi.msg(f"[IDA Spotlight] Fatal scan error: {fatal}\n")
            self.progress.emit(100)
            self.finished.emit(str(fatal))


# ----------------------------------------------------------------------
# Globals
# ----------------------------------------------------------------------

VIEW_FORM = None
INSPECT_FORM = None
LAST_CODE_WIDGET = None


def ensure_inspect_view():
    global INSPECT_FORM
    if INSPECT_FORM is not None and qt_alive(getattr(INSPECT_FORM, "inspector", None)):
        return INSPECT_FORM
    INSPECT_FORM = SpotlightInspectForm()
    INSPECT_FORM.Show("IDA Spotlight Inspect")
    return INSPECT_FORM


# ----------------------------------------------------------------------
# Global UI hooks
# ----------------------------------------------------------------------

class SpotlightUIHooks(ida_kernwin.UI_Hooks):
    def screen_ea_changed(self, ea, *args):
        global LAST_CODE_WIDGET

        try:
            w = ida_kernwin.get_current_widget()
        except Exception:
            w = None

        if w is not None and is_code_widget(w):
            LAST_CODE_WIDGET = w

        if INSPECT_FORM is None:
            return
        if not qt_alive(getattr(INSPECT_FORM, "inspector", None)):
            return

        title = widget_title(w)
        INSPECT_FORM.on_screen_ea_changed(title, int(ea))


    def finish_populating_widget_popup(self, widget, popup, ctx):
        try:
            wtype = ida_kernwin.get_widget_type(widget)
        except Exception:
            return

        if wtype not in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            return

        ida_kernwin.attach_action_to_popup(widget, popup, "ida_spotlight:inspect_sync_here", "IDA Spotlight/")
        ida_kernwin.attach_action_to_popup(widget, popup, "ida_spotlight:view_open", "IDA Spotlight/")
        ida_kernwin.attach_action_to_popup(widget, popup, "ida_spotlight:inspect_open", "IDA Spotlight/")


UI_HOOKS = None


# ----------------------------------------------------------------------
# Inspect Form
# ----------------------------------------------------------------------

class SpotlightInspectForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self._sync_titles: List[str] = []
        self._pinned = False
        self._history: List[int] = []
        self._hist_idx: int = -1

        self.widget = None
        self.header = None
        self.inspector = None

    def OnCreate(self, form):
        self.widget = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout(self.widget)

        self.header = QtWidgets.QLabel("Not synced")
        f = self.header.font()
        f.setBold(True)
        self.header.setFont(f)
        layout.addWidget(self.header)

        self.inspector = QtWidgets.QPlainTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setPlainText("Use context menu in IDA View / Pseudocode to sync.\n")
        layout.addWidget(self.inspector, 1)

        self.inspector.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.inspector.customContextMenuRequested.connect(self.open_menu)

        self._update_header()

    def OnClose(self, form):
        global INSPECT_FORM
        INSPECT_FORM = None
        self._sync_titles = []
        self._history = []
        self._hist_idx = -1
        self.header = None
        self.inspector = None
        self.widget = None

    def _update_header(self):
        if self.header is None:
            return
        if not self._sync_titles:
            s = "Not synced"
        else:
            s = "Synced: " + ", ".join(self._sync_titles)
        if self._pinned:
            s += " (Pinned)"
        self.header.setText(s)

    def sync_with_titles(self, titles: List[str]):
        titles = [t for t in titles if t]

        ok = False
        for t in titles:
            if find_code_widget_by_title(t) is not None:
                ok = True
                break

        if not ok:
            ida_kernwin.warning("No matching code widgets found to sync.")
            return

        self._sync_titles = titles
        self._update_header()

        ea = ida_kernwin.get_screen_ea()
        self.update_for_ea(int(ea), push_history=True)

    def _sync_replace_current(self):
        w = ida_kernwin.get_current_widget()
        title = widget_title(w)
        if not title:
            return
        self.sync_with_titles([title])

    def unsync(self):
        self._sync_titles = []
        self._update_header()

    def toggle_pin(self):
        self._pinned = not self._pinned
        self._update_header()

    def history_back(self):
        if self._hist_idx > 0:
            self._hist_idx -= 1
            ea = self._history[self._hist_idx]
            self.update_for_ea(ea, push_history=False)

    def history_forward(self):
        if self._hist_idx + 1 < len(self._history):
            self._hist_idx += 1
            ea = self._history[self._hist_idx]
            self.update_for_ea(ea, push_history=False)


    def open_menu(self, pos):
        menu = QtWidgets.QMenu(self.inspector)

        act_unsync = QtGui.QAction("Unsync", self.inspector)
        act_unsync.triggered.connect(self.unsync)
        menu.addAction(act_unsync)

        menu.addSeparator()

        act_pin = QtGui.QAction("Pin / Unpin", self.inspector)
        act_pin.triggered.connect(self.toggle_pin)
        menu.addAction(act_pin)

        menu.addSeparator()

        act_back = QtGui.QAction("Back", self.inspector)
        act_back.triggered.connect(self.history_back)
        menu.addAction(act_back)

        act_fwd = QtGui.QAction("Forward", self.inspector)
        act_fwd.triggered.connect(self.history_forward)
        menu.addAction(act_fwd)

        menu.exec_(self.inspector.mapToGlobal(pos))


    def on_screen_ea_changed(self, title: str, ea: int):
        if self._pinned:
            return

        if title not in self._sync_titles:
            return

        self.update_for_ea(ea, push_history=True)

    def _push_history(self, start_ea: int):
        if self._hist_idx >= 0 and self._history and self._history[self._hist_idx] == start_ea:
            return
        if self._hist_idx < len(self._history) - 1:
            self._history = self._history[: self._hist_idx + 1]
        self._history.append(start_ea)
        self._hist_idx = len(self._history) - 1

    def update_for_ea(self, ea: int, push_history: bool):
        if not qt_alive(self.inspector):
            return

        start = func_start_from_any_ea(ea)
        if start is None:
            self.inspector.setPlainText("No function at cursor.")
            return

        res = CTX.results.get(start)
        if not res:
            self.inspector.setPlainText(f"Function {fmt_ea(start)} not scored.\nRun Scan in IDA Spotlight View.")
            return

        rows_all = sorted(
            list(CTX.results.values()),
            key=lambda r: (-float(r.get("final_score", 0.0)), int(r.get("length", 0)))
        )
        tiers = compute_priority_tiers(rows_all)
        pr = tiers.get(start, "low")

        # KB correlation + then function info
        func_name = res.get("name", "") or ""
        calls = extract_calls(int(start))
        kb_block = render_kb_correlation_block(int(start), func_name, calls)

        text = kb_block + "\n\n" + render_inspector(res, priority_name=pr)
        self.inspector.setPlainText(text)

        if push_history:
            self._push_history(start)


# ----------------------------------------------------------------------
# KB Settings dialog (DB path only)
# ----------------------------------------------------------------------

class SpotlightKBSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("IDA Spotlight – KB Settings")
        self.setMinimumWidth(650)

        # empty => default path (same as indexer)
        cur = (kb_get_setting("db_path", "") or "").strip()
        self.db_edit = QtWidgets.QLineEdit(cur)
        self.db_edit.setPlaceholderText(default_kb_db_path())

        form = QtWidgets.QFormLayout()
        form.addRow("KB database (SQLite):", self.db_edit)

        btn_ok = QtWidgets.QPushButton("OK")
        btn_ok.clicked.connect(self.accept)

        btn_cancel = QtWidgets.QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)

        btns = QtWidgets.QHBoxLayout()
        btns.addStretch()
        btns.addWidget(btn_ok)
        btns.addWidget(btn_cancel)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(btns)

    def accept(self):
        kb_set_setting("db_path", (self.db_edit.text() or "").strip())
        super().accept()


# ----------------------------------------------------------------------
# View Table widget
# ----------------------------------------------------------------------

class SpotlightTableWidget(QtWidgets.QTableWidget):
    enter_pressed = QtCore.Signal()

    def keyPressEvent(self, event):
        if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
            self.enter_pressed.emit()
            return
        super().keyPressEvent(event)


# ----------------------------------------------------------------------
# View Form
# ----------------------------------------------------------------------

class SpotlightViewForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self._rows: List[Dict[str, Any]] = []
        self._tiers: Dict[int, str] = {}
        self._hide_low_priority: bool = True
        self._hide_library: bool = True

    def OnCreate(self, form):
        self.widget = self.FormToPyQtWidget(form)
        root = QtWidgets.QVBoxLayout(self.widget)

        top = QtWidgets.QHBoxLayout()

        self.btn_scan = QtWidgets.QPushButton("Scan")
        self.btn_scan.clicked.connect(self.start_scan)
        top.addWidget(self.btn_scan)

        self.btn_export = QtWidgets.QPushButton("Export…")
        self.btn_export.clicked.connect(self.export_dialog)
        top.addWidget(self.btn_export)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        top.addWidget(self.progress, 1)

        self.lbl_status = QtWidgets.QLabel("Ready")
        top.addWidget(self.lbl_status)

        root.addLayout(top)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        root.addWidget(splitter, 1)

        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.table = SpotlightTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Function", "Start", "Length", "Score", "Top reason", "Categories"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.table_menu)
        self.table.itemSelectionChanged.connect(self.on_row_selected)
        self.table.doubleClicked.connect(self.on_double_click)
        self.table.enter_pressed.connect(self.jump_selected)
        left_layout.addWidget(self.table, 1)

        self.table.setColumnWidth(0, 240)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 80)
        self.table.setColumnWidth(4, 260)
        self.table.setColumnWidth(5, 220)
        self.table.horizontalHeader().setStretchLastSection(True)

        sb = QtWidgets.QHBoxLayout()
        sb.addWidget(QtWidgets.QLabel("Search:"))
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Filter by function name (substring)…")
        self.search_edit.textChanged.connect(self.populate)
        sb.addWidget(self.search_edit, 1)
        left_layout.addLayout(sb)

        splitter.addWidget(left)

        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)

        title = QtWidgets.QLabel("Inspector")
        f = title.font()
        f.setBold(True)
        title.setFont(f)
        right_layout.addWidget(title)

        self.inspector = QtWidgets.QPlainTextEdit()
        self.inspector.setReadOnly(True)
        self.inspector.setPlainText("Select a function to see details.")
        right_layout.addWidget(self.inspector, 1)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

    def start_scan(self):
        if not CTX.signals:
            ida_kernwin.warning("IDA Spotlight: signals.json not loaded.")
            return

        self.btn_scan.setEnabled(False)
        self.progress.setValue(0)
        self.lbl_status.setText("Scanning…")
        self.inspector.setPlainText("Scanning…")

        self.scanner = ChunkedScanner(chunk_size=100)
        self.scanner.progress.connect(self.progress.setValue)
        self.scanner.finished.connect(self.scan_done)
        self.scanner.start()

    def scan_done(self, err: str):
        self.btn_scan.setEnabled(True)
        if err:
            self.lbl_status.setText("Error")
            self.inspector.setPlainText(f"Scan failed:\n{err}")
            return
        self.lbl_status.setText(f"Done in {CTX.last_scan_seconds:.1f}s")
        self.populate()

    def _get_rows(self) -> List[Dict[str, Any]]:
        rows = list(CTX.results.values())
        rows.sort(key=lambda r: (-float(r.get("final_score", 0.0)), int(r.get("length", 0))))

        if self._hide_low_priority:
            rows = [r for r in rows if float(r.get("final_score", 0.0)) > 0.0]

        if self._hide_library:
            rows = [r for r in rows if not r.get("is_library", False)]

        q = (self.search_edit.text() or "").strip().lower()
        if q:
            rows = [r for r in rows if q in (r.get("name", "").lower())]

        return rows

    def populate(self):
        rows = self._get_rows()
        tiers = compute_priority_tiers(rows)

        self._rows = rows
        self._tiers = tiers

        self.table.setRowCount(len(rows))

        for i, r in enumerate(rows):
            ea = int(r["ea"])
            length = int(r.get("length", 0))
            score = float(r.get("final_score", 0.0))

            if r.get("is_library", False):
                color = LIBRARY_ROW_COLOR
            else:
                pr = tiers.get(ea, "low")
                color = priority_color(pr)

            it_fn = QtWidgets.QTableWidgetItem(r.get("name", ""))
            it_fn.setToolTip(r.get("name", ""))

            it_start = QtWidgets.QTableWidgetItem(fmt_ea(ea))
            it_len = QtWidgets.QTableWidgetItem(hex(length))
            it_score = QtWidgets.QTableWidgetItem(f"{score:.2f}")
            it_reason = QtWidgets.QTableWidgetItem(top_reason_str(r))
            it_cats = QtWidgets.QTableWidgetItem(categories_str(r))

            items = [it_fn, it_start, it_len, it_score, it_reason, it_cats]
            for col, it in enumerate(items):
                it.setData(QtCore.Qt.UserRole, ea)
                if color is not None:
                    it.setBackground(QtGui.QBrush(color))
                self.table.setItem(i, col, it)

        self.inspector.setPlainText("No results." if not rows else "Select a function to see details.")

    def _selected_start_ea(self) -> Optional[int]:
        row = self.table.currentRow()
        if row < 0:
            return None
        it = self.table.item(row, 0)
        if not it:
            return None
        ea = it.data(QtCore.Qt.UserRole)
        try:
            return int(ea)
        except Exception:
            return None

    def on_row_selected(self):
        start_ea = self._selected_start_ea()
        if start_ea is None:
            return
        res = CTX.results.get(start_ea)
        if not res:
            return
        pr = self._tiers.get(start_ea, "low")
        self.inspector.setPlainText(render_inspector(res, priority_name=pr))

    def jump_selected(self):
        start_ea = self._selected_start_ea()
        if start_ea is None:
            return
        ida_kernwin.jumpto(start_ea)

    def inspect_here(self):
        start_ea = self._selected_start_ea()
        if start_ea is None:
            return
        ensure_inspect_view().update_for_ea(start_ea, push_history=True)

    def on_double_click(self, idx):
        self.jump_selected()

    def _current_cell_text(self) -> str:
        r = self.table.currentRow()
        c = self.table.currentColumn()
        it = self.table.item(r, c) if (r >= 0 and c >= 0) else None
        return it.text() if it else ""

    def _current_row_text(self, row: int) -> str:
        return "\t".join(
            (self.table.item(row, c).text() if self.table.item(row, c) else "")
            for c in range(self.table.columnCount())
        )

    def _selected_rows_text(self) -> str:
        rows = sorted({idx.row() for idx in self.table.selectionModel().selectedRows()})
        return "\n".join(self._current_row_text(r) for r in rows)

    def table_menu(self, pos):
        menu = QtWidgets.QMenu()

        act_hide_low = menu.addAction("Hide Low Priority")
        act_hide_low.setCheckable(True)
        act_hide_low.setChecked(self._hide_low_priority)

        act_hide_lib = menu.addAction("Hide Library Functions")
        act_hide_lib.setCheckable(True)
        act_hide_lib.setChecked(self._hide_library)

        act_inspect_here = menu.addAction("Inspect here")

        menu.addSeparator()

        copy_menu = menu.addMenu("Copy")
        act_copy_cell = copy_menu.addAction("Copy cell")
        act_copy_row = copy_menu.addAction("Copy row")
        act_copy_rows = copy_menu.addAction("Copy selected rows")

        menu.addSeparator()

        act_jump = menu.addAction("Jump to function")

        menu.addSeparator()

        export_menu = menu.addMenu("Export")
        act_export_csv = export_menu.addAction("Export CSV…")
        act_export_json = export_menu.addAction("Export JSON…")

        act = menu.exec_(self.table.mapToGlobal(pos))
        if not act:
            return

        if act == act_hide_low:
            self._hide_low_priority = not self._hide_low_priority
            self.populate()
            return

        if act == act_hide_lib:
            self._hide_library = not self._hide_library
            self.populate()
            return

        if act == act_inspect_here:
            self.inspect_here()
            return

        if act == act_copy_cell:
            QtWidgets.QApplication.clipboard().setText(self._current_cell_text())
            return

        if act == act_copy_row:
            r = self.table.currentRow()
            if r >= 0:
                QtWidgets.QApplication.clipboard().setText(self._current_row_text(r))
            return

        if act == act_copy_rows:
            txt = self._selected_rows_text()
            if txt:
                QtWidgets.QApplication.clipboard().setText(txt)
            return

        if act == act_jump:
            self.jump_selected()
            return

        if act == act_export_csv:
            self.export_csv()
            return

        if act == act_export_json:
            self.export_json()
            return

    def export_dialog(self):
        menu = QtWidgets.QMenu()
        act_csv = menu.addAction("Export CSV…")
        act_json = menu.addAction("Export JSON…")
        act = menu.exec_(QtGui.QCursor.pos())
        if act == act_csv:
            self.export_csv()
        elif act == act_json:
            self.export_json()

    def export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self.widget, "Export CSV", "", "CSV (*.csv)")
        if not path:
            return

        rows = self._rows if self._rows is not None else self._get_rows()
        tiers = compute_priority_tiers(rows)

        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Function", "Start", "Length", "Score", "Priority", "Library", "Top reason", "Categories"])
            for r in rows:
                ea = int(r["ea"])
                w.writerow([
                    r.get("name", ""),
                    fmt_ea(ea),
                    hex(int(r.get("length", 0))),
                    f"{float(r.get('final_score', 0.0)):.2f}",
                    tiers.get(ea, "low"),
                    "yes" if r.get("is_library") else "no",
                    top_reason_str(r),
                    categories_str(r),
                ])

    def export_json(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self.widget, "Export JSON", "", "JSON (*.json)")
        if not path:
            return

        rows = self._rows if self._rows is not None else self._get_rows()
        tiers = compute_priority_tiers(rows)

        out = []
        for r in rows:
            ea = int(r["ea"])
            out.append({
                "name": r.get("name", ""),
                "start_ea": ea,
                "start_ea_hex": fmt_ea(ea),
                "length": int(r.get("length", 0)),
                "length_hex": hex(int(r.get("length", 0))),
                "is_library": bool(r.get("is_library", False)),
                "base_score": float(r.get("base_score", 0.0)),
                "context_bonus": float(r.get("context_bonus", 0.0)),
                "final_score": float(r.get("final_score", 0.0)),
                "priority": tiers.get(ea, "low"),
                "top_reason": top_reason_str(r),
                "categories": [k for k, v in r.get("category_hits", {}).items() if v],
                "reasons": list(r.get("reasons", [])),
            })

        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)


# ----------------------------------------------------------------------
# Actions / Plugin glue
# ----------------------------------------------------------------------

class OpenViewHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global VIEW_FORM
        if VIEW_FORM is None:
            VIEW_FORM = SpotlightViewForm()
        VIEW_FORM.Show("IDA Spotlight View")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class OpenInspectHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        ensure_inspect_view()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class InspectSyncHereHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        insp = ensure_inspect_view()
        try:
            w = ida_kernwin.get_current_widget()
        except Exception:
            w = None
        title = widget_title(w) if w is not None else ""
        titles = _paired_view_titles(title)
        insp.sync_with_titles(titles)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class KBConfigureHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        dlg = SpotlightKBSettingsDialog(get_qt_parent())
        dlg.exec_()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class IDASpotlightPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "IDA Spotlight"

    def init(self):
        global UI_HOOKS

        try:
            CTX.signals = SIGNALS
            CTX.categories = sorted(SIGNALS.keys())

            idaapi.msg(f"[IDA Spotlight] Loaded signals.json (categories={len(CTX.categories)})\n")
        except Exception as e:
            CTX.signals, CTX.categories = {}, []
            ida_kernwin.warning(f"IDA Spotlight: failed to load signals.json: {e}")

        try:
            ida_kernwin.create_menu("IDASpotlightMenu", "IDA Spotlight", "View/Open subviews/Strings")
        except Exception:
            ida_kernwin.warning("IDA Spotlight: failed to create IDASpotlightMenu")

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "ida_spotlight:view",
                "IDA Spotlight View",
                OpenViewHandler(),
                None
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "ida_spotlight:inspect",
                "IDA Spotlight Inspect",
                OpenInspectHandler(),
                None
            )
        )

        # Popup actions (no submenu complexity in popup itself; IDA still groups by path)
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "ida_spotlight:inspect_sync_here",
                "Sync IDA Spotlight Inspect to this view",
                InspectSyncHereHandler(),
                None,
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "ida_spotlight:view_open",
                "IDA Spotlight View",
                OpenViewHandler(),
                None,
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "ida_spotlight:inspect_open",
                "IDA Spotlight Inspect",
                OpenInspectHandler(),
                None,
            )
        )

        # Menu action: now opens config dialog (DB path only)
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "ida_spotlight:kb_configure",
                "Configure Spotlight KB",
                KBConfigureHandler(),
                None,
            )
        )

        ida_kernwin.attach_action_to_menu(
            "View/Open subviews/IDA Spotlight/",
            "ida_spotlight:kb_configure",
            ida_kernwin.SETMENU_APP
        )
        ida_kernwin.attach_action_to_menu(
            "View/Open subviews/IDA Spotlight/",
            "ida_spotlight:view",
            ida_kernwin.SETMENU_APP
        )
        ida_kernwin.attach_action_to_menu(
            "View/Open subviews/IDA Spotlight/",
            "ida_spotlight:inspect",
            ida_kernwin.SETMENU_APP
        )

        if UI_HOOKS is None:
            UI_HOOKS = SpotlightUIHooks()
            UI_HOOKS.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        OpenViewHandler().activate(None)

    def term(self):
        global UI_HOOKS
        if UI_HOOKS is not None:
            try:
                UI_HOOKS.unhook()
            except Exception:
                pass
            UI_HOOKS = None


def PLUGIN_ENTRY():
    return IDASpotlightPlugin()
