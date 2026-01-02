# SPDX-License-Identifier: Apache-2.0
"""
Function scanning and scoring logic for IDA Spotlight.

This module contains the core analysis logic including:
- Function call and string extraction
- Base scoring against signal patterns
- Context bonus calculation
- Priority tier computation
- Inspector rendering
"""

import math
import time
from typing import Any, Callable, Dict, List, Optional

import idaapi
import idautils
import ida_funcs
import ida_name
import ida_ua
import ida_lines
import ida_bytes
import idc

from PySide6 import QtCore

from spotlight_utils import fmt_ea, safe_regex_search, sanitize_operand_name, is_filtered_func
from spotlight_config import (
    SIGNALS,
    IGNORED_FUNCTIONS,
    CONTEXT_BONUS_FACTOR,
    LIBRARY_SCORE_PENALTY,
    KB_LIMIT_NAME_RECALL,
    KB_LIMIT_CALLEE_RECALL_PER_CALLEE,
    KB_LIMIT_CALLEE_RECALL_MAX_CALLEES,
)
from spotlight_kb import (
    kb_db_ready,
    kb_db_path,
    kb_db_diagnose,
    kb_paths_for_function_name_raw,
)


__all__ = [
    # Global context
    "SpotlightContext",
    "CTX",
    # Extraction
    "extract_calls",
    "extract_strings_by_xrefs",
    # Result helpers
    "init_func_result",
    "add_reason",
    "top_reason_str",
    "categories_str",
    # Scoring
    "score_function_base",
    "apply_library_penalty",
    "apply_context_bonus",
    # Priority tiers
    "PRIORITY_CRITICAL_PERCENT",
    "PRIORITY_HIGH_PERCENT",
    "compute_priority_tiers",
    # Inspector rendering
    "render_inspector",
    "render_function_recall",
    # Scanner
    "ChunkedScanner",
]


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

# Minimum score threshold for context bonus
CONTEXT_BONUS_THRESHOLD: float = 4.0

# Priority tier percentages
PRIORITY_CRITICAL_PERCENT: float = 0.10
PRIORITY_HIGH_PERCENT: float = 0.30


# ----------------------------------------------------------------------
# Global Scanning Context
# ----------------------------------------------------------------------

class SpotlightContext:
    """
    Global context for storing scanning results and configuration.

    Attributes:
        signals: The signal patterns loaded from configuration.
        categories: Sorted list of signal category names.
        results: Dictionary mapping function EAs to their analysis results.
        last_scan_seconds: Time taken by the last scan operation.
    """

    def __init__(self) -> None:
        """Initialize the context with empty values."""
        self.signals: Dict[str, Dict[str, Dict[str, float]]] = {}
        self.categories: List[str] = []
        self.results: Dict[int, Dict[str, Any]] = {}
        self.last_scan_seconds: float = 0.0


# Global context instance
CTX = SpotlightContext()
CTX.signals = SIGNALS
CTX.categories = sorted(SIGNALS.keys())


# ----------------------------------------------------------------------
# Extraction Functions
# ----------------------------------------------------------------------

def extract_calls(func_start_ea: int) -> List[str]:
    """
    Extract all function calls from a function.

    Args:
        func_start_ea: The start address of the function.

    Returns:
        A list of callee names.
    """
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
            operand = ida_ua.print_operand(insn_ea, 0)
            name = ida_lines.tag_remove(operand) if operand else ""

        name = sanitize_operand_name(name)

        if name:
            calls.append(name)

    return calls


def extract_strings_by_xrefs(func_start_ea: int) -> List[str]:
    """
    Extract all strings referenced by a function via cross-references.

    Args:
        func_start_ea: The start address of the function.

    Returns:
        A list of string literals referenced by the function.
    """
    strings: set[str] = set()
    func = ida_funcs.get_func(int(func_start_ea))
    if not func:
        return []

    for insn_ea in idautils.FuncItems(int(func.start_ea)):
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
# Result Helpers
# ----------------------------------------------------------------------

def init_func_result(start_ea: int, name: str, length: int) -> Dict[str, Any]:
    """
    Initialize a function analysis result dictionary.

    Args:
        start_ea: The function start address.
        name: The function name.
        length: The function length in bytes.

    Returns:
        A dictionary with initialized result fields.
    """
    return {
        "ea": int(start_ea),
        "name": name or f"sub_{int(start_ea):x}",
        "length": int(length),
        "is_library": False,
        "base_score": 0.0,
        "context_bonus": 0.0,
        "final_score": 0.0,
        "category_hits": {category: 0 for category in CTX.categories},
        "reasons": [],
    }


def add_reason(result: Dict[str, Any], category: str, text: str, weight: float) -> None:
    """
    Add a scoring reason to a function result.

    Args:
        result: The function result dictionary.
        category: The category name.
        text: The descriptive text for the reason.
        weight: The score contribution.
    """
    result["reasons"].append({
        "category": category,
        "text": text,
        "weight": float(weight),
    })


def top_reason_str(result: Dict[str, Any]) -> str:
    """
    Get the highest-weighted reason as a string.

    Args:
        result: The function result dictionary.

    Returns:
        The text of the top reason, or empty string.
    """
    reasons = result.get("reasons", [])
    if not reasons:
        return ""
    try:
        top = max(reasons, key=lambda x: float(x.get("weight", 0.0)))
        return top.get("text", "")
    except Exception:
        return ""


def categories_str(result: Dict[str, Any]) -> str:
    """
    Get a comma-separated string of hit categories.

    Args:
        result: The function result dictionary.

    Returns:
        A sorted, comma-separated list of category names with hits.
    """
    categories = [key for key, value in result.get("category_hits", {}).items() if value]
    categories.sort()
    return ", ".join(categories)


# ----------------------------------------------------------------------
# Scoring Functions
# ----------------------------------------------------------------------

def score_function_base(
    result: Dict[str, Any],
    calls: List[str],
    strings: List[str],
) -> None:
    """
    Calculate the base score for a function based on calls and strings.

    Matches calls and strings against the configured signal patterns
    and updates the result dictionary with scores and reasons.

    Args:
        result: The function result dictionary (modified in place).
        calls: List of function calls.
        strings: List of string references.
    """
    # Score function calls
    for category, rules in CTX.signals.items():
        function_map = rules.get("functions", {})
        for call in calls:
            if call in function_map:
                weight = function_map[call]
                result["base_score"] += weight
                result["category_hits"][category] += 1
                add_reason(result, category, f"Calls {call}", weight)

    # Score string references
    for category, rules in CTX.signals.items():
        string_map = rules.get("strings", {})
        for string in strings:
            for pattern, weight in string_map.items():
                if safe_regex_search(pattern, string):
                    result["base_score"] += weight
                    result["category_hits"][category] += 1
                    add_reason(result, category, f"String matches /{pattern}/", weight)

    result["final_score"] = result["base_score"]


def apply_library_penalty(result: Dict[str, Any]) -> None:
    """
    Apply a score penalty to library functions.

    Args:
        result: The function result dictionary (modified in place).
    """
    if not result.get("is_library"):
        return
    penalty = float(LIBRARY_SCORE_PENALTY)
    result["base_score"] -= penalty
    result["final_score"] -= penalty
    add_reason(result, "Library", "Library function penalty", -penalty)


def apply_context_bonus(results: Dict[int, Dict[str, Any]]) -> None:
    """
    Apply context bonuses based on calls to high-scoring functions.

    Functions that call high-scoring functions receive a bonus
    proportional to the callee's score.

    Args:
        results: Dictionary of all function results (modified in place).
    """
    base_scores = {ea: r["base_score"] for ea, r in results.items()}

    for ea, result in results.items():
        best_score = 0.0
        best_ea: Optional[int] = None

        for insn_ea in idautils.FuncItems(int(ea)):
            if not idaapi.is_call_insn(insn_ea):
                continue

            try:
                target = int(idc.get_operand_value(insn_ea, 0))
            except Exception:
                target = 0

            callee = ida_funcs.get_func(target) if target else None
            if not callee:
                continue

            score = base_scores.get(int(callee.start_ea), 0.0)
            if score > best_score:
                best_score = score
                best_ea = int(callee.start_ea)

        if best_score >= CONTEXT_BONUS_THRESHOLD and best_ea is not None:
            bonus = best_score * float(CONTEXT_BONUS_FACTOR)
            result["context_bonus"] = bonus
            result["final_score"] += bonus
            callee_name = ida_funcs.get_func_name(best_ea)
            add_reason(result, "Context", f"Adjacent to {callee_name}", bonus)


# ----------------------------------------------------------------------
# Priority Tiers
# ----------------------------------------------------------------------

def compute_priority_tiers(rows_sorted: List[Dict[str, Any]]) -> Dict[int, str]:
    """
    Compute priority tiers for functions based on their scores.

    Assigns critical/high/medium tiers to functions with positive scores.

    Args:
        rows_sorted: List of function results, sorted by score descending.

    Returns:
        A dictionary mapping function EAs to priority tier names.
    """
    tiers: Dict[int, str] = {}
    positives = [
        r for r in rows_sorted
        if float(r.get("final_score", 0.0)) > 0.0 and not r.get("is_library", False)
    ]
    if not positives:
        return tiers

    total = len(positives)
    critical_count = max(1, int(math.ceil(PRIORITY_CRITICAL_PERCENT * total)))
    high_count = max(1, int(math.ceil(PRIORITY_HIGH_PERCENT * total)))

    critical_count = min(critical_count, total)
    high_count = min(max(high_count, critical_count), total)

    for index, result in enumerate(positives):
        ea = int(result["ea"])
        if index < critical_count:
            tiers[ea] = "critical"
        elif index < high_count:
            tiers[ea] = "high"
        else:
            tiers[ea] = "medium"

    return tiers


# ----------------------------------------------------------------------
# Inspector Rendering
# ----------------------------------------------------------------------

def render_inspector(result: Dict[str, Any], priority_name: Optional[str] = None) -> str:
    """
    Render the inspector panel content for a function.

    Args:
        result: The function result dictionary.
        priority_name: Optional priority tier name.

    Returns:
        A formatted string for display in the inspector panel.
    """
    lines: List[str] = []
    lines.append(f"Function: {result.get('name', '')}")
    lines.append(f"Start: {fmt_ea(result.get('ea', 0))}")

    length = int(result.get("length", 0))
    lines.append(f"Length: {hex(length)} ({length})")
    lines.append(f"Library: {'yes' if result.get('is_library') else 'no'}")

    if priority_name is not None:
        lines.append(f"Priority: {priority_name}")
    lines.append("")

    lines.append(f"Base score: {float(result.get('base_score', 0.0)):.2f}")
    lines.append(f"Context bonus: {float(result.get('context_bonus', 0.0)):.2f}")
    lines.append(f"Final score: {float(result.get('final_score', 0.0)):.2f}")
    lines.append("")

    calls = result.get("calls", [])
    recall = render_function_recall(result["name"], calls)

    if recall:
        lines.append(recall)
        lines.append("")

    return "\n".join(lines)


def render_function_recall(func_name: str, calls: List[str]) -> str:
    """
    Render KB recall information for a function.

    Shows which other IDBs contain similar function names or callees.

    Args:
        func_name: The function name.
        calls: List of callee names.

    Returns:
        A formatted string showing KB recall matches.
    """
    lines: List[str] = []

    if not kb_db_ready():
        reason = kb_db_diagnose(kb_db_path())
        lines.append("KB not ready")
        if reason:
            lines.append(f"Reason: {reason}")
        lines.append(f"Path: {kb_db_path()}")
        return "\n".join(lines)

    # Function name recall
    func_paths = kb_paths_for_function_name_raw(func_name)
    if func_paths:
        lines.append("Function name recall:")
        for path in func_paths[:KB_LIMIT_NAME_RECALL]:
            lines.append(f"- {path}")

    # Callee recall - deduplicate and filter
    unique_callees: List[str] = []
    seen: set[str] = set()
    for callee in calls:
        if not callee or is_filtered_func(callee, IGNORED_FUNCTIONS):
            continue
        callee_lower = callee.lower()
        if callee_lower in seen:
            continue
        seen.add(callee_lower)
        unique_callees.append(callee)

    if unique_callees:
        lines.append("")
        lines.append("Callee recall:")
        for callee in unique_callees[:KB_LIMIT_CALLEE_RECALL_MAX_CALLEES]:
            paths = kb_paths_for_function_name_raw(callee)
            if not paths:
                continue
            lines.append(f"- {callee}:")
            for path in paths[:KB_LIMIT_CALLEE_RECALL_PER_CALLEE]:
                lines.append(f"  - {path}")

    return "\n".join(lines)


# ----------------------------------------------------------------------
# Chunked Scanner
# ----------------------------------------------------------------------

class ChunkedScanner(QtCore.QObject):
    """
    A Qt-based scanner that processes functions in chunks.

    This allows the UI to remain responsive during scanning by
    processing functions in batches with timer-based scheduling.

    Signals:
        progress: Emits progress percentage (0-100).
        finished: Emits an error string (empty on success).
    """

    progress = QtCore.Signal(int)
    finished = QtCore.Signal(str)

    def __init__(self, chunk_size: int = 100) -> None:
        """
        Initialize the scanner.

        Args:
            chunk_size: Number of functions to process per tick.
        """
        super().__init__()
        self._chunk_size = int(chunk_size)
        self._funcs: List[int] = list(idautils.Functions())
        self._total = len(self._funcs)
        self._index = 0
        self._results: Dict[int, Dict[str, Any]] = {}
        self._timer = QtCore.QTimer()
        self._timer.timeout.connect(self._tick)
        self._start_time = 0.0

    def start(self) -> None:
        """Start the scanning process."""
        self._index = 0
        self._results = {}
        self._start_time = time.time()
        self.progress.emit(0)
        self._timer.start(1)

    def _tick(self) -> None:
        """Process one chunk of functions."""
        try:
            if self._total <= 0:
                self._finish_scan()
                return

            processed = 0
            while processed < self._chunk_size and self._index < self._total:
                ea = self._funcs[self._index]
                self._index += 1
                processed += 1

                func = ida_funcs.get_func(ea)
                if not func:
                    continue

                start = int(func.start_ea)
                end = int(func.end_ea)
                length = max(0, end - start)
                name = (
                    ida_funcs.get_func_name(start)
                    or ida_name.get_name(start)
                    or f"sub_{start:x}"
                )

                result = init_func_result(start, name, length)

                # Check library flag
                try:
                    flags = idc.get_func_flags(start)
                    if flags & ida_funcs.FUNC_LIB:
                        result["is_library"] = True
                except Exception:
                    pass

                # Score the function
                try:
                    calls = extract_calls(start)
                    result["calls"] = calls
                    strings = extract_strings_by_xrefs(start)
                    score_function_base(result, calls, strings)
                    apply_library_penalty(result)
                except Exception as e:
                    add_reason(result, "Error", f"Scan error: {e}", 0.0)

                self._results[start] = result

            if self._index < self._total:
                percent = int((self._index * 100) / self._total)
                self.progress.emit(min(percent, 99))
                return

            self._finish_scan()

        except Exception as fatal:
            self._timer.stop()
            idaapi.msg(f"[IDA Spotlight] Fatal scan error: {fatal}\n")
            self.progress.emit(100)
            self.finished.emit(str(fatal))

    def _finish_scan(self) -> None:
        """Finalize the scan and emit results."""
        self._timer.stop()

        if self._total > 0:
            try:
                apply_context_bonus(self._results)
            except Exception as e:
                idaapi.msg(f"[IDA Spotlight] Context bonus failed: {e}\n")

        CTX.results = self._results
        CTX.last_scan_seconds = time.time() - self._start_time
        self.progress.emit(100)
        self.finished.emit("")
