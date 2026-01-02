# SPDX-License-Identifier: Apache-2.0
"""
Utility functions for IDA Spotlight.

This module provides common helper functions including:
- Qt widget validation helpers
- Address formatting utilities
- Regex pattern matching
- String sanitization
- Function lookups
- Widget introspection
- Normalization helpers
- Fingerprint helpers
- IDB collection helpers
"""

import hashlib
import os
import re
from typing import Iterable, List, Optional, Pattern, Set, Tuple

import ida_funcs
import ida_kernwin

import shiboken6


__all__ = [
    # Normalization
    "normalize_name",
    "normalize_dll_name",
    # Fingerprinting
    "fingerprint_md5",
    "build_import_items",
    # Filters
    "is_filtered_func",
    # IDB collection
    "collect_import_modules",
    "iter_segments",
    # Qt helpers
    "qt_alive",
    "get_qt_parent",
    # Address formatting
    "fmt_ea",
    # Pattern matching
    "safe_regex_search",
    # String processing
    "sanitize_operand_name",
    # Function lookups
    "func_start_from_any_ea",
    # Widget introspection
    "is_code_widget",
    "widget_title",
    "extract_view_letter_from_title",
    "paired_view_titles",
    "find_code_widget_by_title",
]


# ----------------------------------------------------------------------
# Normalization helpers
# ----------------------------------------------------------------------

def normalize_name(name: str) -> str:
    """
    Normalize a name to lowercase for comparison.

    Args:
        name: The name string to normalize.

    Returns:
        The normalized lowercase string.
    """
    return (name or "").strip().lower()


def normalize_dll_name(name_raw: str) -> str:
    """
    Normalize a DLL name, adding .dll extension if missing.

    Args:
        name_raw: The raw DLL name string.

    Returns:
        The normalized DLL name with extension.
    """
    normalized = normalize_name(name_raw)
    if not normalized:
        return ""
    if "." in os.path.basename(normalized):
        return normalized
    return normalized + ".dll"


# ----------------------------------------------------------------------
# Fingerprint helpers
# ----------------------------------------------------------------------

def fingerprint_md5(items: Iterable[str]) -> str:
    """
    Compute MD5 fingerprint of sorted items.

    Args:
        items: An iterable of strings to fingerprint.

    Returns:
        The MD5 hexdigest of the sorted, comma-separated items.
    """
    sorted_items = ",".join(sorted(item for item in items if item))
    return hashlib.md5(sorted_items.encode("utf-8", errors="ignore")).hexdigest()


def build_import_items(
    import_modules: List[Tuple[str, List[Tuple[Optional[str], Optional[int]]]]],
    common_import_dlls: Set[str],
    keep_common_imports: bool,
) -> List[str]:
    """
    Build a list of import items in 'dll!func' format.

    Args:
        import_modules: List of (dll_name, [(func_name, ordinal), ...]) tuples.
        common_import_dlls: Set of DLL names to filter out.
        keep_common_imports: If True, include common imports.

    Returns:
        A list of 'dll!func' strings.
    """
    result: List[str] = []
    for dll_raw, entries in import_modules:
        dll_norm = normalize_dll_name(dll_raw)
        if not dll_norm:
            continue
        if not keep_common_imports and dll_norm in common_import_dlls:
            continue

        for name, ordinal in entries:
            if name:
                func_norm = normalize_name(str(name))
            elif ordinal is not None:
                func_norm = normalize_name(f"ord{int(ordinal)}")
            else:
                continue
            result.append(f"{dll_norm}!{func_norm}")
    return result


# ----------------------------------------------------------------------
# Filters
# ----------------------------------------------------------------------

def is_filtered_func(name: str, filters: List[Pattern[str]]) -> bool:
    """
    Check if a function name matches any filter pattern.

    Args:
        name: The function name to check.
        filters: A list of compiled regex patterns.

    Returns:
        True if the name matches any filter pattern, False otherwise.
    """
    for pattern in filters:
        if pattern.match(name):
            return True
    return False


# ----------------------------------------------------------------------
# IDB Collection Helpers
# ----------------------------------------------------------------------

def collect_import_modules() -> List[Tuple[str, List[Tuple[Optional[str], Optional[int]]]]]:
    """
    Collect all import modules and their entries from the current IDB.

    Returns:
        A list of tuples: (dll_name, [(func_name, ordinal), ...])
    """
    import ida_nalt

    modules: List[Tuple[str, List[Tuple[Optional[str], Optional[int]]]]] = []
    try:
        module_count = ida_nalt.get_import_module_qty()
    except Exception:
        return modules

    for index in range(module_count):
        dll_raw = ida_nalt.get_import_module_name(index) or ""
        entries: List[Tuple[Optional[str], Optional[int]]] = []

        def callback(ea: int, name: Optional[str], ordinal: Optional[int]) -> bool:
            entries.append((name, ordinal))
            return True

        try:
            ida_nalt.enum_import_names(index, callback)
        except Exception:
            continue

        modules.append((dll_raw, entries))

    return modules


def iter_segments(
    ignored_sections: Set[str],
    keep_common: bool = False,
) -> List[Tuple[str, str, int, int]]:
    """
    Iterate over segments from current IDB with optional filtering.

    Args:
        ignored_sections: Set of normalized section names to filter out.
        keep_common: If True, include sections from ignored_sections set.

    Returns:
        A list of tuples: (name_raw, name_norm, start_ea, end_ea)
    """
    import ida_segment

    result: List[Tuple[str, str, int, int]] = []
    try:
        segment_count = ida_segment.get_segm_qty()
        for index in range(segment_count):
            segment = ida_segment.getnseg(index)
            if not segment:
                continue

            name_raw = ida_segment.get_segm_name(segment) or ""
            name_norm = normalize_name(name_raw)

            if not keep_common and name_norm in ignored_sections:
                continue

            result.append((name_raw, name_norm, segment.start_ea, segment.end_ea))
    except Exception:
        pass

    return result


# ----------------------------------------------------------------------
# Qt Helpers
# ----------------------------------------------------------------------

def qt_alive(obj: object) -> bool:
    """
    Check if a Qt object is still valid.

    Args:
        obj: A Qt object to check.

    Returns:
        True if the object exists and is valid, False otherwise.
    """
    try:
        return obj is not None and shiboken6.isValid(obj)
    except Exception:
        return False


def get_qt_parent() -> Optional[object]:
    """
    Get a suitable Qt parent widget from the current IDA widget.

    Returns:
        A PyQt widget suitable as a parent, or None.
    """
    try:
        widget = ida_kernwin.get_current_widget()
        return ida_kernwin.PluginForm.FormToPyQtWidget(widget)
    except Exception:
        return None


# ----------------------------------------------------------------------
# Address Formatting
# ----------------------------------------------------------------------

def fmt_ea(ea: int) -> str:
    """
    Format an effective address as a hex string.

    Args:
        ea: The address to format.

    Returns:
        A string like "0x12345678".
    """
    return f"0x{int(ea):x}"


# ----------------------------------------------------------------------
# Pattern Matching
# ----------------------------------------------------------------------

def safe_regex_search(pattern: str, text: str) -> bool:
    """
    Perform a safe regex search that won't raise exceptions.

    Args:
        pattern: The regex pattern to search for.
        text: The text to search in.

    Returns:
        True if the pattern matches, False otherwise or on error.
    """
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except Exception:
        return False


# ----------------------------------------------------------------------
# String Processing
# ----------------------------------------------------------------------

def sanitize_operand_name(name: str) -> str:
    """
    Clean up an operand name by removing segment prefixes.

    Args:
        name: The raw operand name (may contain "seg:name" format).

    Returns:
        The cleaned name with segment prefix removed.
    """
    if not name:
        return ""
    if ":" in name:
        name = name.split(":")[-1]
    return name.strip()


# ----------------------------------------------------------------------
# Function Lookups
# ----------------------------------------------------------------------

def func_start_from_any_ea(ea: int) -> Optional[int]:
    """
    Get the start address of the function containing a given address.

    Args:
        ea: Any address that might be within a function.

    Returns:
        The start address of the containing function, or None.
    """
    func = ida_funcs.get_func(int(ea))
    return int(func.start_ea) if func else None


# ----------------------------------------------------------------------
# Widget Introspection
# ----------------------------------------------------------------------

def is_code_widget(widget: object) -> bool:
    """
    Check if a widget is a code view (disassembly or pseudocode).

    Args:
        widget: An IDA widget handle.

    Returns:
        True if the widget shows code, False otherwise.
    """
    try:
        widget_type = ida_kernwin.get_widget_type(widget)
        return widget_type in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE)
    except Exception:
        return False


def widget_title(widget: object) -> str:
    """
    Get the title of an IDA widget.

    Args:
        widget: An IDA widget handle.

    Returns:
        The widget title, or empty string on error.
    """
    try:
        return ida_kernwin.get_widget_title(widget) or ""
    except Exception:
        return ""


def extract_view_letter_from_title(title: str) -> Optional[str]:
    """
    Extract the view letter (A, B, etc.) from an IDA view title.

    Expected formats: "IDA View-A", "Pseudocode-A"

    Args:
        title: The widget title string.

    Returns:
        The letter suffix (e.g., "A") or None if not matched.
    """
    match = re.match(r"^(IDA View|Pseudocode)-([A-Z])$", (title or "").strip())
    if not match:
        return None
    return match.group(2)


def paired_view_titles(title: str) -> List[str]:
    """
    Get both paired view titles for a given view.

    For "IDA View-A", returns ["IDA View-A", "Pseudocode-A"].

    Args:
        title: The current view title.

    Returns:
        A list of paired view titles.
    """
    letter = extract_view_letter_from_title(title)
    if not letter:
        return [title]
    return [f"IDA View-{letter}", f"Pseudocode-{letter}"]


def find_code_widget_by_title(title: str) -> Optional[object]:
    """
    Find a code widget (disassembly/pseudocode) by its title.

    Args:
        title: The widget title to search for.

    Returns:
        The widget handle, or None if not found or not a code widget.
    """
    try:
        widget = ida_kernwin.find_widget(title)
    except Exception:
        widget = None
    if widget is None:
        return None
    if not is_code_widget(widget):
        return None
    return widget
