# SPDX-License-Identifier: Apache-2.0
"""
Knowledge Base database operations for IDA Spotlight.

This module handles all SQLite database interactions for the KB including:
- Database connection management
- Database readiness checks and diagnostics
- Sample profile extraction for correlation
- Query functions for various recall types
"""

import os
import sqlite3
from typing import Any, Dict, List

import idaapi

from spotlight_utils import (
    fingerprint_md5,
    build_import_items,
    normalize_name,
    is_filtered_func,
    collect_import_modules,
    iter_segments,
)
from spotlight_config import (
    kb_db_path,
    IGNORED_DLLS,
    IGNORED_SECTIONS,
    IGNORED_FUNCTIONS,
    KB_LIMIT_STRONG,
    KB_LIMIT_IMPORT_OVERLAP,
    KB_LIMIT_SECTION_OVERLAP,
    KB_LIMIT_NAME_RECALL,
    KB_LIMIT_MAX_QUERY_IMPORT_FUNCS,
    KB_LIMIT_MAX_QUERY_SECTIONS,
)


__all__ = [
    # Database connection
    "kb_db_connect",
    "kb_db_ready",
    "kb_db_diagnose",
    # Sample profile
    "extract_sample_profile_for_kb",
    # KB queries
    "kb_paths_by_import_fingerprint",
    "kb_paths_by_section_norms",
    "kb_paths_by_import_func_norms",
    "kb_paths_for_function_name_raw",
    # Correlation logging
    "log_kb_sample_correlation",
]


# ----------------------------------------------------------------------
# Database Connection
# ----------------------------------------------------------------------

def kb_db_connect() -> sqlite3.Connection:
    """
    Create a connection to the KB database.

    Returns:
        A SQLite connection with row_factory set to sqlite3.Row.
    """
    connection = sqlite3.connect(kb_db_path())
    connection.row_factory = sqlite3.Row
    return connection


def kb_db_ready() -> bool:
    """
    Check if the KB database is ready for use.

    Verifies that the database file exists and contains the expected schema.

    Returns:
        True if the database is ready, False otherwise.
    """
    db_path = kb_db_path()
    if not os.path.exists(db_path):
        return False
    try:
        with kb_db_connect() as connection:
            cursor = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='idb'"
            )
            return cursor.fetchone() is not None
    except Exception:
        return False


def kb_db_diagnose(path: str) -> str:
    """
    Diagnose issues with the KB database.

    Args:
        path: The path to the database file.

    Returns:
        An empty string if OK, or a diagnostic message describing the problem.
    """
    if not path:
        return "database path is empty"

    if not os.path.exists(path):
        return "file does not exist"

    try:
        connection = sqlite3.connect(path)
    except sqlite3.Error as e:
        return f"sqlite open failed: {e}"

    try:
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='idb'"
        )
        if cursor.fetchone() is None:
            return "sqlite opened, but Spotlight schema missing (table 'idb')"
    except sqlite3.Error as e:
        return f"schema check failed: {e}"
    finally:
        connection.close()

    return ""  # OK


# ----------------------------------------------------------------------
# Sample Profile Extraction
# ----------------------------------------------------------------------

def _iter_section_norms_filtered() -> List[str]:
    """
    Iterate over section names, excluding ignored ones.

    Returns:
        A list of normalized section names.
    """
    return [
        name_norm
        for _, name_norm, _, _ in iter_segments(IGNORED_SECTIONS, keep_common=False)
    ]


def extract_sample_profile_for_kb(keep_common_imports: bool) -> Dict[str, Any]:
    """
    Extract the current sample's profile for KB correlation.

    Args:
        keep_common_imports: If True, include common imports in the fingerprint.

    Returns:
        A dictionary containing import fingerprint, dll norms,
        import function norms, and section norms.
    """
    import_modules = collect_import_modules()

    import_items = build_import_items(
        import_modules=import_modules,
        common_import_dlls=IGNORED_DLLS,
        keep_common_imports=keep_common_imports,
    )

    import_fingerprint = fingerprint_md5(import_items)

    dll_norms = sorted({item.split("!", 1)[0] for item in import_items})
    import_func_norms = sorted({item.split("!", 1)[1] for item in import_items})

    section_norms = sorted(set(_iter_section_norms_filtered()))

    return {
        "import_items": import_items,
        "import_fingerprint": import_fingerprint,
        "dll_norms": dll_norms,
        "import_func_norms": import_func_norms,
        "section_norms": section_norms,
    }


# ----------------------------------------------------------------------
# KB Queries
# ----------------------------------------------------------------------

def kb_paths_by_import_fingerprint(fingerprint: str) -> List[str]:
    """
    Find IDB paths matching an import fingerprint.

    Args:
        fingerprint: The MD5 import fingerprint.

    Returns:
        A list of matching IDB paths.
    """
    fingerprint = (fingerprint or "").strip()
    if not fingerprint:
        return []
    with kb_db_connect() as connection:
        rows = connection.execute(
            """
            SELECT path
            FROM idb
            WHERE import_fingerprint = ?
            ORDER BY path
            LIMIT ?
            """,
            (fingerprint, KB_LIMIT_STRONG + 1),
        ).fetchall()
        return [row["path"] for row in rows]


def kb_paths_by_section_norms(section_norms: List[str]) -> List[str]:
    """
    Find IDB paths containing any of the specified sections.

    Args:
        section_norms: A list of normalized section names.

    Returns:
        A list of matching IDB paths.
    """
    section_norms = [s for s in (section_norms or []) if s]
    if not section_norms:
        return []
    placeholders = ",".join(["?"] * len(section_norms))
    with kb_db_connect() as connection:
        rows = connection.execute(
            f"""
            SELECT DISTINCT idb.path AS path
            FROM feat_section s
            JOIN idb ON idb.id = s.idb_id
            WHERE s.name_norm IN ({placeholders})
            ORDER BY path
            LIMIT ?
            """,
            (*section_norms, KB_LIMIT_SECTION_OVERLAP + 1),
        ).fetchall()
        return [row["path"] for row in rows]


def kb_paths_by_import_func_norms(import_func_norms: List[str]) -> List[str]:
    """
    Find IDB paths containing any of the specified import functions.

    Args:
        import_func_norms: A list of normalized import function names.

    Returns:
        A list of matching IDB paths.
    """
    import_func_norms = [s for s in (import_func_norms or []) if s]
    if not import_func_norms:
        return []
    placeholders = ",".join(["?"] * len(import_func_norms))
    with kb_db_connect() as connection:
        rows = connection.execute(
            f"""
            SELECT DISTINCT idb.path AS path
            FROM feat_import_func f
            JOIN idb ON idb.id = f.idb_id
            WHERE f.func_norm IN ({placeholders})
            ORDER BY path
            LIMIT ?
            """,
            (*import_func_norms, KB_LIMIT_IMPORT_OVERLAP + 1),
        ).fetchall()
        return [row["path"] for row in rows]


def kb_paths_for_function_name_raw(name_raw: str) -> List[str]:
    """
    Find IDB paths containing a function with the given name.

    Args:
        name_raw: The raw function name.

    Returns:
        A list of matching IDB paths.
    """
    name = (name_raw or "").strip()
    if not name:
        return []
    if is_filtered_func(name, IGNORED_FUNCTIONS):
        return []
    name_norm = normalize_name(name)
    with kb_db_connect() as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT idb.path AS path
            FROM func
            JOIN idb ON idb.id = func.idb_id
            WHERE func.name_norm = ?
            ORDER BY path
            LIMIT ?
            """,
            (name_norm, KB_LIMIT_NAME_RECALL + 1),
        ).fetchall()
        return [row["path"] for row in rows]


# ----------------------------------------------------------------------
# KB Correlation Logging
# ----------------------------------------------------------------------

def log_kb_sample_correlation() -> None:
    """
    Log the KB correlation summary to the IDA output window.

    Prints information about samples matching the current IDB via:
    - Import fingerprint (strict and loose)
    - Import function overlap
    - Section overlap
    """
    if not kb_db_ready():
        idaapi.msg("[IDA Spotlight] KB not ready\n")
        return

    idaapi.msg("\n[IDA Spotlight] KB correlation summary\n")
    idaapi.msg("-------------------------------------\n")

    profile_strict = extract_sample_profile_for_kb(keep_common_imports=False)
    profile_loose = extract_sample_profile_for_kb(keep_common_imports=True)

    strict_matches = kb_paths_by_import_fingerprint(profile_strict["import_fingerprint"])
    loose_matches = kb_paths_by_import_fingerprint(profile_loose["import_fingerprint"])

    if strict_matches:
        idaapi.msg("Strong (strict import fingerprint):\n")
        for path in strict_matches:
            idaapi.msg(f"  - {path}\n")
    elif loose_matches:
        idaapi.msg("Strong (loose import fingerprint):\n")
        for path in loose_matches:
            idaapi.msg(f"  - {path}\n")

    import_matches = kb_paths_by_import_func_norms(
        profile_strict["import_func_norms"][:KB_LIMIT_MAX_QUERY_IMPORT_FUNCS]
    )
    section_matches = kb_paths_by_section_norms(
        profile_strict["section_norms"][:KB_LIMIT_MAX_QUERY_SECTIONS]
    )

    if import_matches:
        idaapi.msg("\nMedium (import overlap):\n")
        for path in import_matches:
            idaapi.msg(f"  - {path}\n")

    if section_matches:
        idaapi.msg("\nMedium (section overlap):\n")
        for path in section_matches:
            idaapi.msg(f"  - {path}\n")
