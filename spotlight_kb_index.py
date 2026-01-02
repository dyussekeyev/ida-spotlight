# SPDX-License-Identifier: Apache-2.0
"""
IDA Spotlight KB Indexer.

This standalone script indexes IDB/I64 files into a SQLite knowledge base
for cross-sample correlation and function recall.

Usage:
    idat -A -S"spotlight_kb_index.py --idb-dir=/path/to/idbs" dummy.idb
"""

import argparse
import glob
import math
import os
import sqlite3
import sys
import time
from typing import List, Pattern, Set

import idapro
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import idautils

from spotlight_config import (
    load_config,
    default_kb_db_path,
)
from spotlight_utils import (
    fingerprint_md5,
    build_import_items,
    normalize_name,
    normalize_dll_name,
    is_filtered_func,
    collect_import_modules,
    iter_segments,
)


# Load configuration
_BASE_DIR: str = os.path.dirname(__file__)
_, _CONFIG = load_config(_BASE_DIR)

_IGNORED_FUNCTIONS: List[Pattern[str]] = _CONFIG["ignored_functions"]
_IGNORED_SECTIONS: Set[str] = _CONFIG["ignored_sections"]
_IGNORED_DLLS: Set[str] = _CONFIG["ignored_dlls"]


# ----------------------------------------------------------------------
# SQLite schema
# ----------------------------------------------------------------------

_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS idb (
  id INTEGER PRIMARY KEY,
  path TEXT UNIQUE,
  mtime INTEGER,
  indexed_at INTEGER,
  import_fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS func (
  id INTEGER PRIMARY KEY,
  idb_id INTEGER,
  name_raw TEXT,
  name_norm TEXT,
  ea INTEGER,
  FOREIGN KEY(idb_id) REFERENCES idb(id)
);

CREATE TABLE IF NOT EXISTS feat_import_dll (
  id INTEGER PRIMARY KEY,
  idb_id INTEGER,
  name_raw TEXT,
  name_norm TEXT,
  UNIQUE(idb_id, name_norm),
  FOREIGN KEY(idb_id) REFERENCES idb(id)
);

CREATE TABLE IF NOT EXISTS feat_import_func (
  id INTEGER PRIMARY KEY,
  idb_id INTEGER,
  import_dll_id INTEGER,
  func_raw TEXT,
  func_norm TEXT,
  FOREIGN KEY(idb_id) REFERENCES idb(id),
  FOREIGN KEY(import_dll_id) REFERENCES feat_import_dll(id)
);

CREATE TABLE IF NOT EXISTS feat_section (
  id INTEGER PRIMARY KEY,
  idb_id INTEGER,
  name_raw TEXT,
  name_norm TEXT,
  entropy REAL,
  FOREIGN KEY(idb_id) REFERENCES idb(id)
);

CREATE INDEX IF NOT EXISTS idx_func_norm ON func(name_norm);
CREATE INDEX IF NOT EXISTS idx_import_dll_norm ON feat_import_dll(name_norm);
CREATE INDEX IF NOT EXISTS idx_import_func_norm ON feat_import_func(func_norm);
CREATE INDEX IF NOT EXISTS idx_section_norm ON feat_section(name_norm);
"""


# ----------------------------------------------------------------------
# Database Helpers
# ----------------------------------------------------------------------

def _db_connect(path: str) -> sqlite3.Connection:
    """
    Create a database connection.

    Args:
        path: Path to the SQLite database.

    Returns:
        A SQLite connection with foreign keys enabled.
    """
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys=ON;")
    return connection


def _db_init(connection: sqlite3.Connection) -> None:
    """
    Initialize the database schema.

    Args:
        connection: The database connection.
    """
    connection.executescript(_SCHEMA_SQL)
    connection.commit()


def _upsert_idb(connection: sqlite3.Connection, idb_path: str) -> int:
    """
    Insert or update an IDB record.

    Args:
        connection: The database connection.
        idb_path: Path to the IDB file.

    Returns:
        The IDB record ID.
    """
    mtime = int(os.path.getmtime(idb_path))
    now = int(time.time())
    connection.execute(
        """
        INSERT INTO idb(path, mtime, indexed_at)
        VALUES(?,?,?)
        ON CONFLICT(path)
        DO UPDATE SET mtime=excluded.mtime, indexed_at=excluded.indexed_at
        """,
        (idb_path, mtime, now),
    )
    return connection.execute(
        "SELECT id FROM idb WHERE path=?", (idb_path,)
    ).fetchone()[0]


def _clear_idb_rows(connection: sqlite3.Connection, idb_id: int) -> None:
    """
    Clear all feature rows for an IDB.

    Args:
        connection: The database connection.
        idb_id: The IDB record ID.
    """
    for table in ("func", "feat_import_func", "feat_import_dll", "feat_section"):
        connection.execute(f"DELETE FROM {table} WHERE idb_id=?", (idb_id,))


def _segment_entropy(start: int, end: int, limit: int = 1_000_000) -> float:
    """
    Calculate the entropy of a segment.

    Args:
        start: Segment start address.
        end: Segment end address.
        limit: Maximum bytes to analyze.

    Returns:
        The entropy value (0.0 to 8.0).
    """
    size = max(0, end - start)
    if size <= 0:
        return 0.0
    data = ida_bytes.get_bytes(start, min(size, limit)) or b""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    data_len = len(data)
    for count in freq:
        if count:
            prob = count / data_len
            entropy -= prob * math.log(prob, 2)
    return entropy


def _iter_idbs(root: str) -> List[str]:
    """
    Iterate over all IDB/I64 files in a directory tree.

    Args:
        root: The root directory to search.

    Returns:
        A list of IDB file paths.
    """
    results: List[str] = []
    for pattern in ("**/*.idb", "**/*.i64"):
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            if os.path.isfile(path):
                results.append(path)
    return results


# ----------------------------------------------------------------------
# Indexing Logic
# ----------------------------------------------------------------------

def _index_current_idb(
    connection: sqlite3.Connection,
    idb_path: str,
    keep_auto_named_funcs: bool,
    keep_library_funcs: bool,
    keep_common_sections: bool,
    keep_common_imports: bool,
) -> None:
    """
    Index the currently open IDB into the database.

    Args:
        connection: The database connection.
        idb_path: Path to the IDB file.
        keep_auto_named_funcs: Whether to keep auto-named functions.
        keep_library_funcs: Whether to keep library functions.
        keep_common_sections: Whether to keep common sections.
        keep_common_imports: Whether to keep common imports.
    """
    idb_id = _upsert_idb(connection, idb_path)

    with connection:
        _clear_idb_rows(connection, idb_id)

        # ---------------- Functions ----------------
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if not func:
                continue

            if not keep_library_funcs and (func.flags & ida_funcs.FUNC_LIB):
                continue

            name_raw = ida_funcs.get_func_name(func_ea)
            if not name_raw:
                continue

            if not keep_auto_named_funcs and is_filtered_func(name_raw, _IGNORED_FUNCTIONS):
                continue

            connection.execute(
                "INSERT INTO func(idb_id, name_raw, name_norm, ea) VALUES(?,?,?,?)",
                (idb_id, name_raw, normalize_name(name_raw), int(func_ea)),
            )

        # ---------------- Imports ----------------
        import_modules = collect_import_modules()

        import_items = build_import_items(
            import_modules=import_modules,
            common_import_dlls=_IGNORED_DLLS,
            keep_common_imports=keep_common_imports,
        )

        import_fingerprint = fingerprint_md5(import_items)

        connection.execute(
            "UPDATE idb SET import_fingerprint=? WHERE id=?",
            (import_fingerprint, idb_id),
        )

        for dll_raw, entries in import_modules:
            dll_norm = normalize_dll_name(dll_raw)
            if not dll_norm:
                continue

            if not keep_common_imports and dll_norm in _IGNORED_DLLS:
                continue

            connection.execute(
                """
                INSERT INTO feat_import_dll(idb_id, name_raw, name_norm)
                VALUES(?,?,?)
                ON CONFLICT(idb_id, name_norm) DO NOTHING
                """,
                (idb_id, dll_raw, dll_norm),
            )

            dll_id = connection.execute(
                "SELECT id FROM feat_import_dll WHERE idb_id=? AND name_norm=?",
                (idb_id, dll_norm),
            ).fetchone()[0]

            for name, ordinal in entries:
                if name:
                    func_raw = str(name)
                    func_norm = normalize_name(func_raw)
                elif ordinal is not None:
                    func_raw = f"ord{int(ordinal)}"
                    func_norm = normalize_name(func_raw)
                else:
                    continue

                connection.execute(
                    """
                    INSERT INTO feat_import_func(idb_id, import_dll_id, func_raw, func_norm)
                    VALUES(?,?,?,?)
                    """,
                    (idb_id, dll_id, func_raw, func_norm),
                )

        # ---------------- Sections ----------------
        for name_raw, name_norm, start_ea, end_ea in iter_segments(
            _IGNORED_SECTIONS, keep_common_sections
        ):
            connection.execute(
                """
                INSERT INTO feat_section(idb_id, name_raw, name_norm, entropy)
                VALUES(?,?,?,?)
                """,
                (idb_id, name_raw, name_norm, _segment_entropy(start_ea, end_ea)),
            )


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> None:
    """Main entry point for the KB indexer."""
    print("Using Python:", sys.executable)

    parser = argparse.ArgumentParser(
        description="IDA Spotlight KB indexer"
    )

    parser.add_argument("--idb-dir", required=True, help="Directory containing IDB files")
    parser.add_argument("--db", default=None, help="Path to KB database")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of IDBs to index")
    parser.add_argument("--keep-auto-named-funcs", action="store_true", help="Keep auto-named functions")
    parser.add_argument("--keep-library-funcs", action="store_true", help="Keep library functions")
    parser.add_argument("--keep-common-sections", action="store_true", help="Keep common sections")
    parser.add_argument("--keep-common-imports", action="store_true", help="Keep common imports")

    args = parser.parse_args()

    db_path = args.db if args.db else default_kb_db_path()
    print("KB database:", db_path)

    with _db_connect(db_path) as connection:
        _db_init(connection)
        idbs = _iter_idbs(args.idb_dir)

        if not idbs:
            print("No IDB/I64 files found in:", args.idb_dir)
            return

        if args.limit:
            idbs = idbs[: args.limit]

        total = len(idbs)
        for index, idb_path in enumerate(idbs, 1):
            print(f"[{index}/{total}] Indexing {idb_path}")
            try:
                idapro.open_database(idb_path, True)
                _index_current_idb(
                    connection,
                    idb_path,
                    keep_auto_named_funcs=args.keep_auto_named_funcs,
                    keep_library_funcs=args.keep_library_funcs,
                    keep_common_sections=args.keep_common_sections,
                    keep_common_imports=args.keep_common_imports,
                )
            except Exception as e:
                print(f"[!] Failed to index {idb_path}: {e}")
            finally:
                try:
                    idapro.close_database()
                except Exception:
                    pass

    print("Spotlight KB indexing complete")


if __name__ == "__main__":
    main()
