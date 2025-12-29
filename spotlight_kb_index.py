#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import argparse
import glob
import hashlib
import math
import os
import sqlite3
import sys
import time

import idapro
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import idautils

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
_, CFG = load_signals_and_config(BASE_DIR)

FUNC_FILTERS = build_func_filters(CFG)
COMMON_SECTIONS = build_common_sections(CFG)
COMMON_IMPORT_DLLS = build_common_import_dlls(CFG)


# ----------------------------------------------------------------------
# SQLite schema
# ----------------------------------------------------------------------

SCHEMA_SQL = """
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
# Helpers
# ----------------------------------------------------------------------

def db_connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def db_init(conn: sqlite3.Connection):
    conn.executescript(SCHEMA_SQL)
    conn.commit()


def upsert_idb(conn: sqlite3.Connection, idb_path: str) -> int:
    mtime = int(os.path.getmtime(idb_path))
    now = int(time.time())
    conn.execute(
        """
        INSERT INTO idb(path, mtime, indexed_at)
        VALUES(?,?,?)
        ON CONFLICT(path)
        DO UPDATE SET mtime=excluded.mtime, indexed_at=excluded.indexed_at
        """,
        (idb_path, mtime, now),
    )
    return conn.execute(
        "SELECT id FROM idb WHERE path=?", (idb_path,)
    ).fetchone()[0]


def clear_idb_rows(conn: sqlite3.Connection, idb_id: int):
    for tbl in ("func", "feat_import_func", "feat_import_dll", "feat_section"):
        conn.execute(f"DELETE FROM {tbl} WHERE idb_id=?", (idb_id,))


def spotlight_import_fingerprint(items: list[str]) -> str:
    s = ",".join(sorted(items))
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()


def segment_entropy(start: int, end: int, limit: int = 1_000_000) -> float:
    size = max(0, end - start)
    if size <= 0:
        return 0.0
    data = ida_bytes.get_bytes(start, min(size, limit)) or b""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    for c in freq:
        if c:
            p = c / len(data)
            ent -= p * math.log(p, 2)
    return ent


def iter_idbs(root: str):
    for pat in ("**/*.idb", "**/*.i64"):
        for p in glob.glob(os.path.join(root, pat), recursive=True):
            if os.path.isfile(p):
                yield p


# ----------------------------------------------------------------------
# Indexing logic
# ----------------------------------------------------------------------

def index_current_idb(
    conn,
    idb_path,
    keep_auto_named_funcs,
    keep_library_funcs,
    keep_common_sections,
    keep_common_imports,
):
    idb_id = upsert_idb(conn, idb_path)

    with conn:
        clear_idb_rows(conn, idb_id)

        # ---------------- Functions ----------------
        for fea in idautils.Functions():
            f = ida_funcs.get_func(fea)
            if not f:
                continue

            if not keep_library_funcs and (f.flags & ida_funcs.FUNC_LIB):
                continue

            name_raw = ida_funcs.get_func_name(fea)
            if not name_raw:
                continue

            if not keep_auto_named_funcs and is_filtered_func(name_raw, FUNC_FILTERS):
                continue

            conn.execute(
                "INSERT INTO func(idb_id, name_raw, name_norm, ea) VALUES(?,?,?,?)",
                (idb_id, name_raw, normalize_name(name_raw), int(fea)),
            )

        # ---------------- Imports ----------------
        import_items = []

        for i in range(ida_nalt.get_import_module_qty()):
            dll_raw = ida_nalt.get_import_module_name(i) or ""
            dll_norm = normalize_dll_name(dll_raw)
            if not dll_norm:
                continue

            if not keep_common_imports and dll_norm in COMMON_IMPORT_DLLS:
                continue

            conn.execute(
                """
                INSERT INTO feat_import_dll(idb_id, name_raw, name_norm)
                VALUES(?,?,?)
                ON CONFLICT(idb_id, name_norm) DO NOTHING
                """,
                (idb_id, dll_raw, dll_norm),
            )

            dll_id = conn.execute(
                "SELECT id FROM feat_import_dll WHERE idb_id=? AND name_norm=?",
                (idb_id, dll_norm),
            ).fetchone()[0]

            def cb(ea, name, ord_):
                if name:
                    fn = normalize_name(str(name))
                elif ord_ is not None:
                    fn = f"ord{ord_}"
                else:
                    return True

                import_items.append(f"{dll_norm}!{fn}")
                conn.execute(
                    """
                    INSERT INTO feat_import_func(idb_id, import_dll_id, func_raw, func_norm)
                    VALUES(?,?,?,?)
                    """,
                    (idb_id, dll_id, name or f"ord{ord_}", fn),
                )
                return True

            ida_nalt.enum_import_names(i, cb)

        conn.execute(
            "UPDATE idb SET import_fingerprint=? WHERE id=?",
            (spotlight_import_fingerprint(import_items), idb_id),
        )

        # ---------------- Sections ----------------
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if not seg:
                continue

            name_raw = ida_segment.get_segm_name(seg)
            name_norm = normalize_name(name_raw)

            if not keep_common_sections and name_norm in COMMON_SECTIONS:
                continue

            conn.execute(
                """
                INSERT INTO feat_section(idb_id, name_raw, name_norm, entropy)
                VALUES(?,?,?,?)
                """,
                (idb_id, name_raw, name_norm, segment_entropy(seg.start_ea, seg.end_ea)),
            )


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    print("Using Python:", sys.executable)

    ap = argparse.ArgumentParser(
        description="IDA Spotlight KB indexer (functions-only MVP)"
    )

    ap.add_argument("--idb-dir", required=True)
    ap.add_argument("--db", default=None)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--keep-auto-named-funcs", action="store_true")
    ap.add_argument("--keep-library-funcs", action="store_true")
    ap.add_argument("--keep-common-sections", action="store_true")
    ap.add_argument("--keep-common-imports", action="store_true")

    args = ap.parse_args()

    db_path = args.db if args.db else default_kb_db_path()
    print("KB database:", db_path)

    with db_connect(db_path) as conn:
        db_init(conn)
        idbs = list(iter_idbs(args.idb_dir))

        if not idbs:
            print("No IDB/I64 files found in:", args.idb_dir)
            return

        if args.limit:
            idbs = idbs[: args.limit]

        for i, path in enumerate(idbs, 1):
            print(f"[{i}/{len(idbs)}] Indexing {path}")
            try:
                idapro.open_database(path, True)
                index_current_idb(
                    conn,
                    path,
                    keep_auto_named_funcs=args.keep_auto_named_funcs,
                    keep_library_funcs=args.keep_library_funcs,
                    keep_common_sections=args.keep_common_sections,
                    keep_common_imports=args.keep_common_imports,
                )
            except Exception as e:
                print(f"[!] Failed to index {path}: {e}")
            finally:
                try:
                    idapro.close_database()
                except Exception:
                    pass

    print("Spotlight KB indexing complete")


if __name__ == "__main__":
    main()
