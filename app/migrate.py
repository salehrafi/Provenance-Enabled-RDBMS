"""Minimal versioned migration runner for Oracle.

Runs db/migrations/NNN_*.sql in order as the schema owner and records each applied file in
SCHEMA_MIGRATIONS. Statements are separated by a line containing only "/" (sqlplus style),
which keeps PL/SQL blocks intact.

Usage:  python -m app.migrate
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import oracledb

from app.config import ROOT_DIR, get_settings

MIGRATIONS_DIR = ROOT_DIR / "db" / "migrations"
_PLSQL = re.compile(
    r"^(CREATE\s+(OR\s+REPLACE\s+)?(PACKAGE|PROCEDURE|FUNCTION|TRIGGER|TYPE)\b|BEGIN\b|DECLARE\b)",
    re.IGNORECASE,
)


def split_statements(text: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    for line in text.splitlines():
        if line.strip() == "/":
            stmt = _clean("\n".join(buf))
            if stmt:
                statements.append(stmt)
            buf = []
        else:
            buf.append(line)
    if _clean("\n".join(buf)):
        raise ValueError("Trailing statement without terminating '/' line")
    return statements


def _clean(stmt: str) -> str:
    lines = stmt.strip().splitlines()
    while lines and (not lines[0].strip() or lines[0].strip().startswith("--")):
        lines.pop(0)
    stmt = "\n".join(lines).strip()
    if stmt and not _PLSQL.match(stmt):
        stmt = stmt.rstrip(";").rstrip()
    return stmt


def run() -> None:
    s = get_settings()
    conn = oracledb.connect(user=s.db_owner_user, password=s.db_owner_password, dsn=s.db_dsn)
    cur = conn.cursor()
    cur.execute(
        """
        DECLARE n NUMBER;
        BEGIN
          SELECT COUNT(*) INTO n FROM user_tables WHERE table_name = 'SCHEMA_MIGRATIONS';
          IF n = 0 THEN
            EXECUTE IMMEDIATE 'CREATE TABLE schema_migrations (
               version VARCHAR2(100) PRIMARY KEY,
               checksum VARCHAR2(64) NOT NULL,
               applied_at TIMESTAMP DEFAULT SYS_EXTRACT_UTC(SYSTIMESTAMP) NOT NULL)';
          END IF;
        END;"""
    )
    cur.execute("SELECT version, checksum FROM schema_migrations")
    applied = dict(cur.fetchall())

    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    for path in files:
        text = path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(text.encode()).hexdigest()
        if path.name in applied:
            if applied[path.name] != checksum:
                print(f"  ! {path.name} changed after it was applied (checksum mismatch)")
            continue
        print(f"  -> applying {path.name}")
        for i, stmt in enumerate(split_statements(text), start=1):
            try:
                cur.execute(stmt)
            except oracledb.DatabaseError as exc:
                head = stmt.splitlines()[0][:100]
                raise SystemExit(f"{path.name} statement {i} failed ({head}): {exc}") from exc
            if cur.warning:
                head = stmt.splitlines()[0][:100]
                errors = _compile_errors(cur)
                raise SystemExit(f"{path.name} statement {i} compiled with errors ({head}):\n{errors}")
        cur.execute(
            "INSERT INTO schema_migrations (version, checksum) VALUES (:v, :c)", {"v": path.name, "c": checksum}
        )
        conn.commit()

    errors = _compile_errors(cur)
    if errors:
        raise SystemExit(f"Invalid objects after migration:\n{errors}")
    cur.execute("SELECT object_type, object_name FROM user_objects WHERE status = 'INVALID'")
    invalid = cur.fetchall()
    if invalid:
        raise SystemExit(f"Invalid objects: {invalid}")
    print(f"  migrations up to date ({len(files)} files)")
    conn.close()


def _compile_errors(cur: oracledb.Cursor) -> str:
    cur.execute("SELECT name, type, line, position, text FROM user_errors ORDER BY name, sequence")
    return "\n".join(f"    {n} {t} line {l}:{p} {txt}" for n, t, l, p, txt in cur.fetchall())


if __name__ == "__main__":
    try:
        run()
    except SystemExit as e:
        if e.code not in (0, None):
            print(e.code, file=sys.stderr)
            sys.exit(1)
