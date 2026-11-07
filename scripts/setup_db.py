"""One-command local database setup.

1. Creates .env with generated passwords/secrets if it does not exist.
2. Creates the PROV_OWNER / PROV_APP schemas and the PROV_CTX context (as SYSDBA, using OS
   authentication through sqlplus; passwords are piped via stdin, never on the command line).
3. Applies migrations as PROV_OWNER.

Usage:
    python scripts/setup_db.py           # create / update
    python scripts/setup_db.py --reset   # drop both schemas first (deletes all project data)
"""

from __future__ import annotations

import os
import secrets
import string
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
sys.path.insert(0, str(ROOT))


def _password(n: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "P" + "".join(secrets.choice(alphabet) for _ in range(n - 1))


def ensure_env() -> None:
    if ENV_PATH.exists():
        print(f"using existing {ENV_PATH.name}")
        return
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    values = {
        "DB_OWNER_PASSWORD": _password(),
        "DB_APP_PASSWORD": _password(),
        "JWT_SECRET": secrets.token_urlsafe(48),
        "DEMO_PASSWORD": "Demo-" + secrets.token_urlsafe(9),
    }
    lines = []
    for line in template.splitlines():
        key = line.split("=", 1)[0].strip()
        lines.append(f"{key}={values[key]}" if key in values else line)
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"created {ENV_PATH.name} with generated secrets")


def run_sqlplus(script: Path, replacements: dict[str, str]) -> None:
    from app.config import get_settings

    s = get_settings()
    sql = script.read_text(encoding="utf-8")
    for key, value in replacements.items():
        sql = sql.replace("{{" + key + "}}", value)
    env = {**os.environ, "ORACLE_SID": s.oracle_sid}
    result = subprocess.run(
        [s.sqlplus_path, "-S", "-L", "/ as sysdba"],
        input=sql,
        text=True,
        capture_output=True,
        env=env,
    )
    output = (result.stdout + result.stderr).strip()
    if output:
        print("\n".join("  " + line for line in output.splitlines() if line.strip()))
    if result.returncode != 0:
        raise SystemExit(f"sqlplus failed running {script.name} (exit {result.returncode})")


def main() -> None:
    ensure_env()
    from app.config import get_settings

    get_settings.cache_clear()
    s = get_settings()
    pdb = {"PDB": s.oracle_pdb}

    if "--reset" in sys.argv:
        print("dropping schemas ...")
        run_sqlplus(ROOT / "db" / "bootstrap" / "drop_schemas.sql", pdb)

    print("bootstrapping schemas (SYSDBA) ...")
    run_sqlplus(
        ROOT / "db" / "bootstrap" / "create_schemas.sql",
        {**pdb, "OWNER_PASSWORD": s.db_owner_password, "APP_PASSWORD": s.db_app_password},
    )

    print("applying migrations ...")
    from app import migrate

    migrate.run()
    print("done.")


if __name__ == "__main__":
    main()
