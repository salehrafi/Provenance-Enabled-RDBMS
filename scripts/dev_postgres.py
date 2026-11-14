"""Run a local PostgreSQL 16 for development on machines without Docker.

Uses the PostgreSQL binaries shipped in the `pgserver` wheel (installed by requirements-dev.txt).
The cluster lives in .pgdata/ and listens on 127.0.0.1 only, with `trust` authentication for
the local superuser. That is fine for a developer laptop and wrong for anything else: use
docker compose or a managed PostgreSQL everywhere other than your own machine.

    python scripts/dev_postgres.py start     # initdb on first run, then start
    python scripts/dev_postgres.py stop
    python scripts/dev_postgres.py status
    python scripts/dev_postgres.py destroy   # stop and delete .pgdata (all local data)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / ".pgdata"
PORT = int(os.environ.get("DEV_PG_PORT", "54329"))


def _bin(name: str) -> str:
    try:
        import pgserver
    except ImportError:
        sys.exit("pgserver is not installed. Run: pip install -r requirements-dev.txt (Python 3.12), or use Docker.")
    exe = Path(pgserver.__file__).parent / "pginstall" / "bin" / name
    if sys.platform == "win32":
        exe = exe.with_suffix(".exe")
    return str(exe)


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, text=True, capture_output=True)


def running() -> bool:
    return DATA.exists() and _run(_bin("pg_ctl"), "-D", str(DATA), "status", check=False).returncode == 0


def start() -> None:
    if not (DATA / "PG_VERSION").exists():
        DATA.mkdir(exist_ok=True)
        _run(_bin("initdb"), "-D", str(DATA), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--locale=C")
        with open(DATA / "postgresql.conf", "a", encoding="utf-8") as f:
            # No timezone setting: this build ships without the tz database and runs in GMT. The
            # application never relies on named time zones in SQL for that reason.
            f.write(f"\nport = {PORT}\nlisten_addresses = '127.0.0.1'\n")
        print(f"initialised cluster in {DATA}")
    if running():
        print(f"already running on 127.0.0.1:{PORT}")
        return
    # pg_ctl keeps the server's stdout handle open, so do not capture its output.
    subprocess.run([_bin("pg_ctl"), "-D", str(DATA), "-l", str(DATA / "server.log"), "-w", "start"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"PostgreSQL started on 127.0.0.1:{PORT} (superuser: postgres, no password)")


def stop() -> None:
    if running():
        _run(_bin("pg_ctl"), "-D", str(DATA), "-m", "fast", "-w", "stop")
        print("stopped")
    else:
        print("not running")


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "start":
        start()
    elif cmd == "stop":
        stop()
    elif cmd == "status":
        print(f"running on 127.0.0.1:{PORT}" if running() else "not running")
    elif cmd == "destroy":
        stop()
        shutil.rmtree(DATA, ignore_errors=True)
        print(f"deleted {DATA}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
