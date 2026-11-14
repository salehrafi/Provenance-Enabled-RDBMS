#!/usr/bin/env bash
# Prove a backup is restorable and that the audit history inside it is intact.
#   ADMIN_URL=postgresql://postgres:...@host:5432/postgres scripts/restore_check.sh backups/provenance-...dump
# Restores into a throw-away database, then runs the full hash-chain and checkpoint verification
# for every organization. Exit status 0 only if the restore and every verification succeed.
set -euo pipefail
: "${ADMIN_URL:?set ADMIN_URL to a superuser connection string (database postgres)}"
dump="${1:?usage: restore_check.sh <backup.dump>}"
( cd "$(dirname "$dump")" && sha256sum --check "$(basename "$dump").sha256" )
scratch="provenance_restore_$$"
base="${ADMIN_URL%/*}"
psql -v ON_ERROR_STOP=1 -qc "CREATE DATABASE $scratch TEMPLATE template0 ENCODING 'UTF8'" "$ADMIN_URL"
trap 'psql -qc "DROP DATABASE IF EXISTS $scratch WITH (FORCE)" "$ADMIN_URL" >/dev/null' EXIT
psql -v ON_ERROR_STOP=1 -qc "GRANT CREATE ON DATABASE $scratch TO prov_owner" "$base/$scratch"
pg_restore --dbname="$base/$scratch" --role=prov_owner --no-owner --exit-on-error "$dump"
# Verify using the application's own code, pointed at the restored copy.
export DATABASE_URL="${DATABASE_URL_TEMPLATE:-$(python - <<PY
import os, re
u = os.environ["DATABASE_URL"] if "DATABASE_URL" in os.environ else ""
print(re.sub(r"/[^/?]+(\?|$)", r"/$scratch\1", u, count=1))
PY
)}"
python -m app.cli verify
echo "restore check passed: $dump"
