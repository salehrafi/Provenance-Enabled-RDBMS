#!/usr/bin/env bash
# Logical backup of the application schema, with a checksum.
#   PGURL=postgresql://postgres:...@host:5432/provenance scripts/backup.sh [output-dir]
# This is the portable, easy-to-test backup. For a tight RPO use continuous WAL archiving as well
# (see docs/OPERATIONS.md); the two are complementary.
set -euo pipefail
: "${PGURL:?set PGURL to a connection string for a role that can read schema prov (the owner or a superuser)}"
out="${1:-backups}"; mkdir -p "$out"
file="$out/provenance-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump --format=custom --schema=prov --no-owner --file="$file" "$PGURL"
( cd "$out" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256" )
echo "backup written: $file ($(du -h "$file" | cut -f1))"
