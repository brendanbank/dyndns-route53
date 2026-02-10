#!/usr/bin/env bash
#
# Backup and restore SQLite databases for dyndns-route53
#
# Usage (Docker, default):
#   ./scripts/backup.sh
#   ./scripts/backup.sh --output /path/to/backups
#
# Usage (local install):
#   ./scripts/backup.sh --local
#   ./scripts/backup.sh --local --output /path/to/backups
#
# Restore:
#   ./scripts/backup.sh --restore ./backups/
#   ./scripts/backup.sh --restore ./backups/ --local
#
# Silent mode (errors only, for cron):
#   ./scripts/backup.sh --quiet
#
# Keep only last 5 backups:
#   ./scripts/backup.sh --keep 5
#

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Defaults ---
MODE="docker"
ACTION="backup"
OUTPUT_DIR="./backups"
RESTORE_DIR=""
QUIET=false
KEEP=0
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

DOCKER_CONTAINER_DB_DIR="/app/instance"
LOCAL_DB_DIR="instance"
DATABASES=("dyndns" "events")

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --local)   MODE="local"; shift ;;
        --output)  OUTPUT_DIR="$2"; shift 2 ;;
        --restore) ACTION="restore"; RESTORE_DIR="$2"; shift 2 ;;
        --quiet|-q) QUIET=true; shift ;;
        --keep)    KEEP="$2"; shift 2 ;;
        --help|-h) ACTION="help"; shift ;;
        *)         echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# --- Help ---
if [[ "$ACTION" == "help" ]]; then
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Backup and restore dyndns-route53 SQLite databases."
    echo "Uses 'sqlite3 .backup' for safe, consistent backups (WAL-mode safe)."
    echo
    echo "Options:"
    echo "  --local              Use local instance/ directory instead of Docker"
    echo "  --output DIR         Backup output directory (default: ./backups/)"
    echo "  --restore DIR        Restore from the most recent backup in DIR"
    echo "  --keep N             Keep the last N backups per database, delete older ones"
    echo "  -q, --quiet          Only print errors (for cron jobs)"
    echo "  -h, --help           Show this help message"
    echo
    echo "Examples:"
    echo "  $0                           # Docker backup to ./backups/"
    echo "  $0 --output /mnt/backups     # Docker backup to custom dir"
    echo "  $0 --local                   # Local backup to ./backups/"
    echo "  $0 --restore ./backups/      # Docker restore from latest backup"
    echo "  $0 --restore ./backups/ --local  # Local restore from latest backup"
    exit 0
fi

# --- Helpers ---
info()  { $QUIET || echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { $QUIET || echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

file_size() {
    local size
    if [[ "$(uname)" == "Darwin" ]]; then
        size=$(stat -f%z "$1" 2>/dev/null || echo 0)
    else
        size=$(stat -c%s "$1" 2>/dev/null || echo 0)
    fi
    if [[ $size -ge 1048576 ]]; then
        echo "$(( size / 1048576 )) MB"
    elif [[ $size -ge 1024 ]]; then
        echo "$(( size / 1024 )) KB"
    else
        echo "${size} bytes"
    fi
}

# --- Backup ---
do_backup() {
    info "Starting backup (mode: ${MODE})"
    mkdir -p "$OUTPUT_DIR"

    for db in "${DATABASES[@]}"; do
        local backup_file="${OUTPUT_DIR}/${db}-${TIMESTAMP}.db"

        if [[ "$MODE" == "docker" ]]; then
            local container_db="${DOCKER_CONTAINER_DB_DIR}/${db}.db"
            local container_tmp="/tmp/${db}-backup.db"

            info "Backing up ${db}.db via Docker..."
            if $QUIET; then
                docker compose exec -T web sqlite3 "$container_db" ".backup ${container_tmp}" 2>/dev/null \
                    || error "Failed to create backup of ${db}.db in container"
                docker compose cp "web:${container_tmp}" "$backup_file" 2>/dev/null \
                    || error "Failed to copy ${db} backup from container"
                docker compose exec -T web rm -f "$container_tmp" 2>/dev/null
            else
                docker compose exec -T web sqlite3 "$container_db" ".backup ${container_tmp}" \
                    || error "Failed to create backup of ${db}.db in container"
                docker compose cp "web:${container_tmp}" "$backup_file" \
                    || error "Failed to copy ${db} backup from container"
                docker compose exec -T web rm -f "$container_tmp"
            fi
        else
            local local_db="${LOCAL_DB_DIR}/${db}.db"
            if [[ ! -f "$local_db" ]]; then
                warn "Skipping ${db}.db — file not found at ${local_db}"
                continue
            fi
            info "Backing up ${db}.db locally..."
            sqlite3 "$local_db" ".backup ${backup_file}" \
                || error "Failed to back up ${db}.db"
        fi

        info "  -> ${backup_file} ($(file_size "$backup_file"))"
    done

    # Prune old backups if --keep is set
    if [[ "$KEEP" -gt 0 ]]; then
        info "Pruning backups, keeping last ${KEEP} per database..."
        for db in "${DATABASES[@]}"; do
            local old_files
            old_files=$(ls -t "${OUTPUT_DIR}"/${db}-*.db 2>/dev/null | tail -n +$((KEEP + 1)))
            if [[ -n "$old_files" ]]; then
                local count
                count=$(echo "$old_files" | wc -l | tr -d ' ')
                echo "$old_files" | xargs rm -f
                info "  -> deleted ${count} old ${db} backup(s)"
            fi
        done
    fi

    $QUIET || echo
    info "Backup complete. Files in ${OUTPUT_DIR}/"
}

# --- Restore ---
do_restore() {
    [[ -z "$RESTORE_DIR" ]] && error "Restore directory is required: --restore <dir>"
    [[ ! -d "$RESTORE_DIR" ]] && error "Restore directory not found: ${RESTORE_DIR}"

    info "Starting restore from ${RESTORE_DIR} (mode: ${MODE})"
    $QUIET || echo

    for db in "${DATABASES[@]}"; do
        # Find the most recent backup file for this database
        local latest
        latest=$(ls -t "${RESTORE_DIR}"/${db}-*.db 2>/dev/null | head -n1)

        if [[ -z "$latest" ]]; then
            warn "No ${db} backup found in ${RESTORE_DIR} — skipping"
            continue
        fi

        info "Restoring ${db}.db from ${latest} ($(file_size "$latest"))"

        if [[ "$MODE" == "docker" ]]; then
            local container_db="${DOCKER_CONTAINER_DB_DIR}/${db}.db"
            local container_tmp="/tmp/${db}-restore.db"

            docker compose cp "$latest" "web:${container_tmp}" \
                || error "Failed to copy ${db} backup to container"
            docker compose exec -T web sqlite3 "$container_db" ".restore ${container_tmp}" \
                || error "Failed to restore ${db}.db in container"
            docker compose exec -T web rm -f "$container_tmp"
        else
            local local_db="${LOCAL_DB_DIR}/${db}.db"
            sqlite3 "$local_db" ".restore ${latest}" \
                || error "Failed to restore ${db}.db"
        fi

        info "  -> ${db}.db restored successfully"
    done

    $QUIET || echo
    info "Restore complete."
    warn "If you are running in Docker, restart the containers: docker compose restart"
}

# --- Main ---
case "$ACTION" in
    backup)  do_backup ;;
    restore) do_restore ;;
esac
