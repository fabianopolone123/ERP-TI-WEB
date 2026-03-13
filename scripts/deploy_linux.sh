#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
SERVICE_NAME="${SERVICE_NAME:-erp-ti}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/erp-ti-backups}"

log() {
    printf '[deploy] %s\n' "$*"
}

fail() {
    printf '[deploy][error] %s\n' "$*" >&2
    exit 1
}

read_env_value() {
    local key="$1"
    local env_file="$ROOT_DIR/.env"

    [[ -f "$env_file" ]] || return 1

    awk -v key="$key" '
        /^[[:space:]]*#/ { next }
        index($0, "=") == 0 { next }
        {
            current_key = substr($0, 1, index($0, "=") - 1)
            if (current_key == key) {
                print substr($0, index($0, "=") + 1)
                exit
            }
        }
    ' "$env_file"
}

resolve_db_file() {
    local db_path_raw
    db_path_raw="$(read_env_value "ERP_DB_PATH" || true)"

    if [[ -z "${db_path_raw// }" ]]; then
        printf '%s\n' "$ROOT_DIR/db.sqlite3"
        return 0
    fi

    if [[ "$db_path_raw" == *.sqlite3 ]]; then
        printf '%s\n' "$db_path_raw"
        return 0
    fi

    printf '%s\n' "$db_path_raw/db.sqlite3"
}

ensure_clean_worktree() {
    cd "$ROOT_DIR"

    if [[ -n "$(git status --porcelain)" ]]; then
        git status --short
        fail "O repositorio possui alteracoes locais. Faca commit/stash antes do deploy."
    fi
}

backup_database() {
    local db_file="$1"
    local timestamp="$2"
    local backup_file

    if [[ ! -f "$db_file" ]]; then
        log "Banco nao encontrado em $db_file. Backup ignorado."
        return 0
    fi

    mkdir -p "$BACKUP_DIR"
    backup_file="$BACKUP_DIR/db.sqlite3.$timestamp.bak"
    cp -a "$db_file" "$backup_file"
    log "Backup do banco criado em $backup_file"
}

update_release_marker() {
    local timestamp="$1"
    local short_sha="$2"
    local fixed_version
    local marker_raw
    local marker_file
    local next_version

    fixed_version="$(read_env_value "ERP_APP_VERSION" || true)"
    if [[ -n "${fixed_version// }" ]]; then
        log "ERP_APP_VERSION esta fixo no .env. Arquivo de versao nao sera atualizado."
        return 0
    fi

    marker_raw="$(read_env_value "ERP_APP_VERSION_FILE" || true)"
    marker_file="${marker_raw:-.release-version}"
    if [[ "$marker_file" != /* ]]; then
        marker_file="$ROOT_DIR/$marker_file"
    fi

    next_version="${timestamp}-${short_sha}"
    printf '%s\n' "$next_version" > "$marker_file"
    log "Versao publicada atualizada para $next_version"
}

main() {
    local branch
    local before_sha
    local after_sha
    local timestamp
    local db_file

    [[ -d "$ROOT_DIR/.git" ]] || fail "Repositorio Git nao encontrado em $ROOT_DIR"
    [[ -d "$VENV_DIR" ]] || fail "Ambiente virtual nao encontrado em $VENV_DIR"

    ensure_clean_worktree

    cd "$ROOT_DIR"
    branch="$(git rev-parse --abbrev-ref HEAD)"
    before_sha="$(git rev-parse --short HEAD)"

    log "Atualizando branch $branch"
    git fetch --prune origin
    git pull --ff-only origin "$branch"
    after_sha="$(git rev-parse --short HEAD)"
    log "Codigo atualizado: $before_sha -> $after_sha"

    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"

    log "Instalando dependencias Python"
    python -m pip install -r requirements.txt

    db_file="$(resolve_db_file)"
    timestamp="$(date '+%Y.%m.%d-%H%M%S')"

    backup_database "$db_file" "$timestamp"

    log "Validando aplicacao"
    python manage.py check

    log "Aplicando migrations"
    python manage.py migrate --noinput

    update_release_marker "$timestamp" "$after_sha"

    log "Reiniciando servico $SERVICE_NAME"
    sudo systemctl restart "$SERVICE_NAME"
    sudo systemctl --no-pager --full status "$SERVICE_NAME"

    log "Deploy concluido com sucesso."
}

main "$@"
