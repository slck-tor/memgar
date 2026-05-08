#!/usr/bin/env bash
# memgar.com one-shot deployment script.
# Run on the production server after `git clone`.
#
#   ./deploy/deploy.sh           # build + start
#   ./deploy/deploy.sh update    # pull + rebuild + rolling restart
#   ./deploy/deploy.sh logs      # tail logs
#   ./deploy/deploy.sh status    # health check
#   ./deploy/deploy.sh rollback  # revert to previous image

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE="docker compose -f deploy/docker-compose.prod.yml --env-file .env"

require_env() {
    if [ ! -f .env ]; then
        echo "ERROR: .env not found.  Copy deploy/.env.example to .env and fill it in." >&2
        exit 1
    fi
}

cmd_up() {
    require_env
    echo "▶ Building images..."
    $COMPOSE build
    echo "▶ Starting stack..."
    $COMPOSE up -d
    echo "▶ Waiting 30s for services to become healthy..."
    sleep 30
    cmd_status
}

cmd_update() {
    require_env
    echo "▶ Pulling latest commit..."
    git pull --ff-only
    echo "▶ Rebuilding images..."
    $COMPOSE build memgar-api
    echo "▶ Rolling restart..."
    $COMPOSE up -d --no-deps --build memgar-api
    sleep 10
    cmd_status
}

cmd_status() {
    echo "── Container status ──"
    $COMPOSE ps
    echo
    echo "── API health ──"
    curl -sf https://api.memgar.com/health | python3 -m json.tool || echo "(API not reachable yet — check DNS / Caddy logs)"
}

cmd_logs() {
    $COMPOSE logs -f --tail=200 "${2:-memgar-api}"
}

cmd_rollback() {
    require_env
    echo "▶ Rolling back to previous image..."
    docker tag memgar:previous memgar:latest
    $COMPOSE up -d --no-deps memgar-api
    cmd_status
}

cmd_backup() {
    ts=$(date +%Y%m%d-%H%M%S)
    out="backups/memgar-${ts}.tar.gz"
    mkdir -p backups
    echo "▶ Backing up volumes to ${out}..."
    docker run --rm \
        -v memgar_memgar-cache:/cache:ro \
        -v memgar_memgar-integrity:/integrity:ro \
        -v memgar_caddy-data:/caddy:ro \
        -v "$(pwd)/backups":/backup \
        alpine \
        tar czf "/backup/memgar-${ts}.tar.gz" /cache /integrity /caddy
    echo "✓ Backup at ${out}"
}

case "${1:-up}" in
    up)        cmd_up ;;
    update)    cmd_update ;;
    status)    cmd_status ;;
    logs)      cmd_logs "$@" ;;
    rollback)  cmd_rollback ;;
    backup)    cmd_backup ;;
    *)
        echo "Usage: $0 {up|update|status|logs [service]|rollback|backup}"
        exit 1
        ;;
esac
