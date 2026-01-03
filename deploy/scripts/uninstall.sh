#!/bin/bash
# ============================================================================
# KISS Mail - Uninstall Script
# ============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[KISS Mail]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

echo ""
echo -e "${RED}╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  ${NC}"
echo -e "${RED}╠╩╗║╚═╗╚═╗║║║╠═╣║║  ${NC}"
echo -e "${RED}╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝${NC}"
echo ""
echo "  KISS Mail Uninstaller"
echo ""

KEEP_DATA=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-data)
            KEEP_DATA=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--keep-data]"
            echo ""
            echo "Options:"
            echo "  --keep-data    Keep mail data directory"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

read -p "Are you sure you want to uninstall KISS Mail? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

log "Stopping KISS Mail container..."
docker stop kiss-mail 2>/dev/null || true

log "Removing KISS Mail container..."
docker rm kiss-mail 2>/dev/null || true

log "Removing KISS Mail image..."
docker rmi kiss-mail:latest 2>/dev/null || true
docker rmi ghcr.io/pegasusheavy/kiss-mail:latest 2>/dev/null || true

log "Removing Nginx configuration..."
rm -f /etc/nginx/conf.d/kiss-mail.conf 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/kiss-mail 2>/dev/null || true
rm -f /etc/nginx/sites-available/kiss-mail 2>/dev/null || true
systemctl reload nginx 2>/dev/null || true

if [[ "$KEEP_DATA" == "true" ]]; then
    warn "Keeping data directory: /opt/kiss-mail"
else
    log "Removing data directory..."
    rm -rf /opt/kiss-mail
fi

echo ""
log "KISS Mail has been uninstalled."
if [[ "$KEEP_DATA" == "true" ]]; then
    echo "  Data preserved at: /opt/kiss-mail"
fi
echo ""
