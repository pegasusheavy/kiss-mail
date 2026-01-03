#!/bin/bash
# ============================================================================
# KISS Mail - Upgrade Script
# ============================================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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
echo -e "${GREEN}╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  ${NC}"
echo -e "${GREEN}╠╩╗║╚═╗╚═╗║║║╠═╣║║  ${NC}"
echo -e "${GREEN}╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝${NC}"
echo ""
echo "  KISS Mail Upgrade"
echo ""

# Check if container exists
if ! docker ps -a --format '{{.Names}}' | grep -q '^kiss-mail$'; then
    error "KISS Mail container not found. Is it installed?"
fi

# Get current image
CURRENT_IMAGE=$(docker inspect kiss-mail --format '{{.Config.Image}}' 2>/dev/null || echo "unknown")
log "Current image: $CURRENT_IMAGE"

# Pull latest image
log "Pulling latest image..."
if docker pull ghcr.io/pegasusheavy/kiss-mail:latest; then
    NEW_IMAGE="ghcr.io/pegasusheavy/kiss-mail:latest"
else
    warn "Could not pull from registry, building from source..."
    
    tmpdir=$(mktemp -d)
    cd "$tmpdir"
    
    if command -v git &> /dev/null; then
        git clone --depth 1 https://github.com/pegasusheavy/kiss-mail.git .
    else
        curl -sL https://github.com/pegasusheavy/kiss-mail/archive/main.tar.gz | tar xz --strip-components=1
    fi
    
    docker build -t kiss-mail:latest .
    NEW_IMAGE="kiss-mail:latest"
    
    cd /
    rm -rf "$tmpdir"
fi

# Get current container config
log "Backing up container configuration..."
ENV_VARS=$(docker inspect kiss-mail --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -E '^KISS_MAIL_|^RUST_LOG=' || true)
VOLUMES=$(docker inspect kiss-mail --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}')

# Stop and remove old container
log "Stopping current container..."
docker stop kiss-mail

log "Removing old container..."
docker rm kiss-mail

# Recreate container with same config
log "Starting new container..."

# Build docker run command
DOCKER_CMD="docker run -d --name kiss-mail --restart unless-stopped"
DOCKER_CMD+=" -p 25:2525 -p 587:2525 -p 143:1143 -p 110:1100 -p 8080:8080 -p 8025:8025"

# Add volumes
for vol in $VOLUMES; do
    DOCKER_CMD+=" -v $vol"
done

# Add environment variables
while IFS= read -r line; do
    if [[ -n "$line" ]]; then
        DOCKER_CMD+=" -e $line"
    fi
done <<< "$ENV_VARS"

DOCKER_CMD+=" $NEW_IMAGE"

eval $DOCKER_CMD

# Wait for startup
sleep 5

# Verify
if docker ps --format '{{.Names}}' | grep -q '^kiss-mail$'; then
    log "Upgrade successful!"
    echo ""
    echo "  New image: $NEW_IMAGE"
    echo "  Status: $(docker inspect kiss-mail --format '{{.State.Status}}')"
    echo ""
else
    error "Container failed to start. Check logs with: docker logs kiss-mail"
fi

# Cleanup old images
log "Cleaning up old images..."
docker image prune -f

echo ""
log "Upgrade complete!"
