#!/bin/bash
set -euo pipefail
umask 077
cd /root/bio
if [[ -f .env ]]; then
    set -a
    . ./.env
    set +a
fi
exec .venv/bin/ais-server serve --tailscale
