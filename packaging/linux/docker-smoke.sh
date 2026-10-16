#!/bin/sh
# =============================================================================
# DomainRecon - Test de fumée du paquet .deb dans un conteneur Ubuntu vierge
# =============================================================================
# Lancé par packaging/linux/build-in-docker.ps1 :
#   docker-smoke.sh <fichier .deb> <version>
# Image nue : Python 3 (pour smoke_test.py) et certificats, puis installation du
# paquet sans les paquets recommandés (serveur sans bureau). Test : --version,
# --server, /api/health, scan rapide de example.com, export PDF, scan complet
# avec capture d'écran (Chromium embarqué), arrêt propre (SIGINT).
# =============================================================================
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage : $0 <fichier .deb> <version>" >&2
    exit 2
fi
DEB=$1
VERSION=$2
SMOKE=$(dirname "$0")/../smoke_test.py
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends python3 ca-certificates
apt-get install -y --no-install-recommends "$DEB"
dpkg -s domainrecon | grep -E '^(Package|Version|Status):'
test -x /usr/bin/domainrecon

python3 "$SMOKE" \
    --exe /usr/bin/domainrecon \
    --expect-version "$VERSION" \
    --data-dir /tmp/smoke-deb \
    --version-flag --quick-scan example.com --pdf --scan example.com

apt-get remove -y domainrecon
test ! -e /usr/bin/domainrecon
echo "[ok] Paquet désinstallé"
