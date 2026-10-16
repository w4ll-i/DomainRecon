#!/bin/sh
# =============================================================================
# DomainRecon - Construction du paquet .deb dans un conteneur Ubuntu 22.04
# =============================================================================
# Lancé par packaging/linux/build-in-docker.ps1, dans un conteneur ubuntu:22.04 :
#   /work/src        copie des fichiers nécessaires du dépôt (interface déjà
#                    construite dans domainrecon/web, frontend/node_modules
#                    présent pour les textes de licence)
#   /work/pip-cache  cache de pip (sur le disque de l'hôte)
# Python 3.13 (PPA deadsnakes), dépendances figées (packaging/requirements.lock),
# PyGObject et pycairo (fenêtre native), puis packaging/build.py --target linux
# --skip-frontend. Le paquet est produit dans /work/src/release/<version>/,
# le travail de construction dans /work/src/private/build/.
# L'environnement Python vit dans le conteneur (supprimé à la fin) : pas de
# liens symboliques sur le dossier partagé avec l'hôte.
# =============================================================================
set -eu

SRC=/work/src
export DEBIAN_FRONTEND=noninteractive
export PIP_CACHE_DIR=/work/pip-cache
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONDONTWRITEBYTECODE=1

apt-get update
apt-get install -y --no-install-recommends software-properties-common gpg-agent ca-certificates
add-apt-repository -y ppa:deadsnakes/ppa
apt-get update
apt-get install -y --no-install-recommends \
    python3.13 python3.13-venv python3.13-dev build-essential \
    libgirepository1.0-dev libcairo2-dev pkg-config gir1.2-gtk-3.0 gir1.2-webkit2-4.1 libwebkit2gtk-4.1-0 \
    dpkg-dev binutils

python3.13 -m venv /opt/venv
/opt/venv/bin/python -m pip install --require-hashes -r "$SRC/packaging/requirements.lock"
# Fenêtre native : PyGObject 3.50 (girepository 1.0, disponible sur Ubuntu 22.04).
/opt/venv/bin/python -m pip install "PyGObject==3.50.0" "pycairo==1.29.1"
/opt/venv/bin/python -VV

cd "$SRC"
/opt/venv/bin/python packaging/build.py --target linux --skip-frontend
VERSION=$(/opt/venv/bin/python packaging/build.py --print-version)
dpkg-deb --contents "release/${VERSION}/domainrecon_${VERSION}_amd64.deb" | head -n 20
# Fichiers lisibles par l'utilisateur de l'hôte (le conteneur écrit en root).
chmod -R a+rwX "$SRC/release" "$SRC/private" 2>/dev/null || true
