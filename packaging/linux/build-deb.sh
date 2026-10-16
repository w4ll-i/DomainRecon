#!/bin/sh
# =============================================================================
# DomainRecon - Construction du paquet .deb (appelé par packaging/build.py)
# =============================================================================
# Usage : build-deb.sh <dossier de l'application> <version> <fichier .deb> <racine du dépôt>
# Variables d'environnement (calculées par build.py à partir de Playwright) :
#   DEB_DEPENDS     champ Depends (liste séparée par des virgules)
#   DEB_RECOMMENDS  champ Recommends
# Arborescence : /opt/domainrecon (application), /usr/bin/domainrecon (lien),
# /usr/share/applications/domainrecon.desktop, icônes hicolor, copyright.
# Les CR (checkout Windows) sont retirés des fichiers de paquet.
# =============================================================================
set -eu

if [ "$#" -ne 4 ]; then
    echo "Usage : $0 <dossier de l'application> <version> <fichier .deb> <racine du dépôt>" >&2
    exit 2
fi

APP_DIR=$1
VERSION=$2
OUTPUT=$3
ROOT=$4
: "${DEB_DEPENDS:?DEB_DEPENDS non défini}"
: "${DEB_RECOMMENDS:?DEB_RECOMMENDS non défini}"

LINUX_DIR="$ROOT/packaging/linux"
ICONS_DIR="$ROOT/packaging/icons"
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

# Application et lien dans le PATH
mkdir -p "$STAGING/opt/domainrecon" "$STAGING/usr/bin" "$STAGING/DEBIAN" \
    "$STAGING/usr/share/applications" "$STAGING/usr/share/doc/domainrecon"
cp -a "$APP_DIR/." "$STAGING/opt/domainrecon/"
# Droits indépendants de ceux du dossier de build (umask restrictif, checkout Windows) :
# lisible par tous, modifiable par root seul ; les liens symboliques ne sont pas suivis.
chmod -R u+rwX,go+rX,go-w "$STAGING/opt/domainrecon"
ln -s /opt/domainrecon/domainrecon "$STAGING/usr/bin/domainrecon"

# Menu et icônes
tr -d '\r' < "$LINUX_DIR/domainrecon.desktop" > "$STAGING/usr/share/applications/domainrecon.desktop"
for size in 256 128 48; do
    mkdir -p "$STAGING/usr/share/icons/hicolor/${size}x${size}/apps"
    cp "$ICONS_DIR/domainrecon-$size.png" "$STAGING/usr/share/icons/hicolor/${size}x${size}/apps/domainrecon.png"
done

# Licence (Debian : /usr/share/doc/<paquet>/copyright)
cp "$ROOT/LICENSE" "$STAGING/usr/share/doc/domainrecon/copyright"

# Droits : dossiers 755, fichiers de /usr/share 644, exécutable 755
find "$STAGING" -type d -exec chmod 755 {} +
find "$STAGING/usr/share" -type f -exec chmod 644 {} +
chmod 755 "$STAGING/opt/domainrecon/domainrecon"

# Métadonnées
# Valeur sûre dans le remplacement d'un « s|…|…| » de sed : « \ », « & » et « | »
# (alternatives « a | b » du champ Depends) sont protégés par une barre oblique inverse.
sed_escape() {
    printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}
INSTALLED_SIZE=$(du -sk --exclude=DEBIAN "$STAGING" | cut -f1)
tr -d '\r' < "$LINUX_DIR/control.in" | sed \
    -e "s|@VERSION@|$(sed_escape "$VERSION")|" \
    -e "s|@DEPENDS@|$(sed_escape "$DEB_DEPENDS")|" \
    -e "s|@RECOMMENDS@|$(sed_escape "$DEB_RECOMMENDS")|" \
    -e "s|@INSTALLED_SIZE@|$INSTALLED_SIZE|" \
    > "$STAGING/DEBIAN/control"
tr -d '\r' < "$LINUX_DIR/postinst" > "$STAGING/DEBIAN/postinst"
chmod 755 "$STAGING/DEBIAN/postinst"

mkdir -p "$(dirname "$OUTPUT")"
# xz : lisible par toutes les versions de dpkg (zstd, défaut d'Ubuntu, ne l'est pas par Debian < 12).
dpkg-deb --root-owner-group -Zxz --build "$STAGING" "$OUTPUT"
dpkg-deb --info "$OUTPUT"
