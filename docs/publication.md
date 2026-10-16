# Publier une version

Les livrables sont construits et publiés par le workflow GitHub Actions `.github/workflows/release.yml`, à
partir d'un tag `v<version>`. Ils ne sont jamais versionnés dans le dépôt : GitHub refuse les fichiers de
plus de 100 Mo, et leur place est la page Releases.

## 1. Préparer

1. Mettre à jour la version dans `domainrecon/__init__.py` (`__version__`) et dans `pyproject.toml`
   (`version`). Un test vérifie qu'elles sont égales.
2. Remplacer les numéros de version de la documentation : badge et tableau des livrables du
   [README](../README.md), [Installation](installation.md), [Développement](developpement.md). Des tests
   vérifient le badge et les noms des livrables.
3. Écrire les notes de version dans `docs/releases/<version>.md` : elles deviennent le texte de la release.
   Partir de [docs/releases/1.0.0.md](releases/1.0.0.md).
4. Compléter le [CHANGELOG](../CHANGELOG.md) (section datée de la nouvelle version, liens en bas du fichier).
5. Régénérer le verrou des dépendances de construction : `python packaging/build.py --lock` (exige `uv`).

## 2. Vérifier

- La CI doit être verte sur `main`.
- Facultatif : lancer le workflow **Release** à la main (**Actions > Release > Run workflow**), sans tag. Il
  construit et teste les livrables, téléchargeables comme artefacts, sans rien publier.
- Facultatif : construire en local (voir [Développement](developpement.md#construire-les-livrables)). Les
  fichiers arrivent dans `release/<version>/`, avec `SHA256SUMS` et `NOTES.md`, exactement comme sur la page
  Releases.

## 3. Taguer

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 4. Ce que fait le workflow

1. Vérifie que le tag vaut `v` suivi de la version du code (`python packaging/build.py --check-tag`).
2. Construit l'interface, puis Windows (installeur et portables) et Linux (`.deb`) en parallèle.
3. Teste chaque livrable : démarrage, `/api/health`, scan avec capture d'écran ; installation, portables et
   désinstallation sous Windows ; `.deb` sur Ubuntu 22.04, Ubuntu 24.04 et Debian 12.
4. Rassemble les livrables dans `release/<version>/`, calcule `SHA256SUMS` et copie
   `docs/releases/<version>.md` en `NOTES.md`.
5. Atteste la provenance des fichiers (attestations GitHub).
6. Crée une **release brouillon** : titre `DomainRecon <version>`, texte tiré de `NOTES.md`, suivi des notes
   générées par GitHub, et les cinq fichiers joints.

| Fichier joint | Contenu |
|---|---|
| `DomainRecon-<version>-setup.exe` | Installeur Windows |
| `DomainRecon-<version>-portable.exe` | Portable Windows, un seul fichier |
| `DomainRecon-<version>-portable-win64.zip` | Portable Windows, dossier |
| `domainrecon_<version>_amd64.deb` | Paquet Debian et Ubuntu |
| `SHA256SUMS` | Empreintes SHA-256 des quatre livrables |

## 5. Publier

Relire le brouillon sur la page Releases (fichiers, notes), puis cliquer sur **Publish release**.
