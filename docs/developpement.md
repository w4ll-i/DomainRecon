# Développement

Lancer DomainRecon depuis les sources, le tester et construire les livrables. Pour proposer une modification,
voir aussi [CONTRIBUTING.md](../CONTRIBUTING.md).

## Prérequis

- Python 3.10 ou plus récent (3.13 pour construire les livrables) ;
- Node.js 22 LTS (au minimum 20.19, exigé par Vite) ;
- Git.

## Lancer depuis les sources

```bash
git clone https://github.com/w4ll-i/DomainRecon.git
cd DomainRecon
python -m venv .venv
. .venv/bin/activate                                 # Windows : .venv\Scripts\activate
python -m pip install -e ".[dev]"                    # Linux, fenêtre native : ".[dev,gtk]"
python -m playwright install --only-shell chromium   # captures d'écran et PDF
cd frontend && npm ci && npm run build && cd ..      # interface, construite dans domainrecon/web
domainrecon --browser                                # ou : python -m domainrecon
```

Sous Linux, `python -m playwright install --with-deps --only-shell chromium` installe aussi les bibliothèques
système de Chromium (apt, sudo).

Les données d'un lancement depuis les sources vont dans `private/data/` (ignoré par git). Un `.env` est
accepté dans ce dossier ou à la racine du dépôt ; [`.env.example`](../.env.example) décrit les variables.

### Interface avec rechargement à chaud

Dans un premier terminal :

```bash
domainrecon --server --port 8000 --no-open
```

Dans un second :

```bash
cd frontend
npm run dev
```

Vite relaie `/api` vers `127.0.0.1:8000`.

## Tests et vérifications

```bash
python -m pytest -q                                # tests Python, sans accès réseau
python -m pytest -q --cov --cov-report=term        # avec couverture (seuil : 60 %)
ruff check . && ruff format --check .              # lint et formatage
cd frontend
npm run typecheck && npm run lint && npm run test  # types, lint, Vitest
npm run e2e:install                                # une fois : navigateur de Playwright Test
npm run build && npm run e2e                       # Playwright, sur le vrai backend
```

`npm run e2e` lance lui-même `tests/e2e_server.py` (base de démonstration, faux scanner, port 8765) avec
l'interpréteur de la variable `E2E_PYTHON` (défaut : `python` sous Windows, `python3` ailleurs). Cet
interpréteur doit avoir `domainrecon` installé, par exemple `E2E_PYTHON=.venv/bin/python npm run e2e`.
`E2E_REQUIRE_PDF=1` interdit au scénario d'export de se contenter du message « PDF indisponible ».

L'intégration continue (`.github/workflows/ci.yml`) lance le lint Python, les tests sur Python 3.10 à 3.14
(avec un vrai Chromium sur 3.13), les tests aux versions minimales des dépendances, l'interface (types, lint,
Vitest, build), les tests de bout en bout et la validation des fichiers du paquet Linux.

## Ajouter un module

Un module se compose d'un fichier dans `domainrecon/scanner/modules/`, de ses textes français et anglais dans
`domainrecon/i18n/modules/` et de ses tests dans `tests/scanner/modules/`. Il est découvert automatiquement.
Les règles sont dans le [contrat des modules](contrat-modules.md) ; le test de contrat refuse un module qui
ne les respecte pas, par exemple sans « Comment corriger ».

## Construire les livrables

`packaging/build.py` enchaîne : build de l'interface, installation de Chromium, PyInstaller
(`packaging/domainrecon.spec`), licences (`THIRD_PARTY_NOTICES.md`), contrôle du dossier produit, livrables
de la plateforme, puis `SHA256SUMS` et `NOTES.md`. Les dépendances de construction sont installées depuis
`packaging/requirements.lock` (versions et empreintes figées). PyInstaller ne fait pas de compilation croisée :
chaque plateforme se construit sur elle-même.

| Dossier | Contenu |
|---|---|
| `private/build/` | Travail : PyInstaller, Chromium de Playwright (`private/build/ms-playwright`), dossier intermédiaire de l'application (`private/build/dist/DomainRecon`). |
| `release/<version>/` | Livrables finaux, `SHA256SUMS` et `NOTES.md` (copie de `docs/releases/<version>.md`). |

Les deux dossiers sont ignorés par git. `--build-dir` et `--release-dir` (ou `DOMAINRECON_BUILD_DIR` et
`DOMAINRECON_RELEASE_DIR`) les déplacent ; `python packaging/build.py --print-paths` les affiche sans rien
construire.

### Windows

Prérequis : Python 3.13, Node.js 22, Inno Setup 6 (`winget install --id JRSoftware.InnoSetup -e`).

```powershell
py -V:3.13 -m venv .venv-build
.venv-build\Scripts\python -m pip install --require-hashes -r packaging\requirements.lock
.venv-build\Scripts\python packaging\build.py --target windows
```

Le même script s'écrit `python packaging/build.py --target windows` depuis un environnement déjà activé.
Résultat, dans `release\1.0.0\` :

- `DomainRecon-1.0.0-setup.exe` (installeur Inno Setup) ;
- `DomainRecon-1.0.0-portable.exe` (monofichier, `packaging/domainrecon-onefile.spec`) ;
- `DomainRecon-1.0.0-portable-win64.zip` ;
- `SHA256SUMS` et `NOTES.md`.

`--skip-installer` omet l'installeur, `--skip-onefile` omet le `.exe` monofichier :
`python packaging/build.py --target windows --skip-installer --skip-onefile` ne produit que le zip.

### Linux

Sur Ubuntu 22.04, pour un paquet compatible avec toutes les versions prises en charge :

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get install -y python3.13 python3.13-venv python3.13-dev \
  libgirepository1.0-dev libcairo2-dev pkg-config gir1.2-gtk-3.0 gir1.2-webkit2-4.1 libwebkit2gtk-4.1-0
python3.13 -m venv .venv-build
.venv-build/bin/python -m pip install --require-hashes -r packaging/requirements.lock
.venv-build/bin/python -m pip install "PyGObject==3.50.0" "pycairo==1.29.1"
.venv-build/bin/python packaging/build.py --target linux
```

Résultat : `release/1.0.0/domainrecon_1.0.0_amd64.deb`, avec `SHA256SUMS` et `NOTES.md`.

### Après la construction

- Tester un livrable : `python packaging/smoke_test.py --exe <exécutable> --expect-version 1.0.0 --scan example.com`
  (démarrage en `--server`, `/api/health`, scan avec capture d'écran, arrêt).
- Réécrire `SHA256SUMS` et `NOTES.md` après avoir ajouté un livrable construit ailleurs (par exemple le
  `.deb` à côté des fichiers Windows) : `python packaging/build.py --checksums`.

Les livrables ne sont jamais versionnés : ils sont publiés sur la page Releases. Voir
[Publier une version](publication.md).
