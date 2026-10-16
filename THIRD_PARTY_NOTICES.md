# Avis de tiers — DomainRecon

DomainRecon est un logiciel à code source disponible : tous droits réservés, sauf ce que la licence accorde (voir [LICENSE](LICENSE)).

Les livrables (installeur Windows, version portable, paquet `.deb`) embarquent
des composants tiers, chacun sous sa propre licence. La liste exacte — versions
et textes de licence compris — est générée à chaque construction par
`packaging/notices.py` et livrée dans le paquet : fichier `THIRD_PARTY_NOTICES.md`
à côté de l'exécutable (dans `/opt/domainrecon/` sous Linux).

## Principaux composants embarqués

| Composant | Rôle | Licence |
|---|---|---|
| CPython | Interpréteur Python embarqué | PSF-2.0 |
| PyInstaller (chargeur) | Démarrage des exécutables | GPL-2.0-or-later avec exception pour le chargeur |
| Chromium Headless Shell (fourni par Playwright) | Captures d'écran et rapports PDF | BSD-3-Clause et licences de ses composants (fichier `LICENSE.headless_shell` livré avec le navigateur) |
| Playwright (Python et pilote) | Pilotage de Chromium | Apache-2.0 |
| Node.js (pilote Playwright) | Exécution du pilote | MIT et licences de ses composants |
| pywebview | Fenêtre native | BSD-3-Clause |
| pythonnet, clr-loader (Windows) | Accès à .NET pour la fenêtre WebView2 | MIT |
| Microsoft.Web.WebView2 (Windows, fourni par pywebview) | Composants du SDK WebView2 | Licence du SDK WebView2 de Microsoft |
| PyGObject, pycairo (Linux) | Accès à GTK et WebKitGTK | LGPL-2.1-or-later ; LGPL-2.1-only ou MPL-1.1 |
| FastAPI, Starlette, Uvicorn, Pydantic, SQLAlchemy, httpx, socksio, dnspython, idna, tldextract, python-whois, python-dotenv | Serveur, base de données, collecte (socksio : proxy sortant SOCKS) | MIT, BSD-3-Clause, ISC (détail dans la liste générée) |
| cryptography, cffi, pycparser | Chiffrement des clés API enregistrées (OpenSSL est embarqué dans les roues de cryptography) | Apache-2.0 OR BSD-3-Clause ; MIT-0 ; BSD-3-Clause |
| plyer | Notifications de bureau des alertes de surveillance | MIT |
| React, React Router, TanStack Query, i18next, Chart.js, Cytoscape, d3-geo, topojson-client, lucide-react | Interface | MIT, ISC (détail dans la liste générée) |
| Inter, JetBrains Mono (@fontsource) | Polices de l'interface : texte et données | SIL Open Font License 1.1 |
| Natural Earth 1:110m (paquet npm world-atlas) | Interface : carte du monde vectorielle embarquée, hors ligne | Domaine public (naturalearthdata.com) |

La carte géographique est un fond vectoriel Natural Earth (domaine public) embarqué dans
l'application : aucune tuile n'est chargée en ligne.

## Régénérer la liste complète

Depuis l'environnement de build (dépendances installées, `npm ci` fait dans `frontend/`) :

```bash
python packaging/notices.py --output THIRD_PARTY_NOTICES.generated.md --version 1.0.0
```
