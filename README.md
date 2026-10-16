<p align="center">
  <img src="docs/assets/logo-badge.svg" alt="Logo DomainRecon" width="96">
</p>

<h1 align="center">DomainRecon</h1>

<p align="center">
  <strong>Auditez vos domaines : une note de sécurité, les points à corriger et comment les corriger.</strong><br>
  Application de bureau pour Windows et Linux, en français et en anglais, entièrement locale.
</p>

<p align="center">
  <a href="https://github.com/w4ll-i/DomainRecon/releases"><img src="https://img.shields.io/badge/version-1.0.0-58a6ff" alt="Version 1.0.0"></a>
  <img src="https://img.shields.io/badge/plateformes-Windows%20%7C%20Linux-lightgrey" alt="Windows et Linux">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-code%20source%20disponible-lightgrey" alt="Licence : code source disponible"></a>
  <a href="https://github.com/w4ll-i/DomainRecon/actions/workflows/ci.yml"><img src="https://github.com/w4ll-i/DomainRecon/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<p align="center">
  <a href="https://github.com/w4ll-i/DomainRecon/releases">Télécharger</a> ·
  <a href="docs/README.md">Documentation</a> ·
  <a href="docs/releases/1.0.0.md">Notes de version</a> ·
  <a href="#english">English</a>
</p>

![Résultat d'un scan : note, points à corriger et familles](docs/assets/screenshots/resultat.png)

DomainRecon analyse un domaine que vous administrez (DNS, sous-domaines, certificat TLS, en-têtes HTTP,
e-mail, ports, réputation, fuites, WHOIS, capture d'écran) et en tire une note de A à F, la liste des
problèmes triés par gravité et, pour chacun, les étapes pour le corriger. Tout tourne sur votre machine :
pas de compte, pas de serveur central.

## Fonctionnalités

- **84 modules** en 8 familles : Web, TLS, E-mail, DNS et sous-domaines, Réseau, Identité, Réputation,
  Fuites de données. [Liste complète](docs/modules.md).
- **Note de sécurité** calculée sur les seuls critères mesurés, avec la couverture du barème : un module en
  échec n'est jamais compté comme réussi. [Barème](docs/score.md).
- **Comprendre et corriger** : pour chaque constat, l'explication, les étapes, un extrait de configuration
  à copier et la documentation officielle.
- **Profils** rapide, complet ou personnalisé. Les modules actifs (scan de 33 ports TCP, brute-force de
  sous-domaines, fichiers sensibles) exigent l'autorisation de tester la cible.
- **Surveillance** planifiée avec alertes sur le bureau, Discord, Slack, Teams, webhook ou e-mail.
- **Lot** de domaines, **comparaison** de deux scans, historique et timeline.
- **Exports** PDF, HTML, Markdown, CSV, JSON, SARIF et JUnit.
- **Ligne de commande** pour scripts et intégration continue (`--fail-under B`).
- Tout est embarqué : Python, interface, polices, carte du monde, Chromium pour les captures et le PDF.

<table>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/nouveau-scan.png" alt="Écran Scanner et choix du profil"></td>
    <td width="50%"><img src="docs/assets/screenshots/famille-web.png" alt="Famille Web et ses onglets"></td>
  </tr>
  <tr>
    <td align="center">Lancer un scan et choisir le profil</td>
    <td align="center">Une famille en détail, module par module</td>
  </tr>
</table>

## Téléchargement

Les livrables sont sur la page [Releases](https://github.com/w4ll-i/DomainRecon/releases), avec le fichier
`SHA256SUMS` des empreintes et une attestation de provenance pour chacun.

| Système | Fichier | Usage |
|---|---|---|
| Windows 10 / 11 (64 bits) | `DomainRecon-1.0.0-setup.exe` | Installeur, sans droits d'administrateur |
| Windows 10 / 11 (64 bits) | `DomainRecon-1.0.0-portable.exe` | Portable, un seul fichier |
| Windows 10 / 11 (64 bits) | `DomainRecon-1.0.0-portable-win64.zip` | Portable, dossier à extraire |
| Ubuntu 22.04+ / Debian 12+ (amd64) | `domainrecon_1.0.0_amd64.deb` | Paquet `apt` |

Les exécutables Windows ne sont pas signés : Windows affiche un avertissement SmartScreen au premier
lancement. Vérifiez l'empreinte, puis cliquez sur **Informations complémentaires > Exécuter quand même**.
Détails dans le [guide d'installation](docs/installation.md).

## Démarrage rapide

1. Installez DomainRecon et lancez-le. Une visite guidée présente l'interface au premier lancement.
2. Saisissez un domaine que vous administrez, par exemple `example.com`, et cliquez sur **Scan**.
3. Lisez la note et la liste **À corriger** ; ouvrez **Comprendre et corriger** sur chaque constat.
4. Exportez le rapport, ou placez le domaine sous **Surveillance**.

En ligne de commande :

```bash
domainrecon scan example.com --format html -o rapport.html
```

## Usage responsable

N'analysez que des domaines que vous administrez ou que vous êtes explicitement autorisé à tester. Un scan
contacte la cible et interroge des services tiers. Les modules actifs et sensibles ne se lancent que dans un
profil personnalisé, après avoir coché l'autorisation de tester la cible. Scanner un système sans
autorisation peut être illégal.

## Documentation

| Page | Contenu |
|---|---|
| [Installation](docs/installation.md) | Livrables, empreintes, SmartScreen, Windows et Linux |
| [Guide d'utilisation](docs/utilisation.md) | Scan, profils, résultats, corrections, exports |
| [Modules](docs/modules.md) et [score](docs/score.md) | Les 84 modules, le barème de la note |
| [Clés d'API](docs/cles-api.md) | Services facultatifs, où obtenir une clé |
| [Surveillance](docs/surveillance.md) et [lot](docs/lot-et-comparaison.md) | Alertes, plusieurs domaines, comparaison |
| [Ligne de commande](docs/ligne-de-commande.md) | Sous-commandes et options |
| [Confidentialité](docs/confidentialite.md) | Ce qui reste en local |
| [FAQ et dépannage](docs/faq.md) | Problèmes courants |
| [Développement](docs/developpement.md) | Sources, tests, construction des livrables |

Sommaire complet : [docs/README.md](docs/README.md).

## Licence

DomainRecon est un logiciel à **code source disponible**, pas un logiciel libre. Vous pouvez lire et auditer
le code, utiliser les versions officielles pour auditer vos propres domaines, signaler un problème et proposer
une modification. Réutiliser le code, redistribuer ou publier une version modifiée demande une autorisation
écrite. Le texte qui fait foi est dans [LICENSE](LICENSE) ; les composants tiers gardent leur propre licence
([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

## Contribuer

Les tickets et les demandes de fusion sont bienvenus : voir [CONTRIBUTING.md](CONTRIBUTING.md). Pour une faille
de sécurité, suivez [SECURITY.md](SECURITY.md) plutôt que d'ouvrir un ticket public.

## English

DomainRecon is a desktop application for Windows and Linux that audits domains you own: 84 checks across DNS,
TLS, HTTP headers, e-mail, network, reputation and data leaks, an A to F security grade, and step-by-step
remediation advice for every finding. Everything runs locally. The interface is available in English:
choose the interface language in **Settings** (**Réglages** in French).

- Download: [Releases](https://github.com/w4ll-i/DomainRecon/releases) (Windows installer, portable `.exe`,
  portable `.zip`, `.deb` package). Windows executables are unsigned: verify `SHA256SUMS`, then choose
  **More info > Run anyway** on the SmartScreen prompt.
- Only scan domains you own or are explicitly authorized to test.
- License: source-available, not open source. See [LICENSE](LICENSE) (the English text is binding).
- The documentation is in French; commands and screenshots are the same in both languages.
