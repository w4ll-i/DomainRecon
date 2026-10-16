# Journal des modifications

Toutes les modifications notables de DomainRecon sont consignées ici. Le format suit
[Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet respecte le
[versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

## [1.0.0] - 2026-10-16

Première version publique.

### Ajouté

- Application de bureau pour Windows et Linux : fenêtre native (WebView2, WebKitGTK), repli dans le
  navigateur, mode serveur seul.
- 84 modules de scan en 8 familles (Web, TLS, E-mail, DNS et sous-domaines, Réseau, Identité, Réputation,
  Fuites de données), répartis en catégories passif, actif, clé d'API et sensible.
- Profils rapide, complet et personnalisé ; autorisation de tester la cible exigée, côté serveur, pour les
  modules actifs et sensibles.
- Note de sécurité de A à F et score sur 100, calculés sur les seuls critères mesurés, avec couverture du
  barème, pénalités pour les services sensibles exposés et plafond en cas de faille critique.
- Volet « Comprendre et corriger » pour chaque constat : explication, étapes, extrait de configuration et
  documentation officielle, en français et en anglais.
- Résultat en direct, page par famille avec un onglet par module, carte réseau, carte géographique hors
  ligne, capture d'écran, notes et tags.
- Tableau de bord, historique, timeline d'un domaine, comparaison de deux scans, lot de domaines.
- Surveillance planifiée avec règles d'alerte et canaux : centre de notifications, bureau, Discord, Slack,
  Teams, webhook JSON, e-mail SMTP ; tâche système (Planificateur de tâches Windows, minuteur systemd).
- Exports PDF, HTML, Markdown, CSV, JSON, SARIF et JUnit.
- Ligne de commande : `scan`, `batch`, `history`, `export`, `modules`, `import`, `monitor`, avec
  `--fail-under` pour l'intégration continue.
- Clés d'API chiffrées au repos, avec test de chaque clé depuis les Réglages ; proxy sortant.
- Interface en français et en anglais, visite guidée, aide, FAQ et glossaire intégrés.
- Import d'une ancienne base DomainRecon, sauvegarde de la base, désinstallation complète depuis les Réglages.
- API locale documentée, avec suivi des scans en direct (Server-Sent Events).
- Protections : écoute locale par défaut, contrôle de l'en-tête `Host`, jeton d'accès facultatif, refus des
  cibles non publiques (anti-SSRF), politique de sécurité du contenu stricte.
- Livrables : installeur Windows, portable Windows en un seul fichier, portable Windows zip, paquet `.deb`
  pour Ubuntu 22.04+ et Debian 12+, avec empreintes `SHA256SUMS` et attestations de provenance.

[Non publié]: https://github.com/w4ll-i/DomainRecon/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/w4ll-i/DomainRecon/releases/tag/v1.0.0
