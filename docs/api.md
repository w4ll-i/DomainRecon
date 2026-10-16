# API locale

DomainRecon est servi par une API HTTP locale (FastAPI) : l'interface l'utilise, et vous pouvez l'appeler
depuis vos scripts. La documentation interactive est servie sur `/api/docs` (désactivable avec `API_DOCS=0`).
Pour exposer l'API sur le réseau et exiger un jeton, voir [Configuration](configuration.md#exposer-domainrecon-sur-le-réseau).

## Routes

Toutes les routes qui renvoient un scan acceptent `?lang=fr` ou
`?lang=en` (sinon l'en-tête `Accept-Language`, sinon le français) : les
messages du scanner sont stockés sous forme de codes et traduits à la lecture ;
un scan antérieur à la v1 est renvoyé avec son texte d'origine.

| Méthode | Route | Jeton* | Description |
|---|---|---|---|
| `GET` | `/api/health` | non | État de l'API et de la base (`503` si la base est indisponible ou en lecture seule) |
| `POST` | `/api/scans` | oui | Lance un scan en tâche de fond (`{"domain": "…"}`) → `202 {"id", "status": "running"}`. Options : `profile` (`rapide`, `complet` par défaut, ou `personnalise` avec `selected`, la liste des modules choisis) et `authorized_target` (`true` exigé, côté serveur, pour un module actif ou sensible). `400` si cette autorisation manque ou si aucun module ne peut être lancé ; `total` de la progression = nombre de modules lancés. Le profil et les modules lancés sont enregistrés avec le scan (`profile`, `modules_launched`) |
| `GET` | `/api/scans/{id}` | oui | État de la tâche : `status`, `done`/`total`, `scan_id` une fois terminée |
| `GET` | `/api/scans/{id}/events` | oui | Avancement en direct (`text/event-stream` : `module`, `progress`, `done`, `failed`, `cancelled`), rejoué à la connexion |
| `POST` | `/api/scans/{id}/cancel` | oui | Annule la tâche (corps `{}` en JSON) : `202`, `404` inconnue, `409` déjà terminée |
| `POST` | `/api/scan` | oui | Scan complet synchrone (compatibilité) |
| `GET` | `/api/scan/{id}` | oui | Scan enregistré, avec `families` et `findings` |
| `DELETE` | `/api/scan/{id}` | oui | Supprime un scan et sa capture |
| `PATCH` | `/api/scan/{id}/meta` | oui | Modifie tags et notes |
| `GET` | `/api/history` | oui | Historique : `limit`, `offset`, `domain`, `grade`, `status` |
| `GET` | `/api/dns-timeline/{domain}` | oui | Timeline d'un domaine |
| `GET` | `/api/screenshot/{filename}` | oui | Capture d'écran (PNG) |
| `GET` | `/api/system/info` | oui | Version, dossier des données, mode portable, exécutable figé |
| `POST` | `/api/system/open-data-dir` | oui | Ouvre le dossier des données (corps `{}` en JSON ; depuis la machine locale seulement, sinon `403`) |
| `POST` | `/api/system/heartbeat` | oui | Battement de l'interface (corps `{}` en JSON) → `204` ; en mode navigateur, le serveur s'arrête environ 2 minutes après le dernier |
| `GET` | `/api/system/vpn` | oui | Statut du VPN Mullvad, en lecture seule : `connected`, `ip`, `country`, `provider`, `mullvad_cli`, `message` (dans la langue de la requête). Lu par `mullvad status` si le CLI est installé, sinon par `am.i.mullvad.net` (sans proxy) ; `connected` vaut `null` si le statut est illisible |
| `GET` | `/api/settings` | oui | Réglages : clés API masquées (`sk-…1234`), délais, capture d'écran, proxy |
| `PUT` | `/api/settings` | oui | Modifie les réglages indiqués (JSON) : champ absent ou `null` inchangé, `""` supprime une clé ou le proxy ; les clés sont chiffrées avant d'être enregistrées. `api_keys` (`{nom: valeur}`) accepte toute clé déclarée par un module ; GET la renvoie masquée pour toutes les clés |
| `POST` | `/api/settings/test/{service}` | oui | Teste la clé enregistrée d'un service (`shodan`, `virustotal`, `censys`, `abuseipdb`, `urlscan`, `otx`, `safebrowsing`, `securitytrails`, `builtwith`, `circl`, `intelx`, `github`) (et de tout service dont un module fournit le test) par un appel réel minimal (corps `{}` en JSON) → `{"service", "success", "message"}` ; `404` si le service est inconnu |
| `GET` | `/api/modules` | oui | Catalogue des modules de scan, tel que chaque module le déclare : clé, famille, catégorie, clés API (renseignées ou non), vague, dépendances, profil rapide, délai propre, critères du score et textes d'aide dans la langue de la requête (`help`), puis, si le module les renseigne, son « Comment corriger » : `fix` (étapes, une par ligne), `fix_snippet` (extrait à copier) et `fix_ref` (documentation officielle), absents sinon |
| `GET` | `/api/scan/{id}/export` | oui | Rapport d'un scan : `format` = `json`, `csv`, `md`, `html`, `pdf`, `sarif` ou `junit`, `lang` = `fr` ou `en` ; fichier en pièce jointe. `422` format inconnu, `503` PDF indisponible (Chromium absent) |
| `GET` | `/api/dashboard` | oui | Tableau de bord : dernier scan, note, tendance et constats de chaque domaine, totaux |
| `GET` | `/api/compare?a=&b=` | oui | Différences entre deux scans d'un même domaine (`400` si les domaines diffèrent). Un constat n'est « résolu » que si son module a tourné dans le second scan |
| `POST` | `/api/batches` | oui | Lot : `{"domains": […], "profile", "selected", "authorized_target"}` → `202`, scans lancés un par un |
| `GET` | `/api/batches`, `/api/batches/{id}` | oui | Lots récents ; état et résultats d'un lot |
| `POST` | `/api/batches/{id}/cancel` | oui | Annule les scans restants du lot |
| `GET` `POST` | `/api/watches` | oui | Liste ou crée une surveillance (`domain`, `profile`, `frequency`, `rules`, `channels`, `lang`) |
| `GET` `PATCH` `DELETE` | `/api/watches/{id}` | oui | Lit, modifie ou supprime une surveillance |
| `POST` | `/api/watches/{id}/run` | oui | Lance la surveillance tout de suite |
| `GET` | `/api/monitor/task` | oui | État de la tâche système de surveillance |
| `POST` | `/api/monitor/task/install`, `/api/monitor/task/uninstall` | oui | Installe ou retire la tâche système (corps `{}` en JSON, sans droits administrateur ; depuis la machine locale seulement, sinon `403` `api.local_only`) |
| `POST` | `/api/import` | oui | Importe une ancienne base DomainRecon : `multipart/form-data`, un seul champ fichier `file` (512 Mio au plus, un import à la fois). → `{"read", "imported", "ignored", "duplicates", "unusable", "unknown_columns"}`, avec `read = imported + ignored` et `ignored = duplicates + unusable` ; renvoyer le même fichier n'importe rien. Depuis la machine locale et l'interface seulement (`403`). `400` formulaire, fichier absent, pas une base SQLite ou pas une base DomainRecon ; `409` import déjà en cours ; `413` trop gros ; `415` pas du multipart. Les captures d'écran ne sont pas reprises |
| `POST` | `/api/system/backup` | oui | Copie cohérente de la base SQLite (`.db`, réimportable par `/api/import`) ; `409` sans base SQLite. Corps `{}` en JSON, machine locale seulement |
| `POST` | `/api/system/uninstall` | oui | Désinstallation complète. `{"dry_run": true}` liste ce qui serait supprimé ; `{"confirm": "SUPPRIMER", "remove_program": false}` arrête la surveillance, retire la tâche système, supprime données, clés, réglages, caches et temporaires de DomainRecon, puis prépare la suite après fermeture (désinstalleur Windows, programme portable). → détail par élément et étapes restantes ; `400` sans le mot de confirmation. Machine locale seulement ; ensuite l'API répond `410` |
| `POST` | `/api/system/uninstall/finish` | oui | Ferme l'application après la désinstallation (`{"exiting": false}` si elle ne sait pas se fermer seule) |
| `GET` `DELETE` | `/api/notifications` | oui | Centre de notifications : liste (`unread`, `items`) ; `DELETE` les efface toutes |
| `POST` | `/api/notifications/read` | oui | Marque des notifications comme lues |
| `DELETE` | `/api/notifications/{id}` | oui | Supprime une notification |
| `GET` | `/api/notify/channels` | oui | Canaux d'alerte (`discord`, `slack`, `teams`, `webhook`, `email`, `desktop`), secrets masqués |
| `PUT` `DELETE` | `/api/notify/channels/{nom}` | oui | Configure ou retire un canal (secrets chiffrés) |
| `POST` | `/api/notify/channels/{nom}/test` | oui | Envoie un message de test sur ce canal |
| `GET` | `/` et toute route hors `/api` | non | Interface web (application monopage) |

\* Seulement si `API_TOKEN` est défini.

## Clés d'API

Les clés API enregistrées dans les Réglages sont chiffrées dans la base (Fernet) ;
la clé de chiffrement est le fichier `.secret_key` du dossier des données, créé
au premier usage. Une sauvegarde de la base sans ce fichier ne révèle aucune clé ;
sans lui, les clés sont à ressaisir.

## Exemples

Exemples sur `127.0.0.1:8000` (mode `--server` ; en mode fenêtre ou
navigateur, le port est 47815 ou un port libre) :

```bash
# Lancer un scan en tâche de fond, puis suivre son avancement en direct
curl -s -X POST http://127.0.0.1:8000/api/scans -H "Content-Type: application/json" -d '{"domain": "example.com"}'
# {"id": "3f2c…", "status": "running"}
curl -N http://127.0.0.1:8000/api/scans/3f2c…/events
# event: module
# data: {"name": "dns_records", "family": "dns", "status": "ok", "duration": 0.42}
# …
# event: done
# data: {"scan_id": 12}
curl "http://127.0.0.1:8000/api/scan/12?lang=en"
```

## Réponses et erreurs

Un scan renvoyé contient, en plus des résultats des modules (`dns_records`,
`tls_certificate`…), `security_score`, `module_status` (statut réel de chaque
module lancé : `ok`, `failed`, `timeout`, `skipped` ; un module non lancé n'y
figure pas), `families` (pour `web`, `tls`, `email`, `dns`, `network`,
`identity`, `reputation`, `leaks` : `state`, `grade`, `summary`) et
`findings` (points à corriger triés par gravité : `severity`, `family`,
`module`, `message`). Les erreurs ont toujours la forme
`{"detail": "<message traduit>", "code": "<code du message>", "params": {…}}` :
`400` cible invalide ou refusée, `401` jeton, `403` action réservée à la
machine locale, `404` introuvable, `413` corps de plus de 1 Mio (512 Mio pour
`/api/import`), `415` corps non JSON, `422` paramètre invalide, `429` trop de
scans en cours (`Retry-After: 30`), `503` base indisponible.

## Protections

- Chaque réponse porte `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY` et une `Content-Security-Policy`. Celle de l'interface est stricte : scripts,
  styles, polices et requêtes vers l'application seule (`script-src 'self'`, sans `'unsafe-inline'` ni CDN).
  Les réponses de l'API et les captures ont `default-src 'none'`.
- Aucune ressource externe au chargement de l'interface : polices, bibliothèques et carte du monde sont
  embarquées.
- `POST` et `PATCH` exigent `Content-Type: application/json` (protection CSRF) ; corps limité à 1 Mio ;
  scans simultanés limités (`MAX_CONCURRENT_SCANS`). Seule exception : `POST /api/import` reçoit un fichier
  en `multipart/form-data` (512 Mio au plus), réservé aux requêtes locales venues de l'interface.
- Ouvrir le dossier des données, installer ou retirer la tâche système, importer ou sauvegarder une base et
  désinstaller ne sont possibles que depuis la machine locale (`403` sinon), même avec le jeton.
