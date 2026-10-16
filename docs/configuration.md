# Configuration

Tous les réglages sont facultatifs. La plupart se font dans l'écran **Réglages** (clés d'API, délais, capture
d'écran, proxy, canaux d'alerte, thème, langue). Les réglages du serveur passent par des variables
d'environnement ou un fichier `.env` placé dans le dossier des données. Le fichier
[`.env.example`](../.env.example) les décrit tous.

## Dossier des données

| Mode | Dossier des données (et du `.env`) |
|---|---|
| Installé (Windows) | `%LOCALAPPDATA%\DomainRecon` |
| Installé (Linux) | `$XDG_DATA_HOME/domainrecon` (défaut `~/.local/share/domainrecon`) |
| Portable (zip) | `data\` à côté de l'exécutable |
| Portable (`.exe` seul) | `DomainRecon-data\` à côté du `.exe` |
| Depuis les sources | `private/data/` à la racine du dépôt (`.env` accepté aussi à la racine) |

## Variables

| Variable | Défaut | Rôle |
|---|---|---|
| `HOST` | `127.0.0.1` | Interface d'écoute de `domainrecon --server` (l'option `--host` a priorité). |
| `PORT` | `8000` | Port de `domainrecon --server` (l'option `--port` a priorité). |
| `DATA_DIR` | selon le mode | Dossier des données (relatif : depuis le dossier de l'application). |
| `DATABASE_URL` | SQLite dans le dossier des données | Autre base (PostgreSQL, depuis les sources). |
| `LOG_LEVEL` | `INFO` | Niveau des journaux. |
| `API_TOKEN` | aucun | Jeton exigé par l'API (voir plus bas). |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Valeurs acceptées dans l'en-tête `Host` (`*` : aucun contrôle). |
| `CORS_ORIGINS` | vide | Origines autorisées à appeler l'API depuis un autre site. L'interface n'en a pas besoin. |
| `API_DOCS` | `1` | `0` masque `/api/docs`, `/api/redoc` et `/api/openapi.json`. |
| `MAX_CONCURRENT_SCANS` | `2` | Scans simultanés au maximum ; au-delà, l'API répond `429`. |
| `ALLOW_PRIVATE_TARGETS` | `0` | `1` autorise l'analyse de cibles non publiques (votre réseau local). |
| `SCHEDULER` | `1` | `0` désactive le planificateur intégré de la surveillance. |
| `DOMAINRECON_PORTABLE` | `0` | `1` active le mode portable sans fichier `portable.flag`. |
| `DOMAINRECON_NUCLEI_PATH` | aucun | Chemin du binaire [Nuclei](https://github.com/projectdiscovery/nuclei), pour le module `nuclei`. |

Une valeur vide vaut « non définie » ; une valeur invalide est signalée dans les journaux et remplacée par la
valeur par défaut. Le `.env` doit être en UTF-8 (ou en UTF-16 avec BOM, ce qu'écrit Windows PowerShell 5.1).

## Proxy sortant

Le réglage **proxy** de l'écran Réglages (chiffré au repos) s'applique, pendant un scan, à toutes les requêtes
HTTP des modules : sondes de la cible, services tiers et capture d'écran. À défaut, les variables standard
`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` et `NO_PROXY` sont utilisées. Les requêtes DNS et WHOIS, le scan de
ports et la sonde TLS n'y passent pas (connexions directes, par conception). La protection contre les
requêtes vers des adresses internes reste active derrière le proxy.

L'écran Réglages affiche aussi le statut du VPN Mullvad, en lecture seule.

## Usage local par défaut

- Le serveur n'écoute que sur `127.0.0.1` : DomainRecon n'est joignable que depuis votre machine.
- Aucun jeton n'est exigé en local.
- L'en-tête `Host` doit figurer dans `ALLOWED_HOSTS` : une page web tierce ne peut pas atteindre l'API par
  DNS rebinding.

## Exposer DomainRecon sur le réseau

```bash
domainrecon --server --host 0.0.0.0 --port 8000
```

avec, dans le `.env` du dossier des données :

```ini
ALLOWED_HOSTS=localhost,127.0.0.1,::1,recon.lan,192.168.1.10
API_TOKEN=remplacez-moi
```

- **`ALLOWED_HOSTS`** : un nom ou une adresse absents reçoivent `400`. Joker accepté (`*.exemple.com`) ; le
  port est ignoré.
- **`API_TOKEN`** : toute requête doit porter le jeton, dans l'en-tête `X-API-Token: <jeton>` ou
  `Authorization: Bearer <jeton>`, sinon `401`. Pour en générer un :
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`. L'interface demande le jeton à la première
  requête refusée.
- **HTTPS** : le jeton circule en clair sur HTTP. Hors d'un réseau de confiance, placez DomainRecon derrière
  un reverse proxy HTTPS (Caddy, nginx, Traefik) et ajoutez à `ALLOWED_HOSTS` le nom public transmis dans
  `Host`.

Certaines actions restent réservées à la machine locale, même avec le jeton : ouvrir le dossier des données,
installer la tâche de surveillance, importer ou sauvegarder une base, désinstaller.

## Cibles analysées

Par défaut, seules les adresses publiques sont analysées : boucle locale, réseaux privés, lien local (dont les
métadonnées cloud `169.254.169.254`), plages partagées, réservées ou multicast sont refusés. Le contrôle porte
sur les adresses résolues, pas sur le texte saisi, et il est refait à chaque requête HTTP, redirections
comprises. La capture d'écran passe par un proxy local qui applique la même règle à chaque ressource chargée.
`ALLOW_PRIVATE_TARGETS=1` lève cette restriction pour analyser votre propre réseau : ne l'activez jamais sur
une instance exposée.

## API

Le serveur expose une API locale documentée : voir [API](api.md).
