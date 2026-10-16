# Ligne de commande

La commande `domainrecon` lance l'application et offre des sous-commandes. Sous Windows, utilisez
`DomainRecon-console.exe`, dans le dossier d'installation ou de la version portable (`DomainRecon.exe` ouvre
la fenêtre, sans console). Les scans lancés en ligne de commande sont enregistrés dans le même historique que
ceux de l'interface.

`domainrecon --help` et `domainrecon <commande> --help` donnent le détail de chaque option.

## Lancer l'application

```text
domainrecon                 fenêtre native (mode par défaut)
domainrecon --browser       serveur local et navigateur par défaut
domainrecon --server        serveur seul, sans interface (API, accès réseau)
```

| Option | Effet |
|---|---|
| `--host HÔTE` | Interface d'écoute (défaut : `127.0.0.1`). |
| `--port PORT` | Port d'écoute. Fenêtre et navigateur : 47815 s'il est libre, sinon un port libre. `--server` : `PORT` du `.env`, sinon 8000. |
| `--no-open` | N'ouvre pas le navigateur (`--browser`). |
| `--version` | Affiche la version et quitte. |

`--host` et `--port` ont priorité sur le `.env`. Un port stable garde la même adresse d'un lancement à l'autre,
donc la langue choisie reste mémorisée.

- **Repli** : si la fenêtre native ne peut pas s'ouvrir (WebView2 absent sous Windows, WebKitGTK absent sous
  Linux), DomainRecon s'ouvre dans le navigateur.
- **Arrêt** : fermer la fenêtre arrête DomainRecon. En mode `--browser` ou `--server`, fermez la console ou
  faites Ctrl+C. En mode `--browser`, le serveur s'arrête aussi seul environ 2 minutes après la fermeture du
  dernier onglet, jamais pendant un scan.

## Sous-commandes

| Commande | Rôle |
|---|---|
| `scan` | Scanne un domaine, l'enregistre et produit un rapport. |
| `batch` | Scanne les domaines d'un fichier `.txt` ou `.csv`, un par un, et résume les notes. |
| `history` | Liste les scans enregistrés et leurs identifiants. |
| `export` | Écrit le rapport d'un scan enregistré. |
| `modules` | Liste les modules du registre. |
| `import` | Importe les scans d'une ancienne base SQLite DomainRecon. |
| `monitor` | Surveillance : `run-due`, `list`, `task`. |

### scan

```bash
domainrecon scan example.com
domainrecon scan example.com --profile rapide --format html -o rapport.html
domainrecon scan example.com --profile personnalise --modules dns_records,open_ports --authorized
domainrecon scan example.com --fail-under B
```

| Option | Effet |
|---|---|
| `--profile rapide\|complet\|personnalise` | Profil (défaut : `complet`). `personnalise` exige `--modules`. |
| `--modules a,b,c` | Modules du profil personnalisé (clés de [Modules](modules.md)). |
| `--authorized` | Déclare l'autorisation de tester la cible (modules actifs ou sensibles). |
| `--fail-under NOTE` | Code de sortie 1 si la note est inférieure à NOTE (A à F ; `N/A` compte comme inférieure). |
| `--format FORMAT` | `text` (défaut), `json`, `csv`, `md`, `html`, `pdf`, `sarif`, `junit`. |
| `-o, --output FICHIER` | Écrit le rapport dans ce fichier (obligatoire pour `pdf`). |
| `--lang fr\|en` | Langue des textes. |
| `-q, --quiet` | Pas d'avancement sur la sortie d'erreur. |

`--fail-under` et les formats `sarif` et `junit` servent à intégrer DomainRecon à une chaîne d'intégration
continue.

### batch

```bash
domainrecon batch domaines.txt --format pdf --output-dir rapports
```

Mêmes options que `scan` pour le profil, l'autorisation, `--fail-under` et la langue. `--format` (tous sauf
`text`) écrit un rapport par domaine dans le dossier `--output-dir`.

### history et export

```bash
domainrecon history -n 20 --domain example.com
domainrecon export 12 --format sarif -o scan12.sarif
```

`history` filtre par domaine (`--domain`), note (`--grade`) et statut (`--status success|partial|error`), en
texte ou en JSON (`--format json`). `export` prend l'identifiant donné par `history` ; son format par défaut
est `html`.

### modules

```bash
domainrecon modules --family web
domainrecon modules --format json
```

### import

```bash
domainrecon import ancienne_base.db --dry-run
domainrecon import ancienne_base.db
```

La base est lue en lecture seule ; les doublons sont ignorés. `--dry-run` compte sans rien écrire.

### monitor

```bash
domainrecon monitor run-due              # lance les surveillances échues
domainrecon monitor run-due --dry-run    # les liste sans rien lancer
domainrecon monitor list                 # surveillances et prochaine échéance
domainrecon monitor task install         # tâche système horaire (status, install, uninstall)
```

Voir [Surveillance et alertes](surveillance.md).

## Rapports PDF

Le PDF est produit par le Chromium embarqué dans les livrables. Depuis les sources, installez-le avec
`python -m playwright install --only-shell chromium`. Sans lui, la commande propose un autre format ; le scan
reste enregistré.
