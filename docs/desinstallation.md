# Désinstallation

## Désinstallation simple

| Mode | Retirer le programme | Vos données |
|---|---|---|
| Installeur Windows | **Paramètres > Applications > DomainRecon > Désinstaller** | Le désinstalleur demande s'il faut les supprimer ; par défaut, elles sont conservées. |
| Portable un seul fichier | Supprimez le `.exe` | Supprimez le dossier `DomainRecon-data` à côté. |
| Portable zip | Supprimez le dossier extrait | Comprises dans le dossier (`data\`). |
| Paquet .deb | `sudo apt remove domainrecon` | Restent dans `~/.local/share/domainrecon`. |

## Désinstallation complète

**Réglages > Zone de danger > Désinstaller complètement DomainRecon** retire tout ce que l'application a
créé, en quatre étapes :

1. liste « à blanc » de ce qui sera supprimé, avec la taille libérée ;
2. sauvegarde facultative de la base (`.db`, réimportable) ;
3. mot de confirmation à taper : `SUPPRIMER` (ou `DELETE` en anglais) ;
4. bilan élément par élément, puis bouton **Fermer DomainRecon**.

Sont supprimés dans tous les cas :

- la base `domainrecon.db` et ses fichiers `-journal`, `-wal`, `-shm` (historique, surveillances, réglages,
  clés d'API chiffrées) ;
- les captures (`screenshots/`), les journaux (`logs/`), le stockage de la fenêtre native (`webview/`) ;
- `.env` et `.secret_key` ;
- la tâche de surveillance : tâche planifiée `DomainRecon-Monitor` sous Windows, unités systemd
  `domainrecon-monitor.service` et `domainrecon-monitor.timer` sous Linux ;
- les fichiers temporaires `domainrecon-import-*`, `domainrecon-cert-*` et `domainrecon-backup-*`.

Ensuite, selon le mode :

| Mode | Dossier des données | Après la fermeture |
|---|---|---|
| Installeur Windows | `%LOCALAPPDATA%\DomainRecon` | Le désinstalleur est lancé en silencieux : programme, raccourcis et entrée « Applications installées » sont retirés. |
| Portable un seul fichier | `DomainRecon-data` à côté du `.exe` | Case « supprimer aussi le programme » : le `.exe` est supprimé. |
| Portable zip | `data\` du dossier | Même case : seuls les fichiers connus du programme sont supprimés, le dossier seulement s'il est vide. |
| Paquet .deb | `~/.local/share/domainrecon` | Reste à taper `sudo apt remove domainrecon` (bouton Copier). |
| Depuis les sources | `private/data/` | Le dossier des sources reste en place. Le cache Chromium de Playwright, partagé, n'est pas supprimé. |

## Garde-fous

- Aucun chemin ne vient de l'interface. L'action n'est acceptée que depuis la machine locale et exige le mot
  de confirmation.
- Rien n'est supprimé hors des dossiers propres à DomainRecon : chemins résolus, liens symboliques et
  jonctions retirés sans être suivis.
- Un `DATA_DIR` personnalisé ne perd que les fichiers connus. Un dossier dangereux (racine d'un disque,
  dossier personnel, dossier temporaire) et une base externe (PostgreSQL, fichier hors du dossier des
  données) ne sont jamais touchés et sont signalés.
- Ce qui est verrouillé pendant l'exécution (journal, `webview/` sous Windows) est supprimé juste après la
  fermeture.
