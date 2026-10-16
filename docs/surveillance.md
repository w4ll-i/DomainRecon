# Surveillance et alertes

L'écran **Surveillance** relance régulièrement le scan d'un domaine et vous prévient quand la situation se
dégrade. Pour chaque domaine surveillé : un profil de scan, une fréquence (quotidienne, hebdomadaire ou
mensuelle), des règles d'alerte et des canaux.

## Règles d'alerte

| Règle | Déclenchement |
|---|---|
| Baisse de la note | La note affichée baisse (de A à B, par exemple). |
| Nouveaux constats | Un constat critique ou élevé apparaît. |
| Certificat bientôt expiré | Le certificat expire dans N jours ou moins (14 par défaut). |
| Nouveau port ouvert | Un port s'ouvre (scan de ports : profil personnalisé avec autorisation). |
| Nouveau sous-domaine | Un sous-domaine apparaît. |

Une alerte n'est pas répétée tant que la situation ne change pas.

## Canaux

| Canal | Configuration |
|---|---|
| Centre de notifications | Toujours actif, dans l'application. |
| Notification de bureau | Notification du système. |
| Discord, Slack, Teams | Adresse du webhook entrant. |
| Webhook JSON | Adresse d'un service à vous, qui reçoit un JSON générique. |
| E-mail | Serveur SMTP chiffré, identifiants, destinataires. |

Les canaux se configurent dans **Réglages > Canaux d'alerte**, avec un bouton d'envoi de test. Leurs secrets
sont chiffrés comme les clés d'API.

## Exécution

- **Application ouverte** : un planificateur intégré lance les scans échus.
- **Application fermée** : une tâche système prend le relais. Le bouton de l'écran Surveillance, ou
  `domainrecon monitor task install`, crée une tâche du Planificateur de tâches sous Windows
  (`DomainRecon-Monitor`), ou un minuteur systemd de l'utilisateur sous Linux. Elle exécute
  `domainrecon monitor run-due` toutes les heures, sans droits d'administrateur.
  `domainrecon monitor task uninstall` la retire, `domainrecon monitor task status` affiche son état.
- **À la main** : `domainrecon monitor run-due` lance les surveillances échues ; `--dry-run` les liste sans
  rien lancer. `domainrecon monitor list` affiche les surveillances et leur prochaine échéance.

Une surveillance ne tourne jamais deux fois en même temps : chaque exécution prend un bail dans la base. Le
planificateur intégré, la tâche système et `monitor run-due` peuvent donc coexister ; « Lancer maintenant »
pendant un scan ne crée pas de doublon.

Le planificateur intégré se désactive avec `SCHEDULER=0` (voir [Configuration](configuration.md)).
Installer ou retirer la tâche système n'est possible que depuis la machine locale.
