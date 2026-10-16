# Confidentialité

DomainRecon est une application locale. Il n'y a ni compte, ni serveur central, ni télémétrie.

## Ce qui reste sur votre machine

- L'historique des scans, les captures d'écran, les rapports, les réglages et les journaux sont écrits dans le
  dossier des données (voir [Installation](installation.md#où-sont-mes-données-)).
- Les clés d'API et les secrets des canaux d'alerte sont chiffrés dans la base ; la clé de chiffrement est le
  fichier `.secret_key` du même dossier.
- L'interface ne charge aucune ressource externe : polices, bibliothèques et carte du monde sont embarquées.
- Le serveur n'écoute que sur `127.0.0.1` par défaut.

## Ce qui sort de votre machine pendant un scan

Un scan doit contacter des tiers pour mesurer quelque chose. Seules les données nécessaires partent :

| Destinataire | Ce qui est envoyé | Quand |
|---|---|---|
| La cible | Requêtes DNS, HTTP, TLS ; capture d'écran ; sondes des modules actifs | À chaque scan, selon le profil |
| Sources publiques (crt.sh, Cert Spotter, ipinfo.io, HackerTarget, serveurs WHOIS, Wayback Machine…) | Le nom de domaine ou l'adresse IP analysés | Modules passifs |
| Services à clé d'API (VirusTotal, Shodan, Censys…) | Le domaine ou l'adresse, avec votre clé | Seulement si vous avez enregistré la clé |
| Vos canaux d'alerte (webhook, e-mail) | Le message d'alerte | Seulement si vous les configurez |
| `am.i.mullvad.net` | Une requête de statut | Quand l'écran Réglages affiche le statut du VPN, si le CLI Mullvad est absent |

Le réglage **proxy** fait passer les requêtes HTTP des modules par le proxy de votre choix (voir
[Configuration](configuration.md#proxy-sortant)).

## Effacer vos données

Supprimez un scan depuis l'historique, ou tout effacer avec la [désinstallation complète](desinstallation.md).
