# Clés d'API

Aucune clé n'est nécessaire pour utiliser DomainRecon : les 56 modules passifs fonctionnent sans. Une clé
débloque un module qui en dépend (clé **requise**) ou enrichit un module qui tourne déjà sans elle (clé
**facultative**).

## Enregistrer une clé

1. Ouvrez **Réglages > Clés API**.
2. Collez la clé dans le champ du service (saisie masquée), puis cliquez sur **Enregistrer les clés**.
3. Cliquez sur **Tester** : DomainRecon fait un appel réel minimal au service avec la clé enregistrée et
   affiche le résultat.

Les clés sont chiffrées dans la base locale (Fernet). La clé de chiffrement est le fichier `.secret_key` du
dossier des données : une sauvegarde de la base sans ce fichier ne révèle aucune clé, mais sans lui les clés
sont à ressaisir. Les clés ne quittent votre machine que vers le service concerné.

## Services pris en charge

| Service | Modules | Clé | Où l'obtenir | Coût |
|---|---|---|---|---|
| SecurityTrails | `securitytrails`, `subdomains_passive` | Requise pour `securitytrails` | [securitytrails.com](https://securitytrails.com/) | Offre gratuite limitée |
| Censys | `censys` | Requise (identifiant et secret) | [censys.com](https://censys.com/) | Offre gratuite limitée |
| VirusTotal | `virustotal` | Requise | [virustotal.com](https://www.virustotal.com/) | API publique gratuite, quotas réduits |
| AbuseIPDB | `abuseipdb` | Requise | [abuseipdb.com](https://www.abuseipdb.com/) | Offre gratuite |
| Google Safe Browsing | `safebrowsing` | Requise | [Google Cloud Console](https://console.cloud.google.com/) | Gratuit pour un usage non commercial |
| LeakIX | `leakix` | Requise | [leakix.net](https://leakix.net/) | Offre gratuite limitée |
| Intelligence X | `intelx`, `paste` | Requise pour `intelx` | [intelx.io](https://intelx.io/) | Offre gratuite limitée |
| GitHub | `github_dork`, `paste` | Requise pour `github_dork` | [Jeton d'accès personnel](https://github.com/settings/tokens) | Gratuit |
| EmailRep | `emailrep` | Requise | [emailrep.io](https://emailrep.io/) | Offre gratuite limitée |
| Shodan | `shodan` | Facultative | [shodan.io](https://www.shodan.io/) | Compte gratuit limité, offres payantes |
| AlienVault OTX | `otx`, `pdns_data` | Facultative | [otx.alienvault.com](https://otx.alienvault.com/) | Gratuit |
| urlscan.io | `urlscan` | Facultative | [urlscan.io](https://urlscan.io/) | Offre gratuite |
| ipinfo.io | `geo_data`, `network_extended` | Facultative | [ipinfo.io](https://ipinfo.io/) | Offre gratuite |
| BuiltWith | `builtwith` | Facultative | [builtwith.com](https://builtwith.com/) | API gratuite limitée, offres payantes |
| CIRCL (DNS passif) | `pdns_data` | Facultative (identifiant et mot de passe) | [circl.lu](https://www.circl.lu/services/passive-dns/) | Accès gratuit sur demande |
| Have I Been Pwned | `hibp` | Facultative | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) | Payant (abonnement) |

Les conditions et les quotas sont ceux des services au moment de la publication : vérifiez-les sur leur
site. Respectez leurs conditions d'utilisation.

## Ce qui change selon la catégorie

- Un module **clé d'API** (SecurityTrails, Censys, VirusTotal, AbuseIPDB, Google Safe Browsing) entre dans
  le profil complet dès que sa clé est enregistrée.
- Un module **sensible** qui demande une clé (LeakIX, Intelligence X, GitHub, EmailRep) exige en plus le
  profil personnalisé et l'autorisation de tester la cible.

La liste complète des modules et de leurs clés est dans [Modules](modules.md).
