# Modules

DomainRecon compte **84 modules**, répartis en 8 familles. Cette liste est tirée du registre
des modules (`domainrecon modules --format json`) ; un test vérifie qu'elle lui correspond.

## Catégories

| Catégorie | Modules | Quand le module est lancé |
|---|---|---|
| Passif | 56 | Profil complet (tous) et profil rapide (16 essentiels). Interroge la cible comme un visiteur ordinaire ou des sources publiques. |
| Clé d'API | 5 | Profils complet et personnalisé, dès que la clé du service est enregistrée dans les Réglages. |
| Actif | 14 | Profil personnalisé seulement, avec l'autorisation de tester la cible. Envoie à la cible des requêtes qui dépassent un usage normal. |
| Sensible | 9 | Profil personnalisé seulement, avec l'autorisation de tester la cible. Recherche des fuites, des secrets ou des données personnelles. |

Une clé d'API facultative améliore un module sans être nécessaire à son lancement. Voir [Clés d'API](cles-api.md).

## Par famille

- [Web](#web) : 29 modules
- [TLS](#tls) : 5 modules
- [E-mail](#e-mail) : 7 modules
- [DNS et sous-domaines](#dns-et-sous-domaines) : 16 modules
- [Réseau](#réseau) : 10 modules
- [Identité](#identité) : 3 modules
- [Réputation](#réputation) : 8 modules
- [Fuites de données](#fuites-de-données) : 6 modules

### Web

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| En-têtes de sécurité | `security_headers` | Passif | oui |  |
| HSTS et précharge | `hsts_preload` | Passif |  |  |
| Versions HTTP | `http_versions` | Passif |  |  |
| En-têtes complémentaires | `headers_extra` | Passif | oui |  |
| Note de la CSP | `csp_grade` | Passif | oui |  |
| Technologies | `technologies` | Passif | oui |  |
| WAF / CDN | `waf` | Passif | oui |  |
| Redirections | `redirect_chain` | Passif | oui |  |
| Fichiers web | `web_files` | Passif | oui |  |
| Fichiers informatifs et .well-known | `web_files_extra` | Passif |  |  |
| Cookies | `cookie_security` | Passif | oui |  |
| CORS | `cors` | Passif | oui |  |
| Fichiers sensibles exposés | `sensitive_files` | Actif |  |  |
| Panneaux d'administration | `admin_panels` | Actif |  |  |
| Empreinte CMS et expositions | `cms_data` | Actif |  |  |
| Endpoints API et de développement | `api_endpoints` | Actif |  |  |
| Buckets de stockage exposés | `cloud_storage` | Sensible |  |  |
| Méthodes HTTP | `http_methods` | Actif |  |  |
| MDN Observatory | `observatory` | Passif |  |  |
| Divulgations (versions, débogage, 404) | `dast_data` | Actif |  |  |
| Nuclei (scan de vulnérabilités) | `nuclei` | Actif |  |  |
| Pile technique | `tech_stack` | Passif | oui |  |
| Failles des technologies | `tech_cves` | Passif |  |  |
| Renseignements HTML | `html_intel` | Passif |  |  |
| Domaines liés | `linked_domains` | Passif |  |  |
| Empreinte du favicon | `favicon_hash` | Passif |  |  |
| Dépendances JavaScript | `js_dependencies` | Passif |  |  |
| Secrets dans le JavaScript | `js_secrets` | Sensible |  |  |
| BuiltWith | `builtwith` | Passif |  | BuiltWith (facultative) |

### TLS

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| Certificat TLS | `tls_certificate` | Passif | oui |  |
| TLS approfondi (protocoles et suites) | `tls_deep` | Actif |  |  |
| Audit cryptographique du certificat | `crypto_audit` | Passif |  |  |
| Révocation du certificat (OCSP et CRL) | `cert_revocation` | Passif |  |  |
| Historique des certificats (Certificate Transparency) | `ct_logs` | Passif |  |  |

### E-mail

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| Sécurité e-mail | `email_security` | Passif | oui |  |
| Clés DKIM | `dkim` | Passif |  |  |
| MTA-STS et TLS-RPT | `mta_sts` | Passif |  |  |
| BIMI | `bimi` | Passif |  |  |
| Risque d'usurpation | `spoofability` | Passif | oui |  |
| Fournisseur de messagerie | `mail_provider` | Passif |  |  |
| Sonde SMTP | `smtp_security` | Actif |  |  |

### DNS et sous-domaines

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| Enregistrements DNS | `dns_records` | Passif | oui |  |
| Enregistrements DNS complémentaires (CAA, SRV, TLSA) | `dns_records_extra` | Passif |  |  |
| Sous-domaines (sources passives complémentaires) | `subdomains_passive` | Passif |  | SecurityTrails (facultative) |
| Sous-domaines | `subdomains` | Passif |  |  |
| Brute-force de sous-domaines | `subdomain_bruteforce` | Actif |  |  |
| Transfert de zone DNS (AXFR) | `zone_transfer` | Actif |  |  |
| DNS wildcard (joker) | `wildcard_dns` | Passif |  |  |
| IP privée exposée en DNS | `dns_rebinding` | Passif |  |  |
| DNSSEC | `dnssec_data` | Passif |  |  |
| Comparaison DNS chiffré (DoH/DoT) | `doh_comparison` | Passif |  |  |
| Certificats publics (Certificate Transparency) | `certsh_data` | Passif |  |  |
| SecurityTrails | `securitytrails` | Clé d'API |  | SecurityTrails (requise) |
| DNS passif (historique) | `pdns_data` | Passif |  | CIRCL (facultative), AlienVault OTX (facultative) |
| DNS inverse (PTR) | `reverse_dns` | Passif | oui |  |
| Takeover de sous-domaines | `subdomain_takeover` | Actif |  |  |
| Détournement de sous-domaines (noms étendus) | `takeover_extended` | Passif |  |  |

### Réseau

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| Géolocalisation | `geo_data` | Passif | oui | ipinfo.io (facultative) |
| Ports ouverts | `open_ports` | Actif |  |  |
| Réseau étendu | `network_extended` | Passif |  | ipinfo.io (facultative) |
| BGP et système autonome | `bgp` | Passif |  |  |
| Registre RDAP de l'IP | `rdap_ip` | Passif |  |  |
| DNS passif (Robtex) | `robtex` | Passif |  |  |
| Shodan | `shodan` | Passif |  | Shodan (facultative) |
| Censys | `censys` | Clé d'API |  | Censys (requise) |
| Bannières de services | `banners` | Actif |  |  |
| IP d'origine derrière un CDN | `origin_ip` | Sensible |  |  |

### Identité

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| WHOIS / RDAP | `whois_data` | Passif |  |  |
| Capture d'écran | `screenshot` | Passif |  |  |
| Wayback Machine | `wayback_data` | Passif |  |  |

### Réputation

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| Listes noires DNS (DNSBL) | `dnsbl` | Passif |  |  |
| Réputation VirusTotal | `virustotal` | Clé d'API |  | VirusTotal (requise) |
| Réputation AlienVault OTX | `otx` | Passif |  | AlienVault OTX (facultative) |
| Réputation AbuseIPDB | `abuseipdb` | Clé d'API |  | AbuseIPDB (requise) |
| Google Safe Browsing | `safebrowsing` | Clé d'API |  | Google Safe Browsing (requise) |
| Hameçonnage (PhishTank, OpenPhish) | `phishing` | Passif |  |  |
| Historique urlscan.io | `urlscan` | Passif |  | urlscan.io (facultative) |
| Typosquatting | `typosquatting` | Passif |  |  |

### Fuites de données

| Module | Clé | Catégorie | Profil rapide | Clés d'API |
|---|---|---|---|---|
| Have I Been Pwned (brèches) | `hibp` | Sensible |  | Have I Been Pwned (facultative) |
| LeakIX (services exposés et fuites) | `leakix` | Sensible |  | LeakIX (requise) |
| Intelligence X (fuites d'identifiants) | `intelx` | Sensible |  | Intelligence X (requise) |
| GitHub dorks (secrets dans le code public) | `github_dork` | Sensible |  | GitHub (requise) |
| Pastes et code public | `paste` | Sensible |  | GitHub (facultative), Intelligence X (facultative) |
| EmailRep (réputation des adresses) | `emailrep` | Sensible |  | EmailRep (requise) |

## Consulter la liste à jour

```bash
domainrecon modules                 # tous les modules, dans l'ordre d'exécution
domainrecon modules --family tls    # une seule famille
domainrecon modules --format json   # format machine
```

Dans l'application, le profil **Personnalisé** de l'écran Scanner présente les mêmes modules, famille par
famille, avec leur badge de catégorie. L'API locale les expose sur `GET /api/modules`.

Ajouter un module : voir [Contrat des modules](contrat-modules.md).
