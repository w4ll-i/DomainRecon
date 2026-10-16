# Score de sécurité

Chaque scan reçoit un score sur 100 et une note de A à F. Le principe : **seuls les critères mesurés
comptent**, et une note n'est donnée que si la mesure est assez large.

## Notes

| Score | Note |
|---|---|
| 90 à 100 | A |
| 75 à 89 | B |
| 55 à 74 | C |
| 35 à 54 | D |
| 0 à 34 | F |
| | `N/A` : couverture inférieure à 50 %, ou aucun critère compté |

## Barème des critères historiques

| Critère | Points | Calcul |
|---|---|---|
| En-têtes de sécurité | 25 | 6 en-têtes OWASP, valeur vérifiée (partiel = moitié des points). HSTS non noté sur une cible IP. |
| Certificat TLS | 20 | Valide : 10 ; +5 au-delà de 30 jours restants (+2 au-delà de 7) ; +5 en TLS 1.3 (+3 en TLS 1.2). Invalide ou sans HTTPS : 0. |
| Sécurité e-mail | 15 | Note SPF, DMARC, DKIM : A 15, B 12, C 8, D 4, F 0. Plafonnée à C tant que DMARC n'est pas appliqué. |
| WAF | 10 (bonus) | Détection passive. Sans WAF, le critère sort du calcul, sans pénalité. Un CDN seul ne rapporte rien. |
| Cookies | 10 | Note Secure, HttpOnly, SameSite : A 10, B 7, C 4, D 2, F 0. |
| CORS | 10 | 10 sans problème ; 4 pour une origine reflétée sans credentials ou `*` avec credentials ; 0 pour une origine arbitraire reflétée avec credentials. |
| Redirection HTTPS | 5 | HTTP redirige vers HTTPS, ou le site n'est servi qu'en HTTPS. |
| Subdomain takeover (module actif) | 5 | 5 sans takeover ; 2 ou 4 à vérifier selon le risque ; 0 si confirmé. |

Les autres modules déclarent leurs propres critères (50 en tout, de 2 à 25 points chacun), qui s'ajoutent
au barème applicable.

## Calcul

```text
score = round(points obtenus / points des critères comptés × 100) - pénalités, borné entre 0 et 100
```

- Un critère qui n'a pas pu être évalué (module en échec ou hors délai, site injoignable, aucun cookie posé,
  critère sans objet) est **exclu du calcul** au lieu de compter comme conforme.
- Un module non lancé par le profil choisi n'est jamais compté comme réussi : son critère reste dans le
  barème applicable et la couverture baisse. Exception : un module actif, sensible ou à clé d'API non lancé
  est simplement omis.
- **Couverture** : part du barème applicable qui a pu être mesurée. Confiance élevée à partir de 80 %,
  moyenne en dessous, faible sous 50 % (note `N/A`).

## Pénalités

Services sensibles trouvés ouverts par le scan de ports (module actif), cumulables :

| Gravité | Points | Services (ports) |
|---|---|---|
| Critique | -15 | Telnet (23), SMB (445), API Docker (2375), Redis (6379), Elasticsearch (9200), Memcached (11211), MongoDB (27017) |
| Élevée | -10 | MS-RPC (135), NetBIOS (139), SQL Server (1433), Oracle (1521), NFS (2049), MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900), CouchDB (5984), WinRM (5985, 5986) |
| Moyenne | -5 | FTP (21) |

Aucune pénalité si le scan de ports a échoué ou n'a pas été lancé.

## Plafond

Une faille critique plafonne la note à **D** (score ramené à 54 au plus) : prise de contrôle de sous-domaine
confirmée, ou CORS qui reflète une origine arbitraire avec `Access-Control-Allow-Credentials: true`.

## Dans les données du scan

Le détail est exposé dans `security_score` (export JSON, API) :

```json
"security_score": {
  "version": 4,
  "score": 71, "grade": "C", "grade_reason": null, "max_score": 100,
  "coverage": 90,
  "measured_points": 57,
  "measured_max": 80,
  "confidence": "high",
  "breakdown": {
    "waf": { "score": 0, "max": 10, "measured": true, "counted": false, "applicable": true, "detail": "Aucun WAF détecté, sans pénalité" }
  },
  "penalties": [],
  "grade_cap": null,
  "grade_cap_reasons": []
}
```

Un scan noté avec une version antérieure du barème est relu tel qu'il a été enregistré, sans recalcul.
