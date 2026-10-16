# Politique de sécurité

## Versions prises en charge

| Version | Correctifs de sécurité |
|---|---|
| 1.0.x | Oui |
| Antérieures à 1.0 | Non |

Les correctifs sont publiés dans une nouvelle version, sur la page
[Releases](https://github.com/w4ll-i/DomainRecon/releases).

## Signaler une faille

Ne signalez pas une faille dans un ticket public.

Utilisez le signalement privé de GitHub : onglet **Security** du dépôt, puis **Report a vulnerability**
([lien direct](https://github.com/w4ll-i/DomainRecon/security/advisories/new)). Le rapport n'est visible que
par vous et par le mainteneur.

Indiquez si possible :

- la version et le livrable concernés (installeur, portable, `.deb`, sources) ;
- la description de la faille et son impact ;
- les étapes pour la reproduire, ou une preuve de concept ;
- une piste de correction, si vous en avez une.

## Ce qui se passe ensuite

- Accusé de réception sous 7 jours.
- Évaluation, puis correctif dans une nouvelle version selon la gravité.
- Publication d'un avis de sécurité une fois le correctif disponible. Vous y êtes cité si vous le souhaitez.

Merci de laisser le temps de publier le correctif avant toute divulgation.

## Périmètre

Sont concernés : l'application, son API locale, ses livrables et leur construction. Par exemple : contournement
de l'autorisation des modules actifs, de la protection anti-SSRF, du contrôle de l'en-tête `Host` ou du jeton
d'accès, exposition des clés d'API, exécution de code par un résultat de scan ou un rapport.

Ne sont pas concernés : les failles des services tiers interrogés par les modules, et les résultats d'un scan
sur un domaine (signalez-les à son propriétaire).

Testez uniquement sur votre propre installation et sur des domaines que vous administrez.
