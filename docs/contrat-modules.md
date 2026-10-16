# Contrat des modules de scan — DomainRecon

Document de référence pour les développeurs qui ajoutent ou reprennent un module
(une famille de modules par développeur, en parallèle dans le même arbre).
Racine : `DomainRecon/`. Python ≥ 3.10, fichiers en UTF-8 **sans BOM**, fins de
ligne LF, commentaires et messages en français.

**Règle d'or : un module = des fichiers neufs, à vous. Vous ne modifiez AUCUN
fichier partagé** (liste en §12). Si un fichier partagé vous manque, signalez-le
au chef d'équipe au lieu de le modifier.

---

## 1. Ce que vous créez (et rien d'autre)

| Fichier | Rôle | Obligatoire |
|---|---|---|
| `domainrecon/scanner/modules/<clé>.py` | Déclaration `SPEC = ModuleSpec(...)`, `run()`, règles | oui |
| `domainrecon/i18n/modules/<clé>.fr.json` | Textes français du module | oui |
| `domainrecon/i18n/modules/<clé>.en.json` | Textes anglais du module | oui |
| `tests/scanner/modules/test_<clé>.py` | Tests du module (sans réseau) | oui |
| `domainrecon/scanner/impl/<clé>.py` (ou `impl/<clé>_*.py`) | Logique longue, testable seule | si besoin |

`<clé>` : `^[a-z][a-z0-9_]*$`, identique au nom des fichiers, à la clé de
`module_status`, aux préfixes des textes. Pas un nom réservé (`status`, `modules`,
`profile`, `tags`, `notes`, `families`, `findings`…). Exemples : `hibp`,
`dnsbl`, `github_leaks`, `ct_logs`.

Le dossier `modules/` est parcouru automatiquement : **aucune liste à compléter**.
Les fichiers dont le nom commence par `_` sont ignorés par la découverte.

Module d'exemple complet et commenté : `domainrecon/scanner/modules/email_security.py`.

---

## 2. Procédure pas à pas

1. Lire `scanner/registry.py` (ModuleSpec, ScanContext), `scanner/rules.py`
   (constats, score), `scanner/keys.py` (clés API) et le module d'exemple.
2. Créer `modules/<clé>.py` sur le gabarit du §3.
3. Créer les deux fragments de textes (§9), « Comment corriger » compris (§9.1).
4. Écrire `tests/scanner/modules/test_<clé>.py` (§10).
5. Vérifier, depuis `DomainRecon/` :

   ```
   PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 <python> -m pytest -q -p no:cacheprovider tests/scanner/modules tests/core/test_i18n.py
   <python> -m ruff check --no-cache domainrecon/scanner/modules/<clé>.py tests/scanner/modules/test_<clé>.py
   <python> -m ruff format --no-cache --check domainrecon tests
   ```

   puis la suite complète (`tests`) avant de rendre le travail.
6. Essai réel (§11) sur une cible publique autorisée.
7. Nouvelle dépendance PyPI : l'essayer dans le venv et la **signaler** au chef
   d'équipe (il met à jour `pyproject.toml` et `packaging/requirements.lock`).

---

## 3. Gabarit d'un nouveau module

```python
# =============================================================================
# DomainRecon - Module « hibp » : comptes du domaine dans des fuites de données
# =============================================================================
# Ce que fait le module, sa source (URL de la documentation officielle), ses limites.
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..keys import ApiKey, KeyTest, Probe
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule
from ..score import as_dict, as_list

_API = "https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"


async def run(context: ScanContext) -> dict:
    key = context.secrets.get("hibp_key")
    try:
        response = await context.http.get(
            _API.format(domain=context.apex), headers={"hibp-api-key": key}, timeout=15
        )
    except httpx.HTTPError as e:
        # Jamais str(e) : le texte d'une erreur httpx cite l'URL (et parfois la clé).
        raise ModuleError(msg("network.service_error", context="HIBP", detail=type(e).__name__)) from None
    if response.status_code == 429:
        raise ModuleError(msg("network.quota", service="HIBP"))
    if response.status_code == 404:
        return {"measured": True, "error": None, "accounts": 0, "breaches": []}
    if response.status_code != 200:
        raise ModuleError(msg("network.http_status", status=response.status_code, service="HIBP"))
    data = response.json()
    breaches = sorted({b for names in data.values() for b in names})
    return {"measured": True, "error": None, "accounts": len(data), "breaches": breaches}


def _check_breaches(f: FindingInput) -> dict | None:
    data = as_dict(f.data)
    count = len(as_list(data.get("breaches")))
    return {"count": count} if count else None


def _score(data: dict) -> Outcome:
    found = as_list(as_dict(data.get("hibp")).get("breaches"))
    return Outcome(0 if found else 5, msg("hibp.score_detail", count=len(found)), True)


SPEC = ModuleSpec(
    name="hibp",
    family="leaks",
    category="cle_api",
    run=run,
    keys=(ApiKey(name="hibp_key", service="hibp", label="Have I Been Pwned"),),
    key_tests={
        "hibp": KeyTest(
            "Have I Been Pwned",
            ("hibp_key",),
            probes=lambda s: [
                Probe(
                    "https://haveibeenpwned.com/api/v3/subscription/status",
                    headers={"hibp-api-key": s["hibp_key"]},
                )
            ],
        )
    },
    wave=1,
    timeout=30,
    skip_reason=skip_for_ip_target,
    optional=True,
    findings=(FindingRule(code="finding.hibp.breaches", severity="high", check=_check_breaches),),
    score_rules=(ScoreRule(criterion="hibp", weight=5, evaluate=_score),),
)
```

(`import httpx` en tête de fichier dans un vrai module.)

---

## 4. Champs du ModuleSpec

| Champ | Défaut | Règle |
|---|---|---|
| `name` | — | la clé (= nom du fichier) |
| `family` | — | `web`, `tls`, `email`, `dns`, `network`, `identity`, `reputation`, `leaks` |
| `category` | — | `passif`, `actif`, `cle_api`, `sensible` (§6) ; `api_key` accepté (ancien nom) |
| `run` | — | `async def run(context) -> dict` (§5) |
| `keys` | `()` | tuple d'`ApiKey` (§7) ; `required=False` = clé facultative |
| `key_tests` | `{}` | `{service: KeyTest}` : test de clé fourni par le module |
| `api_key` | `None` | ancienne forme : nom d'UNE clé requise |
| `wave` | `1` | 1 indépendant ; 2 lit la vague 1 ; 3 lourd, actif ou sensible |
| `depends_on` | `()` | modules de la même vague ou d'une vague antérieure ; leur résultat est dans `context.results` (absent s'ils ont échoué) |
| `timeout` | `None` | délai propre en secondes (≤ 900), **jamais écrasé** par les Réglages ; `None` = délai du profil (Réglages, 60 s / 30 s par défaut) |
| `skip_reason` | aucun | `skip_reason(context) -> message ou None` : « sans objet » sans exécuter. Aides : `skip_for_ip_target`, `skip_without_address` |
| `quick` | `False` | profil « rapide » (passif seulement ; dépendances rapides aussi) |
| `optional` | `False` | son échec ne dégrade pas le statut global du scan (services tiers capricieux) |
| `order` | `1000` | ordre d'exécution dans la vague et d'affichage (les 18 historiques : 10 à 180), puis le nom |
| `findings` | `()` | règles « À corriger » (§8) |
| `score_rules` | `()` | `ScoreRule` (critère) et `PenaltyRule` (pénalité hors barème) (§8) |
| `verdict` | `False` | son échec ou son absence, faute de note et de constat, rend la famille « non mesurée » |
| `placeholder` | `{measured: False, error}` | valeur enregistrée sans résultat ; à garder par défaut |

Réservés aux 18 modules historiques (ne pas utiliser) : `column`, `http_probe`,
`finalize`, `status_extras`, `score_extras`, `nxdomain`, `legacy_measured`.

Un `ModuleSpec` est validé à l'import : une erreur écarte le module (journal,
`registry.BROKEN_MODULES`) sans empêcher l'application de démarrer, et le test de
contrat échoue.

---

## 5. Contrat de `run(context)`

- Renvoie un **dict** avec `measured` (bool) et `error` (message `msg(...)` ou
  `None`), plus vos données. `measured=False` = mesure impossible (statut
  `failed`) ; ajouter `skipped: True` pour « sans objet » (statut `skipped`).
- Échec réel : `raise ModuleError(msg("code", ...))`. Sans objet découvert en
  route : `raise ModuleSkipped(msg(...))` (`scanner/errors.py`).
- **Types JSON uniquement** (str, int, float, bool, None, list, dict, `msg()`).
  Un set, datetime, bytes, objet… : le module passe en échec
  (`orchestrator.not_serializable`) — le scan est gardé, votre résultat perdu.
- **Aucun texte en dur** destiné à l'utilisateur : `msg("code", **params)` avec un
  code **littéral** (jamais calculé).
- **Jamais de clé API** dans un message, un journal ou le résultat. Ne jamais
  appeler `response.raise_for_status()` ni mettre `str(exception_httpx)` dans un
  message (l'URL peut contenir `?key=…`). Tester `status_code` ; clé en en-tête
  quand le service le permet.
- Ne jamais avaler `asyncio.CancelledError` (pas de `except BaseException`).
- Borner vos attentes : délais httpx, `timeout` du module, `asyncio.wait_for`
  pour les boucles. Code bloquant (bibliothèque synchrone) dans
  `await asyncio.to_thread(...)` avec ses propres bornes (un thread n'est pas
  interrompu par le délai du module).
- Volume : ne pas renvoyer des mégaoctets (listes plafonnées, avec le total).

Statuts possibles : `ok`, `failed`, `timeout`, `skipped`, et `not_launched` à la
lecture (module hors profil, clé absente, autorisation refusée).

---

## 6. Catégories, profils et autorisation

| Catégorie | Définition | Profils |
|---|---|---|
| `passif` | Sources publiques ou requêtes d'un visiteur ordinaire (DNS public, page d'accueil, journaux CT, API sans clé) | rapide (si `quick`), complet, personnalisé |
| `cle_api` | Passif, mais exige au moins une clé requise | complet (si toutes ses clés requises sont renseignées), personnalisé |
| `actif` | Sonde la cible au-delà d'un usage normal : scan de ports, fuzzing, requêtes forgées, nombreuses requêtes | personnalisé **et** `authorized_target: true` |
| `sensible` | Données personnelles ou fuites (identifiants, courriels), ou action à risque | personnalisé **et** `authorized_target: true` |

En cas de doute, prendre la catégorie la plus prudente (actif > passif). Un
module actif ou sensible n'est jamais dans les profils rapide et complet.
Tests réels d'un module actif : uniquement `scanme.nmap.org`,
`zonetransfer.me`, `testphp.vulnweb.com`, `badssl.com`.

---

## 7. Clés API

```python
ApiKey(name="censys_id", service="censys", label="Censys", free_text=True)
ApiKey(name="censys_secret", service="censys", label="Censys")
ApiKey(name="bonus_key", service="bonus", label="Bonus", required=False)
```

- `name` : nom de stockage (`[a-z][a-z0-9_]{1,63}`). Les 14 noms historiques
  (`shodan_key`, `virustotal_key`, `censys_id`, `censys_secret`, `abuseipdb_key`,
  `urlscan_key`, `otx_key`, `safebrowsing_key`, `securitytrails_key`,
  `builtwith_key`, `circl_user`, `circl_password`, `intelx_key`, `github_token`)
  sont à **réutiliser** pour ces services. Toute autre clé déclarée est acceptée
  par les Réglages (chiffrée, colonne `extra_secrets`) sans rien modifier.
- Deux modules qui déclarent la même clé doivent la déclarer à l'identique
  (`service`, `label`, `free_text`, `hidden`), sinon le second est écarté.
- `required=True` : sans elle le module n'est pas lancé. `False` : il tourne sans
  et lit `context.secrets.get(nom)` (mode dégradé).
- `free_text=True` : identifiant libre (sinon jeton ASCII sans espace) ;
  `hidden=True` : jamais affiché, espaces permis (mot de passe).
- **Valeurs** : `context.secrets[nom]`, seulement les clés que VOTRE module a
  déclarées et que l'utilisateur a renseignées.
- **Test de clé** (bouton « Tester » ; `POST /api/settings/test/<service>`) :
  services déjà testés par l'application : `shodan`, `virustotal`, `censys`,
  `abuseipdb`, `urlscan`, `otx`, `safebrowsing`, `securitytrails`, `builtwith`,
  `circl`, `intelx`, `github`. Pour un nouveau service, fournir
  `key_tests={"service": KeyTest(label, (clés,), probes=...)}` (requêtes GET
  minimales, URL fixe en https, qui ne consomment pas de crédit) ou
  `KeyTest(label, (clés,), run=async_fonction(secrets, client) -> CheckOutcome)`.
  Le test de contrat exige que chaque clé déclarée ait un service testable.

---

## 8. Constats et score

**Constats** (`scanner/rules.py`) : une `FindingRule` par code de message.

```python
FindingRule(code="finding.hibp.breaches", severity="high", check=_check)
```

- `check(f)` reçoit un `FindingInput` : `f.data` (votre résultat relu de la base),
  `f.measured(nom)`, `f.data_of(nom)` (autre module), `f.scan`.
- Rend `None`/`False` (rien), `True` (constat sans paramètre), un dict
  (paramètres du message), `hit(severity=..., **params)` (gravité variable) ou
  une liste de ceux-ci.
- Gravités : `critical`, `high`, `medium`, `low`. Lecture **défensive**
  (`as_dict`, `as_list`, `as_int` de `score.py`) : un ancien scan ou une donnée
  inattendue ne doit jamais lever (une règle qui lève est ignorée et journalisée).
- Évaluée seulement si le module est mesuré (`requires_measured=False` pour une
  règle qui recoupe plusieurs modules et fait ses propres contrôles).

**Score** :

```python
ScoreRule(criterion="hibp", weight=5, evaluate=_score)  # -> Outcome(points, detail, measured, ...)
PenaltyRule(evaluate=lambda data: [{"key": "...", "label": msg(...), "points": 10, "severity": "high"}])
```

- `criterion` unique dans tout le registre (prendre la clé du module).
- `evaluate(data)` : `data["<clé>"]` est votre résultat ; appelée seulement si le
  module a été lancé et mesuré. `Outcome(points, detail, measured, counted=True,
  cap_reason=None, applicable=True)` : `counted=False` pour un bonus non obtenu,
  `applicable=False` pour un critère sans objet, `cap_reason` plafonne la note à D.
- Le score est normalisé sur les critères mesurés. Poids : contrôle majeur 15–25,
  important 10, secondaire 5, réputation et fuites 3–5. Un critère d'un module à
  clé, actif ou sensible non lancé est omis (il ne fait pas baisser la couverture).
- Familles, notes de famille et constats sont calculés à partir de ces
  déclarations : rien d'autre à brancher.

---

## 9. Textes (i18n)

Fragments `domainrecon/i18n/modules/<clé>.fr.json` et `<clé>.en.json`, fusionnés
au catalogue au chargement. Format : objet JSON plat `{code: gabarit}`, UTF-8 sans
BOM, LF, clés triées, indentation 2, ligne finale (comme `json.dumps(...,
ensure_ascii=False, indent=2, sort_keys)` + `\n`).

- Obligatoires : `module.<clé>.title`, `module.<clé>.checks` (ce que le module
  vérifie), `module.<clé>.why` (pourquoi c'est important).
- Vos codes commencent par `module.<clé>.`, `<clé>.` ou `finding.<clé>.` ; aucun
  ne redéfinit un code existant. Mêmes codes et mêmes paramètres en FR et EN.
- Gabarits `str.format` à paramètres nommés, sans spécificateur ni conversion
  (`{port}`, jamais `{port:>5}` ni `{x!r}`). Chaque code doit être utilisé (appel
  `msg("code")` littéral, `FindingRule.code` ou aide).
- Messages communs réutilisables : `network.http_status` {status, service},
  `network.quota` {service}, `network.service_error` {context, detail},
  `net.timeout`, `http.unreachable` {errors}, `orchestrator.skip_ip_target`,
  `orchestrator.no_address`, `orchestrator.skip_generic`, `common.exception`
  {error, detail}, `common.join` {items}.
- « Comment corriger » (`fix`, `fix_snippet`, `fix_ref`) : mêmes fragments, mais
  textes **littéraux**, pas des gabarits (§9.1).

### 9.1 « Comment corriger » : `fix`, `fix_snippet`, `fix_ref`

Trois textes par module et par langue, dans les **mêmes fragments** que l'aide
(`<clé>.fr.json` et `<clé>.en.json`, y compris pour les 18 modules historiques ;
jamais dans `fr.json` ni `en.json`). L'interface (volet « Comprendre et corriger »
d'un constat) les lit dans `GET /api/modules`.

| Clé | Contenu | Statut |
|---|---|---|
| `module.<clé>.fix` | étapes concrètes de correction, une par ligne | **obligatoire** pour chaque module, en FR et en EN (le test de contrat refuse un module sans `fix`) |
| `module.<clé>.fix_snippet` | extrait prêt à copier (configuration, enregistrement DNS…) | facultatif (74 modules sur 84 en ont un) |
| `module.<clé>.fix_ref` | URL https de la documentation officielle | facultatif, mais attendu dès qu'une page officielle traite le sujet (les 84 modules en ont une) |

Règles communes :

- Une partie non renseignée = **clé absente** (jamais `""`, jamais `null`).
  `fix_snippet` et `fix_ref` exigent `fix`.
- Mêmes parties en FR et en EN : si une clé existe dans une langue, elle existe dans l'autre.
- **Texte littéral, pas un gabarit** : aucun paramètre `{nom}` ; accolades, `:` et
  `$` s'écrivent tels quels, **jamais doublés** (un bloc nginx `server { … }` ou un
  JSON s'écrit comme dans le fichier de configuration). Ces textes ne passent jamais
  par `render()` : ils sont lus par `domainrecon/i18n/fix.py`.
- Aucun espace ni saut de ligne en début ou en fin de texte ; lignes séparées par
  `\n` (jamais de retour chariot) ; ni tabulation ni caractère invisible (espace de
  largeur nulle, marque de sens d'écriture…).
- Fragment au format habituel : clés triées (`…checks`, `…fix`, `…fix_ref`,
  `…fix_snippet`, `…title`, `…why`). Pour éviter les erreurs d'échappement (guillemets,
  `\n`), écrire le fichier avec Python, en LF même sous Windows :

  ```python
  import json, pathlib

  f = pathlib.Path("domainrecon/i18n/modules/<clé>.fr.json")
  textes = json.loads(f.read_text(encoding="utf-8"))
  textes["module.<clé>.fix"] = "Première étape.\nDeuxième étape."
  f.write_text(
      json.dumps(textes, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
  )
  ```

**`fix`** : les étapes de correction.

- 1 à 10 étapes, **une par ligne**, sans ligne vide, 500 caractères au plus par ligne.
- À l'impératif et concret : où agir (console du registrar, fichier de configuration
  du serveur, panneau de l'hébergeur), quoi changer, avec quelle valeur ; terminer
  par la vérification quand elle existe (commande, relance du scan). Le conseil est
  **par module**, pas par constat : une étape peut viser un cas (« Si le certificat
  expire dans moins de 30 jours : … »).
- **Ni numéro ni puce** en tête de ligne (`1.`, `2)`, `-`, `*`, `•`, `Étape 1 :`) :
  l'interface numérote.
- Code court en ligne (en-tête, directive, commande, valeur, nom de fichier) entre
  accents graves, en nombre pair par ligne : `` `X-Frame-Options: DENY` ``. Pas de
  bloc de trois accents graves (le code à copier va dans `fix_snippet`). Aucun autre
  balisage : ni HTML, ni Markdown, ni lien (la documentation va dans `fix_ref`).
- Module purement informatif (rien à « corriger » : géolocalisation, technologies,
  WHOIS…) : `fix` dit **quoi faire de l'information** (la comparer à l'attendu, la
  réduire, la surveiller), jamais « rien à faire » seul.
- Mêmes étapes, dans le même ordre et en même nombre, en FR et en EN.

**`fix_snippet`** : extrait prêt à copier.

- Du code seul, sans prose (l'explication est dans `fix`), 2500 caractères au plus.
  **ASCII imprimable uniquement** : guillemets droits `"`, pas de `“ ”`, pas
  d'espace insécable, pas de tabulation (indenter avec des espaces) : ce qui est
  copié doit fonctionner tel quel.
- Valeurs d'exemple : domaine `example.com`, adresses `203.0.113.10` et
  `2001:db8::1`. Jamais de clé, de jeton ni de donnée réelle.
- Une seule variante : le code tel quel. **Plusieurs variantes** (6 au plus) :
  chacune précédée d'une **ligne d'en-tête** `# libellé`, et l'extrait commence par
  un en-tête :

  ```
  # nginx
  add_header X-Frame-Options "DENY" always;

  # Apache
  Header always set X-Frame-Options "DENY"
  ```

- Une ligne qui commence par `# ` (dièse et espace) en première colonne est
  **toujours** un en-tête : pas de commentaire de code à cet endroit (l'indenter ou,
  mieux, l'omettre). `#!/bin/sh` ou `#note` (sans espace) n'en sont pas.
- Libellé : nom de produit ou de format (`nginx`, `Apache`, `IIS`, `Caddy`,
  `HAProxy`, `DNS`, `PowerShell`, `Bash`…), 1 à 40 caractères, unique dans l'extrait,
  **identique en FR et en EN**. Même suite de variantes dans les deux langues.

**`fix_ref`** : documentation officielle.

- Une seule URL `https://` (en minuscules), absolue, ASCII, sans espace, sans
  identifiants ni paramètre de suivi, 300 caractères au plus.
- Source officielle : RFC (rfc-editor.org), MDN, OWASP, ANSSI, documentation de
  l'éditeur ou du service. La page la plus proche du sujet, pas la page d'accueil.
  Peut différer entre FR et EN (page localisée).

Chargement et API :

- `GET /api/modules` : chaque entrée de `modules` porte `fix`, `fix_snippet` et
  `fix_ref` **à côté de `help`**, dans la langue de la requête (`?lang=` ou
  `Accept-Language`). Les champs non renseignés sont **absents** (pas `null`) ; une
  partie manquante dans une langue est prise en français ; une `fix_ref` qui n'est
  pas en https est écartée.
- Côté interface : étapes = `fix` coupé sur `\n` ; variantes = lignes `# libellé`
  (à défaut, une seule variante sans nom) ; code en ligne = segments entre accents
  graves. Voir `fix_steps` et `snippet_variants` (`i18n/fix.py`).

- Exports : les rapports HTML, PDF et Markdown ont une section « Comment corriger »
  (« How to fix »), après les points à corriger : un bloc par module qui a relevé
  un constat, avec les étapes numérotées, chaque variante de l'extrait sous son
  libellé et l'adresse de `fix_ref` écrite en texte (pas de lien : le rapport HTML
  ne référence aucune ressource externe). Voir `reports/model.py` (`FixEntry`).

Contrôles (test de contrat) : `test_conseil_de_correction_coherent` (FR et EN
concordants, `fix_ref` en https, forme ci-dessus) et
`test_conseil_de_correction_obligatoire` (`fix` en FR et en EN pour CHAQUE module).
Les deux sont actifs : `EXIGER_CONSEILS_DE_CORRECTION` vaut `True` dans
`test_contrat_modules.py` depuis que les 84 modules ont leurs textes. Un module
ajouté sans `fix` fait donc échouer la suite. Pour contrôler un module seul :
`<python> -m pytest -q -p no:cacheprovider tests/scanner/modules/test_contrat_modules.py
-k "conseil and <clé>"`.

---

## 10. Tests du module

Fichier `tests/scanner/modules/test_<clé>.py`. Fixtures fournies par
`tests/scanner/modules/conftest.py` (le réseau réel y est coupé) :

| Fixture | Usage |
|---|---|
| `http_simule(routes)` | simule toutes les requêtes HTTP du scanner ; `routes = {"https://hôte/chemin": (statut, en-têtes, corps) \| dict/list JSON \| exception \| fonction}` ; rend les requêtes reçues |
| `dns_simule(zone)` | résolveur simulé de `scanner.dns` : `{(nom, "TXT"): ["v=spf1 …"], (nom, "A"): [outils.rdata("A", "93.184.216.34")]}` |
| `contexte(**champs)` | `ScanContext` prêt (example.com, 93.184.216.34, client simulé), `secrets={...}` |
| `outils` | `outils.executer(SPEC, ctx)`, `outils.verifier_sortie(valeur, secrets)`, `outils.txt`, `outils.rdata` |

Cas à couvrir au minimum : succès (réponse conforme à la documentation officielle
actuelle du service), rien trouvé, échec HTTP (`ModuleError`), quota (429),
réponse illisible, sans objet (IP littérale, adresse absente), clé absente ou
facultative, sortie conforme (`verifier_sortie`) et **aucune clé** dans le
résultat ni les messages, constats et critère de score sur des données
représentatives. Modules à clé : réponses simulées, jamais d'appel réel.

Le test de contrat (`tests/scanner/modules/test_contrat_modules.py`) vérifie
automatiquement, pour CHAQUE module : chargement sans défaut, famille et
catégorie valides, `run` asynchrone, textes FR/EN, « Comment corriger » cohérent
(§9.1), règles et critères valides, clés testables, valeur de repli sérialisable,
présence de `test_<clé>.py`, et que
**hors ligne** (HTTP refusé, DNS NXDOMAIN, sockets coupés) le module rend une
sortie conforme ou lève `ModuleError`/`ModuleSkipped` en moins de 30 s, sans
recopier de clé.

---

## 11. Outils disponibles

| Besoin | Outil |
|---|---|
| API tierce | `context.http` (httpx partagé du scan : TLS vérifié, aucune redirection, proxy du scan, anti-SSRF) ; ou `async with common._api_client(timeout=...) as client` |
| Requête vers la cible | `async with common._http_client(timeout=10) as client` puis `http_utils.fetch(client, url, site=context.domain)` / `fetch_first(client, context.domain, "/chemin")` (corps borné, redirections suivies sans quitter le site, TLS non vérifié) |
| Page d'accueil | `home = await context.homepage()` : une seule requête par scan, partagée (`home.status_code`, `home.headers` en minuscules, `home.text`, `home.url`, `home.error`) |
| DNS | `querier = dns.DnsQuerier(query_timeout=3, budget=10)` puis `await asyncio.to_thread(querier.lookup, nom, "TXT")` → `DnsLookup(status, answers, error)` ; DNS direct, sans proxy |
| Connexion directe (socket) | `targets.ensure_ip_allowed(ip)` avant toute connexion ; utiliser `context.addresses` / `context.ip_address` (déjà validées) |
| Cache | `@cached(MEDIUM_TTL, scope=common.proxy_scope, ignore=("client",))` de `scanner/cache.py` sur la fonction qui interroge l'API (`SHORT_TTL` 5 min réputation, `MEDIUM_TTL` 1 h, `LONG_TTL` 24 h) ; seuls les résultats sans erreur sont gardés |
| Cible | `context.domain` (nom ou IP), `context.apex` (domaine enregistrable : WHOIS, e-mail), `context.site` (journaux CT), `context.is_ip_target`, `context.shared_platform` |
| Autres modules | `context.results["<dépendance>"]` (déclarée dans `depends_on`) |
| Clés | `context.secrets["<nom>"]` |
| Journal | `context.logger` (jamais de clé, d'URL avec clé ni de proxy) |

Jamais `httpx.AsyncClient()` directement : il contournerait la politique
anti-SSRF et le proxy.

Essai réel (passif) : domaines publics `example.com`, `wikipedia.org`,
`cloudflare.com`, `badssl.com`. Actif : uniquement les cibles d'entraînement du §6.

---

## 12. Fichiers à NE PAS modifier

Toute modification passe par le chef d'équipe.

- `domainrecon/scanner/registry.py`, `modules/__init__.py`, `rules.py`, `keys.py`,
  `page.py`, `orchestrator.py`, `families.py`, `findings.py`, `score.py`,
  `cache.py`, `common.py`, `http_utils.py`, `proxy.py`, `targets.py`, `errors.py`,
  `dns.py` et les autres fichiers existants de `domainrecon/scanner/`
  (implémentation des 18 modules historiques) ;
- `domainrecon/scanner/modules/<18 modules historiques>.py` et
  `domainrecon/scanner/impl/__init__.py` ;
- `domainrecon/i18n/__init__.py`, `domainrecon/i18n/fix.py`, `domainrecon/i18n/fr.json`,
  `domainrecon/i18n/en.json`, et les fragments des autres modules ;
- `domainrecon/api/**` (routes, `service_checks.py`, `schemas.py`, `storage.py`,
  `jobs.py`), `domainrecon/core/**` (`models.py`, `settings_store.py`…) ;
- `tests/conftest.py`, `tests/scanner/modules/conftest.py`,
  `tests/scanner/modules/test_contrat_modules.py`, et tous les tests existants ;
- `pyproject.toml`, `packaging/**`, `frontend/**`, `README.md`, `.github/**`.

---

## 13. Liste de contrôle avant rendu

- [ ] `modules/<clé>.py`, fragments FR/EN, `tests/scanner/modules/test_<clé>.py` créés ; rien d'autre modifié.
- [ ] Catégorie juste (§6) ; clés déclarées (§7) avec un service testable.
- [ ] Sortie JSON avec `measured`/`error` ; erreurs en `ModuleError(msg(...))` ; aucune clé ni URL avec clé dans un message.
- [ ] Textes : titre, ce qu'il vérifie, pourquoi ; tous les codes utilisés ; FR et EN identiques en codes et paramètres.
- [ ] « Comment corriger » (§9.1) : `module.<clé>.fix` en FR et EN (une étape par ligne), `fix_snippet` et `fix_ref` si utiles.
- [ ] Constats et critère de score si le module conclut quelque chose de sécurité.
- [ ] Tests verts (module, contrat, i18n, suite complète), `ruff check` et `ruff format --check` propres.
- [ ] Essai réel sur une cible publique autorisée ; nouvelle dépendance signalée.
