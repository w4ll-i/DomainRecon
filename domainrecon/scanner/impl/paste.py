# =============================================================================
# DomainRecon - Module « paste » : sources de pastes et de code public
# =============================================================================
# Fonctions pures et lectures de sources, testables seules.
#   - Sourcegraph (sans clé) : recherche dans le code public indexé,
#     GET https://sourcegraph.com/.api/search/stream?q=…&v=V3, flux d'événements SSE
#     (« event: matches » puis « data: [ {type, repository, path, lineMatches:[{line,
#     lineNumber}]} ] »). Service tiers non officiel pour un usage anonyme, donc facultatif :
#     une page de contrôle anti-robot (Cloudflare, HTML) ou un refus est un état, pas une panne ;
#   - GitHub (jeton facultatif) : recherche de code sur des extensions de vidage (txt, log, sql, csv) ;
#   - Intelligence X (clé facultative) : bucket de pastes (media = 1).
# Sources écartées : psbdmp.ws n'existe plus (plus d'adresse DNS) ; psbdmp.cc n'a
# pas d'API publique. Google CSE (cx absent, fermé aux nouveaux clients, arrêt 2027) est abandonné.
# Valeurs sensibles : l'extrait est masqué (adresses, mots de passe, jetons), jamais enregistré brut.
# =============================================================================

import json
import re
from urllib.parse import quote

from ..score import as_dict, as_list
from .leaks_commun import mask_text, mentions_domain

SOURCEGRAPH_URL = "https://sourcegraph.com/.api/search/stream"
# Extensions de fichiers de vidage ou de journaux cherchées (Sourcegraph : expression régulière).
DUMP_EXTENSIONS = ("txt", "log", "sql", "csv", "bak", "env", "conf", "cfg", "ini", "json", "yml", "yaml")
# Extensions cherchées sur GitHub (une requête chacune, l'API n'accepte pas « OR »).
GITHUB_EXTENSIONS = ("txt", "log", "sql", "csv")
MAX_LINES_PER_FILE = 2
MAX_PASTES = 30

_KEYWORDS_HIGH = ("password", "passwd", "credential", "secret", "private_key", "token", "api_key", "apikey")
_KEYWORDS_MEDIUM = ("email", "username", "login", "user", "auth")


def snippet_severity(text: str) -> str:
    """Gravité d'un extrait d'après les mots qu'il contient (avant masquage)."""
    low = text.lower()
    if any(k in low for k in _KEYWORDS_HIGH):
        return "high"
    if any(k in low for k in _KEYWORDS_MEDIUM):
        return "medium"
    return "low"


def sourcegraph_query(domain: str) -> str:
    extensions = "|".join(DUMP_EXTENSIONS)
    return f'"{domain}" file:\\.({extensions})$ count:30 patternType:literal'


def parse_sourcegraph_stream(body: str, domain: str) -> list[dict]:
    """Résultats d'un flux SSE de Sourcegraph : un élément par ligne qui cite vraiment le domaine.

    Lève ValueError si le corps n'est pas un flux d'événements (page HTML de contrôle anti-robot, texte)."""
    if "event:" not in body:
        raise ValueError("pas un flux d'événements")
    pastes: list[dict] = []
    event = ""
    for raw in body.splitlines():
        line = raw.strip("\r")
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:") and event == "matches":
            try:
                matches = json.loads(line[5:].strip())
            except ValueError:
                continue
            for match in as_list(matches):
                item = as_dict(match)
                if item.get("type") != "content":
                    continue
                repository = str(item.get("repository") or "")[:200]
                path = str(item.get("path") or "")[:400]
                kept = 0
                for line_match in as_list(item.get("lineMatches")):
                    text = str(as_dict(line_match).get("line") or "")
                    if not mentions_domain(text, domain):
                        continue  # faux positif : la ligne ne cite pas le domaine en entier
                    number = as_dict(line_match).get("lineNumber")
                    pastes.append(
                        {
                            "source": "sourcegraph",
                            "url": f"https://sourcegraph.com/{quote(repository, safe='/.-_')}/-/blob/{quote(path, safe='/.-_')}",
                            "title": f"{repository} - {path}"[:300],
                            "date": "",
                            "snippet": mask_text(text, 120),
                            "line": number
                            if isinstance(number, int) and not isinstance(number, bool)
                            else None,
                            "severity": snippet_severity(text),
                        }
                    )
                    kept += 1
                    if kept >= MAX_LINES_PER_FILE:
                        break
    return pastes


def github_pastes(items: list[dict], domain: str) -> list[dict]:
    """Résultats d'une recherche GitHub de fichiers de vidage (déjà normalisés par github_dork.normalize_item)."""
    pastes: list[dict] = []
    for item in items:
        pastes.append(
            {
                "source": "github",
                "url": item["url"],
                "title": f"{item['repo']} - {item['path']}"[:300],
                "date": "",
                "snippet": item["snippet"],
                "line": None,
                "severity": "high"
                if item["severity"] == "critical"
                else snippet_severity(item["snippet"] + item["path"]),
            }
        )
    return pastes


def intelx_pastes(records: list[dict]) -> list[dict]:
    """Pastes d'Intelligence X (métadonnées seulement)."""
    return [
        {
            "source": "intelx",
            "url": "",
            "title": (record["name"] or record["storageid"] or "paste")[:300],
            "date": record["date"],
            "snippet": "",
            "line": None,
            "severity": "medium",
        }
        for record in records
    ]


_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_URL_ID = re.compile(r"[^A-Za-z0-9]+")


def merge(pastes: list[dict]) -> list[dict]:
    """Fusion des sources : sans doublon (même URL et même extrait), les plus graves d'abord, bornée."""
    seen: set[str] = set()
    unique: list[dict] = []
    for paste in pastes:
        key = _URL_ID.sub("", paste["url"] + "|" + paste["snippet"] + "|" + paste["title"]).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(paste)
    unique.sort(key=lambda p: (_SEVERITY_RANK.get(p["severity"], 3), p["source"], p["title"]))
    return unique[:MAX_PASTES]
