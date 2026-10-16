# =============================================================================
# DomainRecon - Module « leakix » : analyse des réponses de LeakIX
# =============================================================================
# Fonctions pures (sans réseau), testables seules.
# Documentation : https://leakix.net/api-documentation (client officiel : github.com/LeakIX/l9format)
#   GET https://leakix.net/domain/<domaine>  et  GET https://leakix.net/host/<ip>
#   en-têtes « api-key » et « Accept: application/json » ; réponse 200 :
#       {"Services": [événement…] | null, "Leaks": [événement…] | null}
#   (204 / 404 : rien pour cette cible). Événement (l9format) : event_type
#   (« leak » ou « service »), event_source (plugin), ip, host, reverse, port,
#   protocol, summary, time, service{credentials{noauth,username,password,…},
#   software{name,version}}, leak{stage, type, severity, dataset{rows,files,size,
#   collections,infected,ransom_notes}}, tags.
# L'ancienne API (/api/domain/<d>, liste plate, champ « severity » à la racine) est
# morte : le format ancien reste toutefois lu (liste plate), par prudence.
# Valeurs sensibles : service.credentials (identifiants trouvés par LeakIX) n'est
# JAMAIS recopié ; seul « noauth » (service ouvert sans authentification) l'est.
# =============================================================================

from ..score import as_dict, as_int, as_list
from .leaks_commun import mask_text, mentions_domain

# Nombre maximal d'événements gardés par catégorie.
MAX_EVENTS = 100
# Gravités LeakIX reconnues, de la plus à la moins grave.
SEVERITIES = ("critical", "high", "medium", "low")


def _severity(event: dict) -> str:
    leak = as_dict(event.get("leak"))
    value = str(leak.get("severity") or event.get("severity") or "").lower()
    return value if value in SEVERITIES else "info"


def _is_leak(event: dict) -> bool:
    return str(event.get("event_type") or "").lower() == "leak" or bool(as_dict(event.get("leak")))


def _event(raw: dict) -> dict:
    """Événement réduit à des champs sûrs (aucun identifiant, résumé masqué)."""
    leak = as_dict(raw.get("leak"))
    dataset = as_dict(leak.get("dataset"))
    service = as_dict(raw.get("service"))
    software = as_dict(service.get("software"))
    credentials = as_dict(service.get("credentials"))
    return {
        "kind": "leak" if _is_leak(raw) else "service",
        "severity": _severity(raw),
        "source": str(raw.get("event_source") or "")[:60],
        "host": str(raw.get("host") or raw.get("reverse") or "")[:255],
        "ip": str(raw.get("ip") or "")[:64],
        "port": as_int(raw.get("port")),
        "protocol": str(raw.get("protocol") or "")[:20],
        "summary": mask_text(str(raw.get("summary") or ""), 200),
        "time": str(raw.get("time") or "")[:25],
        "stage": str(leak.get("stage") or "")[:30],
        "leak_type": str(leak.get("type") or "")[:40],
        "dataset_rows": as_int(dataset.get("rows")),
        "dataset_size": as_int(dataset.get("size")),
        "ransom": as_int(dataset.get("ransom_notes")) or 0,
        "noauth": credentials.get("noauth") is True,
        "software": str(software.get("name") or "")[:60],
    }


def _events(payload: object) -> list[dict]:
    """Événements bruts d'une réponse : {Services, Leaks} (format actuel) ou liste plate (ancien format)."""
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    data = as_dict(payload)
    lowered = {str(k).lower(): v for k, v in data.items()}
    events: list[dict] = []
    for key in ("leaks", "services"):
        events.extend(e for e in as_list(lowered.get(key)) if isinstance(e, dict))
    return events


def parse_response(payload: object, target: str, *, by_domain: bool) -> dict:
    """Résultat structuré d'une réponse LeakIX.

    `by_domain` : la requête portait sur un domaine ; un événement dont l'hôte n'est pas ce domaine (ni un
    sous-domaine) est écarté (faux positif : adresse partagée), un hôte vide est gardé.
    """
    leaks: list[dict] = []
    services: list[dict] = []
    ignored = 0
    for raw in _events(payload):
        event = _event(raw)
        if by_domain and event["host"] and not mentions_domain(event["host"], target):
            ignored += 1
            continue
        (leaks if event["kind"] == "leak" else services).append(event)
    rank = {name: i for i, name in enumerate((*SEVERITIES, "info"))}
    leaks.sort(key=lambda e: (rank[e["severity"]], e["time"]))
    services.sort(key=lambda e: (rank[e["severity"]], e["host"]))
    return {
        "leak_count": len(leaks),
        "service_count": len(services),
        "critical_count": sum(1 for e in leaks if e["severity"] == "critical"),
        "high_count": sum(1 for e in leaks if e["severity"] == "high"),
        "noauth_count": sum(1 for e in services if e["noauth"]),
        "ignored": ignored,
        "leaks": leaks[:MAX_EVENTS],
        "services": services[:MAX_EVENTS],
    }
