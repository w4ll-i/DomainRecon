# =============================================================================
# DomainRecon - Module « banners » : bannières et versions des services ouverts
# =============================================================================
# Pour chaque port ouvert
# trouvé par « open_ports », une sonde propre au protocole lit l'annonce du
# service (SSH, FTP, SMTP, HTTP/HTTPS, MySQL, PostgreSQL, Redis, Memcached,
# Elasticsearch, CouchDB, Consul, Docker, MongoDB…), en extrait produit et
# version, et détecte les accès sans authentification (Redis qui répond
# +PONG, API Docker ouverte…). Voir impl/banners.py pour les sondes.
# Catégorie ACTIF : le module envoie de vraies commandes à des services
# (PING, INFO server, requêtes HTTP) ; il n'est lancé qu'en profil personnalisé,
# avec l'autorisation de tester la cible.
# Limites : IP d'un CDN ou d'un pare-feu = bannière du CDN ; un port filtré
# entre-temps est « injoignable » (pas une erreur).
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError, ModuleSkipped
from ..impl import banners as probes
from ..registry import ModuleSpec, ScanContext, skip_without_address
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int, as_list


def open_port_numbers(value: object) -> list[int]:
    """Numéros des ports ouverts d'un résultat « open_ports » (liste de dicts, d'entiers ou de textes)."""
    ports: set[int] = set()
    for entry in as_list(value):
        if isinstance(entry, dict):
            if entry.get("state", "open") != "open":
                continue
            entry = entry.get("port")
        number = as_int(entry)
        if number is not None and 0 < number < 65536:
            ports.add(number)
    return sorted(ports)


async def run(context: ScanContext) -> dict:
    ip = context.ip_address
    if "open_ports" not in context.results:
        # Le scan de ports a échoué ou n'a pas tourné : rien à sonder.
        raise ModuleSkipped(msg("banners.no_scan"))
    opened = open_port_numbers(context.results["open_ports"])
    if not opened:
        raise ModuleSkipped(msg("banners.no_open_port"))
    ports = [p for p in opened if probes.plan_for(p) is not None]
    if not ports:
        raise ModuleSkipped(msg("banners.no_probe"))
    entries = await probes.grab_all(ip, ports, context.domain)
    if not any(e["reachable"] for e in entries):
        raise ModuleError(msg("banners.unreachable"))
    return {
        "measured": True,
        "error": None,
        "ip": ip,
        "ports_open": len(opened),
        "ports_probed": len(entries),
        "banners": entries,
        "unauthenticated": [e["port"] for e in entries if e.get("exposure")],
        "versions_disclosed": [e["port"] for e in entries if e.get("product") and e.get("version")],
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _entries(f: FindingInput) -> list[dict]:
    return [e for e in as_list(as_dict(f.data).get("banners")) if isinstance(e, dict)]


def _check_unauthenticated(f: FindingInput) -> list:
    return [
        hit(severity=str(e.get("risk") or "high"), port=e.get("port"), service=str(e.get("service") or "?"))
        for e in _entries(f)
        if e.get("exposure")
    ]


def _check_version(f: FindingInput) -> list:
    return [
        hit(port=e.get("port"), product=str(e["product"]), version=str(e["version"]))
        for e in _entries(f)
        if e.get("product") and e.get("version") and not e.get("exposure")
    ][:10]


def _score(data: dict) -> Outcome:
    banners = as_dict(data.get("banners"))
    if as_list(banners.get("unauthenticated")):
        return Outcome(0, msg("banners.score_unauthenticated"), True)
    if as_list(banners.get("versions_disclosed")):
        return Outcome(3, msg("banners.score_versions"), True)
    return Outcome(5, msg("banners.score_clean"), True)


SPEC = ModuleSpec(
    name="banners",
    family="network",
    category="actif",
    run=run,
    skip_reason=skip_without_address,
    wave=2,
    depends_on=("open_ports",),
    timeout=90,
    optional=True,
    order=260,
    findings=(
        FindingRule(code="finding.banners.unauthenticated", severity="high", check=_check_unauthenticated),
        FindingRule(code="finding.banners.version_disclosed", severity="low", check=_check_version),
    ),
    score_rules=(ScoreRule(criterion="banners", weight=5, evaluate=_score),),
)
