# =============================================================================
# DomainRecon - Module « intelx » : fuites d'identifiants (Intelligence X)
# =============================================================================
# Recherche « @domaine » dans les bases de fuites, de pastes et de dark web indexées par
# Intelligence X (https://intelx.io, documentation : https://help.intelx.io/api/).
# Nécessite une clé : compte gratuit (free.intelx.io, 200 résultats par bucket) ou offre
# payante (2.intelx.io) ; l'hôte est trouvé automatiquement (voir impl/intelx.py).
# Points notables :
#   - indépendant : il n'attend pas la découverte d'un panneau d'administration
#     (couplage qui donnerait des faux positifs et priverait l'utilisateur de la recherche) ;
#   - la clé est dans l'en-tête x-key uniquement, jamais dans l'URL ;
#   - hôte gratuit géré, attente active des résultats (statuts du service), recherche
#     libérée à la fin.
# Valeurs sensibles : métadonnées seulement (nom masqué, bucket, date, type) ; aucun
# contenu ni identifiant n'est téléchargé ni enregistré.
# Catégorie « sensible » : exige l'autorisation de tester la cible (cadre légal).
# =============================================================================

from ...i18n import msg
from ..errors import ModuleError
from ..impl import intelx as impl
from ..impl.leaks_commun import intelx_key
from ..registry import ModuleSpec, ScanContext, skip_for_ip_target
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_int

# Buckets d'identifiants : bases de fuites et collectes de journaux de logiciels voleurs.
_CREDENTIAL_PREFIXES = ("leaks.", "dumpster", "darknet.")


def _is_credential_bucket(bucket: object) -> bool:
    return isinstance(bucket, str) and bucket.lower().startswith(_CREDENTIAL_PREFIXES)


async def run(context: ScanContext) -> dict:
    term = f"@{context.apex}"
    key = context.secrets.get("intelx_key")
    if not key:
        raise ModuleError(msg("intelx.key_missing"))
    found = await impl.search(context.http, key, term, media=0)
    records = found["records"]
    buckets: dict[str, int] = {}
    for record in records:
        bucket = record["bucket"] or "?"
        buckets[bucket] = buckets.get(bucket, 0) + 1
    credentials = sum(n for bucket, n in buckets.items() if _is_credential_bucket(bucket))
    return {
        "measured": True,
        "error": None,
        "term": term,
        "plan": found["host"],
        "total_found": len(records),
        "truncated": found["truncated"],
        "credential_records": credentials,
        "buckets": buckets,
        "results": records,
    }


# -----------------------------------------------------------------------------
# Constats et score
# -----------------------------------------------------------------------------


def _check_leaks(f: FindingInput) -> object:
    data = as_dict(f.data)
    total = as_int(data.get("total_found")) or 0
    if total <= 0:
        return None
    credentials = as_int(data.get("credential_records")) or 0
    return hit(severity="high" if credentials else "medium", count=total, credentials=credentials)


def _score(data: dict) -> Outcome:
    intelx = as_dict(data.get("intelx"))
    total = as_int(intelx.get("total_found")) or 0
    credentials = as_int(intelx.get("credential_records")) or 0
    if total == 0:
        return Outcome(5, msg("intelx.score_clean"), True)
    detail = msg("intelx.score_found", count=total, buckets=len(as_dict(intelx.get("buckets"))))
    return Outcome(0 if credentials else 2, detail, True)


SPEC = ModuleSpec(
    name="intelx",
    family="leaks",
    category="sensible",
    run=run,
    keys=(intelx_key(required=True),),
    wave=3,
    timeout=100,
    skip_reason=skip_for_ip_target,
    optional=True,
    order=320,
    findings=(FindingRule(code="finding.intelx.leaks", severity="medium", check=_check_leaks),),
    score_rules=(ScoreRule(criterion="intelx", weight=5, evaluate=_score),),
)
