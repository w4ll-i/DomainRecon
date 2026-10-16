# =============================================================================
# DomainRecon - Tests du module « otx » (sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import otx
from domainrecon.scanner.rules import FindingInput

CLE = "otx-cle-secrete-0123456789abcdef"
SPEC = otx.SPEC
GENERAL = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
PDNS = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"


def _pulse(name="Liste", tags=(), families=(), adversary=""):
    return {
        "name": name,
        "tags": list(tags),
        "malware_families": [{"id": f, "display_name": f} for f in families],
        "adversary": adversary,
    }


def _general(pulses, count=None, validation=()):
    """Réponse conforme à /indicators/domain/{domaine}/general d'OTX."""
    return {
        "indicator": "example.com",
        "type": "domain",
        "validation": [{"source": s, "name": n, "message": ""} for s, n in validation],
        "false_positive": [],
        "pulse_info": {"count": len(pulses) if count is None else count, "pulses": pulses, "references": []},
    }


def _lancer(contexte, outils, http_simule, routes, secrets=None, **champs):
    requetes = http_simule(routes)
    context = contexte(secrets=secrets if secrets is not None else {"otx_key": CLE}, **champs)
    return outils.executer(SPEC, context), requetes


def test_succes_malveillant_avec_dns_passif(contexte, outils, http_simule):
    pulses = [_pulse(f"P{i}", ["phishing"], ["Emotet"]) for i in range(3)]
    pdns = {
        "passive_dns": [
            {
                "address": "1.2.3.4",
                "first": "2025-01-01",
                "last": "2026-01-01",
                "record_type": "A",
                "asn": "AS1",
            }
        ]
    }
    sortie, requetes = _lancer(contexte, outils, http_simule, {GENERAL: _general(pulses), PDNS: pdns})
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["verdict"] == "malicious" and sortie["malicious"] is True
    assert sortie["malware_families"] == ["Emotet"] and sortie["threat_types"] == ["phishing"]
    assert sortie["passive_dns"][0]["ip"] == "1.2.3.4" and sortie["passive_dns_available"] is True
    assert sortie["authenticated"] is True
    assert all(r.headers["X-OTX-API-KEY"] == CLE and CLE not in str(r.url) for r in requetes)


def test_faux_positif_grand_domaine_en_liste_blanche(contexte, outils, http_simule):
    """Régression de l'ancien « malicious = pulses > 0 » : 50 pulses mais domaine en liste blanche."""
    pulses = [_pulse(f"P{i}", ["malware"], ["Mikey"]) for i in range(50)]
    general = _general(pulses, count=50, validation=[("whitelist", "Whitelisted domain")])
    sortie, _ = _lancer(contexte, outils, http_simule, {GENERAL: general, PDNS: (429, {}, "{}")})
    assert sortie["verdict"] == "mentioned" and sortie["malicious"] is False
    assert sortie["passive_dns_available"] is False and sortie["passive_dns"] == []
    assert SPEC.score_rules[0].evaluate({"otx": sortie}).points == 3
    assert SPEC.findings[0].check(_entree(sortie)) is None


def test_rien_trouve_et_sans_cle(contexte, outils, http_simule):
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {GENERAL: _general([]), PDNS: (429, {}, "{}")}, secrets={}
    )
    outils.verifier_sortie(sortie)
    assert sortie["verdict"] == "clean" and sortie["authenticated"] is False
    assert all("X-OTX-API-KEY" not in r.headers for r in requetes)
    cache.clear_cache()
    sortie, _ = _lancer(contexte, outils, http_simule, {GENERAL: (404, {}, "{}"), PDNS: (404, {}, "{}")})
    assert sortie["found"] is False and sortie["verdict"] == "clean"


def test_suspect_par_etiquettes(contexte, outils, http_simule):
    sortie, _ = _lancer(
        contexte, outils, http_simule, {GENERAL: _general([_pulse("A", ["scanner"])]), PDNS: (200, {}, "{}")}
    )
    assert sortie["verdict"] == "suspicious"


@pytest.mark.parametrize(
    ("statut", "code"), [(429, "network.quota"), (403, "network.http_status"), (500, "network.http_status")]
)
def test_echecs_http(contexte, outils, http_simule, statut, code):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {GENERAL: (statut, {}, "{}")})
    assert erreur.value.message["$t"] == code and CLE not in str(erreur.value)


def test_illisible_delai_connexion(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {GENERAL: (200, {}, "pas du json")})
    assert erreur.value.message["$t"] == "otx.unreadable"
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {GENERAL: {"autre": 1}})
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {GENERAL: httpx.ReadTimeout("long")})
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, {})


def test_cible_ip(contexte, outils, http_simule):
    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/93.184.216.34/general"
    sortie, requetes = _lancer(contexte, outils, http_simule, {url: _general([])}, domain="93.184.216.34")
    assert sortie["verdict"] == "clean" and "passive_dns" not in sortie
    assert [r.url.path for r in requetes] == ["/api/v1/indicators/IPv4/93.184.216.34/general"]


def test_cle_facultative():
    assert SPEC.required_keys == () and SPEC.optional_keys == ("otx_key",) and SPEC.category == "passif"


def _entree(donnees):
    scan = {"modules": {"otx": {"data": donnees}}}
    return FindingInput(scan, "otx", lambda s, m: s["modules"][m]["data"], lambda s, m: True)


def test_constats_et_score():
    malveillant = {"verdict": "malicious", "pulse_count": 7, "malware_families": ["Emotet"]}
    suspect = {"verdict": "suspicious", "pulse_count": 2, "threat_types": ["scanner"]}
    assert SPEC.findings[0].check(_entree(malveillant)) == {"pulses": 7, "malware": "Emotet"}
    assert SPEC.findings[1].check(_entree(suspect)) == {"pulses": 2, "tags": "scanner"}
    assert SPEC.findings[0].check(_entree(suspect)) is None
    assert SPEC.findings[1].check(_entree("illisible")) is None
    assert SPEC.score_rules[0].evaluate({"otx": malveillant}).points == 0
    assert SPEC.score_rules[0].evaluate({"otx": suspect}).points == 1
    assert SPEC.score_rules[0].evaluate({"otx": {"verdict": "clean"}}).points == 3
