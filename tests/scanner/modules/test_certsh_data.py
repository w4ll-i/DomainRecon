# =============================================================================
# DomainRecon - Tests du module « certsh_data » : certificats CT (sans réseau)
# =============================================================================

import pytest

from domainrecon.scanner import dns as scanner_dns
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import certsh, ct_common
from domainrecon.scanner.modules import certsh_data
from domainrecon.scanner.rules import FindingInput

SPEC = certsh_data.SPEC
CRT = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"


def _entree(ident, noms, debut="2026-09-01T00:00:00", fin="2099-01-01T00:00:00", emetteur="Let's Encrypt"):
    """Entrée au format réel de crt.sh (relevé le 15/10/2026 : id, not_before, not_after, name_value…)."""
    return {
        "issuer_ca_id": 1,
        "issuer_name": f"C=US, O={emetteur}, CN=R11",
        "common_name": noms[0],
        "name_value": "\n".join(noms),
        "id": ident,
        "not_before": debut,
        "not_after": fin,
        "serial_number": "00ab",
        "result_count": len(noms),
    }


@pytest.fixture(autouse=True)
def moteur(monkeypatch):
    """Résolution simulée : les noms « old-* » et « interne-* » ne résolvent pas ; pas de joker DNS."""
    appels: list[str] = []

    async def resolve_ip(name):
        appels.append(name)
        return None if name.startswith(("old-", "interne-")) else "93.184.216.34"

    async def pas_de_joker(domain):
        return set()

    monkeypatch.setattr(certsh, "resolve_ip", resolve_ip)
    monkeypatch.setattr(scanner_dns, "_wildcard_addresses", pas_de_joker)
    monkeypatch.setattr(ct_common, "CRTSH_RETRY_DELAY", 0)
    return appels


def _finding(data):
    return FindingInput({}, "certsh_data", lambda scan, name: data, lambda scan, name: True)


def _lancer(contexte, outils, http_simule, routes):
    http_simule(routes)
    return outils.executer(SPEC, contexte())


ENTREES = [
    _entree(10, ["www.example.com", "example.com"], "2026-09-01T00:00:00", "2099-01-01T00:00:00"),
    _entree(
        30, ["*.example.com", "example.com"], "2026-10-01T00:00:00", "2099-04-01T00:00:00", "DigiCert Inc"
    ),
    _entree(20, ["old-shop.example.com"], "2024-01-01T00:00:00", "2024-04-01T00:00:00"),
    _entree(40, ["interne-vpn.example.com", "www.example.com"], "2026-08-01T00:00:00", "2099-02-01T00:00:00"),
    _entree(10, ["www.example.com", "example.com"], "2026-09-01T00:00:00", "2099-01-01T00:00:00"),
]


def test_succes_certificats_et_noms_vus_seulement_en_ct(contexte, outils, http_simule):
    sortie = _lancer(contexte, outils, http_simule, {CRT: ENTREES})
    outils.verifier_sortie(sortie)
    assert sortie["source"] == "crt.sh" and sortie["partial"] is False
    assert sortie["total_certs"] == 5 and sortie["unique_certs"] == 4
    assert [c["id"] for c in sortie["certs"]] == [30, 10, 40, 20]
    assert sortie["certs"][0]["issuer"] == "DigiCert Inc" and sortie["certs"][0]["wildcard"] is True
    assert sortie["certs"][3]["expired"] is True and sortie["certs"][0]["expired"] is False
    assert sortie["active_certs"] == 3 and sortie["wildcard_certs"] == 1
    assert sortie["issuers"] == [{"name": "Let's Encrypt", "count": 3}, {"name": "DigiCert Inc", "count": 1}]
    assert sortie["date_range"] == {"oldest": "2024-01-01", "newest": "2026-10-01"}
    assert {e["name"]: e for e in sortie["ct_only"]}.keys() == {
        "old-shop.example.com",
        "interne-vpn.example.com",
    }
    vieux = next(e for e in sortie["ct_only"] if e["name"] == "old-shop.example.com")
    assert vieux["expired"] is True and vieux["last_seen"] == "2024-01-01"
    constat = SPEC.findings[0].check(_finding(sortie))
    assert constat[0].params["count"] == 2


def test_rien_trouve(contexte, outils, http_simule):
    sortie = _lancer(contexte, outils, http_simule, {CRT: []})
    outils.verifier_sortie(sortie)
    assert sortie["certs"] == [] and sortie["ct_only"] == [] and sortie["date_range"] == {}
    assert SPEC.findings[0].check(_finding(sortie)) is None


def test_joker_dns_pas_de_noms_ct_seulement(contexte, outils, http_simule, monkeypatch):
    """Sous un joker DNS tout nom résout : « absent du DNS » ne serait pas mesurable, rien n'est affirmé."""

    async def joker(domain):
        return {"198.51.100.7"}

    monkeypatch.setattr(scanner_dns, "_wildcard_addresses", joker)
    sortie = _lancer(contexte, outils, http_simule, {CRT: ENTREES})
    assert sortie["wildcard_dns"] is True and sortie["ct_only"] == [] and sortie["ct_only_checked"] == 0


def test_secours_cert_spotter_partiel(contexte, outils, http_simule):
    routes = {
        CRT: (503, {}, ""),
        CERTSPOTTER: [
            {
                "id": "7",
                "dns_names": ["www.example.com", "old-api.example.com"],
                "not_before": "2026-10-01T00:00:00Z",
                "not_after": "2099-01-01T00:00:00Z",
                "issuer": {"name": "C=US, O=Let's Encrypt, CN=R11"},
            }
        ],
    }
    sortie = _lancer(contexte, outils, http_simule, routes)
    assert sortie["source"] == "certspotter" and sortie["partial"] is True
    assert sortie["fallback_cause"]["$t"] == "dns.crtsh_http"
    assert sortie["certs"][0]["issuer"] == "Let's Encrypt" and sortie["certs"][0]["id"] == 7
    assert [e["name"] for e in sortie["ct_only"]] == ["old-api.example.com"]


def test_aucune_source_ne_repond(contexte, outils, http_simule):
    http_simule({})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "dns.ct_both_failed"


def test_reponse_illisible(contexte, outils, http_simule):
    http_simule({CRT: (200, {}, "pas du json"), CERTSPOTTER: (200, {}, "{}")})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_noms_hors_domaine_ignores(contexte, outils, http_simule):
    entrees = [_entree(1, ["myexample.com", "autre.org", "evil.example.com.attaquant.net", "ok.example.com"])]
    sortie = _lancer(contexte, outils, http_simule, {CRT: entrees})
    assert sortie["name_count"] == 1 and sortie["ct_only"] == []


def test_requete_partagee_avec_subdomains(contexte, outils, http_simule):
    """Une seule requête crt.sh pour les deux modules (cache de impl/ct_common)."""
    requetes = http_simule({CRT: ENTREES})
    outils.executer(SPEC, contexte())
    outils.executer(SPEC, contexte())
    assert len([r for r in requetes if r.url.host == "crt.sh"]) == 1


def test_donnees_inattendues_ne_levent_pas():
    for data in (None, [], "x", {"ct_only": "oops"}, {"ct_only": [None, 3], "ct_only_count": "x"}):
        SPEC.findings[0].check(_finding(data))


def test_emetteur_lisible():
    assert certsh.issuer_label("C=US, O=Let's Encrypt, CN=R11") == "Let's Encrypt"
    assert certsh.issuer_label("C=BE, CN=GlobalSign") == "GlobalSign"
    assert certsh.issuer_label("") == ""


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
