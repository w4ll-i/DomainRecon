# =============================================================================
# DomainRecon - Tests du module « censys » (Censys Platform API v3), sans réseau
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import msg
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.modules import censys

JETON = "censys_pat_secret_0123456789abcdef"
ORGANISATION = "6f1c2b9e-1111-2222-3333-444455556666"
HOTE = "https://api.platform.censys.io/v3/global/asset/host/93.184.216.34"


def reponse_hote() -> dict:
    """Réponse de GET /v3/global/asset/host/{ip} (https://docs.censys.com/reference/get-started)."""
    return {
        "result": {
            "resource": {
                "ip": "93.184.216.34",
                "autonomous_system": {
                    "asn": 15133,
                    "name": "EDGECAST",
                    "bgp_prefix": "93.184.216.0/24",
                    "country_code": "US",
                    "description": "EDGECAST",
                },
                "location": {"country_code": "US", "city": "Los Angeles"},
                "dns": {"reverse_dns": {"names": ["example.com", 12]}},
                "labels": [{"value": "cdn"}, "web"],
                "last_updated_at": "2026-10-10T08:00:00Z",
                "services": [
                    {
                        "port": 443,
                        "protocol": "HTTP",
                        "transport_protocol": "tcp",
                        "software": [{"vendor": "nginx", "product": "nginx", "version": "1.25.3"}],
                        "cert": {"fingerprint_sha256": "ab" * 32},
                        "labels": [{"value": "tls"}],
                    },
                    {"port": 80, "protocol": "HTTP", "transport_protocol": "tcp", "cert": "pas un dict"},
                ],
            }
        }
    }


def test_succes_avec_jeton_et_organisation(http_simule, contexte, outils):
    requetes = http_simule({HOTE: reponse_hote()})
    result = outils.executer(
        censys.SPEC, contexte(secrets={"censys_secret": JETON, "censys_id": ORGANISATION})
    )

    outils.verifier_sortie(result, secrets=[JETON])
    assert result["found"] is True and result["asn"] == "AS15133" and result["as_name"] == "EDGECAST"
    assert result["ports"] == [80, 443] and result["services_total"] == 2
    assert result["services"][0]["product"] == "nginx" and result["services"][0]["version"] == "1.25.3"
    assert result["certificates"] == ["ab" * 32] and result["labels"] == ["cdn", "web", "tls"]
    assert result["reverse_dns"] == ["example.com"] and result["country"] == "US"
    # Jeton en Bearer (jamais dans l'URL), organisation en en-tête.
    assert requetes[0].headers["authorization"] == f"Bearer {JETON}"
    assert requetes[0].headers["x-organization-id"] == ORGANISATION
    assert JETON not in str(requetes[0].url)


def test_organisation_invalide_ignoree(http_simule, contexte, outils):
    requetes = http_simule({HOTE: reponse_hote()})
    outils.executer(censys.SPEC, contexte(secrets={"censys_secret": JETON, "censys_id": "x\r\nInjection: 1"}))
    assert "x-organization-id" not in requetes[0].headers


def test_hote_inconnu(http_simule, contexte, outils):
    http_simule({HOTE: (404, {}, '{"error": "not found"}')})
    result = outils.executer(censys.SPEC, contexte(secrets={"censys_secret": JETON}))
    outils.verifier_sortie(result, secrets=[JETON])
    assert result["measured"] is True and result["found"] is False


def test_jeton_absent_sans_objet(http_simule, contexte, outils):
    requetes = http_simule({})
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(censys.SPEC, contexte())
    assert erreur.value.message == msg("censys.no_key") and requetes == []


@pytest.mark.parametrize(
    ("reponse", "attendu"),
    [
        ((401, {}, '{"message": "Access credentials are invalid"}'), msg("censys.key_rejected")),
        (
            (403, {}, "Censys Legacy Search was decommissioned"),
            msg("network.http_status", status=403, service="Censys"),
        ),
        ((429, {}, "limite"), msg("network.quota", service="Censys")),
        ((500, {}, "panne"), msg("network.http_status", status=500, service="Censys")),
        ((200, {}, "<html>pas du JSON</html>"), msg("censys.unreadable")),
        ((200, {}, "[1, 2, 3]"), msg("censys.unreadable")),
        (httpx.ReadTimeout("lent"), msg("net.timeout")),
    ],
)
def test_echecs(http_simule, contexte, outils, reponse, attendu):
    http_simule({HOTE: reponse})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(censys.SPEC, contexte(secrets={"censys_secret": JETON}))
    assert erreur.value.message == attendu
    assert JETON not in str(erreur.value)


def test_erreur_reseau_sans_le_jeton(http_simule, contexte, outils):
    http_simule({HOTE: httpx.ConnectError(f"échec avec {JETON}")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(censys.SPEC, contexte(secrets={"censys_secret": JETON}))
    assert JETON not in str(erreur.value) and JETON not in repr(erreur.value.message)


def test_sans_objet_adresse(contexte, http_simule, outils):
    http_simule({})
    assert censys.SPEC.skip_reason(contexte(addresses=[])) == msg("orchestrator.no_address")
    with pytest.raises(ModuleSkipped):
        outils.executer(censys.SPEC, contexte(addresses=["10.1.2.3"], secrets={"censys_secret": JETON}))


def test_declaration_des_cles():
    assert censys.SPEC.category == "cle_api" and censys.SPEC.required_keys == ("censys_secret",)
    assert censys.SPEC.optional_keys == ("censys_id",)
    assert {key.service for key in censys.SPEC.keys} == {"censys"}
