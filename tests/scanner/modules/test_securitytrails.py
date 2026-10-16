# =============================================================================
# DomainRecon - Tests du module « securitytrails » (sans réseau, réponses simulées)
# =============================================================================

import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.modules import securitytrails

SPEC = securitytrails.SPEC
CLE = "st-cle-secrete-0123456789abcdef"
SOUS_DOMAINES = "https://api.securitytrails.com/v1/domain/example.com/subdomains"
HISTORIQUE = "https://api.securitytrails.com/v1/history/example.com/dns/a"


def _sous_domaines(*labels):
    """Réponse conforme à la documentation SecurityTrails (labels relatifs au domaine)."""
    return {
        "endpoint": "/v1/domain/example.com/subdomains",
        "subdomains": list(labels),
        "subdomain_count": len(labels),
    }


def _historique():
    return {
        "records": [
            {
                "first_seen": "2020-01-01",
                "last_seen": "2022-05-01",
                "organizations": ["Ancien hébergeur"],
                "type": "a",
                "values": [{"ip": "198.51.100.10", "ip_count": 3}],
            },
            {
                "first_seen": "2022-05-02",
                "last_seen": "2026-10-01",
                "organizations": ["CDN"],
                "type": "a",
                "values": [{"ip": "93.184.216.34", "ip_count": 9}, {"ip": "93.184.216.35", "ip_count": 9}],
            },
        ],
        "pages": 1,
        "type": "a",
    }


def _lancer(contexte, outils, http_simule, routes, secrets=None):
    requetes = http_simule(routes)
    context = contexte(secrets={"securitytrails_key": CLE} if secrets is None else secrets)
    return outils.executer(SPEC, context), requetes


def test_succes(contexte, outils, http_simule):
    sortie, requetes = _lancer(
        contexte,
        outils,
        http_simule,
        {SOUS_DOMAINES: _sous_domaines("www", "api", "vpn"), HISTORIQUE: _historique()},
    )
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["subdomains"] == ["api.example.com", "vpn.example.com", "www.example.com"]
    assert sortie["subdomain_count"] == 3
    assert [h["last_seen"] for h in sortie["history"]] == ["2026-10-01", "2022-05-01"]
    assert sortie["history_ips"] == ["198.51.100.10", "93.184.216.34", "93.184.216.35"] or sortie[
        "history_ips"
    ] == sorted(["198.51.100.10", "93.184.216.34", "93.184.216.35"])
    # La clé voyage dans l'en-tête APIKEY, jamais dans l'URL.
    assert requetes and all(r.headers["apikey"] == CLE and CLE not in str(r.url) for r in requetes)
    assert all(r.url.scheme == "https" for r in requetes)


def test_rien_trouve(contexte, outils, http_simule):
    sortie, _ = _lancer(
        contexte,
        outils,
        http_simule,
        {SOUS_DOMAINES: _sous_domaines(), HISTORIQUE: {"records": [], "pages": 0}},
    )
    outils.verifier_sortie(sortie, [CLE])
    assert sortie["subdomains"] == [] and sortie["history"] == []


def test_historique_refuse_les_sous_domaines_restent(contexte, outils, http_simule):
    """L'historique est souvent hors de l'offre gratuite : ce n'est pas un échec du module."""
    sortie, _ = _lancer(
        contexte, outils, http_simule, {SOUS_DOMAINES: _sous_domaines("www"), HISTORIQUE: (403, {}, "{}")}
    )
    assert sortie["subdomains"] == ["www.example.com"] and sortie["history"] == []
    assert sortie["history_error"]["$t"] == "securitytrails.key_rejected"


@pytest.mark.parametrize(
    ("statut", "code"),
    [
        (401, "securitytrails.key_rejected"),
        (403, "securitytrails.key_rejected"),
        (429, "network.quota"),
        (500, "network.http_status"),
    ],
)
def test_echec_http(contexte, outils, http_simule, statut, code):
    http_simule({SOUS_DOMAINES: (statut, {}, '{"message":"x"}')})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"securitytrails_key": CLE}))
    assert erreur.value.message["$t"] == code
    assert CLE not in str(render(erreur.value.message, "fr"))


def test_reponse_illisible(contexte, outils, http_simule):
    for corps in ("pas du json", "[]", '{"subdomains": "oops"}'):
        http_simule({SOUS_DOMAINES: (200, {}, corps)})
        with pytest.raises(ModuleError) as erreur:
            outils.executer(SPEC, contexte(secrets={"securitytrails_key": CLE}))
        assert erreur.value.message["$t"] == "securitytrails.unreadable"


def test_labels_invalides_ecartes(contexte, outils, http_simule):
    sortie, _ = _lancer(
        contexte,
        outils,
        http_simule,
        {SOUS_DOMAINES: _sous_domaines("ok", "../etc", "a b", 5, "", "ok2"), HISTORIQUE: {"records": []}},
    )
    assert sortie["subdomains"] == ["ok.example.com", "ok2.example.com"]


def test_erreur_reseau_sans_fuite_de_cle(contexte, outils, http_simule):
    http_simule({})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"securitytrails_key": CLE}))
    assert CLE not in str(render(erreur.value.message, "fr"))


def test_cle_absente(contexte, outils, http_simule):
    http_simule({})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={}))
    assert erreur.value.message["$t"] == "securitytrails.no_key"


def test_resultats_gardes_24_h(contexte, outils, http_simule):
    routes = {SOUS_DOMAINES: _sous_domaines("www"), HISTORIQUE: _historique()}
    requetes = http_simule(routes)
    outils.executer(SPEC, contexte(secrets={"securitytrails_key": CLE}))
    outils.executer(SPEC, contexte(secrets={"securitytrails_key": CLE}))
    assert len(requetes) == 2  # une seule fois chaque point d'accès, malgré deux exécutions


def test_declaration(contexte):
    assert SPEC.category == "cle_api" and SPEC.required_keys == ("securitytrails_key",)
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
