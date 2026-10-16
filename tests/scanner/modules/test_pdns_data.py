# =============================================================================
# DomainRecon - Tests du module « pdns_data » : DNS passif (sans réseau)
# =============================================================================

import base64

import pytest

from domainrecon.i18n import render
from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import pdns
from domainrecon.scanner.modules import pdns_data

SPEC = pdns_data.SPEC
UTILISATEUR, MOT_DE_PASSE, CLE_OTX = "circl-util", "motdepasse-secret-9876", "otx-cle-secrete-0123456789"
ROBTEX = "https://freeapi.robtex.com/pdns/forward/example.com"
CIRCL = "https://www.circl.lu/pdns/query/example.com"
OTX = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
SECRETS = {"circl_user": UTILISATEUR, "circl_password": MOT_DE_PASSE, "otx_key": CLE_OTX}


def _ndjson(*lignes):
    import json

    return (200, {}, "\n".join(json.dumps(ligne) for ligne in lignes) + "\n")


ROBTEX_OK = _ndjson(
    {
        "rrname": "example.com",
        "rrdata": "93.184.216.34",
        "rrtype": "A",
        "time_first": 1232555788,
        "time_last": 1792067066,
        "count": 5,
    },
    {
        "rrname": "example.com",
        "rrdata": "ns.icann.org",
        "rrtype": "NS",
        "time_first": 1562000000,
        "time_last": 1792067066,
        "count": 5,
    },
)
CIRCL_OK = _ndjson(
    {
        "count": 3,
        "rdata": "93.184.216.34",
        "rrname": "example.com",
        "rrtype": "A",
        "time_first": 1200000000,
        "time_last": 1700000000,
    },
    {
        "count": 1,
        "rdata": "198.51.100.9",
        "rrname": "example.com",
        "rrtype": "A",
        "time_first": 1100000000,
        "time_last": 1150000000,
    },
)
OTX_OK = {
    "passive_dns": [
        {
            "address": "93.184.216.34",
            "first": "2019-03-01T10:00:00",
            "last": "2026-01-01T00:00:00",
            "hostname": "example.com",
            "record_type": "A",
        },
        {
            "address": "2606:2800:21f::1",
            "first": "2021-01-01T00:00:00",
            "last": "2025-01-01T00:00:00",
            "hostname": "example.com",
            "record_type": "AAAA",
        },
    ]
}


def _lancer(contexte, outils, http_simule, routes, secrets=None):
    requetes = http_simule(routes)
    return outils.executer(SPEC, contexte(secrets=secrets or {})), requetes


def test_sans_aucune_cle_robtex_seul(contexte, outils, http_simule):
    sortie, requetes = _lancer(contexte, outils, http_simule, {ROBTEX: ROBTEX_OK})
    outils.verifier_sortie(sortie)
    assert (
        sortie["total"] == 2
        and sortie["unique_ips"] == ["93.184.216.34"]
        and sortie["record_types"] == {"A": 1, "NS": 1}
    )
    adresse = next(r for r in sortie["records"] if r["rrtype"] == "A")
    assert (
        adresse["first_seen"] == "2009-01-21" and adresse["sources"] == ["robtex"] and adresse["count"] == 5
    )
    etats = {s["name"]: s["status"] for s in sortie["sources"]}
    assert etats == {"circl": "skipped", "otx": "skipped", "robtex": "ok"}
    assert [r.url.host for r in requetes] == [
        "freeapi.robtex.com"
    ]  # aucune requête sans identifiants vers CIRCL / OTX


def test_trois_sources_fusionnees(contexte, outils, http_simule):
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {ROBTEX: ROBTEX_OK, CIRCL: CIRCL_OK, OTX: OTX_OK}, SECRETS
    )
    outils.verifier_sortie(sortie, [UTILISATEUR, MOT_DE_PASSE, CLE_OTX])
    courant = next(r for r in sortie["records"] if r["rdata"] == "93.184.216.34")
    assert courant["sources"] == ["circl", "otx", "robtex"] and courant["first_seen"] == "2008-01-10"
    assert courant["last_seen"] == "2026-10-15" or courant["last_seen"] > "2026-01-01"
    assert sortie["unique_ips"] == ["198.51.100.9", "2606:2800:21f::1", "93.184.216.34"] or set(
        sortie["unique_ips"]
    ) == {
        "198.51.100.9",
        "2606:2800:21f::1",
        "93.184.216.34",
    }
    # Identifiants : Basic pour CIRCL, en-tête dédié pour OTX, jamais dans une URL.
    circl = next(r for r in requetes if r.url.host == "www.circl.lu")
    attendu = "Basic " + base64.b64encode(f"{UTILISATEUR}:{MOT_DE_PASSE}".encode()).decode()
    assert circl.headers["authorization"] == attendu
    otx = next(r for r in requetes if r.url.host == "otx.alienvault.com")
    assert otx.headers["x-otx-api-key"] == CLE_OTX
    assert all(CLE_OTX not in str(r.url) and MOT_DE_PASSE not in str(r.url) for r in requetes)


def test_rien_trouve(contexte, outils, http_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, {ROBTEX: (200, {}, "")})
    outils.verifier_sortie(sortie)
    assert sortie["total"] == 0 and sortie["records"] == []


def test_identifiants_refuses_les_autres_sources_continuent(contexte, outils, http_simule):
    sortie, _ = _lancer(
        contexte,
        outils,
        http_simule,
        {ROBTEX: ROBTEX_OK, CIRCL: (401, {}, ""), OTX: (403, {}, "{}")},
        SECRETS,
    )
    rapports = {s["name"]: s for s in sortie["sources"]}
    assert rapports["circl"]["error"]["$t"] == "pdns_data.circl_rejected"
    assert rapports["otx"]["error"]["$t"] == "pdns_data.otx_rejected"
    assert sortie["total"] == 2
    texte = str(render(sortie, "fr"))
    assert MOT_DE_PASSE not in texte and CLE_OTX not in texte


def test_robtex_quota_depasse(contexte, outils, http_simule):
    """Robtex : 10 requêtes par heure ; le dépassement arrive en HTTP 200 avec un corps « ratelimited »."""
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {ROBTEX: (200, {}, '{"status":"ratelimited"}')})
    assert erreur.value.message["$t"] == "pdns_data.all_failed"
    rapports = erreur.value.message["p"]["errors"]
    assert rapports[0]["$t"] == "network.quota"


def test_robtex_quota_mais_circl_repond(contexte, outils, http_simule):
    sortie, _ = _lancer(
        contexte,
        outils,
        http_simule,
        {ROBTEX: (429, {}, ""), CIRCL: CIRCL_OK},
        {"circl_user": UTILISATEUR, "circl_password": MOT_DE_PASSE},
    )
    assert sortie["total"] == 2 and {s["name"]: s["status"] for s in sortie["sources"]}["robtex"] == "error"


def test_circl_utilisateur_sans_mot_de_passe_passe(contexte, outils, http_simule):
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {ROBTEX: ROBTEX_OK}, {"circl_user": UTILISATEUR}
    )
    assert {s["name"]: s["status"] for s in sortie["sources"]}["circl"] == "skipped"
    assert all(r.url.host != "www.circl.lu" for r in requetes)


def test_lignes_et_reponses_illisibles(contexte, outils, http_simule):
    corps = '{"rrname":"example.com","rrdata":"1.2.3.4","rrtype":"A","time_first":1,"time_last":2}\nn\'importe quoi\n[1,2]\n{"rrname":3}\n'
    sortie, _ = _lancer(contexte, outils, http_simule, {ROBTEX: (200, {}, corps)})
    assert sortie["total"] == 1
    cache.clear_cache()
    http_simule({ROBTEX: (200, {}, "x"), OTX: (200, {}, "pas du json")})
    sortie = outils.executer(SPEC, contexte(secrets={"otx_key": CLE_OTX}))
    rapports = {s["name"]: s for s in sortie["sources"]}
    assert rapports["otx"]["error"]["$t"] == "pdns_data.unreadable" and sortie["total"] == 0


def test_toutes_les_sources_en_echec(contexte, outils, http_simule):
    http_simule({})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets=SECRETS))
    assert erreur.value.message["$t"] == "pdns_data.all_failed"
    assert not any(secret in str(render(erreur.value.message, "fr")) for secret in SECRETS.values())


def test_dates():
    assert pdns.to_date(1792067066) == "2026-10-15"
    assert pdns.to_date("2021-05-06T12:00:00") == "2021-05-06"
    assert pdns.to_date(None) == "" and pdns.to_date(True) == "" and pdns.to_date(-5) == ""


def test_declaration(contexte):
    assert SPEC.category == "passif" and SPEC.required_keys == () and set(SPEC.optional_keys) == set(SECRETS)
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
