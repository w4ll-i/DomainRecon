# =============================================================================
# DomainRecon - Tests du module « wayback_data » (Wayback Machine, sans réseau)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import wayback_cdx
from domainrecon.scanner.modules import wayback_data

SPEC = wayback_data.SPEC
CDX = "https://web.archive.org/cdx/search/cdx"
DISPO = "https://archive.org/wayback/available"

EN_TETE = ["timestamp", "original", "statuscode"]
PREMIERE = [EN_TETE, ["20020120142510", "http://example.com:80/", "200"]]
DERNIERE = [EN_TETE, ["20261015052905", "https://example.com/", "200"]]
ANNEES = [["timestamp"], ["20020120142510"], ["20030101000000"], ["20260101000000"]]
URLS = [["original"], ["http://example.com:80/"], ["https://example.com/a"], ["javascript:alert(1)"]]
PROCHE = {
    "url": "example.com",
    "archived_snapshots": {
        "closest": {
            "status": "200",
            "available": True,
            "url": "http://web.archive.org/web/20261015052905/https://example.com/",
            "timestamp": "20261015052905",
        }
    },
}


def _cdx(**par_requete):
    """Route du CDX : réponse selon les paramètres (limit=1, limit=-1, collapse, matchType)."""

    def gestionnaire(request: httpx.Request) -> httpx.Response:
        q = request.url.params
        if q.get("matchType") == "host":
            cle = "urls"
        elif q.get("collapse") == "timestamp:4":
            cle = "years"
        elif q.get("limit") == "-1":
            cle = "last"
        else:
            cle = "first"
        valeur = par_requete[cle]
        if isinstance(valeur, BaseException):
            raise valeur
        if callable(valeur):
            return valeur(request)
        if isinstance(valeur, tuple):
            return httpx.Response(valeur[0], content=valeur[1])
        return httpx.Response(200, json=valeur)

    return gestionnaire


def _routes(first=PREMIERE, last=DERNIERE, years=ANNEES, urls=URLS, dispo=PROCHE):
    return {CDX: _cdx(first=first, last=last, years=years, urls=urls), DISPO: dispo}


def _lancer(contexte, outils, http_simule, routes, **champs):
    requetes = http_simule(routes)
    return outils.executer(SPEC, contexte(**champs)), requetes


def test_succes_premiere_et_derniere_capture(contexte, outils, http_simule):
    sortie, requetes = _lancer(contexte, outils, http_simule, _routes())
    outils.verifier_sortie(sortie)
    assert sortie["available"] is True and sortie["partial"] is False
    # Dates des captures de la page d'accueil, au format AAAAMMJJ.
    assert sortie["first_seen"] == "20020120" and sortie["last_seen"] == "20261015"
    assert sortie["years_active"] == ["2002", "2003", "2026"]
    assert sortie["closest"]["timestamp"] == "20261015052905"
    assert sortie["archive_url"] == "https://web.archive.org/web/*/example.com"
    # Schéma non http(s) écarté : une URL archivée est une donnée externe non fiable.
    assert sortie["sample_urls"] == ["http://example.com:80/", "https://example.com/a"]
    # Sur l'URL exacte du domaine, en https : la première (limit=1) et la dernière (limit=-1) sont demandées.
    cdx = [r for r in requetes if r.url.path == "/cdx/search/cdx"]
    assert {
        r.url.params["limit"]
        for r in cdx
        if r.url.params.get("collapse") is None and r.url.params.get("matchType") is None
    } == {"1", "-1"}
    assert all(r.url.scheme == "https" for r in requetes)
    assert all(r.url.params["url"] == "example.com" for r in requetes)


def test_rien_d_archive(contexte, outils, http_simule):
    vide = (200, b"")  # le CDX répond par un corps vide
    routes = _routes(
        first=vide, last=vide, years=vide, urls=vide, dispo={"url": "example.com", "archived_snapshots": {}}
    )
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    outils.verifier_sortie(sortie)
    assert sortie["measured"] is True and sortie["available"] is False
    assert sortie["first_seen"] is None and sortie["last_seen"] is None and sortie["years_active"] == []


def test_entete_seul_sans_ligne_de_donnee(contexte, outils, http_simule):
    routes = _routes(
        first=[EN_TETE],
        last=[EN_TETE],
        years=[["timestamp"]],
        urls=[["original"]],
        dispo={"archived_snapshots": {}},
    )
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["available"] is False


def test_resultat_partiel_si_une_requete_est_trop_lente(contexte, outils, http_simule):
    routes = _routes(years=httpx.ReadTimeout("délai"), urls=httpx.ReadTimeout("délai"))
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    outils.verifier_sortie(sortie)
    assert sortie["measured"] is True and sortie["partial"] is True
    assert sortie["first_seen"] == "20020120" and sortie["years_active"] == [] and sortie["sample_urls"] == []


def test_derniere_capture_de_repli_si_la_requete_echoue(contexte, outils, http_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, _routes(last=(500, b"")))
    assert sortie["last_seen"] == "20261015" and sortie["partial"] is True


def test_un_resultat_partiel_n_est_pas_garde_en_cache(contexte, outils, http_simule):
    _lancer(contexte, outils, http_simule, _routes(years=httpx.ReadTimeout("x")))
    sortie, requetes = _lancer(contexte, outils, http_simule, _routes())
    assert sortie["partial"] is False and requetes  # le second scan a réinterrogé archive.org


def test_un_resultat_complet_est_garde_en_cache(contexte, outils, http_simule):
    _lancer(contexte, outils, http_simule, _routes())
    sortie, requetes = _lancer(contexte, outils, http_simule, {})
    assert requetes == [] and sortie["first_seen"] == "20020120"


def test_echec_http_de_toutes_les_requetes_essentielles(contexte, outils, http_simule):
    routes = _routes(first=(503, b""), last=(503, b""), dispo=(503, {}, ""))
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, routes)
    assert "503" in render(erreur.value.message, "fr")


def test_quota_429(contexte, outils, http_simule):
    routes = _routes(first=(429, b""), last=(429, b""), dispo=(429, {}, ""))
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, routes)
    assert "Quota" in render(erreur.value.message, "fr") and "Wayback" in render(erreur.value.message, "fr")


def test_service_injoignable(contexte, outils, http_simule):
    with pytest.raises(ModuleError) as erreur:
        _lancer(contexte, outils, http_simule, {})  # aucune route : connexion refusée
    assert "Wayback" in render(erreur.value.message, "fr") and "ConnectError" in render(
        erreur.value.message, "fr"
    )


def test_delai_depasse(contexte, outils, http_simule):
    boom = httpx.ReadTimeout("délai")
    with pytest.raises(ModuleError):
        _lancer(contexte, outils, http_simule, _routes(first=boom, last=boom, dispo=boom))


def test_reponse_illisible(contexte, outils, http_simule):
    illisible = (200, b"<html>pas du json</html>")
    with pytest.raises(ModuleError):
        _lancer(
            contexte, outils, http_simule, _routes(first=illisible, last=illisible, dispo=(200, {}, "oups"))
        )


def test_url_de_capture_hors_archive_org_ecartee(contexte, outils, http_simule):
    piege = {
        "archived_snapshots": {
            "closest": {
                "available": True,
                "timestamp": "20260101000000",
                "status": "200",
                "url": "https://evil.example/web/2026/",
            }
        }
    }
    sortie, _ = _lancer(contexte, outils, http_simule, _routes(dispo=piege))
    assert sortie["closest"] is None


def test_donnees_inattendues_ne_font_pas_planter(contexte, outils, http_simule):
    routes = _routes(
        first=[EN_TETE, ["pas-un-horodatage", "x", "200"], 42],
        last={"a": 1},
        years=["x"],
        urls=[["original"], [None]],
    )
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    outils.verifier_sortie(sortie)
    assert sortie["first_seen"] is None


def test_urls_tronquees(contexte, outils, http_simule):
    longue = "https://example.com/" + "a" * 500
    sortie, _ = _lancer(contexte, outils, http_simule, _routes(urls=[["original"], [longue]]))
    assert len(sortie["sample_urls"][0]) == wayback_cdx.MAX_URL_LENGTH


def test_sans_objet_pour_une_adresse_ip(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_declaration_du_module():
    assert SPEC.category == "passif" and SPEC.optional is True and SPEC.quick is False
    assert SPEC.timeout == 60 and SPEC.keys == ()


def test_sans_client_http(contexte, http_simule, outils):
    http_simule({})
    context = contexte()
    context.http = None
    with pytest.raises(ModuleError):
        outils.executer(SPEC, context)


def test_delai_global_depasse_rend_un_resultat_partiel(contexte, outils, http_simule, monkeypatch):
    """Une requête qui ne répond jamais est abandonnée au bout de TOTAL_BUDGET ; les autres sont gardées."""
    import asyncio

    reel = wayback_cdx._fetch

    async def lent(client, url, params, timeout):
        if params.get("matchType") == "host":
            await asyncio.sleep(30)
        return await reel(client, url, params, timeout)

    monkeypatch.setattr(wayback_cdx, "_fetch", lent)
    monkeypatch.setattr(wayback_cdx, "TOTAL_BUDGET", 0.3)
    sortie, _ = _lancer(contexte, outils, http_simule, _routes())
    assert sortie["partial"] is True and sortie["sample_urls"] == [] and sortie["first_seen"] == "20020120"
