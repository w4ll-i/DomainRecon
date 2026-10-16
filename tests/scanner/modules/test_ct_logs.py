# =============================================================================
# DomainRecon - Tests du module « ct_logs » (sans réseau)
# =============================================================================
# Réponses simulées au format actuel de crt.sh (id, issuer_name, common_name,
# name_value, not_before, not_after, serial_number : plus de logged_at ni de
# min_cert_id) et de Cert Spotter (API v1 « issuances », expand=dns_names,issuer).
# =============================================================================

import datetime as dt
import json

import httpx
import pytest

from domainrecon.i18n import is_msg
from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import ct_common
from domainrecon.scanner.impl import ct_logs as history
from domainrecon.scanner.modules import ct_logs
from domainrecon.scanner.rules import FindingInput

SPEC = ct_logs.SPEC
UTC = dt.timezone.utc  # noqa: UP017 - Python 3.10 : datetime.UTC absent
MAINTENANT = dt.datetime.now(UTC)
CRTSH = "https://crt.sh/"
SPOTTER = "https://api.certspotter.com/v1/issuances"


@pytest.fixture(autouse=True)
def cache_vide(monkeypatch):
    cache.clear_cache()
    monkeypatch.setattr(ct_common, "CRTSH_RETRY_DELAY", 0)
    yield
    cache.clear_cache()


def jour(delta: int) -> str:
    return (MAINTENANT - dt.timedelta(days=delta)).strftime("%Y-%m-%dT%H:%M:%S")


def entree(identifiant, serie, noms, delta=10, jours=90, emetteur="C=US, O=Let's Encrypt, CN=R11"):
    return {
        "issuer_ca_id": 1,
        "issuer_name": emetteur,
        "common_name": noms[0],
        "name_value": "\n".join(noms),
        "id": identifiant,
        "not_before": jour(delta),
        "not_after": jour(delta - jours),
        "serial_number": serie,
        "result_count": 1,
    }


def donnees(valeur: dict) -> FindingInput:
    return FindingInput({}, "ct_logs", lambda scan, module: valeur, lambda scan, module: True)


def constats(valeur: dict) -> dict[str, object]:
    trouves = {}
    for regle in SPEC.findings:
        resultat = regle.check(donnees(valeur))
        if resultat:
            trouves[regle.code] = resultat
    return trouves


def lancer(contexte, outils, **champs):
    resultat = outils.executer(SPEC, contexte(**champs))
    outils.verifier_sortie(resultat)
    json.dumps(resultat)
    return resultat


# --- Succès ------------------------------------------------------------------------------------


def test_historique_crtsh(http_simule, contexte, outils):
    requetes = http_simule(
        {
            CRTSH: [
                entree(1, "aa", ["example.com", "*.example.com"], delta=5),
                entree(
                    2,
                    "bb",
                    ["www.example.com"],
                    delta=200,
                    jours=90,
                    emetteur="C=US, O=Sectigo Limited, CN=X",
                ),
                entree(3, "cc", ["example.com"], delta=800, jours=365, emetteur="C=GB, O=DigiCert Inc, CN=Y"),
            ]
        }
    )
    resultat = lancer(contexte, outils)
    assert requetes[0].url.params["q"] == "%.example.com" and requetes[0].url.params["output"] == "json"
    assert resultat["source"] == "crt.sh" and resultat["partial"] is False
    assert resultat["total_certs"] == 3 and resultat["active_certs"] == 1 and resultat["expired_certs"] == 2
    assert resultat["issued_last_30_days"] == 1
    assert [i["name"] for i in resultat["issuers"]] == [
        "Let's Encrypt",
        "Sectigo Limited",
        "DigiCert Inc",
    ] or {i["name"] for i in resultat["issuers"]} == {"Let's Encrypt", "Sectigo Limited", "DigiCert Inc"}
    assert resultat["first_seen"] < resultat["last_seen"]
    assert resultat["wildcard_names"] == 1
    assert {n["name"] for n in resultat["names"]} == {"example.com", "*.example.com", "www.example.com"}
    assert resultat["certs"][0]["not_before"] >= resultat["certs"][-1]["not_before"]  # plus récent d'abord
    assert constats(resultat) == {}


def test_certificat_et_precertificat_comptes_une_fois(http_simule, contexte, outils):
    """crt.sh liste le pré-certificat et le certificat final (ids différents, même numéro de série)."""
    http_simule({CRTSH: [entree(1, "ab12", ["example.com"]), entree(2, "ab12", ["example.com"])]})
    assert lancer(contexte, outils)["total_certs"] == 1


def test_organisation_de_l_emetteur_entre_guillemets(http_simule, contexte, outils):
    """Piège évité : « "CLOUDFLARE » (coupé à la virgule du nom)."""
    emetteur = 'C=US, O="CLOUDFLARE, INC.", CN=Cloudflare Inc ECC CA-3'
    http_simule({CRTSH: [entree(1, "a", ["example.com"], emetteur=emetteur)]})
    assert lancer(contexte, outils)["issuers"][0]["name"] == "CLOUDFLARE, INC."


def test_emetteur_sans_organisation_utilise_le_cn():
    assert history.issuer_organization("C=US, CN=Seule AC") == "Seule AC"
    assert history.issuer_organization("") == ""


def test_aucun_certificat(http_simule, contexte, outils):
    http_simule({CRTSH: []})
    resultat = lancer(contexte, outils)
    assert resultat["measured"] is True and resultat["total_certs"] == 0
    assert resultat["first_seen"] is None and resultat["certs"] == []
    assert constats(resultat) == {}


def test_noms_invalides_et_autres_domaines_ecartes(http_simule, contexte, outils):
    http_simule(
        {
            CRTSH: [
                entree(
                    1, "a", ["example.com", "?.example.com", "autre.org", "user@example.com", "myexample.com"]
                )
            ]
        }
    )
    noms = {n["name"] for n in lancer(contexte, outils)["names"]}
    assert noms == {"example.com"}


def test_volume_borne(http_simule, contexte, outils, monkeypatch):
    monkeypatch.setattr(history, "MAX_LISTED_CERTS", 5)
    monkeypatch.setattr(history, "MAX_LISTED_NAMES", 4)
    http_simule({CRTSH: [entree(i, f"s{i:04d}", [f"h{i}.example.com"], delta=i + 1) for i in range(40)]})
    resultat = lancer(contexte, outils)
    assert resultat["total_certs"] == 40 and resultat["name_count"] == 40
    assert len(resultat["certs"]) == 5 and len(resultat["names"]) == 4


# --- Constats ------------------------------------------------------------------------------------


def test_noms_internes_recents(http_simule, contexte, outils):
    http_simule(
        {
            CRTSH: [
                entree(1, "a", ["vpn.example.com", "www.example.com", "api-staging.example.com"], delta=30),
                entree(2, "b", ["dev.example.com"], delta=900),  # trop ancien : hors fenêtre d'un an
                entree(3, "c", ["example.com"], delta=5),
            ]
        }
    )
    resultat = lancer(contexte, outils)
    assert resultat["internal_names"] == ["api-staging.example.com", "vpn.example.com"]
    parametres = constats(resultat)["finding.ct_logs.internal_names"]
    assert parametres["count"] == 2 and "vpn.example.com" in parametres["examples"]


def test_le_domaine_lui_meme_n_est_pas_un_nom_interne(http_simule, contexte, outils):
    http_simule({CRTSH: [entree(1, "a", ["test.example.com"])]})
    assert (
        lancer(contexte, outils, domain="test.example.com", site="test.example.com")["internal_names"] == []
    )


def test_beaucoup_d_emetteurs_recents(http_simule, contexte, outils):
    autorites = [f"C=US, O=Autorite {i}, CN=AC" for i in range(5)]
    http_simule(
        {
            CRTSH: [
                entree(i, f"s{i}", ["example.com"], delta=20 + i, emetteur=a) for i, a in enumerate(autorites)
            ]
        }
    )
    resultat = lancer(contexte, outils)
    assert resultat["recent_issuer_count"] == 5
    assert constats(resultat)["finding.ct_logs.many_issuers"] == {"count": 5}


def test_quatre_emetteurs_ne_declenchent_rien(http_simule, contexte, outils):
    autorites = [f"C=US, O=Autorite {i}, CN=AC" for i in range(4)]
    http_simule(
        {
            CRTSH: [
                entree(i, f"s{i}", ["example.com"], delta=20 + i, emetteur=a) for i, a in enumerate(autorites)
            ]
        }
    )
    assert "finding.ct_logs.many_issuers" not in constats(lancer(contexte, outils))


# --- Échecs ----------------------------------------------------------------------------------------------


def certspotter(delta=10):
    return [
        {
            "id": "100",
            "tbs_sha256": "a" * 64,
            "dns_names": ["example.com", "mail.example.com"],
            "issuer": {"friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt, CN=R11"},
            "not_before": jour(delta) + "Z",
            "not_after": jour(delta - 90) + "Z",
            "revoked": False,
        }
    ]


def test_repli_sur_cert_spotter(http_simule, contexte, outils):
    requetes = http_simule({CRTSH: (503, {}, "surcharge"), SPOTTER: certspotter()})
    resultat = lancer(contexte, outils)
    assert resultat["source"] == "certspotter" and resultat["partial"] is True
    assert resultat["total_certs"] == 1 and resultat["issuers"][0]["name"] == "Let's Encrypt"
    assert {n["name"] for n in resultat["names"]} == {"example.com", "mail.example.com"}
    assert sum(1 for r in requetes if r.url.host == "crt.sh") == 2  # une nouvelle tentative sur 503
    spotter = next(r for r in requetes if r.url.host == "api.certspotter.com")
    assert spotter.url.params["domain"] == "example.com"


def test_erreur_passagere_de_crtsh_retentee(http_simule, contexte, outils):
    reponses = iter([httpx.Response(502), httpx.Response(200, json=[entree(1, "a", ["example.com"])])])
    http_simule({CRTSH: lambda requete: next(reponses)})
    resultat = lancer(contexte, outils)
    assert resultat["source"] == "crt.sh" and resultat["total_certs"] == 1


def test_les_deux_sources_en_echec(http_simule, contexte, outils):
    http_simule({CRTSH: (500, {}, ""), SPOTTER: (429, {}, "")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert is_msg(erreur.value.message)


def test_delai_de_crtsh_puis_cert_spotter(http_simule, contexte, outils):
    http_simule({CRTSH: httpx.ReadTimeout("lent"), SPOTTER: certspotter()})
    assert lancer(contexte, outils)["source"] == "certspotter"


def test_json_illisible(http_simule, contexte, outils):
    http_simule({CRTSH: (200, {}, "<html>maintenance</html>"), SPOTTER: (500, {}, "")})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_reponse_inattendue(http_simule, contexte, outils):
    http_simule({CRTSH: {"erreur": "x"}, SPOTTER: {"erreur": "x"}})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_reponse_trop_volumineuse(http_simule, contexte, outils, monkeypatch):
    monkeypatch.setattr(ct_common, "CRTSH_MAX_BYTES", 100)
    http_simule({CRTSH: [entree(i, f"s{i}", ["example.com"]) for i in range(10)], SPOTTER: (500, {}, "")})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_resultat_mis_en_cache(http_simule, contexte, outils):
    requetes = http_simule({CRTSH: [entree(1, "a", ["example.com"])]})
    lancer(contexte, outils)
    lancer(contexte, outils)
    assert len(requetes) == 1


def test_echec_non_mis_en_cache(http_simule, contexte, outils):
    http_simule({CRTSH: (500, {}, ""), SPOTTER: (500, {}, "")})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())
    http_simule({CRTSH: [entree(1, "a", ["example.com"])]})
    assert lancer(contexte, outils)["total_certs"] == 1


def test_cible_ip_sans_objet(contexte):
    assert is_msg(SPEC.skip_reason(contexte(domain="93.184.216.34")))
    assert SPEC.skip_reason(contexte()) is None


def test_domaine_du_site_interroge(http_simule, contexte, outils):
    """Sous une plateforme mutualisée, c'est le domaine du site (et non l'apex) qui est interrogé."""
    requetes = http_simule({CRTSH: []})
    lancer(contexte, outils, domain="mon.github.io", apex="github.io", site="mon.github.io")
    assert requetes[0].url.params["q"] == "%.mon.github.io"


def test_donnees_inattendues_ne_levent_pas():
    for valeur in (
        None,
        [],
        "x",
        {"internal_names": "x", "recent_issuer_count": "beaucoup"},
        {"measured": False},
    ):
        constats(valeur)


def test_declaration():
    assert SPEC.category == "passif" and SPEC.family == "tls" and SPEC.optional and not SPEC.keys
    assert SPEC.timeout and SPEC.timeout > 60
