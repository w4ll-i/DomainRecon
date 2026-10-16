# =============================================================================
# DomainRecon - Tests du module « tech_cves » (OSV.dev simulé, sans réseau)
# =============================================================================

import asyncio
import json

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import wc_osv
from domainrecon.scanner.modules.tech_cves import SPEC
from domainrecon.scanner.rules import FindingInput

OSV = "https://api.osv.dev/v1/query"


def _avis(identifiant, cve, severite="HIGH", corrige="2.2.28", paquet="Django", ecosysteme="PyPI", **plus):
    """Avis au format OSV (https://google.github.io/osv.dev/api/ ; schéma OSV)."""
    avis = {
        "id": identifiant,
        "summary": "Injection SQL",
        "aliases": [cve] if cve else [],
        "database_specific": {"severity": severite},
        "affected": [
            {
                "package": {"name": paquet, "ecosystem": ecosysteme},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": corrige}]},
                ],
            }
        ],
    }
    avis.update(plus)
    return avis


def _pile(*technologies):
    defaut = {
        "confidence": "high",
        "implied": False,
        "evidence": ["h:x-powered-by"],
        "category_key": "backend_framework",
    }
    return {"measured": True, "error": None, "technologies": [{**defaut, **t} for t in technologies]}


def _reponse_par_paquet(table):
    """Route OSV : réponse choisie d'après le nom du paquet demandé dans le corps."""

    def repondre(requete):
        corps = json.loads(requete.content)
        reponse = table.get(corps["package"]["name"], {})
        if isinstance(reponse, httpx.Response):
            return reponse
        return httpx.Response(200, json=reponse)

    return repondre


def _lancer(contexte, outils, pile):
    valeur = outils.executer(SPEC, contexte(results={"tech_stack": pile}))
    outils.verifier_sortie(valeur)
    return valeur


def _constat(code, data):
    regle = next(r for r in SPEC.findings if r.code == code)
    entree = FindingInput({SPEC.name: data}, SPEC.name, lambda scan, m: scan.get(m), lambda s, m: True)
    return regle.check(entree)


# --- Succès ----------------------------------------------------------------------


def test_succes_vulnerabilites_trouvees(http_simule, contexte, outils):
    requetes = http_simule(
        {
            OSV: _reponse_par_paquet(
                {
                    "Django": {
                        "vulns": [
                            _avis("PYSEC-2022-1", "CVE-2022-28346", "CRITICAL", "2.2.28"),
                            _avis("GHSA-2", "CVE-2020-7471", "HIGH", "2.2.10"),
                        ]
                    }
                }
            )
        }
    )
    valeur = _lancer(contexte, outils, _pile({"name": "Django", "version": "2.2.0"}))
    django = valeur["technologies"][0]
    assert valeur["checked"] == 1 and valeur["vulnerable_count"] == 1
    assert valeur["highest_severity"] == "critical"
    assert django["package"] == "Django" and django["ecosystem"] == "PyPI"
    assert {v["cve"] for v in django["vulnerabilities"]} == {"CVE-2022-28346", "CVE-2020-7471"}
    assert django["vulnerabilities"][0]["fixed"] == "2.2.28"
    corps = json.loads(requetes[0].content)
    assert corps == {"package": {"name": "Django", "ecosystem": "PyPI"}, "version": "2.2.0"}


def test_aucune_vulnerabilite(http_simule, contexte, outils):
    http_simule({OSV: {}})
    valeur = _lancer(contexte, outils, _pile({"name": "Laravel", "version": "11.0.0"}))
    assert valeur["checked"] == 1 and valeur["vulnerable_count"] == 0 and valeur["highest_severity"] is None


def test_pagination_osv(http_simule, contexte, outils):
    pages = iter(
        [
            {"vulns": [_avis("GHSA-1", "CVE-2024-1")], "next_page_token": "suite"},
            {"vulns": [_avis("GHSA-2", "CVE-2024-2")]},
        ]
    )
    http_simule({OSV: lambda requete: httpx.Response(200, json=next(pages))})
    valeur = _lancer(contexte, outils, _pile({"name": "Django", "version": "2.2.0"}))
    assert len(valeur["technologies"][0]["vulnerabilities"]) == 2


def test_gravite_lue_dans_le_vecteur_cvss(http_simule, contexte, outils):
    """OSV met un VECTEUR CVSS dans severity[].score : lu comme un nombre, tout sortirait « moyen »."""
    avis = _avis("X-1", "CVE-2024-9", None)
    avis.pop("database_specific")
    avis["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    http_simule({OSV: {"vulns": [avis]}})
    valeur = _lancer(contexte, outils, _pile({"name": "Django", "version": "2.2.0"}))
    assert valeur["technologies"][0]["vulnerabilities"][0]["severity"] == "critical"


def test_avis_retire_et_doublons_ignores(http_simule, contexte, outils):
    http_simule(
        {
            OSV: {
                "vulns": [
                    _avis("GHSA-1", "CVE-2024-1"),
                    _avis("PYSEC-1", "CVE-2024-1"),
                    _avis("GHSA-3", "CVE-2024-3", withdrawn="2024-01-01T00:00:00Z"),
                ]
            }
        }
    )
    valeur = _lancer(contexte, outils, _pile({"name": "Django", "version": "2.2.0"}))
    assert [v["cve"] for v in valeur["technologies"][0]["vulnerabilities"]] == ["CVE-2024-1"]


# --- Ce qui n'est pas interrogé ----------------------------------------------------------


def test_bibliotheque_de_page_et_detection_faible_non_interrogees(http_simule, contexte, outils):
    requetes = http_simule({OSV: {}})
    pile = _pile(
        {"name": "jQuery", "version": "3.3.1"},  # bibliothèque front : js_dependencies
        {"name": "Django", "version": "2.2.0", "confidence": "low"},  # détection faible
        {"name": "Laravel", "version": "9.0.0", "implied": True},  # déduite
        {"name": "Nginx", "version": "1.18.0", "category_key": "web_server"},  # serveur : hors OSV
        {"name": "PHP", "version": "7.4.3", "category_key": "language"},
    )
    valeur = _lancer(contexte, outils, pile)
    assert requetes == [] and valeur["checked"] == 0 and valeur["technologies"] == []
    assert {u["name"] for u in valeur["unchecked"]} == {"Nginx", "PHP"}


def test_sans_pile_technique_sans_objet(contexte):
    with pytest.raises(ModuleSkipped):
        asyncio.run(SPEC.run(contexte()))


def test_plafond_de_paquets(http_simule, contexte, outils):
    http_simule({OSV: {}})
    pile = _pile(*({"name": "Django", "version": f"2.{i}.0"} for i in range(30)))
    assert _lancer(contexte, outils, pile)["checked"] == 12


# --- Échecs --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reponse", "extrait"),
    [
        (httpx.Response(500, text="erreur"), "HTTP 500"),
        (httpx.Response(429, text=""), "Quota"),
        (httpx.Response(200, text="pas du json"), "OSV.dev"),
        (httpx.ConnectError("connexion refusée"), "OSV.dev"),
        (httpx.ReadTimeout("délai dépassé"), "OSV.dev"),
    ],
)
def test_echec_du_service(http_simule, contexte, reponse, extrait):
    http_simule({OSV: (lambda requete: reponse) if isinstance(reponse, httpx.Response) else reponse})
    context = contexte(results={"tech_stack": _pile({"name": "Django", "version": "2.2.0"})})
    with pytest.raises(ModuleError) as erreur:
        asyncio.run(SPEC.run(context))
    texte = render(erreur.value.message, "fr")
    assert extrait in texte
    assert "api.osv.dev" not in texte


def test_un_echec_partiel_ne_perd_pas_le_reste(http_simule, contexte, outils):
    http_simule(
        {
            OSV: _reponse_par_paquet(
                {
                    "Django": httpx.Response(500, text=""),
                    "Flask": {"vulns": [_avis("G-1", "CVE-2024-5", paquet="Flask")]},
                }
            )
        }
    )
    valeur = _lancer(
        contexte, outils, _pile({"name": "Django", "version": "2.2.0"}, {"name": "Flask", "version": "1.0.0"})
    )
    assert valeur["checked"] == 1 and valeur["failed"] == 1 and valeur["vulnerable_count"] == 1


def test_ecosysteme_inconnu_refuse():
    with pytest.raises(wc_osv.OsvError):
        asyncio.run(wc_osv.lookup(None, "Inconnu", "x", "1.0.0"))


# --- CVSS --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vecteur", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_score_cvss3(vecteur, score):
    assert wc_osv.cvss3_score(vecteur) == score


@pytest.mark.parametrize("vecteur", ["CVSS:4.0/AV:N", "", None, "CVSS:3.1/AV:N", "n'importe quoi"])
def test_vecteur_illisible(vecteur):
    assert wc_osv.cvss3_score(vecteur) is None


# --- Constats et score ----------------------------------------------------------------------------


def _donnees_avec_failles():
    return {
        "measured": True,
        "checked": 2,
        "highest_severity": "critical",
        "vulnerable_count": 1,
        "technologies": [
            {
                "name": "Django",
                "version": "2.2.0",
                "vulnerabilities": [
                    {"cve": "CVE-2022-28346", "severity": "critical", "fixed": "2.2.28"},
                    {"cve": "CVE-2020-7471", "severity": "high", "fixed": "2.2.10"},
                ],
            },
            {"name": "Flask", "version": "3.0.0", "vulnerabilities": []},
        ],
    }


def test_constat_gravite_la_plus_haute():
    constats = _constat("finding.tech_cves.vulnerable", _donnees_avec_failles())
    assert len(constats) == 1
    assert constats[0].severity == "critical"
    assert constats[0].params["count"] == 2 and constats[0].params["fixed"] == "2.2.28"


def test_constat_rien_a_signaler():
    assert (
        _constat("finding.tech_cves.vulnerable", {"technologies": [{"name": "Flask", "vulnerabilities": []}]})
        is None
    )


def test_constat_donnee_inattendue():
    for donnees in (None, 3, {"technologies": "x"}, {"technologies": [None, {"vulnerabilities": "y"}]}):
        assert _constat("finding.tech_cves.vulnerable", donnees) is None


def test_score_selon_la_gravite():
    note = SPEC.score_rules[0].evaluate
    assert note({"tech_cves": _donnees_avec_failles()}).points == 0
    assert note({"tech_cves": {"checked": 1, "highest_severity": "high", "vulnerable_count": 1}}).points == 2
    assert note({"tech_cves": {"checked": 1, "highest_severity": None, "vulnerable_count": 0}}).points == 8


def test_score_sans_objet_quand_rien_n_a_ete_verifie():
    sortie = SPEC.score_rules[0].evaluate({"tech_cves": {"checked": 0}})
    assert sortie.applicable is False


def test_declaration():
    assert SPEC.depends_on == ("tech_stack",) and SPEC.wave == 2 and SPEC.optional is True
