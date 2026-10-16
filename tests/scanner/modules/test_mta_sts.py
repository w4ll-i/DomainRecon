# =============================================================================
# DomainRecon - Tests du module « mta_sts » (sans réseau)
# =============================================================================

import ssl

import dns.exception
import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import mta_sts as impl
from domainrecon.scanner.modules.mta_sts import SPEC
from domainrecon.scanner.rules import FindingInput

URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"
POLITIQUE = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.mail.example.net\nmax_age: 604800\n"
TEXTE_PLAIN = {"content-type": "text/plain; charset=utf-8"}


def _zone(outils, *, sts=True, rpt=True, mx=("10 mail.example.com.",), hote=True):
    zone = {("example.com", "MX"): [outils.rdata("MX", valeur) for valeur in mx]}
    if sts:
        zone[("_mta-sts.example.com", "TXT")] = ["v=STSv1; id=20260101T000000"]
    if hote:
        zone[("mta-sts.example.com", "A")] = [outils.rdata("A", "93.184.216.34")]
        zone[("mta-sts.example.com", "AAAA")] = []
    if rpt:
        zone[("_smtp._tls.example.com", "TXT")] = [
            "v=TLSRPTv1; rua=mailto:tls@example.com,https://rapports.example.com/tls"
        ]
    return zone


def _lancer(outils, contexte, dns_simule, http_simule, zone, routes):
    dns_simule(zone)
    http_simule(routes)
    resultat = outils.executer(SPEC, contexte())
    outils.verifier_sortie(resultat)
    return resultat


def _donnees(resultat):
    return {"mta_sts": resultat}


def _constat(code, data):
    rule = next(r for r in SPEC.findings if r.code == code)
    return rule.check(
        FindingInput({"mta_sts": data}, "mta_sts", lambda scan, m: scan[m], lambda scan, m: True)
    )


def _score(resultat):
    return SPEC.score_rules[0].evaluate(_donnees(resultat))


# --- Analyse syntaxique -----------------------------------------------------------


def test_analyse_de_la_politique():
    politique = impl.parse_policy(
        "version: STSv1\r\nmode: Enforce\r\nmx: A.example.com.\r\nmx: *.example.net\r\nmax_age: 86400\r\n"
    )
    assert politique["version"] == "STSv1" and politique["mode"] == "enforce"
    assert politique["mx"] == ["a.example.com", "*.example.net"] and politique["max_age"] == 86400


def test_max_age_invalide_et_lignes_inconnues():
    politique = impl.parse_policy("max_age: beaucoup\nfoo: bar\nsans separateur\n")
    assert politique["max_age"] is None and politique["max_age_raw"] == "beaucoup"


@pytest.mark.parametrize(
    ("motif", "hote", "attendu"),
    [
        ("mail.example.com", "mail.example.com", True),
        ("mail.example.com", "MAIL.example.com.", True),
        ("*.example.com", "mx1.example.com", True),
        ("*.example.com", "a.b.example.com", False),  # un seul label
        ("*.example.com", "example.com", False),
        ("*.example.com", "mx1.example.net", False),
        ("mail.example.com", "mail2.example.com", False),
    ],
)
def test_comparaison_des_motifs_mx(motif, hote, attendu):
    assert impl.mx_pattern_matches(motif, hote) is attendu


def test_destinations_tls_rpt():
    valides, invalides = impl.parse_rua(
        "v=TLSRPTv1; rua=mailto:a@example.com, https://x.example.com/r,ftp://y,mailto:sans-arobase"
    )
    assert valides == ["mailto:a@example.com", "https://x.example.com/r"]
    assert invalides == ["ftp://y", "mailto:sans-arobase"]


def test_classement_des_erreurs_reseau():
    tls = httpx.ConnectError("x")
    tls.__cause__ = ssl.SSLCertVerificationError()
    assert impl.classify_fetch_error(tls) == "tls"
    assert impl.classify_fetch_error(httpx.ConnectTimeout("x")) == "timeout"
    assert impl.classify_fetch_error(httpx.ConnectError("x")) == "unreachable"


# --- Module -----------------------------------------------------------------------


def test_succes_enforce_et_mx_couverts(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(
        outils, contexte, dns_simule, http_simule, _zone(outils), {URL: (200, TEXTE_PLAIN, POLITIQUE)}
    )
    assert resultat["state"] == "enforce"
    assert resultat["policy"]["valid"] and resultat["policy"]["max_age"] == 604800
    assert resultat["mx_check"]["uncovered"] == [] and resultat["mx_check"]["unused_patterns"] == [
        "*.mail.example.net"
    ]
    assert resultat["tls_rpt"]["found"] and len(resultat["tls_rpt"]["rua"]) == 2
    assert _score(resultat).points == 4
    for rule in SPEC.findings:
        if rule.code != "finding.mta_sts.mx_uncovered":
            assert not _constat(rule.code, resultat), rule.code


def test_la_politique_est_demandee_sans_redirection(outils, contexte, dns_simule, http_simule):
    dns_simule(_zone(outils))
    autre = "https://autre.example.net/mta-sts.txt"
    recues = http_simule({URL: (301, {"location": autre}, ""), autre: (200, TEXTE_PLAIN, POLITIQUE)})
    resultat = outils.executer(SPEC, contexte())
    assert [str(r.url) for r in recues] == [
        URL
    ]  # la redirection (interdite par la RFC 8461) n'est pas suivie
    assert resultat["state"] == "broken" and resultat["policy"]["status"] == 301


def test_mx_non_couvert_est_signale(outils, contexte, dns_simule, http_simule):
    zone = _zone(outils, mx=("10 mail.example.com.", "20 secours.example.org."))
    resultat = _lancer(outils, contexte, dns_simule, http_simule, zone, {URL: (200, TEXTE_PLAIN, POLITIQUE)})
    assert resultat["mx_check"]["uncovered"] == ["secours.example.org"]
    constat = _constat("finding.mta_sts.mx_uncovered", resultat)
    assert constat.severity == "high" and constat.params["hosts"] == ["secours.example.org"]
    assert _score(resultat).points == 2
    # En mode testing, le même défaut est moins grave.
    test = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800\n"
    resultat = _lancer(outils, contexte, dns_simule, http_simule, zone, {URL: (200, TEXTE_PLAIN, test)})
    assert resultat["state"] == "testing"
    assert _constat("finding.mta_sts.mx_uncovered", resultat).severity == "medium"
    assert _constat("finding.mta_sts.not_enforced", resultat) == {"mode": "testing"}


def test_mode_none_et_duree_courte(outils, contexte, dns_simule, http_simule):
    politique = "version: STSv1\nmode: none\nmax_age: 3600\n"
    resultat = _lancer(
        outils, contexte, dns_simule, http_simule, _zone(outils), {URL: (200, TEXTE_PLAIN, politique)}
    )
    assert resultat["state"] == "none" and resultat["policy"]["valid"]
    assert _score(resultat).points == 1
    politique = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 3600\n"
    resultat = _lancer(
        outils, contexte, dns_simule, http_simule, _zone(outils), {URL: (200, TEXTE_PLAIN, politique)}
    )
    assert _constat("finding.mta_sts.short_max_age", resultat) == {"days": 0}


def test_absent_est_un_bonus_non_obtenu(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone(outils, sts=False, rpt=False), {})
    assert resultat["state"] == "absent"
    note = _score(resultat)
    assert note.counted is False and note.applicable is True
    assert _constat("finding.mta_sts.missing", resultat) is True
    assert not _constat("finding.mta_sts.broken", resultat)


def test_domaine_sans_messagerie_critere_sans_objet(outils, contexte, dns_simule, http_simule):
    zone = _zone(outils, sts=False, rpt=False, mx=("0 .",))
    resultat = _lancer(outils, contexte, dns_simule, http_simule, zone, {})
    assert resultat["has_mail"] is False
    assert _score(resultat).applicable is False
    assert not _constat("finding.mta_sts.missing", resultat)


def test_hote_de_politique_inexistant_cas_cloudflare(outils, contexte, dns_simule, http_simule):
    """Le TXT est publié mais mta-sts.<domaine> n'existe pas : annoncé, inutilisable (aucune requête HTTPS)."""
    dns_simule(_zone(outils, hote=False))
    recues = http_simule({})
    resultat = outils.executer(SPEC, contexte())
    assert recues == [] and resultat["state"] == "broken" and resultat["policy"]["host_resolves"] is False
    assert _constat("finding.mta_sts.broken", resultat)["detail"]
    assert _score(resultat).points == 0 and _score(resultat).counted is True
    assert "mta-sts.example.com" in render(resultat["issues"][0], "fr")


@pytest.mark.parametrize(
    ("route", "attendu"),
    [
        ((404, TEXTE_PLAIN, "absent"), "HTTP 404"),
        (httpx.ConnectTimeout("x"), "délai dépassé"),
        (httpx.ConnectError("x"), "connexion HTTPS impossible"),
    ],
)
def test_echecs_de_recuperation_de_la_politique(outils, contexte, dns_simule, http_simule, route, attendu):
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone(outils), {URL: route})
    assert resultat["state"] == "broken"
    assert attendu in render(resultat["issues"], "fr")[0]


def test_certificat_https_invalide(outils, contexte, dns_simule, http_simule):
    erreur = httpx.ConnectError("x")
    erreur.__cause__ = ssl.SSLCertVerificationError()
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone(outils), {URL: erreur})
    assert resultat["state"] == "broken" and resultat["policy"]["error"] == "tls"
    assert "certificat" in render(resultat["issues"][0], "fr")


def test_politique_illisible_ou_invalide(outils, contexte, dns_simule, http_simule):
    for corps in (
        "<html>pas une politique</html>",
        "version: STSv2\nmode: enforce\nmx: a.example.com\nmax_age: 1\n",
        "version: STSv1\nmode: parfois\nmx: a.example.com\nmax_age: 1\n",
        "version: STSv1\nmode: enforce\nmax_age: 1\n",
    ):
        resultat = _lancer(
            outils, contexte, dns_simule, http_simule, _zone(outils), {URL: (200, TEXTE_PLAIN, corps)}
        )
        assert resultat["state"] == "broken" and not resultat["policy"]["valid"], corps


def test_mauvais_type_de_contenu_tolere_mais_signale(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone(outils),
        {URL: (200, {"content-type": "text/html"}, POLITIQUE)},
    )
    assert resultat["state"] == "enforce"
    assert any("text/plain" in texte for texte in render(resultat["issues"], "fr"))


def test_plusieurs_enregistrements_sts(outils, contexte, dns_simule, http_simule):
    zone = _zone(outils)
    zone[("_mta-sts.example.com", "TXT")] = ["v=STSv1; id=1", "v=STSv1; id=2"]
    resultat = _lancer(outils, contexte, dns_simule, http_simule, zone, {})
    assert resultat["state"] == "broken" and resultat["txt"]["count"] == 2


def test_tls_rpt_absent_avec_mta_sts(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone(outils, rpt=False),
        {URL: (200, TEXTE_PLAIN, POLITIQUE)},
    )
    assert _constat("finding.mta_sts.tls_rpt_missing", resultat) is True


def test_tls_rpt_destinations_invalides(outils, contexte, dns_simule, http_simule):
    zone = _zone(outils)
    zone[("_smtp._tls.example.com", "TXT")] = ["v=TLSRPTv1; rua=ftp://nope"]
    resultat = _lancer(outils, contexte, dns_simule, http_simule, zone, {URL: (200, TEXTE_PLAIN, POLITIQUE)})
    assert resultat["tls_rpt"]["invalid_rua"] == ["ftp://nope"]


def test_echec_dns_leve_module_error(outils, contexte, dns_simule, http_simule):
    """Délai dépassé sur la requête TXT : on ne conclut pas à « MTA-STS absent »."""
    zone = _zone(outils)
    zone[("_mta-sts.example.com", "TXT")] = dns.exception.Timeout
    dns_simule(zone)
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_sans_objet_adresse_ip(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_aucune_cle_requise():
    assert SPEC.keys == () and SPEC.category == "passif"


def test_regles_resistent_aux_donnees_inattendues():
    for rule in SPEC.findings:
        for data in (None, [], "x", {"state": None}, {"mx_check": [], "policy": 3, "state": "enforce"}):
            rule.check(
                FindingInput({"mta_sts": data}, "mta_sts", lambda scan, m: scan[m], lambda scan, m: True)
            )
    assert SPEC.score_rules[0].evaluate({"mta_sts": None}).points == 0
