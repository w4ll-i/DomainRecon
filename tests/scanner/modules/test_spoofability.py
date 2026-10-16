# =============================================================================
# DomainRecon - Tests du module « spoofability » (calcul pur, sans réseau)
# =============================================================================

import asyncio

import pytest

from domainrecon.i18n import msg, render
from domainrecon.scanner import email_security
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import spoofability as impl
from domainrecon.scanner.modules.spoofability import SPEC
from domainrecon.scanner.rules import FindingInput


def _email(*, spf="-all", spf_found=True, spf_grade="A", dmarc="reject", pct=None, sp=None, issues=()):
    return {
        "measured": True,
        "spf": {"found": spf_found, "all": spf, "grade": spf_grade, "issues": list(issues), "error": None},
        "dmarc": {
            "found": dmarc is not None,
            "policy": dmarc,
            "subdomain_policy": sp or dmarc,
            "pct": pct,
            "error": None,
        },
    }


def _constat(code, data):
    rule = next(r for r in SPEC.findings if r.code == code)
    return rule.check(
        FindingInput({"spoofability": data}, "spoofability", lambda s, m: s[m], lambda s, m: True)
    )


def test_declaration():
    assert SPEC.family == "email" and SPEC.category == "passif" and SPEC.quick
    assert SPEC.depends_on == ("email_security",) and SPEC.keys == () and not SPEC.score_rules


@pytest.mark.parametrize(
    ("email", "score", "verdict", "risque"),
    [
        (_email(spf="-all", dmarc="reject"), 5, "protected", "minimal"),
        (_email(spf="~all", dmarc="reject"), 5, "protected", "minimal"),
        (_email(spf="-all", dmarc="quarantine"), 15, "protected", "low"),
        (_email(spf="-all", dmarc="none"), 50, "spoofable", "high"),
        (_email(spf="~all", dmarc="none"), 60, "spoofable", "high"),
        (_email(spf=None, spf_found=False, spf_grade="F", dmarc=None), 95, "spoofable", "critical"),
        (_email(spf="+all", spf_grade="F", dmarc="reject"), 80, "spoofable", "critical"),
        (_email(spf="-all", dmarc="reject", pct=50), 40, "partial", "medium"),
    ],
)
def test_matrice_spf_dmarc(email, score, verdict, risque):
    result = impl.compute("example.com", email)
    assert result["measured"] is True
    assert (result["score"], result["verdict"], result["risk"]) == (score, verdict, risque)


def test_dkim_et_catch_all_ne_comptent_pas():
    """DKIM/catch-all n'empêchent pas l'usurpation."""
    base = _email(spf="~all", dmarc="none")
    avec_dkim = dict(base, dkim={"found": True}, catch_all=False)
    assert impl.compute("example.com", base)["score"] == impl.compute("example.com", avec_dkim)["score"]


def test_include_ouvert_contourne_dmarc():
    issues = [msg("email.spf_include_pass_all", target="ouvert.example.net")]
    result = impl.compute("example.com", _email(spf="-all", spf_grade="F", dmarc="reject", issues=issues))
    assert result["spf_level"] == "open" and result["verdict"] == "spoofable"
    assert any("autorise tout expéditeur" in s for s in render(result["scenarios"], "fr"))


def test_spf_en_erreur_sans_effet_majeur_si_dmarc_applique():
    result = impl.compute("example.com", _email(spf="-all", spf_grade="F", dmarc="reject"))
    assert result["spf_level"] == "broken" and result["verdict"] == "protected" and result["score"] == 10


def test_sous_domaines_moins_proteges():
    result = impl.compute("example.com", _email(dmarc="reject", sp="none"))
    assert result["subdomain_exposed"] is True and result["subdomain_score"] == 80
    assert result["score"] == 48 and result["verdict"] == "partial"
    assert _constat("finding.spoofability.subdomains", result) is True
    assert _constat("finding.spoofability.partial", result)["score"] == 48
    assert not _constat("finding.spoofability.spoofable", result)


def test_dmarc_invalide_ou_illisible():
    invalide = impl.compute("example.com", _email(dmarc="bizarre"))
    assert invalide["dmarc_level"] == "invalid" and invalide["verdict"] == "spoofable"
    illisible = impl.compute(
        "example.com", {"spf": {}, "dmarc": {"error": msg("net.timeout"), "found": None}}
    )
    assert illisible["measured"] is False and illisible["error"] is not None


def test_constats():
    result = impl.compute("example.com", _email(spf=None, spf_found=False, spf_grade="F", dmarc=None))
    assert _constat("finding.spoofability.spoofable", result) == {"score": 95, "risk": "critical"}
    assert not _constat("finding.spoofability.partial", result)
    protege = impl.compute("example.com", _email())
    for rule in SPEC.findings:
        assert not _constat(rule.code, protege)


def test_scenarios_en_clair():
    result = impl.compute("exemple.fr", _email(dmarc="none"))
    assert "@exemple.fr" in render(result["scenarios"], "fr")[0]
    assert all(isinstance(f["points"], int) for f in result["factors"])


def test_run_avec_vrai_resultat_email_security(contexte, dns_simule, outils):
    """Chaîne complète : l'analyse e-mail réelle (DNS simulé) alimente le score."""
    dns_simule(
        {
            ("example.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
            ("_spf.google.com", "TXT"): ["v=spf1 ip4:203.0.113.0/24 ~all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:r@example.com"],
            ("example.com", "MX"): [outils.rdata("MX", "10 mx.example.com.")],
        }
    )
    email = asyncio.run(email_security.analyze_email_security("example.com", dmarc_domain="example.com"))
    assert email["measured"]
    result = outils.executer(SPEC, contexte(results={"email_security": email}))
    outils.verifier_sortie(result)
    assert (
        result["dmarc_level"] == "monitor"
        and result["spf_level"] == "soft"
        and result["verdict"] == "spoofable"
    )


def test_run_sans_resultat_email_security(contexte, outils):
    for results in ({}, {"email_security": {"measured": False, "error": None}}):
        with pytest.raises(ModuleError):
            outils.executer(SPEC, contexte(results=results))


def test_sans_objet_adresse_ip(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_regles_resistent_aux_donnees_inattendues():
    for rule in SPEC.findings:
        for data in (None, [], "x", {"verdict": "spoofable", "score": "a"}):
            rule.check(
                FindingInput({"spoofability": data}, "spoofability", lambda s, m: s[m], lambda s, m: True)
            )
