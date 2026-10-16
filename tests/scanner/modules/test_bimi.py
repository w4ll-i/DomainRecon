# =============================================================================
# DomainRecon - Tests du module « bimi » (sans réseau)
# =============================================================================

import datetime as dt

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import bimi as impl
from domainrecon.scanner.modules.bimi import SPEC
from domainrecon.scanner.rules import FindingInput

LOGO_URL = "https://example.com/bimi/logo.svg"
VMC_URL = "https://example.com/bimi/vmc.pem"
SVG_OK = (
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">'
    "<title>Exemple</title><rect width='100' height='100' fill='#036'/></svg>"
)
SVG_HEADERS = {"content-type": "image/svg+xml"}
DMARC_APPLIQUE = {"measured": True, "dmarc": {"found": True, "policy": "reject", "pct": None}}


def _certificat(*, eku=True, logotype=True, noms=("example.com",), jours_avant=10, jours_apres=300) -> bytes:
    cle = ec.generate_private_key(ec.SECP256R1())
    sujet = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Exemple SA")])
    maintenant = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(sujet)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Autorité de test")]))
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - dt.timedelta(days=jours_avant))
        .not_valid_after(maintenant + dt.timedelta(days=jours_apres))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in noms]), critical=False)
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([impl.BIMI_EKU_OID]), critical=False)
    if logotype:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(impl.LOGOTYPE_OID, b"\x30\x00"), critical=False
        )
    return builder.sign(cle, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _zone(
    record="v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem",
    nom="example.com",
):
    return {(f"default._bimi.{nom}", "TXT"): [record]}


def _routes(*, svg=SVG_OK, pem=None):
    return {
        LOGO_URL: (200, SVG_HEADERS, svg),
        VMC_URL: (200, {"content-type": "application/x-pem-file"}, pem if pem is not None else _certificat()),
    }


def _lancer(outils, contexte, dns_simule, http_simule, zone, routes, **champs):
    dns_simule(zone)
    http_simule(routes)
    resultat = outils.executer(SPEC, contexte(**champs))
    outils.verifier_sortie(resultat)
    return resultat


def _constat(code, data):
    rule = next(r for r in SPEC.findings if r.code == code)
    return rule.check(FindingInput({"bimi": data}, "bimi", lambda scan, m: scan[m], lambda scan, m: True))


def _score(resultat):
    return SPEC.score_rules[0].evaluate({"bimi": resultat})


def test_succes_logo_et_certificat_valides(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone(),
        _routes(),
        results={"email_security": DMARC_APPLIQUE},
    )
    assert resultat["found"] and not resultat["declined"] and resultat["issues"] == []
    assert resultat["logo"]["valid"] and resultat["logo"]["content_type"] == "image/svg+xml"
    assert resultat["vmc"]["valid"] and resultat["vmc"]["bimi_usage"] and resultat["vmc"]["has_logotype"]
    assert resultat["vmc"]["subject_org"] == "Exemple SA" and resultat["dmarc_enforced"] is True
    assert _score(resultat).points == 2
    for rule in SPEC.findings:
        assert not _constat(rule.code, resultat), rule.code


def test_absent_n_est_pas_penalise(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(outils, contexte, dns_simule, http_simule, {}, {})
    assert resultat["found"] is False and resultat["issues"] == []
    assert _score(resultat).counted is False


def test_refus_explicite_l_vide(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone("v=BIMI1; l=;"), {})
    assert resultat["found"] and resultat["declined"] and resultat["logo"] is None
    assert _score(resultat).counted is False


def test_repli_sur_le_domaine_organisationnel(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone(nom="example.com"),
        _routes(),
        domain="www.example.com",
        apex="example.com",
    )
    assert resultat["found"] and resultat["source_domain"] == "example.com"


def test_dmarc_non_applique(outils, contexte, dns_simule, http_simule):
    email = {"measured": True, "dmarc": {"found": True, "policy": "none"}}
    resultat = _lancer(
        outils, contexte, dns_simule, http_simule, _zone(), _routes(), results={"email_security": email}
    )
    assert resultat["dmarc_enforced"] is False
    assert _constat("finding.bimi.dmarc_not_enforced", resultat) is True
    assert _score(resultat).points == 1
    # pct < 100 : appliqué en partie seulement, donc pas suffisant non plus.
    email = {"measured": True, "dmarc": {"found": True, "policy": "reject", "pct": 50}}
    assert impl.dmarc_enforced(email) is False
    # Sans résultat d'email_security, on ne conclut pas.
    assert impl.dmarc_enforced(None) is None
    assert impl.dmarc_enforced({"measured": False}) is None


def test_logo_non_conforme(outils, contexte, dns_simule, http_simule):
    svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 50"><script>alert(1)</script></svg>'
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone(), _routes(svg=svg))
    texte = " | ".join(render(resultat["logo"]["issues"], "fr"))
    assert "Tiny PS" in texte and "script" in texte and "carré" in texte
    assert _constat("finding.bimi.logo_invalid", resultat)["detail"]


def test_svg_avec_entite_refuse_sans_analyse():
    """Faux positif / danger évité : un DOCTYPE ou une entité n'est jamais développé."""
    bombe = b'<!DOCTYPE svg [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><svg>&b;</svg>'
    problemes = impl.check_logo_svg(bombe)
    assert len(problemes) == 1 and problemes[0]["p"]["what"] == "DOCTYPE"


def test_svg_invalide_et_pas_un_svg():
    assert impl.check_logo_svg(b"<svg><oups>")[0]["$t"] == "bimi.logo_invalid_xml"
    assert impl.check_logo_svg(b"<html/>")[0]["$t"] == "bimi.logo_not_svg"


def test_logo_http_et_inaccessible(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(
        outils, contexte, dns_simule, http_simule, _zone("v=BIMI1; l=http://example.com/logo.svg"), {}
    )
    assert "HTTPS" in render(resultat["logo"]["issues"][0], "fr")
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone(),
        {LOGO_URL: (404, {}, ""), VMC_URL: httpx.ConnectTimeout("x")},
    )
    assert "HTTP 404" in render(resultat["logo"]["issues"][0], "fr")
    assert "délai dépassé" in render(resultat["vmc"]["issues"][0], "fr")


def test_logo_trop_lourd_et_mauvais_type(outils, contexte, dns_simule, http_simule):
    gros = SVG_OK.replace("</svg>", "<!--" + "x" * 40000 + "--></svg>")
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone(),
        {LOGO_URL: (200, {"content-type": "text/html"}, gros), VMC_URL: (200, {}, _certificat())},
    )
    texte = " | ".join(render(resultat["logo"]["issues"], "fr"))
    assert "trop lourd" in texte and "image/svg+xml" in texte


def test_certificat_expire(outils, contexte, dns_simule, http_simule):
    pem = _certificat(jours_avant=400, jours_apres=-5)
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone(), _routes(pem=pem))
    assert resultat["vmc"]["days_left"] < 0 and not resultat["vmc"]["valid"]
    assert _constat("finding.bimi.vmc_expired", resultat)["date"] == resultat["vmc"]["not_after"]
    # Expiré seulement : pas de second constat « invalide » pour la même cause.
    assert not _constat("finding.bimi.vmc_invalid", resultat)


def test_certificat_proche_de_l_expiration(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(
        outils, contexte, dns_simule, http_simule, _zone(), _routes(pem=_certificat(jours_apres=10))
    )
    assert "expire dans" in render(resultat["vmc"]["issues"][0], "fr")
    assert not _constat("finding.bimi.vmc_expired", resultat)
    assert _constat("finding.bimi.vmc_invalid", resultat)


def test_certificat_sans_usage_bimi_ni_domaine(outils, contexte, dns_simule, http_simule):
    pem = _certificat(eku=False, noms=("autre.example.net",))
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone(), _routes(pem=pem))
    texte = " | ".join(render(resultat["vmc"]["issues"], "fr"))
    assert "usage BIMI" in texte and "domaine" in texte
    assert _constat("finding.bimi.vmc_invalid", resultat)


def test_certificat_joker_couvre_le_domaine(outils, contexte, dns_simule, http_simule):
    pem = _certificat(noms=("*.example.com",))
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone(nom="mail.example.com"),
        _routes(pem=pem),
        domain="mail.example.com",
        apex="example.com",
    )
    # Le joker *.example.com couvre mail.example.com : aucun défaut de domaine.
    assert resultat["vmc"]["valid"] is True
    assert impl._covers(["*.example.com"], ["example.com"]) is False


def test_certificat_illisible_et_absence_de_vmc(outils, contexte, dns_simule, http_simule):
    resultat = _lancer(outils, contexte, dns_simule, http_simule, _zone(), _routes(pem=b"pas un pem"))
    assert resultat["vmc"]["readable"] is False
    resultat = _lancer(
        outils,
        contexte,
        dns_simule,
        http_simule,
        _zone("v=BIMI1; l=https://example.com/bimi/logo.svg"),
        _routes(),
    )
    assert resultat["vmc"] is None and any(
        "certificat de marque" in t for t in render(resultat["issues"], "fr")
    )


def test_plusieurs_enregistrements(outils, contexte, dns_simule, http_simule):
    zone = {("default._bimi.example.com", "TXT"): ["v=BIMI1; l=;", "v=BIMI1; l=;"]}
    resultat = _lancer(outils, contexte, dns_simule, http_simule, zone, {})
    assert resultat["issues"]


def test_echec_dns_leve_module_error(outils, contexte, dns_simule, http_simule):
    import dns.exception

    dns_simule({("default._bimi.example.com", "TXT"): dns.exception.Timeout})
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_sans_objet_et_declaration(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.skip_reason(contexte()) is None
    assert SPEC.keys == () and SPEC.category == "passif" and SPEC.depends_on == ("email_security",)


def test_regles_resistent_aux_donnees_inattendues():
    for rule in SPEC.findings:
        for data in (None, [], "x", {"found": True, "logo": 3, "vmc": [], "issues": "x"}):
            rule.check(FindingInput({"bimi": data}, "bimi", lambda scan, m: scan[m], lambda scan, m: True))
    assert SPEC.score_rules[0].evaluate({"bimi": None}).counted is False
