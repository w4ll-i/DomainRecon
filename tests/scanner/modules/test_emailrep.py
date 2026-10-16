# =============================================================================
# DomainRecon - Tests du module « emailrep » (sans réseau : réponses simulées conformes à
# https://docs.emailrep.io/)
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import emailrep as impl
from domainrecon.scanner.modules.emailrep import SPEC
from domainrecon.scanner.rules import FindingInput

CLE = "cle-emailrep-secrete-0123456789"
PAGE = (
    "<html><body><a href='mailto:contact@example.com'>Écrire</a> "
    "Support : Support@Example.com, presse@mail.example.com, "
    "partenaire@autre-site.org, logo@2x.png, faux@notexample.com</body></html>"
)

RAPPORT = {
    "email": "contact@example.com",
    "reputation": "high",
    "suspicious": False,
    "references": 20,
    "details": {
        "blacklisted": False,
        "malicious_activity": False,
        "malicious_activity_recent": False,
        "credentials_leaked": True,
        "credentials_leaked_recent": False,
        "data_breach": True,
        "first_seen": "07/01/2008",
        "last_seen": "02/25/2019",
        "domain_exists": True,
        "domain_reputation": "n/a",
        "new_domain": False,
        "days_since_domain_creation": 8605,
        "suspicious_tld": False,
        "spam": False,
        "free_provider": False,
        "disposable": False,
        "deliverable": True,
        "accept_all": True,
        "valid_mx": True,
        "spoofable": True,
        "spf_strict": True,
        "dmarc_enforced": False,
        "profiles": ["twitter", "linkedin"],
    },
}
PROPRE = {"reputation": "medium", "suspicious": False, "references": 3, "details": {"data_breach": False}}


def _routes(accueil=PAGE):
    return {"https://example.com/": (200, {"content-type": "text/html"}, accueil)}


def _constats(data):
    entree = FindingInput({}, "emailrep", lambda scan, module: data, lambda scan, module: True)
    return {rule.code: rule.check(entree) for rule in SPEC.findings}


def _score(data):
    return SPEC.score_rules[0].evaluate({"emailrep": data})


def test_declaration():
    assert SPEC.category == "sensible" and SPEC.family == "leaks"
    assert [(k.name, k.service, k.required) for k in SPEC.keys] == [("emailrep_key", "emailrep", True)]
    assert "emailrep" in SPEC.key_tests


def test_extraction_des_adresses_du_domaine():
    trouvees = impl.extract_emails(PAGE, "example.com")
    # Domaine et sous-domaines seulement ; ni images « @2x.png », ni autre domaine, ni « notexample.com ».
    assert trouvees == ["contact@example.com", "support@example.com", "presse@mail.example.com"]
    assert impl.extract_emails("a&#64;example.com b%40example.com", "example.com") == [
        "a@example.com",
        "b@example.com",
    ]
    assert impl.extract_emails(None, "example.com") == []


def test_succes_adresses_masquees(http_simule, contexte, outils):
    requetes = http_simule(
        {
            **_routes(),
            "https://emailrep.io/contact@example.com": RAPPORT,
            "https://emailrep.io/support@example.com": {"reputation": "none", "details": {}},
            "https://emailrep.io/presse@mail.example.com": PROPRE,
        }
    )
    resultat = outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    outils.verifier_sortie(resultat, [CLE])
    assert (
        resultat["emails_found"] == 3
        and resultat["emails_checked"] == 3
        and resultat["quota_reached"] is False
    )
    assert resultat["leaked_count"] == 1 and resultat["breached_count"] == 0
    premier = resultat["results"][0]
    assert premier["email"] == "c***@example.com" and premier["credentials_leaked"] is True
    assert premier["profiles"] == ["twitter", "linkedin"] and premier["first_seen"] == "07/01/2008"
    # Aucune adresse en clair ; la clé voyage dans l'en-tête « Key » seulement, vers emailrep.io.
    assert "contact@" not in str(resultat) and "support@" not in str(resultat)
    api = [r for r in requetes if r.url.host == "emailrep.io"]
    assert len(api) == 3 and all(r.headers["key"] == CLE for r in api)
    assert all(CLE not in str(r.url) for r in requetes)
    assert not [r for r in requetes if r.url.host == "example.com" and "key" in r.headers]


def test_au_plus_cinq_adresses_interrogees(http_simule, contexte, outils):
    page = " ".join(f"u{i}@example.com" for i in range(9))
    routes = {f"https://emailrep.io/u{i}@example.com": PROPRE for i in range(9)}
    requetes = http_simule({**_routes(page), **routes})
    resultat = outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    assert resultat["emails_found"] == 9 and resultat["emails_checked"] == 5
    assert len([r for r in requetes if r.url.host == "emailrep.io"]) == 5


def test_quota_atteint_garde_le_partiel(http_simule, contexte, outils):
    http_simule(
        {
            **_routes(),
            "https://emailrep.io/contact@example.com": RAPPORT,
            "https://emailrep.io/support@example.com": (429, {}, '{"status": "fail", "reason": "quota"}'),
        }
    )
    resultat = outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    assert resultat["quota_reached"] is True and resultat["emails_checked"] == 1


def test_quota_des_la_premiere_adresse(http_simule, contexte, outils):
    http_simule({**_routes(), "https://emailrep.io/contact@example.com": (429, {}, "")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    assert "Quota" in render(erreur.value.message, "fr")


def test_adresse_refusee_ignoree(http_simule, contexte, outils):
    toutes = {
        "https://emailrep.io/contact@example.com": (400, {}, '{"status": "fail", "reason": "invalid email"}'),
        "https://emailrep.io/support@example.com": PROPRE,
        "https://emailrep.io/presse@mail.example.com": PROPRE,
    }
    http_simule({**_routes(), **toutes})
    resultat = outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    assert resultat["emails_checked"] == 2


@pytest.mark.parametrize(
    ("route", "attendu"),
    [
        ((401, {}, '{"status": "fail", "reason": "invalid api key"}'), "refusée"),
        ((500, {}, ""), "500"),
        ((200, {}, "<html>"), "illisible"),
        ((200, {}, "[1, 2]"), "illisible"),
        (httpx.ReadTimeout("lent"), "délai"),
        (httpx.ConnectError("refusé"), "ConnectError"),
    ],
)
def test_echecs(http_simule, contexte, outils, route, attendu):
    http_simule({**_routes(), "https://emailrep.io/contact@example.com": route})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    texte = render(erreur.value.message, "fr")
    assert attendu in texte and CLE not in texte


def test_sans_adresse_publiee_sans_objet(http_simule, contexte, outils):
    http_simule(_routes("<html>Aucune adresse ici, écrivez-nous via le formulaire.</html>"))
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    assert "Aucune adresse" in render(erreur.value.message, "fr")


def test_pages_de_contact_et_security_txt_lues(http_simule, contexte, outils):
    http_simule(
        {
            **_routes("<html>rien</html>"),
            "https://example.com/contact": (200, {}, "Écrivez à contact@example.com"),
            "https://example.com/.well-known/security.txt": (200, {}, "Contact: mailto:security@example.com"),
            "https://emailrep.io/contact@example.com": PROPRE,
            "https://emailrep.io/security@example.com": PROPRE,
        }
    )
    resultat = outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    assert resultat["emails_found"] == 2 and resultat["emails_checked"] == 2


def test_reponses_gardees_24_h(http_simule, contexte, outils):
    requetes = http_simule(
        {**_routes("contact@example.com"), "https://emailrep.io/contact@example.com": RAPPORT}
    )
    outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    outils.executer(SPEC, contexte(secrets={"emailrep_key": CLE}))
    assert len([r for r in requetes if r.url.host == "emailrep.io"]) == 1  # le quota est journalier


def test_cle_absente(contexte, outils):
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert "non renseignée" in render(erreur.value.message, "fr")


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_constats_et_score():
    donnees = {"leaked_count": 1, "malicious_count": 2, "breached_count": 3}
    constats = _constats(donnees)
    assert constats == {
        "finding.emailrep.leaked": {"count": 1},
        "finding.emailrep.malicious": {"count": 2},
        "finding.emailrep.breached": {"count": 3},
    }
    assert _score(donnees).points == 0
    assert _score({"malicious_count": 2}).points == 1
    assert _score({"breached_count": 1}).points == 2
    assert _score({}).points == 3
    assert all(v is None for v in _constats({}).values())


def test_lecture_defensive():
    for donnees in (None, [], {"leaked_count": "x", "malicious_count": None}):
        assert all(v is None for v in _constats(donnees).values())
        _score(donnees if isinstance(donnees, dict) else {})


def test_rapport_sans_champs_ne_leve_pas():
    rapport = impl.parse_report({"reputation": "inconnue", "details": "x", "references": "beaucoup"})
    assert rapport["reputation"] == "none" and rapport["references"] == 0 and rapport["profiles"] == []
    assert impl.parse_report(None)["credentials_leaked"] is False


def test_test_de_cle():
    sonde = SPEC.key_tests["emailrep"].probes({"emailrep_key": CLE})[0]
    assert sonde.url == "https://emailrep.io/test@example.com" and sonde.headers["Key"] == CLE
