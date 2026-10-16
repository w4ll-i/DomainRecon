# =============================================================================
# DomainRecon - Tests du module « takeover_extended » : noms étendus, empreintes rétablies (sans réseau)
# =============================================================================
# Le moteur (scanner/takeover.py) a ses propres tests (test_takeover_network.py) ;
# ici : la table complétée par impl/takeover_extra.py et le choix des noms à tester.
# =============================================================================

import re

import pytest

from domainrecon.scanner import takeover
from domainrecon.scanner.impl import takeover_extra
from domainrecon.scanner.modules import takeover_extended
from domainrecon.scanner.rules import FindingInput

SPEC = takeover_extended.SPEC


def test_table_installee_a_l_import_et_sans_doublon():
    assert set(takeover_extra.EXTRA_FINGERPRINTS) <= set(takeover.TAKEOVER_FINGERPRINTS)
    assert takeover_extra.install() == 0
    cles = [key for key, *_ in takeover._COMPILED]
    assert len(cles) == len(set(cles)) == len(takeover.TAKEOVER_FINGERPRINTS)
    assert len(takeover.TAKEOVER_FINGERPRINTS) >= 45


def test_formes_valides():
    for key, info in takeover_extra.EXTRA_FINGERPRINTS.items():
        assert info["service"] and re.compile(info["cname"], re.I), key
        assert info["fingerprint"] is None or re.compile(info["fingerprint"], re.I), key


@pytest.mark.parametrize(
    ("cname", "service"),
    [
        ("docs.readme.io", "Readme.io"),
        ("shop.cargocollective.com", "Cargo Collective"),
        ("proxy-ssl.webflow.com", "Webflow"),
        ("x.stats.uptimerobot.com", "UptimeRobot"),
        ("a.hatenablog.com", "HatenaBlog"),
        ("exemple.github.io", "GitHub Pages"),
    ],
)
def test_services_reconnus(cname, service):
    trouve = takeover.match_service(cname)
    assert trouve is not None and trouve[1]["service"] == service


@pytest.mark.parametrize(
    "cname",
    [
        # Services « Not vulnerable » du registre can-i-take-over-xyz : écartés pour ne pas créer de faux positifs.
        "x.global.ssl.fastly.net",
        "site.kinsta.cloud",
        "x.zendesk.com",
        "x.uservoice.com",
        "x.statuspage.io",
        "d111.cloudfront.net",
        # Frontière de label : un autre domaine ne doit pas correspondre.
        "monreadme.io",
        "readme.io.evil.example",
    ],
)
def test_services_non_exploitables_ou_homonymes_ignores(cname):
    assert takeover.match_service(cname) is None


def _simuler(monkeypatch, cname, *, cible="exists", empreinte=(False, True, 200)):
    async def resolve_cname(resolver, name):
        return cname

    async def target_state(resolver, name):
        return cible

    async def fingerprint(client, sub, regex):
        trouvee, repondu, statut = empreinte
        return (bool(trouvee and regex and regex.pattern), repondu, statut)

    monkeypatch.setattr(takeover, "_make_resolver", lambda: object())
    monkeypatch.setattr(takeover, "_resolve_cname", resolve_cname)
    monkeypatch.setattr(takeover, "_cname_target_state", target_state)
    monkeypatch.setattr(takeover, "_fingerprint_check", fingerprint)


PASSIF = {
    "subdomains_passive": {
        "measured": True,
        "subdomains": [{"subdomain": "docs.example.com", "resolution": "resolved"}],
    }
}


def _lancer(contexte, outils, results=None):
    return outils.executer(SPEC, contexte(results=results or PASSIF))


def test_service_retabli_empreinte_confirmee(contexte, outils, monkeypatch):
    _simuler(monkeypatch, "monprojet.readme.io", empreinte=(True, True, 404))
    sortie = _lancer(contexte, outils)
    assert len(sortie) == 1
    assert (
        sortie[0]["service"] == "readme.io" and sortie[0]["confirmed"] is True and sortie[0]["risk"] == "high"
    )
    resultat = SPEC.score_rules[0].evaluate({"takeover_extended": sortie})
    assert resultat.points == 0 and resultat.cap_reason is not None


def test_service_a_preuve_de_propriete_reste_a_verifier(contexte, outils, monkeypatch):
    _simuler(monkeypatch, "monsite.webflow.io", empreinte=(True, True, 404))
    sortie = _lancer(contexte, outils)
    assert sortie[0]["confirmed"] is False and sortie[0]["risk"] == "medium"
    assert SPEC.score_rules[0].evaluate({"takeover_extended": sortie}).points == 2


def test_page_normale_aucun_constat(contexte, outils, monkeypatch):
    """Faux positif évité : le CNAME vise le service mais la page répond normalement."""
    _simuler(monkeypatch, "monprojet.readme.io", empreinte=(False, True, 200))
    sortie = _lancer(contexte, outils)
    assert sortie == []
    assert SPEC.score_rules[0].evaluate({"takeover_extended": sortie}).points == 5


def test_nom_reclamable_cname_pendant(contexte, outils, monkeypatch):
    _simuler(monkeypatch, "forum.trydiscourse.com", cible="nxdomain")
    sortie = _lancer(contexte, outils)
    assert sortie[0]["service"] == "trydiscourse.com" and sortie[0]["confirmed"] is True


def test_constats(contexte, outils, monkeypatch):
    _simuler(monkeypatch, "monprojet.readme.io", empreinte=(True, True, 404))
    sortie = _lancer(contexte, outils)
    donnees = FindingInput({}, "takeover_extended", lambda scan, name: sortie, lambda scan, name: True)
    regles = {rule.code.rsplit(".", 1)[1]: rule for rule in SPEC.findings}
    assert regles["confirmed"].check(donnees) == [{"subdomain": "docs.example.com", "provider": "Readme.io"}]
    assert regles["to_check"].check(donnees) == []
    for data in (None, [], "x", [None, 3, {"subdomain": 5}]):
        donnees = FindingInput({}, "takeover_extended", lambda scan, name, d=data: d, lambda scan, name: True)
        for regle in regles.values():
            regle.check(donnees)


def test_noms_a_tester_exclut_ceux_du_module_historique():
    results = {
        "subdomains": [{"subdomain": "deja.example.com", "resolution": "resolved"}],
        "subdomains_passive": {
            "subdomains": [
                {"subdomain": "deja.example.com", "resolution": "resolved"},
                {"subdomain": "nouveau.example.com", "resolution": "unresolved"},
                {"subdomain": "NOUVEAU.example.com", "resolution": "resolved"},
            ]
        },
        "subdomain_bruteforce": {
            "subdomains_found": [
                {"subdomain": "blog.example.com", "cname": "x.github.io"},
                {"subdomain": "www.example.com", "cname": "ailleurs.example.com"},
                {"subdomain": "deja.example.com"},
                {"subdomain": 5},
            ]
        },
    }
    noms = {e["subdomain"]: e["resolution"] for e in takeover_extended.candidates(results)}
    # Le CNAME vers un service connu passe en tête de file (« unresolved »).
    assert noms == {
        "nouveau.example.com": "unresolved",
        "blog.example.com": "unresolved",
        "www.example.com": "resolved",
    }


def test_sans_nom_ou_sur_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(results={})) is not None
    assert SPEC.skip_reason(contexte(results={"subdomains_passive": {"subdomains": []}})) is not None
    assert SPEC.skip_reason(contexte(domain="93.184.216.34", results=PASSIF)) is not None
    assert SPEC.skip_reason(contexte(results=PASSIF)) is None


def test_declaration():
    assert SPEC.wave == 3 and SPEC.depends_on == ("subdomains_passive",) and SPEC.category == "passif"
