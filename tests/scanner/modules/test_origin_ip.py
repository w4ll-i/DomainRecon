# =============================================================================
# DomainRecon - Tests du module « origin_ip » (IP d'origine derrière un CDN), sans réseau
# =============================================================================

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleSkipped
from domainrecon.scanner.impl import origin_ip as impl
from domainrecon.scanner.modules import origin_ip
from domainrecon.scanner.page import HomePage
from domainrecon.scanner.rules import FindingInput, Hit

CDN_IP = "104.20.23.154"
ORIGINE = "51.15.20.7"
ANCIENNE = "51.15.20.9"
MX_IP = "198.100.1.1"
AUTRE_CDN = "104.20.5.5"
ACCUEIL = (
    "<html><head><title>Boutique Exemple</title></head><body>"
    + "<p>Bienvenue sur la boutique.</p>" * 30
    + "</body></html>"
)
AUTRE_SITE = (
    "<html><head><title>Autre client</title></head><body>"
    + "<p>Tout autre contenu ici.</p>" * 30
    + "</body></html>"
)
DEFAUT = "<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>"


@pytest.fixture(autouse=True)
def cache_vide():
    cache.clear_cache()
    yield
    cache.clear_cache()


def cymru(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"


def zone(outils) -> dict:
    return {
        (cymru(CDN_IP), "TXT"): ["13335 | 104.20.16.0/20 | US | arin | 2014-03-28"],
        ("AS13335.asn.cymru.com", "TXT"): ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"],
        (cymru(AUTRE_CDN), "TXT"): ["13335 | 104.20.0.0/20 | US | arin | 2014-03-28"],
        (cymru(ORIGINE), "TXT"): ["12876 | 51.15.0.0/16 | FR | ripencc | 2015-01-01"],
        (cymru(ANCIENNE), "TXT"): ["12876 | 51.15.0.0/16 | FR | ripencc | 2015-01-01"],
        (cymru(MX_IP), "TXT"): ["16276 | 198.100.0.0/16 | CA | arin | 2012-01-01"],
        ("AS12876.asn.cymru.com", "TXT"): ["12876 | FR | ripencc | 2002-01-01 | SCALEWAY, FR"],
        ("direct.example.com", "A"): [outils.rdata("A", ORIGINE)],
        ("mail.example.com", "A"): [outils.rdata("A", AUTRE_CDN)],
        ("example.com", "MX"): [outils.rdata("MX", "10 mx.example.com.")],
        ("mx.example.com", "A"): [outils.rdata("A", MX_IP)],
        ("example.com", "TXT"): [f"v=spf1 ip4:{ORIGINE} ip4:10.0.0.0/8 -all"],
    }


def routes(**plus) -> dict:
    table = {
        "https://example.com/": (200, {"cf-ray": "8a1b2c3d-CDG", "content-type": "text/html"}, ACCUEIL),
        "https://freeapi.robtex.com/pdns/forward/example.com": (
            200,
            {},
            f'{{"rrname":"example.com","rrdata":"{ANCIENNE}","rrtype":"A","time_first":1433818966,"time_last":1500000000,"count":2}}\n',
        ),
        f"https://{ORIGINE}/": (200, {"content-type": "text/html"}, ACCUEIL),
        f"https://{ANCIENNE}/": (503, {}, "indisponible"),
        f"http://{ANCIENNE}/": (200, {}, DEFAUT),
        f"https://{MX_IP}/": (200, {}, AUTRE_SITE),
        f"http://{MX_IP}/": (200, {}, AUTRE_SITE),
    }
    table.update(plus)
    return table


def contexte_cdn(contexte, **fields):
    return contexte(addresses=[CDN_IP], **fields)


def test_origine_confirmee_et_faux_positifs_ecartes(http_simule, dns_simule, contexte, outils):
    requetes = http_simule(routes())
    dns_simule(zone(outils))
    result = outils.executer(origin_ip.SPEC, contexte_cdn(contexte))

    outils.verifier_sortie(result)
    assert result["behind_cdn"] is True and result["cdn"] == "Cloudflare"
    assert result["cdn_evidence"] == ["asn:AS13335", "header:cf-ray"]
    lignes = {r["ip"]: r for r in result["candidates"]}
    # L'adresse d'origine répond avec la même page : confirmée, vue par deux sources (DNS voisin + SPF).
    assert lignes[ORIGINE]["verdict"] == "confirmed" and lignes[ORIGINE]["scheme"] == "https"
    assert lignes[ORIGINE]["sources"] == ["dns_sibling", "spf"] and lignes[ORIGINE]["names"] == [
        "direct.example.com"
    ]
    assert lignes[ORIGINE]["asn"] == "AS12876" and lignes[ORIGINE]["as_name"] == "SCALEWAY, FR"
    assert result["confirmed"] == [ORIGINE] and result["probable"] == []
    # Faux positifs : page par défaut, autre site hébergé là, ancienne adresse hors service.
    assert lignes[ANCIENNE]["verdict"] == "rejected" and lignes[MX_IP]["verdict"] == "rejected"
    assert lignes[ANCIENNE]["sources"] == ["robtex_history"]
    # Une autre adresse du CDN (mail.example.com proxifié) et le réseau privé du SPF ne sont pas candidats.
    assert AUTRE_CDN not in lignes and "10.0.0.1" not in lignes and result["cdn_filtered"] == 1
    assert result["candidates"][0]["ip"] == ORIGINE
    # La requête de vérification porte l'en-tête Host de la cible.
    directes = [r for r in requetes if r.url.host == ORIGINE]
    assert directes and directes[0].headers["host"] == "example.com"


def test_origine_probable_meme_titre_contenu_different(http_simule, dns_simule, contexte, outils):
    variante = ACCUEIL.replace("Bienvenue sur la boutique.", "Version de test, ancien catalogue.")
    http_simule(routes(**{f"https://{ORIGINE}/": (200, {}, variante)}))
    dns_simule(zone(outils))
    result = outils.executer(origin_ip.SPEC, contexte_cdn(contexte))
    ligne = next(r for r in result["candidates"] if r["ip"] == ORIGINE)
    assert ligne["verdict"] in ("probable", "confirmed")
    if ligne["verdict"] == "probable":
        assert result["probable"] == [ORIGINE] and result["confirmed"] == []


def test_aucun_cdn_sans_objet(http_simule, dns_simule, contexte, outils):
    http_simule({"https://example.com/": (200, {"server": "nginx"}, ACCUEIL)})
    dns_simule({(cymru(ORIGINE), "TXT"): ["12876 | 51.15.0.0/16 | FR | ripencc | 2015-01-01"]})
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(origin_ip.SPEC, contexte(addresses=[ORIGINE]))
    assert erreur.value.message == msg("origin_ip.no_cdn")


def test_cdn_detecte_par_les_seuls_en_tetes(http_simule, dns_simule, contexte, outils):
    http_simule(
        routes(
            **{
                "https://example.com/": (
                    200,
                    {"x-amz-cf-id": "abc", "via": "1.1 x.cloudfront.net (CloudFront)"},
                    ACCUEIL,
                )
            }
        )
    )
    dns_simule({k: v for k, v in zone(outils).items() if k[0] != cymru(CDN_IP)})
    result = outils.executer(origin_ip.SPEC, contexte_cdn(contexte))
    assert result["cdn"] == "Amazon CloudFront" and result["cdn_evidence"] == [
        "header:x-amz-cf-id",
        "header:via",
    ]


def test_page_d_accueil_illisible_candidats_non_verifies(http_simule, dns_simule, contexte, outils):
    table = routes()
    del table["https://example.com/"]  # accueil injoignable : rien à comparer
    requetes = http_simule(table)
    dns_simule(zone(outils))
    result = outils.executer(origin_ip.SPEC, contexte_cdn(contexte))
    assert result["cdn"] == "Cloudflare"  # ASN suffisant
    assert {r["verdict"] for r in result["candidates"]} == {"unverified"}
    assert result["confirmed"] == [] and not [r for r in requetes if r.url.host == ORIGINE]


def test_historique_indisponible_n_est_pas_fatal(http_simule, dns_simule, contexte, outils):
    http_simule(routes(**{"https://freeapi.robtex.com/pdns/forward/example.com": (429, {}, "limite")}))
    dns_simule(zone(outils))
    result = outils.executer(origin_ip.SPEC, contexte_cdn(contexte))
    assert result["history_error"] == msg("network.quota", service="Robtex")
    assert result["confirmed"] == [ORIGINE] and ANCIENNE not in [r["ip"] for r in result["candidates"]]


def test_sans_objet_cible_ip(contexte, http_simule):
    http_simule({})
    assert origin_ip.SPEC.skip_reason(contexte(domain="93.184.216.34")) == msg("orchestrator.skip_ip_target")


def accueil(texte=ACCUEIL, url="https://example.com/") -> HomePage:
    return HomePage(url=url, status_code=200, headers={}, text=texte)


@pytest.mark.parametrize(
    ("statut", "en_tetes", "texte", "attendu"),
    [
        (200, {}, ACCUEIL, "confirmed"),
        (200, {}, DEFAUT, "rejected"),
        (200, {}, AUTRE_SITE, "rejected"),
        (403, {}, ACCUEIL, "rejected"),
        (502, {}, ACCUEIL, "rejected"),
        (200, {}, "", "rejected"),
        (301, {"location": "https://example.com/"}, "", "probable"),
        (301, {"location": "https://ailleurs.example.net/"}, "", "rejected"),
    ],
)
def test_verdicts(statut, en_tetes, texte, attendu):
    assert impl.judge(accueil(), statut, en_tetes, texte)[0] == attendu


def test_page_par_defaut_acceptee_si_l_accueil_est_aussi_une_page_par_defaut():
    # Le site n'est qu'une page par défaut : la même page chez le candidat est un indice, pas un faux positif écarté d'office.
    assert impl.judge(accueil(DEFAUT), 200, {}, DEFAUT)[0] == "confirmed"


def test_similarite_et_titre():
    assert impl.title_of("<TITLE>\n  Mon   Site </title>") == "mon site" and impl.title_of("rien") == ""
    assert impl.similarity("", "x") is None and impl.similarity("abc", "abc") == 1.0


def test_spf_et_candidats():
    assert impl.spf_addresses(["v=spf1 ip4:1.2.3.4 ip4:5.6.7.8/30 ip4:10.0.0.0/8 ip6:2001:db8::/126 -all", "autre"]) == [
        "1.2.3.4", "5.6.7.8", "5.6.7.9", "5.6.7.10", "5.6.7.11",
        "2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3",
    ]  # fmt: skip
    fusion = impl.merge_candidates(
        {
            "1.1.1.1": {"names": ["a"], "sources": ["mx"]},
            "192.168.0.1": {"names": [], "sources": ["spf"]},
            "pas-une-ip": {"names": [], "sources": []},
        },
        ["1.1.1.1", "8.8.4.4", "8.8.8.8"],
        {"8.8.8.8"},
    )
    assert list(fusion) == ["1.1.1.1", "8.8.4.4"] and fusion["1.1.1.1"]["sources"] == ["mx", "robtex_history"]


# --- Constats et score --------------------------------------------------------


def entree(data) -> FindingInput:
    return FindingInput({}, "origin_ip", lambda scan, module: data, lambda scan, module: True)


def test_constats_et_score():
    data = {
        "cdn": "Cloudflare",
        "candidates": [
            {"ip": ORIGINE, "verdict": "confirmed", "sources": ["dns_sibling", "spf"]},
            {"ip": ANCIENNE, "verdict": "probable", "sources": ["robtex_history"]},
            {"ip": MX_IP, "verdict": "rejected", "sources": ["mx"]},
        ],
        "confirmed": [ORIGINE],
        "probable": [ANCIENNE],
    }
    exposee, probable = (rule.check for rule in origin_ip.SPEC.findings)
    (hit_confirme,) = exposee(entree(data))
    assert isinstance(hit_confirme, Hit)
    assert hit_confirme.params == {"ip": ORIGINE, "cdn": "Cloudflare", "source": "dns_sibling, spf"}
    assert [h.params["ip"] for h in probable(entree(data))] == [ANCIENNE]
    assert exposee(entree("inattendu")) == [] and probable(entree({"candidates": 3})) == []

    rule = origin_ip.SPEC.criteria[0]
    assert rule.evaluate({"origin_ip": data}).points == 0
    assert rule.evaluate({"origin_ip": {**data, "confirmed": []}}).points == 2
    assert rule.evaluate({"origin_ip": {"confirmed": [], "probable": []}}).points == 5


def test_declaration():
    spec = origin_ip.SPEC
    assert spec.category == "sensible" and spec.requires_authorization and spec.wave == 3 and not spec.quick
