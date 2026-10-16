# =============================================================================
# DomainRecon - Tests du module « shodan » (API hôte et InternetDB), sans réseau
# =============================================================================

import httpx
import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import cache
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.modules import shodan
from domainrecon.scanner.rules import FindingInput, Hit

CLE = "cle-secrete-shodan-0123456789ABCDEF"
HOTE = "https://api.shodan.io/shodan/host/93.184.216.34"
INTERNETDB = "https://internetdb.shodan.io/93.184.216.34"


@pytest.fixture(autouse=True)
def cache_vide():
    cache.clear_cache()
    yield
    cache.clear_cache()


def reponse_hote() -> dict:
    """Réponse de GET /shodan/host/{ip} (https://developer.shodan.io/api)."""
    return {
        "ip_str": "93.184.216.34",
        "org": "Edgecast",
        "isp": "Edgecast Inc.",
        "asn": "AS15133",
        "os": None,
        "ports": [443, 80, 80],
        "hostnames": ["example.com"],
        "domains": ["example.com"],
        "tags": ["cdn"],
        "country_name": "United States",
        "city": "Los Angeles",
        "last_update": "2026-10-01T12:00:00.000000",
        "vulns": ["CVE-2019-0211", "!CVE-2018-1312", "pas-une-cve"],
        "data": [
            {
                "port": 80,
                "transport": "tcp",
                "product": "Apache httpd",
                "version": "2.4.7",
                "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7\x00\r\n",
                "cpe": ["cpe:/a:apache:http_server:2.4.7"],
                "_shodan": {"module": "http"},
                "vulns": {
                    "CVE-2019-0211": {"cvss": 7.2, "summary": "Élévation de privilèges", "verified": False},
                    "CVE-2017-9798": {"cvss": 5.0, "summary": "Optionsbleed", "verified": False},
                },
            },
            {"port": 443, "transport": "tcp", "product": "nginx", "data": "x", "_shodan": "pas un dict"},
        ],
    }


def test_succes_avec_cle(http_simule, contexte, outils):
    requetes = http_simule({HOTE: reponse_hote()})
    result = outils.executer(shodan.SPEC, contexte(secrets={"shodan_key": CLE}))

    outils.verifier_sortie(result, secrets=[CLE])
    assert result["source"] == "shodan" and result["key_used"] is True and result["found"] is True
    assert result["ports"] == [80, 443] and result["org"] == "Edgecast" and result["asn"] == "AS15133"
    assert result["services_total"] == 2 and result["services"][0]["version"] == "2.4.7"
    # Octets de contrôle retirés des bannières.
    assert "\x00" not in result["services"][0]["banner"]
    # CVE : « ! » retiré, fusion hôte + services, triées par CVSS, la valeur sans forme de CVE écartée.
    assert [v["id"] for v in result["vulns"]] == ["CVE-2019-0211", "CVE-2017-9798", "CVE-2018-1312"]
    assert result["vuln_count"] == 3 and result["vulns"][0]["cvss"] == 7.2
    assert result["cpes"] == ["cpe:/a:apache:http_server:2.4.7"]
    # La clé part dans l'URL (seul mode documenté) mais nulle part ailleurs.
    assert requetes[0].url.params["key"] == CLE
    assert not any("internetdb" in str(r.url) for r in requetes)


def test_sans_cle_internetdb(http_simule, contexte, outils):
    requetes = http_simule(
        {
            INTERNETDB: {
                "cpes": ["cpe:/a:apache:http_server:2.4.7"],
                "hostnames": ["example.com"],
                "ip": "93.184.216.34",
                "ports": [80, 443],
                "tags": [],
                "vulns": ["CVE-2019-0211"],
            }
        }
    )
    result = outils.executer(shodan.SPEC, contexte())

    outils.verifier_sortie(result)
    assert result["source"] == "internetdb" and result["key_used"] is False and result["key_error"] is None
    assert result["ports"] == [80, 443] and result["vuln_count"] == 1 and result["vulns"][0]["cvss"] == 0.0
    assert [r.url.host for r in requetes] == ["internetdb.shodan.io"]


def test_cle_refusee_repli_sur_internetdb(http_simule, contexte, outils):
    http_simule(
        {HOTE: (401, {}, '{"error": "Invalid API key"}'), INTERNETDB: {"ip": "93.184.216.34", "ports": [22]}}
    )
    result = outils.executer(shodan.SPEC, contexte(secrets={"shodan_key": CLE}))

    outils.verifier_sortie(result, secrets=[CLE])
    assert result["source"] == "internetdb" and result["ports"] == [22]
    assert result["key_error"] == msg("shodan.key_rejected") and result["key_used"] is False


def test_quota_de_la_cle_repli_sur_internetdb(http_simule, contexte, outils):
    http_simule({HOTE: (429, {}, "limite"), INTERNETDB: {"ip": "93.184.216.34", "ports": []}})
    result = outils.executer(shodan.SPEC, contexte(secrets={"shodan_key": CLE}))
    assert result["key_error"] == msg("network.quota", service="Shodan") and result["source"] == "internetdb"


def test_adresse_inconnue(http_simule, contexte, outils):
    http_simule({HOTE: (404, {}, '{"error": "No information available for that IP."}')})
    result = outils.executer(shodan.SPEC, contexte(secrets={"shodan_key": CLE}))
    outils.verifier_sortie(result, secrets=[CLE])
    assert result["measured"] is True and result["found"] is False and result["source"] == "shodan"

    http_simule({INTERNETDB: (404, {}, '{"detail": "No information available"}')})
    result = outils.executer(shodan.SPEC, contexte())
    assert result["found"] is False and result["source"] == "internetdb" and "ports" not in result


def test_echec_total_erreur_sans_la_cle(http_simule, contexte, outils):
    erreur_url = httpx.ConnectError(f"échec https://api.shodan.io/shodan/host/x?key={CLE}")
    http_simule({HOTE: erreur_url, INTERNETDB: (500, {}, "panne")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(shodan.SPEC, contexte(secrets={"shodan_key": CLE}))
    assert erreur.value.message == msg("network.http_status", status=500, service="Shodan InternetDB")
    assert CLE not in str(erreur.value)


def test_delai_depasse_et_reponse_illisible(http_simule, contexte, outils):
    http_simule({INTERNETDB: httpx.ReadTimeout("lent")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(shodan.SPEC, contexte())
    assert erreur.value.message == msg("net.timeout")

    http_simule({INTERNETDB: (200, {}, "<html>maintenance</html>")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(shodan.SPEC, contexte())
    assert erreur.value.message == msg("shodan.unreadable", service="Shodan InternetDB")


def test_sans_objet(contexte, http_simule, outils):
    http_simule({})
    assert shodan.SPEC.skip_reason(contexte(addresses=[])) == msg("orchestrator.no_address")
    with pytest.raises(ModuleSkipped):
        outils.executer(shodan.SPEC, contexte(addresses=["127.0.0.1"]))


def entree(data) -> FindingInput:
    return FindingInput({}, "shodan", lambda scan, module: data, lambda scan, module: True)


def test_constat_cve_faux_positif_evite():
    regle = shodan.SPEC.findings[0]
    assert regle.check(entree({"vulns": [], "vuln_count": 0})) is None
    assert regle.check(entree("donnée inattendue")) is None
    assert regle.check(entree({"vulns": "abc"})) is None
    # CVSS élevé : gravité « high » ; CVSS faible et non vérifié (ou InternetDB, sans CVSS) : « medium ».
    haut = regle.check(entree({"vulns": [{"id": "CVE-2019-0211", "cvss": 7.2}], "vuln_count": 3}))
    assert (
        isinstance(haut, Hit)
        and haut.severity == "high"
        and haut.params == {"count": 3, "cve": "CVE-2019-0211"}
    )
    bas = regle.check(
        entree({"vulns": [{"id": "CVE-2017-9798", "cvss": 0.0, "verified": False}], "vuln_count": 1})
    )
    assert bas.severity == "medium"
    verifiee = regle.check(entree({"vulns": [{"id": "CVE-2017-9798", "cvss": 3.0, "verified": True}]}))
    assert verifiee.severity == "high"


@pytest.mark.parametrize(
    ("data", "points"),
    [
        ({"vulns": [], "vuln_count": 0}, 5),
        ({"vulns": [{"id": "CVE-1", "cvss": 0.0}], "vuln_count": 1}, 3),
        ({"vulns": [{"id": "CVE-1", "cvss": 7.5}], "vuln_count": 1}, 1),
        ({"vulns": [{"id": "CVE-1", "cvss": 9.8}], "vuln_count": 2}, 0),
        ("inattendu", 5),
    ],
)
def test_critere_de_score(data, points):
    rule = shodan.SPEC.criteria[0]
    outcome = rule.evaluate({"shodan": data})
    assert outcome.points == points and outcome.measured and rule.weight == 5


def test_declaration_de_la_cle_facultative():
    (cle,) = shodan.SPEC.keys
    assert (cle.name, cle.service, cle.required) == ("shodan_key", "shodan", False)
    assert shodan.SPEC.category == "passif" and shodan.SPEC.required_keys == ()
