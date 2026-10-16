# =============================================================================
# DomainRecon - Tests du module « banners » (sondes par protocole), sans réseau
# =============================================================================
# Aucune vraie connexion : `impl.banners._open_connection` est remplacé par un
# faux serveur par port (accueil + réponses aux requêtes reçues).
# =============================================================================

import asyncio
import ssl
import struct

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner.errors import ModuleError, ModuleSkipped, TargetNotAllowedError
from domainrecon.scanner.impl import banners as impl
from domainrecon.scanner.modules import banners
from domainrecon.scanner.rules import FindingInput, Hit


class FauxTls:
    def version(self):
        return "TLSv1.2"

    def cipher(self):
        return ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)


class FauxEcrivain:
    def __init__(self, lecteur, reponses, tls):
        self.lecteur, self.reponses, self.tls = lecteur, reponses, tls
        self.envoye: list[bytes] = []
        self.ferme = False

    def write(self, data):
        self.envoye.append(data)
        for prefixe, reponse in self.reponses.items():
            if data.startswith(prefixe):
                self.lecteur.feed_data(reponse)
                break

    async def drain(self):
        return None

    def close(self):
        self.ferme = True

    async def wait_closed(self):
        return None

    def get_extra_info(self, nom):
        return FauxTls() if nom == "ssl_object" and self.tls else None


class FauxReseau:
    """Serveurs simulés : {port: {"accueil": octets, "reponses": {préfixe: octets}, "tls": bool, "erreur": exception}}."""

    def __init__(self, serveurs):
        self.serveurs = serveurs
        self.connexions: list[tuple[int, bool]] = []
        self.ecrivains: dict[int, list[FauxEcrivain]] = {}

    async def ouvrir(self, ip, port, **kwargs):
        utilise_tls = "ssl" in kwargs
        self.connexions.append((port, utilise_tls))
        serveur = self.serveurs.get(port)
        if serveur is None:
            raise ConnectionRefusedError
        if serveur.get("erreur") is not None:
            raise serveur["erreur"]
        if utilise_tls != serveur.get("tls", False):
            # Mauvais mode : le serveur TLS refuse le clair, le serveur en clair échoue à la poignée de main.
            raise ssl.SSLError("poignée de main impossible") if utilise_tls else ConnectionResetError
        lecteur = asyncio.StreamReader()
        if serveur.get("accueil"):
            lecteur.feed_data(serveur["accueil"])
        ecrivain = FauxEcrivain(lecteur, serveur.get("reponses", {}), utilise_tls)
        self.ecrivains.setdefault(port, []).append(ecrivain)
        return lecteur, ecrivain


@pytest.fixture
def reseau(monkeypatch):
    monkeypatch.setattr(impl, "IDLE_TIMEOUT", 0.01)
    monkeypatch.setattr(impl, "READ_TIMEOUT", 0.05)

    def installer(serveurs):
        faux = FauxReseau(serveurs)
        monkeypatch.setattr(impl, "_open_connection", faux.ouvrir)
        return faux

    return installer


def ouverts(*ports) -> dict:
    return {"open_ports": [{"port": p, "state": "open", "service": "?"} for p in ports]}


def par_port(result) -> dict:
    return {e["port"]: e for e in result["banners"]}


def test_ssh_http_et_https(reseau, contexte, outils):
    faux = reseau(
        {
            22: {"accueil": b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n"},
            80: {
                "reponses": {b"HEAD / HTTP/1.1": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)\r\n\r\n"}
            },
            443: {
                "tls": True,
                "reponses": {
                    b"HEAD / HTTP/1.1": b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nX-Powered-By: PHP/8.2.1\r\n\r\n"
                },
            },
        }
    )
    result = outils.executer(banners.SPEC, contexte(results=ouverts(22, 80, 443)))

    outils.verifier_sortie(result)
    pages = par_port(result)
    assert (pages[22]["product"], pages[22]["version"]) == ("OpenSSH", "6.6.1p1")
    assert pages[22]["banner"].startswith("SSH-2.0-OpenSSH_6.6.1p1")
    assert (pages[80]["product"], pages[80]["version"]) == ("Apache", "2.4.7")
    assert pages[80]["banner"] == "HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)"
    # Port 443 : poignée de main TLS d'abord (jamais de HTTP en clair), TLS relevé, en-tête Host valide.
    assert faux.connexions.count((443, True)) == 1 and (443, False) not in faux.connexions
    assert pages[443]["tls"] == {"version": "TLSv1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256"}
    assert b"Host: example.com" in faux.ecrivains[443][0].envoye[0]
    assert result["versions_disclosed"] == [22, 80, 443] and result["unauthenticated"] == []


def test_port_tls_qui_refuse_la_poignee_de_main_retombe_en_clair(reseau, contexte, outils):
    faux = reseau(
        {
            8443: {
                "reponses": {b"HEAD /": b"HTTP/1.1 301 Moved Permanently\r\nServer: lighttpd/1.4.55\r\n\r\n"}
            }
        }
    )
    result = outils.executer(banners.SPEC, contexte(results=ouverts(8443)))
    assert faux.connexions == [(8443, True), (8443, False)]
    assert par_port(result)[8443]["product"] == "lighttpd"


def test_port_http_qui_ne_parle_pas_http_reessaie_en_tls(reseau, contexte, outils):
    faux = reseau(
        {
            5985: {
                "tls": True,
                "reponses": {b"HEAD /": b"HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n"},
            }
        }
    )
    result = outils.executer(banners.SPEC, contexte(results=ouverts(5985)))
    assert faux.connexions == [(5985, False), (5985, True)]
    assert par_port(result)[5985]["tls"]["version"] == "TLSv1.2"


def test_redis_ouvert_et_protege(reseau, contexte, outils):
    reseau(
        {
            6379: {
                "reponses": {
                    b"PING": b"+PONG\r\n",
                    b"INFO server": b"$100\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n",
                }
            }
        }
    )
    result = outils.executer(banners.SPEC, contexte(results=ouverts(6379)))
    redis = par_port(result)[6379]
    assert (redis["product"], redis["version"], redis["exposure"], redis["risk"]) == (
        "Redis", "7.0.11", "unauthenticated", "critical",
    )  # fmt: skip
    assert result["unauthenticated"] == [6379]

    reseau({6379: {"reponses": {b"PING": b"-NOAUTH Authentication required.\r\n"}}})
    redis = par_port(outils.executer(banners.SPEC, contexte(results=ouverts(6379))))[6379]
    assert redis["exposure"] is None and redis["risk"] is None and redis["banner"].startswith("-NOAUTH")


def test_services_de_donnees_et_d_administration(reseau, contexte, outils):
    reseau(
        {
            11211: {"reponses": {b"version": b"VERSION 1.6.21\r\n"}},
            9200: {
                "reponses": {
                    b"GET / HTTP/1.1": b'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"name":"n1","cluster_name":"prod",'
                    b'"version":{"number":"7.17.9"},"tagline":"You Know, for Search"}'
                }
            },
            2375: {
                "reponses": {
                    b"GET /version": b'HTTP/1.1 200 OK\r\n\r\n{"Version":"24.0.5","ApiVersion":"1.43"}'
                }
            },
            8500: {"reponses": {b"GET /v1/status/leader": b'HTTP/1.1 200 OK\r\n\r\n"10.0.0.5:8300"'}},
            5984: {
                "reponses": {
                    b"GET / HTTP/1.1": b'HTTP/1.1 200 OK\r\n\r\n{"couchdb":"Welcome","version":"3.3.2"}'
                }
            },
        }
    )
    result = outils.executer(banners.SPEC, contexte(results=ouverts(11211, 9200, 2375, 8500, 5984)))
    pages = par_port(result)
    assert (pages[11211]["product"], pages[11211]["version"], pages[11211]["risk"]) == (
        "memcached",
        "1.6.21",
        "critical",
    )
    assert (pages[9200]["product"], pages[9200]["version"], pages[9200]["risk"]) == (
        "Elasticsearch",
        "7.17.9",
        "high",
    )
    assert (pages[2375]["product"], pages[2375]["version"], pages[2375]["risk"]) == (
        "Docker",
        "24.0.5",
        "critical",
    )
    assert pages[8500]["exposure"] == "unauthenticated" and pages[8500]["risk"] == "high"
    assert (pages[5984]["version"], pages[5984]["risk"]) == ("3.3.2", "medium")


def test_services_proteges_pas_de_faux_positif(reseau, contexte, outils):
    reseau(
        {
            9200: {
                "reponses": {
                    b"GET / HTTP/1.1": b'HTTP/1.1 401 Unauthorized\r\n\r\n{"error":"missing authentication"}'
                }
            },
            2375: {"reponses": {b"GET /version": b"HTTP/1.1 404 Not Found\r\n\r\n<html>nginx</html>"}},
            8500: {"reponses": {b"GET /v1/status/leader": b"HTTP/1.1 403 Forbidden\r\n\r\nACL not found"}},
            11211: {"reponses": {b"version": b"ERROR\r\n"}},
        }
    )
    result = outils.executer(banners.SPEC, contexte(results=ouverts(9200, 2375, 8500, 11211)))
    assert result["unauthenticated"] == []
    assert all(e["exposure"] is None for e in result["banners"])


def test_bases_de_donnees(reseau, contexte, outils):
    greeting = b"\x00\x00\x00\x00" + bytes([10]) + b"8.0.36-0ubuntu0.22.04.1\x00" + b"\x01\x02\x03"
    mongo = (
        b"\x00" * 20 + b"\x08ismaster\x00\x01" + b"\x10maxWireVersion\x00" + struct.pack("<i", 17) + b"\x00"
    )
    reseau(
        {
            3306: {"accueil": greeting},
            5432: {"reponses": {struct.pack("!II", 8, 80877103): b"S"}},
            27017: {"reponses": {impl._MONGO_ISMASTER[:16]: mongo}},
        }
    )
    result = outils.executer(banners.SPEC, contexte(results=ouverts(3306, 5432, 27017)))
    pages = par_port(result)
    assert (pages[3306]["product"], pages[3306]["version"]) == ("MySQL", "8.0.36-0ubuntu0.22.04.1")
    assert pages[5432]["product"] == "PostgreSQL" and pages[5432]["ssl_supported"] is True
    # MongoDB répond à isMaster sans authentification par conception : pas de constat d'accès ouvert.
    assert pages[27017]["product"] == "MongoDB" and pages[27017]["wire_version"] == 17
    assert pages[27017]["exposure"] is None


def test_smtp_ehlo_et_starttls(reseau, contexte, outils):
    reseau(
        {
            25: {
                "accueil": b"220 mail.example.com ESMTP Postfix\r\n",
                "reponses": {b"EHLO": b"250-mail.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n"},
            }
        }
    )
    page = par_port(outils.executer(banners.SPEC, contexte(results=ouverts(25))))[25]
    assert page["product"] == "Postfix" and page["starttls"] is True and "STARTTLS" in page["banner"]


def test_port_injoignable_et_aucun_port_joignable(reseau, contexte, outils):
    reseau({22: {"accueil": b"SSH-2.0-dropbear_2022.83\r\n"}})
    result = outils.executer(banners.SPEC, contexte(results=ouverts(22, 21)))
    pages = par_port(result)
    assert pages[22]["reachable"] is True and pages[22]["product"] == "dropbear"
    assert pages[21] == {"port": 21, "service": "FTP", "probe": "greeting", "reachable": False}

    reseau({22: {"erreur": asyncio.TimeoutError()}, 80: {"erreur": ConnectionRefusedError()}})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(banners.SPEC, contexte(results=ouverts(22, 80)))
    assert erreur.value.message == msg("banners.unreachable")


def test_serveur_muet_ne_bloque_pas(reseau, contexte, outils):
    reseau({21: {}, 110: {"accueil": b"+OK Dovecot ready.\r\n"}})
    result = outils.executer(banners.SPEC, contexte(results=ouverts(21, 110)), timeout=10)
    assert par_port(result)[21]["reachable"] is True and par_port(result)[21]["banner"] == ""
    assert par_port(result)[110]["product"] == "Dovecot"


def test_sans_objet(reseau, contexte, outils):
    reseau({})
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(banners.SPEC, contexte())
    assert erreur.value.message == msg("banners.no_scan")
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(banners.SPEC, contexte(results={"open_ports": []}))
    assert erreur.value.message == msg("banners.no_open_port")
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(banners.SPEC, contexte(results=ouverts(3389, 445)))
    assert erreur.value.message == msg("banners.no_probe")
    assert banners.SPEC.skip_reason(contexte(addresses=[])) == msg("orchestrator.no_address")


def test_adresse_interne_refusee_par_la_politique_de_cibles(reseau, contexte, outils):
    faux = reseau({22: {"accueil": b"SSH-2.0-OpenSSH_9.6\r\n"}})
    with pytest.raises(TargetNotAllowedError):
        outils.executer(banners.SPEC, contexte(addresses=["10.0.0.7"], results=ouverts(22)))
    assert faux.connexions == []


def test_lecture_des_ports_ouverts_defensive():
    assert banners.open_port_numbers(
        [22, "80", {"port": 443, "state": "open"}, {"port": 21, "state": "closed"}, "x", None, 70000]
    ) == [22, 80, 443]
    assert banners.open_port_numbers("inattendu") == []


def test_analyses_unitaires():
    assert impl.software_of("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13") == ("OpenSSH", "9.6p1")
    assert impl.software_of("220 (vsFTPd 3.0.3)") == ("vsFTPd", "3.0.3")
    assert impl.software_of("rien d'intéressant") == (None, None)
    assert impl.parse_http(b"pas du http") == {}
    assert impl.parse_mysql(b"\x00\x00\x00\x00" + bytes([10]) + b"5.5.5-10.6.12-MariaDB\x00x")[0] == "MariaDB"
    assert impl.parse_mysql(b"") == (None, None)
    assert impl.printable(b"\xff\xfd\x18SSH-2.0-x\r\n") == "SSH-2.0-x"
    assert impl.plan_for(3389) is None and impl.plan_for(443)[0] == "HTTPS"


# --- Constats et score --------------------------------------------------------


def entree(data) -> FindingInput:
    return FindingInput({}, "banners", lambda scan, module: data, lambda scan, module: True)


def donnees():
    return {
        "banners": [
            {
                "port": 6379,
                "service": "Redis",
                "product": "Redis",
                "version": "7.0.11",
                "exposure": "unauthenticated",
                "risk": "critical",
            },
            {"port": 22, "service": "SSH", "product": "OpenSSH", "version": "6.6.1p1", "exposure": None},
            {"port": 80, "service": "HTTP", "product": "nginx", "version": None, "exposure": None},
        ]
    }


def test_constats():
    sans_auth, version = (rule.check for rule in banners.SPEC.findings)
    (acces,) = sans_auth(entree(donnees()))
    assert (
        isinstance(acces, Hit)
        and acces.severity == "critical"
        and acces.params == {"port": 6379, "service": "Redis"}
    )
    # La version de Redis exposé n'est pas répétée en « version annoncée » ; nginx sans version : rien.
    hits = version(entree(donnees()))
    assert [h.params for h in hits] == [{"port": 22, "product": "OpenSSH", "version": "6.6.1p1"}]
    assert sans_auth(entree("inattendu")) == [] and version(entree({"banners": "x"})) == []


@pytest.mark.parametrize(
    ("data", "points"),
    [
        ({"unauthenticated": [6379], "versions_disclosed": [22]}, 0),
        ({"unauthenticated": [], "versions_disclosed": [22]}, 3),
        ({"unauthenticated": [], "versions_disclosed": []}, 5),
    ],
)
def test_critere_de_score(data, points):
    rule = banners.SPEC.criteria[0]
    assert rule.evaluate({"banners": data}).points == points


def test_declaration():
    spec = banners.SPEC
    assert spec.category == "actif" and spec.requires_authorization and spec.depends_on == ("open_ports",)
    assert spec.wave == 2 and not spec.quick
