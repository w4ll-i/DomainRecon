# =============================================================================
# DomainRecon - Tests du module « doh_comparison » (sans réseau)
# =============================================================================

import base64

import dns.exception
import dns.message
import httpx
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import doh as engine
from domainrecon.scanner.modules import doh_comparison
from domainrecon.scanner.rules import FindingInput

SPEC = doh_comparison.SPEC
CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
GOOGLE = "https://dns.google/dns-query"
IP_A, IP_B = "93.184.216.34", "93.184.216.35"


def _reponse(ips=(IP_A,), rcode="NOERROR", ad=True, ttl=300):
    flags = "QR RD RA" + (" AD" if ad else "")
    lignes = ["id 0", "opcode QUERY", f"rcode {rcode}", f"flags {flags}", ";QUESTION", "example.com. IN A"]
    if ips:
        lignes += [";ANSWER", *[f"example.com. {ttl} IN A {ip}" for ip in ips]]
    return dns.message.from_text(chr(10).join(lignes) + chr(10))


def _doh(message):
    def repondre(request):
        return httpx.Response(
            200, content=message.to_wire(), headers={"content-type": "application/dns-message"}
        )

    return repondre


@pytest.fixture
def resolveurs(monkeypatch, http_simule, dns_simule, outils):
    """Installe les quatre résolveurs simulés (Cloudflare, Google en DoH ; Quad9 en DoT ; le système)."""

    def installer(cloudflare=None, google=None, quad9=None, systeme=(IP_A,)):
        routes = {}
        routes[CLOUDFLARE] = _doh(cloudflare if cloudflare is not None else _reponse())
        routes[GOOGLE] = _doh(google if google is not None else _reponse())
        requetes = http_simule(routes)

        def dot(query, address, hostname):
            reponse = quad9 if quad9 is not None else _reponse()
            if isinstance(reponse, BaseException):
                raise reponse
            return reponse

        monkeypatch.setattr(engine, "_dot_exchange", dot)
        zone = {("example.com", "A"): [outils.rdata("A", ip) for ip in systeme]} if systeme else {}
        dns_simule(zone)
        return requetes

    return installer


def _finding(data):
    return FindingInput({}, "doh_comparison", lambda scan, name: data, lambda scan, name: True)


def _constats(sortie):
    return {rule.code.rsplit(".", 1)[1]: rule.check(_finding(sortie)) for rule in SPEC.findings}


def test_resolveurs_concordants(contexte, outils, resolveurs):
    resolveurs()
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["consistent"] is True and sortie["anomalies"] == [] and sortie["ip_variation"] is False
    assert sortie["answered"] == ["cloudflare", "google", "quad9", "system"]
    assert sortie["dnssec_validated_by"] == ["cloudflare", "google", "quad9"]
    assert (
        sortie["providers"]["quad9"]["transport"] == "dot"
        and sortie["providers"]["cloudflare"]["transport"] == "doh"
    )
    assert sortie["providers"]["google"]["ips"] == [IP_A] and sortie["providers"]["google"]["ttl"] == 300
    assert _constats(sortie) == {"blocked": None, "sinkhole": None}


def test_requete_doh_binaire_rfc_8484(contexte, outils, resolveurs):
    requetes = resolveurs()
    outils.executer(SPEC, contexte())
    appel = next(r for r in requetes if r.url.host == "cloudflare-dns.com")
    assert appel.method == "GET" and appel.headers["accept"] == "application/dns-message"
    encode = appel.url.params["dns"]
    assert "=" not in encode
    question = dns.message.from_wire(base64.urlsafe_b64decode(encode + "=" * (-len(encode) % 4)))
    assert question.id == 0 and str(question.question[0].name) == "example.com."
    assert question.question[0].rdtype == 1 and question.ednsflags & 0x8000  # DO


def test_adresses_differentes_derriere_un_cdn_pas_une_anomalie(contexte, outils, resolveurs):
    """Pas de faux positif : des adresses différentes d'un résolveur à l'autre sont normales."""
    resolveurs(cloudflare=_reponse((IP_A,)), google=_reponse((IP_B,)), quad9=_reponse(("93.184.216.36",)))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["ip_variation"] is True and sortie["ip_overlap"] is False
    assert sortie["consistent"] is True and sortie["anomalies"] == []
    assert _constats(sortie) == {"blocked": None, "sinkhole": None}


def test_nom_bloque_par_un_resolveur(contexte, outils, resolveurs):
    resolveurs(quad9=_reponse((), rcode="NXDOMAIN", ad=False))
    sortie = outils.executer(SPEC, contexte())
    assert (
        sortie["anomalies"] == [{"type": "blocked", "providers": ["quad9"]}] and sortie["consistent"] is False
    )
    assert _constats(sortie)["blocked"] == {"providers": ["quad9"]}


def test_filtrage_local_du_resolveur_systeme(contexte, outils, resolveurs):
    resolveurs(systeme=())
    sortie = outils.executer(SPEC, contexte())
    assert sortie["anomalies"] == [{"type": "blocked", "providers": ["system"]}]


def test_puits_de_sondage(contexte, outils, resolveurs):
    resolveurs(cloudflare=_reponse(("0.0.0.0",), ad=False))
    sortie = outils.executer(SPEC, contexte())
    assert {"type": "sinkhole", "providers": ["cloudflare"]} in sortie["anomalies"]
    assert _constats(sortie)["sinkhole"] == {"providers": ["cloudflare"]}


def test_domaine_inexistant_partout_pas_de_blocage(contexte, outils, resolveurs):
    nx = _reponse((), rcode="NXDOMAIN", ad=False)
    resolveurs(cloudflare=nx, google=nx, quad9=nx, systeme=())
    sortie = outils.executer(SPEC, contexte())
    assert sortie["anomalies"] == [] and sortie["consistent"] is True


def test_un_resolveur_en_echec_les_autres_comparent(contexte, outils, resolveurs, http_simule):
    resolveurs()
    requetes = http_simule({CLOUDFLARE: (403, {}, ""), GOOGLE: (200, {}, "ceci n'est pas du DNS")})
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert requetes
    fournisseurs = sortie["providers"]
    assert (
        fournisseurs["cloudflare"]["status"] == "error"
        and fournisseurs["cloudflare"]["error"]["$t"] == "network.http_status"
    )
    assert fournisseurs["google"]["error"]["$t"] == "doh_comparison.unreadable"
    assert fournisseurs["quad9"]["status"] == "NOERROR" and fournisseurs["system"]["status"] == "NOERROR"
    assert sortie["answered"] == ["quad9", "system"] and sortie["consistent"] is True


def test_delai_depasse_dot(contexte, outils, resolveurs):
    resolveurs(quad9=dns.exception.Timeout())
    sortie = outils.executer(SPEC, contexte())
    assert sortie["providers"]["quad9"]["error"]["$t"] == "net.timeout"
    assert sortie["consistent"] is True and "quad9" not in sortie["answered"]


def test_erreur_reseau_dot(contexte, outils, resolveurs):
    resolveurs(quad9=OSError("filtré"))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["providers"]["quad9"]["error"]["$t"] == "network.service_error"


def test_aucun_resolveur_chiffre_ne_repond(contexte, outils, http_simule, dns_simule, monkeypatch):
    http_simule({})
    dns_simule({})

    def dot(query, address, hostname):
        raise OSError("coupé")

    monkeypatch.setattr(engine, "_dot_exchange", dot)
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "doh_comparison.no_resolver"


def test_donnees_inattendues_ne_levent_pas():
    for data in (
        None,
        [],
        "x",
        {"anomalies": "oops"},
        {"anomalies": [None, {"type": "blocked", "providers": 3}]},
    ):
        _constats(data)


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
