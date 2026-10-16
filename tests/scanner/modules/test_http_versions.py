# =============================================================================
# DomainRecon - Tests du module « http_versions » (sans réseau)
# =============================================================================

import ssl

import pytest

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import http_versions as logic
from domainrecon.scanner.modules.http_versions import SPEC
from domainrecon.scanner.rules import FindingInput

URL = "https://example.com/"


def _entree(data):
    return FindingInput(
        {"http_versions": data}, "http_versions", lambda scan, m: scan.get(m), lambda s, m: True
    )


@pytest.fixture
def sonde(monkeypatch):
    """Remplace la sonde TLS : table {offre ALPN: réponse | exception}."""
    appels = []

    def installer(reponses):
        def fausse(sni, addresses, offered, timeout=5.0):
            appels.append((sni, tuple(offered), tuple(addresses)))
            reponse = reponses[tuple(offered)]
            if isinstance(reponse, BaseException):
                raise reponse
            return reponse

        monkeypatch.setattr(logic, "probe_alpn", fausse)
        return appels

    return installer


def _lancer(http_simule, contexte, outils, en_tetes=None, **champs):
    http_simule({URL: (200, en_tetes or {}, "<html></html>")})
    valeur = outils.executer(SPEC, contexte(**champs))
    outils.verifier_sortie(valeur)
    return valeur


H2 = {"alpn": "h2", "tls_version": "TLSv1.3"}
H1 = {"alpn": "http/1.1", "tls_version": "TLSv1.2"}
OFFRE = ("h2", "http/1.1")
OFFRE_H1 = ("http/1.1",)


# --- Analyse d'Alt-Svc ------------------------------------------------------------


def test_alt_svc_h3():
    alt = logic.parse_alt_svc('h3=":443"; ma=86400, h3-29=":443"; ma=86400')
    assert alt["http3"] is True and alt["protocols"] == ["h3", "h3-29"] and alt["ma"] == 86400


def test_alt_svc_sans_h3_et_clear():
    assert logic.parse_alt_svc('h2=":8443"')["http3"] is False
    assert logic.parse_alt_svc("clear")["cleared"] is True
    assert logic.parse_alt_svc("n'importe quoi")["protocols"] == []
    assert logic.parse_alt_svc(None)["http3"] is False


def test_alt_svc_ancien_jeton_quic_n_est_pas_http3():
    """Un simple jeton « quic » désigne Google QUIC, pas HTTP/3."""
    alt = logic.parse_alt_svc('quic=":443"; ma=2592000; v="46,43"')
    assert alt["http3"] is False and alt["protocols"] == ["quic"]


def test_alpn_de_l_enregistrement_dns_https():
    assert logic.alpn_from_https_record("1 . alpn=h2,h3 ipv4hint=1.2.3.4") == ["h2", "h3"]
    assert logic.alpn_from_https_record("1 . ipv4hint=1.2.3.4") == []


# --- Module -----------------------------------------------------------------------


def test_succes_h2_et_h3(http_simule, contexte, outils, sonde, dns_simule):
    appels = sonde({OFFRE: H2, OFFRE_H1: H1})
    dns_simule({})
    valeur = _lancer(http_simule, contexte, outils, {"Alt-Svc": 'h3=":443"; ma=86400'})
    assert valeur["https"] is True and valeur["http2"] is True and valeur["http1_1"] is True
    assert (
        valeur["http3"] is True and valeur["http3_source"] == "alt-svc" and valeur["http3_verified"] is False
    )
    assert valeur["negotiated_protocol"] == "h2" and valeur["tls_version"] == "TLSv1.3"
    assert appels[0] == ("example.com", OFFRE, ("93.184.216.34",))
    assert SPEC.score_rules[0].evaluate({"http_versions": valeur}).points == 3


def test_http3_annonce_par_le_dns(http_simule, contexte, outils, sonde, dns_simule):
    sonde({OFFRE: H2, OFFRE_H1: H1})
    dns_simule({("example.com", "HTTPS"): [outils.rdata("HTTPS", "1 . alpn=h2,h3")]})
    valeur = _lancer(http_simule, contexte, outils)
    assert valeur["http3"] is True and valeur["http3_source"] == "dns"
    assert valeur["dns_https_alpn"] == ["h2", "h3"]


def test_http1_seul_constat_et_score(http_simule, contexte, outils, sonde, dns_simule):
    sonde({OFFRE: H1})
    dns_simule({})
    valeur = _lancer(http_simule, contexte, outils)
    assert valeur["http1_1"] is True and valeur["http2"] is False and valeur["http3"] is False
    assert SPEC.findings[0].check(_entree(valeur)) is True
    assert SPEC.score_rules[0].evaluate({"http_versions": valeur}).points == 0


def test_serveur_http2_seul(http_simule, contexte, outils, sonde, dns_simule):
    sonde({OFFRE: H2, OFFRE_H1: ssl.SSLError("no application protocol")})
    dns_simule({})
    valeur = _lancer(http_simule, contexte, outils)
    assert valeur["http2"] is True and valeur["http1_1"] is False


def test_sans_alpn_http1_suppose(http_simule, contexte, outils, sonde, dns_simule):
    sonde({OFFRE: {"alpn": None, "tls_version": "TLSv1.2"}})
    dns_simule({})
    valeur = _lancer(http_simule, contexte, outils)
    assert valeur["alpn_supported"] is False and valeur["http1_1"] is True and valeur["http2"] is False


def test_certificat_invalide_ne_masque_pas_http2(http_simule, contexte, outils, sonde, dns_simule):
    """La sonde ne vérifie pas le certificat (sinon « HTTP/2 absent » à tort)."""
    import inspect

    assert "CERT_NONE" in inspect.getsource(logic.probe_alpn)
    sonde({OFFRE: H2, OFFRE_H1: H1})
    dns_simule({})
    assert _lancer(http_simule, contexte, outils)["http2"] is True


def test_port_443_ferme_site_http_seul(http_simule, contexte, outils, sonde, dns_simule):
    sonde({OFFRE: ConnectionRefusedError()})
    dns_simule({})
    http_simule({"http://example.com/": (200, {}, "ok")})
    valeur = outils.executer(SPEC, contexte())
    outils.verifier_sortie(valeur)
    assert valeur["https"] is False and valeur["tls_error"]
    assert SPEC.score_rules[0].evaluate({"http_versions": valeur}).applicable is False
    assert SPEC.findings[0].check(_entree(valeur)) is False


def test_poignee_de_main_refusee(http_simule, contexte, outils, sonde, dns_simule):
    sonde({OFFRE: ssl.SSLError(1, "[SSL] wrong version number")})
    dns_simule({})
    valeur = _lancer(http_simule, contexte, outils)
    assert valeur["https"] is False
    assert "TLS" in render(valeur["tls_error"], "fr")


def test_delai_de_la_sonde(http_simule, contexte, outils, sonde, dns_simule):
    sonde({OFFRE: TimeoutError()})
    dns_simule({})
    valeur = _lancer(http_simule, contexte, outils)
    assert valeur["https"] is False and valeur["tls_error"]


def test_cible_ip_sans_nom_sni(http_simule, contexte, outils, sonde):
    appels = sonde({OFFRE: H2, OFFRE_H1: H1})
    http_simule({"https://93.184.216.34/": (200, {}, "ok")})
    valeur = outils.executer(SPEC, contexte(domain="93.184.216.34"))
    assert valeur["http2"] is True and appels[0][0] is None and valeur["dns_https_alpn"] is None


def test_adresse_absente_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(addresses=[]))


def test_cible_injoignable_est_un_echec(http_simule, contexte, outils):
    http_simule({})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_donnees_inattendues_ne_levent_pas():
    for donnees in (None, [], {"https": True}, {"https": "oui"}):
        SPEC.findings[0].check(_entree(donnees))
    assert SPEC.score_rules[0].evaluate({"http_versions": None}).applicable is False
