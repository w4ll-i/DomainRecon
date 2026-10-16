# =============================================================================
# DomainRecon - Tests du module « dkim » (sans réseau)
# =============================================================================

import base64

import dns.exception
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from domainrecon.i18n import render
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import dkim as impl
from domainrecon.scanner.modules.dkim import SPEC
from domainrecon.scanner.rules import FindingInput


def _spki(public) -> str:
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


@pytest.fixture(scope="module")
def rsa2048() -> str:
    return _spki(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())


@pytest.fixture(scope="module")
def rsa1024() -> str:
    return _spki(rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key())


def _rsa768() -> str:
    """Clé publique RSA de 768 bits (modulus quelconque : seule la taille compte pour la lecture)."""
    modulus = (1 << 767) | 0x1234567890ABCDEF | 1
    return _spki(rsa.RSAPublicNumbers(65537, modulus).public_key())


def _txt_long(outils, text: str):
    """TXT en chaînes de 200 caractères (DNS : 255 au plus par chaîne), recollées par le module."""
    return outils.txt(*[text[i : i + 200] for i in range(0, len(text), 200)])


def _finding(code: str, data: dict):
    rule = next(r for r in SPEC.findings if r.code == code)
    return rule.check(FindingInput({"dkim": data}, "dkim", lambda scan, m: scan[m], lambda scan, m: True))


def test_liste_de_selecteurs_etendue_sans_doublon():
    assert len(impl.DKIM_SELECTORS) == len(set(impl.DKIM_SELECTORS))
    assert len(impl.DKIM_SELECTORS) >= 60
    # Sélecteurs courants des grands fournisseurs et des logiciels de messagerie.
    for selector in (
        "default",
        "google",
        "selector1",
        "protonmail",
        "zoho",
        "mandrill",
        "mimecast",
        "20230601",
    ):
        assert selector in impl.DKIM_SELECTORS


def test_declaration():
    assert SPEC.family == "email" and SPEC.category == "passif"
    assert SPEC.keys == () and not SPEC.requires_authorization


def test_cle_rsa_2048(rsa2048):
    key = impl.analyze_key(f"v=DKIM1; k=rsa; p={rsa2048}")
    assert key["status"] == "valid" and key["key_type"] == "rsa" and key["key_bits"] == 2048
    assert key["valid_key"] and not key["testing"]


def test_cle_revoquee_et_texte_qui_n_est_pas_une_cle():
    assert impl.analyze_key("v=DKIM1; p=")["status"] == "revoked"
    assert impl.analyze_key("v=spf1 -all") is None
    assert impl.analyze_key("v=DKIM2; p=abc") is None


def test_drapeaux_hachage_services(rsa1024):
    key = impl.analyze_key(f"v=DKIM1; t=y:s; h=sha1; s=email; p={rsa1024}")
    assert key["testing"] and key["strict"]
    assert key["hash_algorithms"] == ["sha1"] and key["services"] == ["email"]
    assert key["key_bits"] == 1024


def test_cle_ed25519():
    raw = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    key = impl.analyze_key(f"v=DKIM1; k=ed25519; p={base64.b64encode(raw).decode()}")
    assert key["key_type"] == "ed25519" and key["key_bits"] == 256 and key["valid_key"]


def test_cle_illisible():
    key = impl.analyze_key("v=DKIM1; p=%%%pasdubase64%%%")
    assert key["status"] == "valid" and key["valid_key"] is False and key["key_bits"] is None


def test_succes_cles_trouvees(contexte, dns_simule, outils, rsa2048, rsa1024):
    dns_simule(
        {
            ("google._domainkey.example.com", "TXT"): [_txt_long(outils, f"v=DKIM1; k=rsa; p={rsa2048}")],
            ("selector1._domainkey.example.com", "TXT"): [_txt_long(outils, f"v=DKIM1; k=rsa; p={rsa1024}")],
            ("selector1._domainkey.example.com", "CNAME"): [
                outils.rdata("CNAME", "selector1-example-com._domainkey.tenant.onmicrosoft.com.")
            ],
        }
    )
    result = outils.executer(SPEC, contexte())
    outils.verifier_sortie(result)
    assert result["measured"] is True and result["found"] is True
    assert result["selectors_tested"] == len(impl.DKIM_SELECTORS)
    keys = {k["selector"]: k for k in result["keys"]}
    assert set(keys) == {"google", "selector1"}
    assert keys["google"]["key_bits"] == 2048
    assert keys["selector1"]["delegated_to"].endswith("onmicrosoft.com")
    assert not _finding("finding.dkim.weak_key", {"keys": [keys["google"]]})
    assert _finding("finding.dkim.weak_key", {"keys": [keys["selector1"]]})[0].severity == "low"


def test_rien_trouve_n_est_pas_un_constat(contexte, dns_simule, outils):
    dns_simule({})
    result = outils.executer(SPEC, contexte())
    outils.verifier_sortie(result)
    assert result["measured"] is True and result["found"] is False and result["keys"] == []
    for rule in SPEC.findings:
        assert not _finding(rule.code, result)


def test_cle_revoquee_n_est_pas_une_cle(contexte, dns_simule, outils):
    """Faux positif évité : le p= vide (example.com) ne prouve pas DKIM."""
    dns_simule({("default._domainkey.example.com", "TXT"): ["v=DKIM1; p="]})
    result = outils.executer(SPEC, contexte())
    assert result["found"] is False and result["keys"] == []
    assert result["revoked_selectors"] == ["default"]


def test_joker_dns_ecarte(contexte, dns_simule, outils):
    """Faux positif évité : un joker *._domainkey répond pour tout sélecteur, il ne désigne aucune clé."""
    resolver = dns_simule({})
    joker = ["v=DKIM1; p="]

    class Joker(dict):
        def get(self, key, default=None):
            name, rtype = key
            if rtype == "TXT" and name.endswith("._domainkey.example.com"):
                return joker
            return default

    resolver.zone = Joker()
    result = outils.executer(SPEC, contexte())
    assert result["wildcard"] == "revoked"
    assert result["found"] is False and result["keys"] == [] and result["revoked_selectors"] == []


def test_echec_dns_total_leve_module_error(contexte, dns_simule, outils):
    """Délai dépassé sur tous les sélecteurs : aucune conclusion, échec propre (pas « DKIM absent »)."""

    class TousEnDelai(dict):
        def get(self, key, default=None):
            return dns.exception.Timeout

    dns_simule({}).zone = TousEnDelai()
    with pytest.raises(ModuleError) as error:
        outils.executer(SPEC, contexte())
    assert "DKIM" in render(error.value.message, "fr")


def test_echec_partiel_ne_fait_pas_echouer(contexte, dns_simule, outils, rsa2048):
    dns_simule(
        {
            ("google._domainkey.example.com", "TXT"): [_txt_long(outils, f"v=DKIM1; p={rsa2048}")],
            ("default._domainkey.example.com", "TXT"): dns.exception.Timeout,
        }
    )
    result = outils.executer(SPEC, contexte())
    assert result["measured"] is True and result["selectors_failed"] == 1 and result["found"] is True


def test_sans_objet_adresse_ip_et_plateforme(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert (
        SPEC.skip_reason(
            contexte(domain="www.mon-site.github.io", apex="github.io", site="mon-site.github.io")
        )
        is not None
    )
    assert SPEC.skip_reason(contexte()) is None


def test_constat_cle_faible():
    donnees = {
        "keys": [
            {"selector": "a", "key_type": "rsa", "key_bits": 768},
            {"selector": "b", "key_type": "rsa", "key_bits": 1024},
            {"selector": "c", "key_type": "rsa", "key_bits": 2048},
        ]
    }
    hits = _finding("finding.dkim.weak_key", donnees)
    assert [(h.severity, h.params["selectors"]) for h in hits] == [("high", ["a"]), ("low", ["b"])]
    assert not _finding(
        "finding.dkim.weak_key", {"keys": [{"selector": "c", "key_type": "rsa", "key_bits": 2048}]}
    )
    assert not _finding(
        "finding.dkim.weak_key", {"keys": [{"selector": "e", "key_type": "ed25519", "key_bits": 256}]}
    )


def test_clef_768_bits_detectee():
    assert impl.analyze_key(f"v=DKIM1; p={_rsa768()}")["key_bits"] == 768


def test_constats_mode_test_sha1_illisible():
    cles = [
        {"selector": "t", "testing": True, "hash_algorithms": ["sha1"], "valid_key": True},
        {"selector": "u", "testing": False, "hash_algorithms": ["sha1", "sha256"], "valid_key": False},
    ]
    assert _finding("finding.dkim.testing_mode", {"keys": cles}) == {"selectors": ["t"]}
    assert _finding("finding.dkim.sha1_only", {"keys": cles}) == {"selectors": ["t"]}
    assert _finding("finding.dkim.key_unreadable", {"keys": cles}) == {"selectors": ["u"]}


def test_regles_resistent_aux_donnees_inattendues():
    for rule in SPEC.findings:
        for data in (None, [], "x", {"keys": "x"}, {"keys": [None, 3]}):
            assert not _finding(rule.code, data), (rule.code, data)
