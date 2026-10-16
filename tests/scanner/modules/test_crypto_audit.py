# =============================================================================
# DomainRecon - Tests du module « crypto_audit » (sans réseau)
# =============================================================================
# Les certificats sont fabriqués par la bibliothèque cryptography (AC, intermédiaire,
# feuille) ; la récupération de la chaîne (tls_x509.fetch_chain) est simulée.
# =============================================================================

import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from domainrecon.i18n import is_msg
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import crypto_audit as audit
from domainrecon.scanner.impl import tls_x509
from domainrecon.scanner.modules import crypto_audit
from domainrecon.scanner.rules import FindingInput

SPEC = crypto_audit.SPEC
UTC = dt.timezone.utc  # noqa: UP017 - Python 3.10 : datetime.UTC absent
MAINTENANT = dt.datetime.now(UTC)


def nom(cn: str, org: str | None = None) -> x509.Name:
    attributs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attributs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attributs)


def cle_ec():
    return ec.generate_private_key(ec.SECP256R1())


def cle_rsa(bits=2048):
    return rsa.generate_private_key(65537, bits)


def fabriquer(
    sujet: str,
    cle,
    emetteur_nom: x509.Name,
    cle_emetteur,
    *,
    ca=False,
    debut=None,
    jours=90,
    san: list[str] | None = None,
    sans_san=False,
    eku=None,
):
    debut = debut or MAINTENANT - dt.timedelta(days=10)
    constructeur = (
        x509.CertificateBuilder()
        .subject_name(nom(sujet))
        .issuer_name(emetteur_nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut)
        .not_valid_after(debut + dt.timedelta(days=jours))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca and not sans_san:
        constructeur = constructeur.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in (san or [sujet])]), critical=False
        )
    if eku is not None:
        constructeur = constructeur.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return constructeur.sign(cle_emetteur, hashes.SHA256()).public_bytes(Encoding.DER)


class Chaine:
    """AC racine -> intermédiaire -> feuille, avec options pour provoquer des défauts."""

    def __init__(self, *, cle_feuille=None, **feuille):
        self.cle_racine, self.cle_inter = cle_ec(), cle_ec()
        self.cle_feuille = cle_feuille or cle_ec()
        self.racine = fabriquer(
            "Racine Test", self.cle_racine, nom("Racine Test"), self.cle_racine, ca=True, jours=3650
        )
        self.inter = fabriquer(
            "Intermediaire Test",
            self.cle_inter,
            nom("Racine Test"),
            self.cle_racine,
            ca=True,
            jours=1500,
        )
        self.feuille = fabriquer(
            "example.com",
            self.cle_feuille,
            nom("Intermediaire Test"),
            self.cle_inter,
            **feuille,
        )

    def servie(self, *, avec_inter=True) -> dict:
        return {
            "served": [self.feuille, *([self.inter] if avec_inter else [])],
            "verified": True,
            "verified_chain": [self.feuille, self.inter, self.racine],
            "verify_code": None,
            "verify_message": None,
            "source": "ssl",
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
        }


def signatures_sha1(monkeypatch, *sujets: str) -> None:
    """cryptography 50 refuse de signer en SHA-1 : on fait lire « sha1 » pour ces certificats."""
    original = tls_x509._signature_name

    def lire(cert):
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return "sha1" if cn in sujets else original(cert)

    monkeypatch.setattr(tls_x509, "_signature_name", lire)


def codes(resultat: dict) -> set[str]:
    return {issue["code"] for issue in resultat["issues"]}


def donnees(valeur: dict) -> FindingInput:
    return FindingInput({}, "crypto_audit", lambda scan, module: valeur, lambda scan, module: True)


def constats(valeur: dict) -> dict[str, object]:
    trouves = {}
    for regle in SPEC.findings:
        resultat = regle.check(donnees(valeur))
        if resultat:
            trouves[regle.code] = resultat
    return trouves


# --- Calendrier de validité ----------------------------------------------------------


@pytest.mark.parametrize(
    ("date", "limite"),
    [
        (dt.datetime(2019, 1, 1, tzinfo=UTC), 825),
        (dt.datetime(2020, 9, 1, tzinfo=UTC), 398),
        (dt.datetime(2026, 3, 14, tzinfo=UTC), 398),
        (dt.datetime(2026, 3, 15, tzinfo=UTC), 200),
        (dt.datetime(2027, 3, 15, tzinfo=UTC), 100),
        (dt.datetime(2029, 3, 15, tzinfo=UTC), 47),
    ],
)
def test_calendrier_des_durees_maximales(date, limite):
    assert audit.max_validity_days(date) == limite


# --- Analyse de la chaîne ----------------------------------------------------------------


def test_chaine_saine():
    resultat = audit.analyze(Chaine().servie())
    assert resultat["measured"] is True and resultat["chain_complete"] is True
    assert resultat["chain_length"] == 2
    assert [c["position"] for c in resultat["chain"]] == ["leaf", "intermediate"]
    # Chaîne approuvée sans SCT (la feuille de test n'en porte pas) : seul défaut mineur.
    assert codes(resultat) == {"no_sct"}
    assert resultat["grade"] == "B"
    assert resultat["leaf"]["validation"] == "DV"
    assert resultat["summary"]["key_type"] == "EC" and resultat["summary"]["key_bits"] == 256


def test_racine_omise_n_est_pas_une_chaine_incomplete():
    """Faux positif évité : seule la feuille est servie, mais la racine est dans le magasin."""
    chaine = Chaine()
    fetched = {**chaine.servie(avec_inter=False), "verified_chain": [chaine.feuille, chaine.racine]}
    assert audit.analyze(fetched)["chain_complete"] is True


def test_intermediaire_manquant_est_signale():
    chaine = Chaine()
    fetched = {
        **chaine.servie(avec_inter=False),
        "verified": False,
        "verified_chain": [],
        "verify_code": 20,
    }
    resultat = audit.analyze(fetched)
    assert resultat["chain_complete"] is False
    assert "incomplete_chain" in codes(resultat)
    assert "finding.crypto_audit.incomplete_chain" in constats(resultat)


def test_intermediaire_present_chaine_privee_complete():
    chaine = Chaine()
    fetched = {**chaine.servie(), "verified": False, "verified_chain": [], "verify_code": 20}
    assert audit.analyze(fetched)["chain_complete"] is True


def test_feuille_seule_lue_par_repli_laisse_la_completude_inconnue():
    fetched = {**Chaine().servie(avec_inter=False), "verified": False, "verified_chain": [], "source": "leaf"}
    resultat = audit.analyze(fetched)
    assert resultat["chain_complete"] is None
    assert "incomplete_chain" not in codes(resultat)


def test_certificat_autosigne_sans_faux_defaut():
    cle = cle_ec()
    auto = fabriquer("example.com", cle, nom("example.com"), cle)
    fetched = {"served": [auto], "verified": False, "verify_code": 18, "source": "ssl", "verified_chain": []}
    resultat = audit.analyze(fetched)
    assert resultat["leaf"]["self_signed"] is True
    assert resultat["chain_complete"] is None
    assert codes(resultat) == set()


def test_signature_sha1_de_la_feuille_est_critique(monkeypatch):
    signatures_sha1(monkeypatch, "example.com")
    resultat = audit.analyze(Chaine().servie())
    issue = next(i for i in resultat["issues"] if i["code"] == "weak_signature")
    assert issue["severity"] == "critical" and issue["params"]["algorithm"] == "SHA1"
    assert resultat["grade"] == "F"
    note = SPEC.score_rules[0].evaluate({"crypto_audit": resultat})
    assert is_msg(note.cap_reason) and note.points <= 5


def test_signature_sha1_de_l_intermediaire_est_haute_sans_plafond(monkeypatch):
    signatures_sha1(monkeypatch, "Intermediaire Test")
    resultat = audit.analyze(Chaine().servie())
    issue = next(i for i in resultat["issues"] if i["code"] == "weak_signature")
    assert issue["severity"] == "high" and issue["params"]["position"] == "intermediate"
    assert SPEC.score_rules[0].evaluate({"crypto_audit": resultat}).cap_reason is None


def test_racine_auto_signee_en_sha1_est_ignoree(monkeypatch):
    signatures_sha1(monkeypatch, "Vieille Racine")
    """Une racine n'est approuvée que par sa présence dans le magasin : sa signature ne compte pas."""
    chaine = Chaine()
    cle = cle_ec()
    racine_sha1 = fabriquer("Vieille Racine", cle, nom("Vieille Racine"), cle, ca=True)
    fetched = {**chaine.servie(), "served": [chaine.feuille, chaine.inter, racine_sha1]}
    assert "weak_signature" not in codes(audit.analyze(fetched))


def test_cle_rsa_trop_courte():
    resultat = audit.analyze(Chaine(cle_feuille=cle_rsa(1024)).servie())
    issue = next(i for i in resultat["issues"] if i["code"] == "weak_key")
    assert issue["params"] == {
        "subject": "example.com",
        "key_type": "RSA",
        "bits": 1024,
        "position": "leaf",
    }
    assert resultat["grade"] in ("D", "F")


def test_rsa_2048_ne_declenche_aucun_conseil():
    """Bruit supprimé : « envisagez 4096 » n'est plus un défaut."""
    assert "weak_key" not in codes(audit.analyze(Chaine(cle_feuille=cle_rsa(2048)).servie()))


@pytest.mark.parametrize(
    ("debut", "jours", "attendu"),
    [
        (dt.datetime(2026, 7, 1, tzinfo=UTC), 365, True),  # émis après le 15/03/2026 : limite de 200 jours
        (dt.datetime(2026, 7, 1, tzinfo=UTC), 200, False),
        (dt.datetime(2026, 7, 1, tzinfo=UTC), 90, False),
        (dt.datetime(2025, 1, 1, tzinfo=UTC), 365, False),  # émis avant : limite de 398 jours
        (dt.datetime(2025, 1, 1, tzinfo=UTC), 500, True),
    ],
)
def test_duree_de_validite_selon_la_date_d_emission(debut, jours, attendu):
    resultat = audit.analyze(Chaine(debut=debut, jours=jours).servie())
    assert ("validity_too_long" in codes(resultat)) is attendu
    if attendu:
        probleme = next(i for i in resultat["issues"] if i["code"] == "validity_too_long")
        assert probleme["params"]["days"] == jours


def test_autorite_privee_non_soumise_au_calendrier():
    """Faux positif évité : une chaîne non approuvée par le magasin public n'est pas jugée sur la durée."""
    chaine = Chaine(debut=dt.datetime(2026, 7, 1, tzinfo=UTC), jours=730)
    fetched = {**chaine.servie(), "verified": False, "verified_chain": [], "verify_code": 20}
    resultat = audit.analyze(fetched)
    assert "validity_too_long" not in codes(resultat) and "no_sct" not in codes(resultat)


def test_intermediaire_expire_et_proche_expiration():
    chaine = Chaine()
    expire = fabriquer(
        "Intermediaire Test",
        chaine.cle_inter,
        nom("Racine Test"),
        chaine.cle_racine,
        ca=True,
        debut=MAINTENANT - dt.timedelta(days=400),
        jours=365,
    )
    resultat = audit.analyze({**chaine.servie(), "served": [chaine.feuille, expire]})
    probleme = next(i for i in resultat["issues"] if i["code"] == "chain_expired")
    assert probleme["severity"] == "high" and probleme["params"]["days"] >= 30
    bientot = fabriquer(
        "Intermediaire Test",
        chaine.cle_inter,
        nom("Racine Test"),
        chaine.cle_racine,
        ca=True,
        debut=MAINTENANT - dt.timedelta(days=350),
        jours=365,
    )
    resultat = audit.analyze({**chaine.servie(), "served": [chaine.feuille, bientot]})
    assert "chain_expiring" in codes(resultat) and "chain_expired" not in codes(resultat)


def test_certificat_sans_san_et_sans_usage_serveur():
    assert "no_san" in codes(audit.analyze(Chaine(sans_san=True).servie()))
    client_seul = Chaine(eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    assert "no_server_auth" in codes(audit.analyze(client_seul.servie()))


def test_joker_et_san_listes():
    resultat = audit.analyze(Chaine(san=["example.com", "*.example.com"]).servie())
    assert resultat["leaf"]["wildcard"] is True
    assert resultat["leaf"]["san"] == ["example.com", "*.example.com"]
    assert resultat["leaf"]["san_count"] == 2


def test_empreinte_et_validite_documentees():
    feuille = audit.analyze(Chaine().servie())["leaf"]
    assert len(feuille["sha256"]) == 64 and feuille["validity_days"] == 90
    assert feuille["days_remaining"] == 79


# --- Constats et score --------------------------------------------------------------------


def test_constats_sur_une_chaine_defectueuse(monkeypatch):
    signatures_sha1(monkeypatch, "example.com")
    resultat = audit.analyze(Chaine(cle_feuille=cle_rsa(1024), sans_san=True).servie())
    trouves = constats(resultat)
    assert {
        "finding.crypto_audit.weak_signature",
        "finding.crypto_audit.weak_key",
        "finding.crypto_audit.no_san",
    } <= set(trouves)
    signature = trouves["finding.crypto_audit.weak_signature"][0]
    assert signature.severity == "critical" and signature.params["algorithm"] == "SHA1"


def test_aucun_constat_sur_chaine_privee_saine():
    chaine = Chaine()
    fetched = {**chaine.servie(), "verified": False, "verified_chain": [], "verify_code": 20}
    resultat = audit.analyze(fetched)
    assert constats(resultat) == {}
    note = SPEC.score_rules[0].evaluate({"crypto_audit": resultat})
    assert note.points == 10 and note.cap_reason is None and note.measured


def test_donnees_inattendues_ne_levent_pas():
    for valeur in (
        None,
        [],
        "x",
        {"issues": "x"},
        {"issues": [1, None, {"code": "weak_key"}]},
        {"measured": False},
    ):
        constats(valeur)
        if isinstance(valeur, dict):
            SPEC.score_rules[0].evaluate({"crypto_audit": valeur})


# --- Module ------------------------------------------------------------------------------------


def test_module_complet(monkeypatch, contexte, outils):
    chaine = Chaine()
    monkeypatch.setattr(tls_x509, "fetch_chain", lambda adresse, port, sni: chaine.servie())
    resultat = outils.executer(SPEC, contexte())
    outils.verifier_sortie(resultat)
    json.dumps(resultat)
    assert resultat["chain_length"] == 2


def test_module_passe_le_nom_sni_sauf_pour_une_ip(monkeypatch, contexte, outils):
    vus = []

    def faux(adresse, port, sni):
        vus.append((adresse, port, sni))
        return Chaine().servie()

    monkeypatch.setattr(tls_x509, "fetch_chain", faux)
    outils.executer(SPEC, contexte())
    outils.executer(SPEC, contexte(domain="93.184.216.34"))
    assert vus == [("93.184.216.34", 443, "example.com"), ("93.184.216.34", 443, None)]


@pytest.mark.parametrize(("raison", "attendu"), [("refused", ModuleSkipped), ("no_tls", ModuleSkipped)])
def test_pas_de_https_sans_objet(monkeypatch, contexte, outils, raison, attendu):
    def faux(*args):
        raise tls_x509.ChainFetchError(raison)

    monkeypatch.setattr(tls_x509, "fetch_chain", faux)
    with pytest.raises(attendu):
        outils.executer(SPEC, contexte())


def test_delai_depasse_est_un_echec(monkeypatch, contexte, outils):
    def faux(*args):
        raise tls_x509.ChainFetchError("timeout")

    monkeypatch.setattr(tls_x509, "fetch_chain", faux)
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_chaine_illisible_est_un_echec(monkeypatch, contexte, outils):
    monkeypatch.setattr(
        tls_x509,
        "fetch_chain",
        lambda *args: {"served": [b"pas un certificat"], "verified": False, "source": "ssl"},
    )
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_sans_adresse_sans_objet(contexte):
    assert is_msg(SPEC.skip_reason(contexte(addresses=[])))


def test_categorie_et_declaration():
    assert SPEC.category == "passif" and SPEC.family == "tls" and not SPEC.keys
