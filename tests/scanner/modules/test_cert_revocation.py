# =============================================================================
# DomainRecon - Tests du module « cert_revocation » (sans réseau)
# =============================================================================
# Autorité, certificat, réponses OCSP et CRL sont fabriqués par la bibliothèque
# cryptography ; les requêtes vers l'autorité passent par le client HTTP simulé
# (fixture http_simule), la chaîne et l'agrafe par des fonctions remplacées.
# =============================================================================

import datetime as dt
import json

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from domainrecon.i18n import is_msg
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import cert_revocation as revocation
from domainrecon.scanner.impl import tls_hello, tls_x509
from domainrecon.scanner.modules import cert_revocation
from domainrecon.scanner.rules import FindingInput

SPEC = cert_revocation.SPEC
UTC = dt.timezone.utc  # noqa: UP017 - Python 3.10 : datetime.UTC absent
MAINTENANT = dt.datetime.now(UTC)
OCSP_URL = "http://ocsp.test/"
CRL_URL = "http://crl.test/ca.crl"
ISSUER_URL = "http://ca.test/issuer.cer"


def nom(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class Autorite:
    """Une AC (clé EC) qui émet un certificat de site portant les URL OCSP / CRL demandées."""

    def __init__(self, *, ocsp=True, crl=True, must_staple=False, jours=60, debut=None, ca_issuers=False):
        self.cle = ec.generate_private_key(ec.SECP256R1())
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(nom("AC Test"))
            .issuer_name(nom("AC Test"))
            .public_key(self.cle.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(MAINTENANT - dt.timedelta(days=900))
            .not_valid_after(MAINTENANT + dt.timedelta(days=900))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.cle.public_key()), critical=False)
            .sign(self.cle, hashes.SHA256())
        )
        cle_site = ec.generate_private_key(ec.SECP256R1())
        debut = debut or MAINTENANT - dt.timedelta(days=10)
        constructeur = (
            x509.CertificateBuilder()
            .subject_name(nom("example.com"))
            .issuer_name(self.cert.subject)
            .public_key(cle_site.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(debut)
            .not_valid_after(debut + dt.timedelta(days=jours))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
        )
        acces = []
        if ocsp:
            acces.append(
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(OCSP_URL)
                )
            )
        if ca_issuers:
            acces.append(
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(ISSUER_URL)
                )
            )
        if acces:
            constructeur = constructeur.add_extension(x509.AuthorityInformationAccess(acces), critical=False)
        if crl:
            point = x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
            constructeur = constructeur.add_extension(x509.CRLDistributionPoints([point]), critical=False)
        if must_staple:
            constructeur = constructeur.add_extension(
                x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False
            )
        constructeur = constructeur.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        self.site = constructeur.sign(self.cle, hashes.SHA256())

    def servie(self, *, avec_ac=True, verifie=True) -> dict:
        der = [self.site.public_bytes(Encoding.DER)]
        if avec_ac:
            der.append(self.cert.public_bytes(Encoding.DER))
        return {
            "served": der,
            "verified": verifie,
            "verified_chain": [],
            "verify_code": None,
            "source": "ssl",
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
        }

    def reponse_ocsp(self, etat, *, cle=None, serie=None, ancien=False, revoque=None) -> bytes:
        cle = cle or self.cle
        debut = MAINTENANT - dt.timedelta(days=10 if ancien else 1)
        fin = MAINTENANT - dt.timedelta(days=3) if ancien else MAINTENANT + dt.timedelta(days=5)
        cert = self.site
        if serie is not None:
            cert = (
                x509.CertificateBuilder()
                .subject_name(nom("autre.test"))
                .issuer_name(self.cert.subject)
                .public_key(self.cle.public_key())
                .serial_number(serie)
                .not_valid_before(MAINTENANT - dt.timedelta(days=1))
                .not_valid_after(MAINTENANT + dt.timedelta(days=1))
                .sign(self.cle, hashes.SHA256())
            )
        repondeur = self.cert
        if cle is not self.cle:
            # Répondeur pirate : son certificat n'est pas émis par l'AC.
            repondeur = (
                x509.CertificateBuilder()
                .subject_name(nom("Pirate"))
                .issuer_name(nom("Pirate"))
                .public_key(cle.public_key())
                .serial_number(7)
                .not_valid_before(MAINTENANT - dt.timedelta(days=1))
                .not_valid_after(MAINTENANT + dt.timedelta(days=1))
                .sign(cle, hashes.SHA256())
            )
        revocation_time = None
        if etat == ocsp.OCSPCertStatus.REVOKED:
            revocation_time = revoque or MAINTENANT - dt.timedelta(days=2)
        constructeur = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=cert,
                issuer=self.cert,
                algorithm=hashes.SHA1(),
                cert_status=etat,
                this_update=debut,
                next_update=fin,
                revocation_time=revocation_time,
                revocation_reason=x509.ReasonFlags.key_compromise if revocation_time else None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, repondeur)
        )
        if repondeur is not self.cert:
            constructeur = constructeur.certificates([repondeur])
        return constructeur.sign(cle, hashes.SHA256()).public_bytes(Encoding.DER)

    def crl(self, *, revoque=False, cle=None, ancienne=False) -> bytes:
        debut = MAINTENANT - dt.timedelta(days=10 if ancienne else 1)
        fin = MAINTENANT - dt.timedelta(days=3) if ancienne else MAINTENANT + dt.timedelta(days=6)
        constructeur = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(debut)
            .next_update(fin)
        )
        if revoque:
            entree = (
                x509.RevokedCertificateBuilder()
                .serial_number(self.site.serial_number)
                .revocation_date(MAINTENANT - dt.timedelta(days=2))
                .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
                .build()
            )
            constructeur = constructeur.add_revoked_certificate(entree)
        return constructeur.sign(cle or self.cle, hashes.SHA256()).public_bytes(Encoding.DER)


@pytest.fixture
def monde(monkeypatch, http_simule, contexte, outils):
    """Installe chaîne, agrafe et routes ; rend une fonction qui lance le module."""

    def installer(autorite: Autorite, routes: dict | None = None, *, agrafe=None, **chaine):
        monkeypatch.setattr(tls_x509, "fetch_chain", lambda adresse, port, sni: autorite.servie(**chaine))
        monkeypatch.setattr(
            revocation, "probe_stapling", lambda *args: agrafe if agrafe is not None else {"supported": False}
        )
        requetes = http_simule(routes or {})
        resultat = outils.executer(SPEC, contexte())
        outils.verifier_sortie(resultat)
        json.dumps(resultat)
        return resultat, requetes

    return installer


def ocsp_ok(contenu: bytes):
    return {OCSP_URL: (200, {"content-type": "application/ocsp-response"}, contenu)}


def donnees(valeur: dict) -> FindingInput:
    return FindingInput({}, "cert_revocation", lambda scan, module: valeur, lambda scan, module: True)


def constats(valeur: dict) -> dict[str, object]:
    trouves = {}
    for regle in SPEC.findings:
        resultat = regle.check(donnees(valeur))
        if resultat:
            trouves[regle.code] = resultat
    return trouves


def note(resultat: dict):
    return SPEC.score_rules[0].evaluate({"cert_revocation": resultat})


# --- OCSP ----------------------------------------------------------------------------------


def test_ocsp_bon(monde):
    autorite = Autorite()
    resultat, requetes = monde(autorite, ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD)))
    assert resultat["status"] == "good"
    assert resultat["ocsp"]["status"] == "good" and resultat["ocsp"]["signature_ok"] is True
    assert resultat["crl"] == {"checked": False}  # OCSP a conclu : pas de CRL téléchargée
    assert [r.method for r in requetes] == ["POST"]
    assert requetes[0].headers["content-type"] == "application/ocsp-request"
    assert constats(resultat) == {}
    assert note(resultat).points == 5


def test_ocsp_revoque_est_critique_et_plafonne(monde):
    autorite = Autorite()
    resultat, _ = monde(autorite, ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.REVOKED)))
    assert resultat["status"] == "revoked"
    assert resultat["ocsp"]["reason"] == "key_compromise" and resultat["ocsp"]["revoked_at"]
    trouves = constats(resultat)
    assert trouves["finding.cert_revocation.revoked"].severity == "critical"
    assert is_msg(note(resultat).cap_reason) and note(resultat).points == 0


def test_reponse_ocsp_non_authentifiee_baisse_la_gravite(monde):
    autorite = Autorite()
    pirate = ec.generate_private_key(ec.SECP256R1())
    contenu = autorite.reponse_ocsp(ocsp.OCSPCertStatus.REVOKED, cle=pirate)
    resultat, _ = monde(autorite, ocsp_ok(contenu))
    assert resultat["ocsp"]["signature_ok"] is False
    assert constats(resultat)["finding.cert_revocation.revoked"].severity == "high"


def test_ocsp_inconnu_bascule_sur_la_crl(monde):
    autorite = Autorite()
    routes = {
        **ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.UNKNOWN)),
        CRL_URL: (200, {}, autorite.crl()),
    }
    resultat, requetes = monde(autorite, routes)
    assert resultat["ocsp"]["status"] == "unknown"
    assert resultat["crl"]["status"] == "good" and resultat["status"] == "good"
    assert [r.method for r in requetes] == ["POST", "GET"]


def test_ocsp_refuse_par_l_autorite_puis_crl(monde):
    autorite = Autorite()
    refus = ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)
    routes = {**ocsp_ok(refus.public_bytes(Encoding.DER)), CRL_URL: (200, {}, autorite.crl())}
    resultat, _ = monde(autorite, routes)
    assert resultat["ocsp"]["status"] == "error" and is_msg(resultat["ocsp"]["error"])
    assert resultat["status"] == "good"


def test_ocsp_http_500_puis_crl_revoquee(monde):
    autorite = Autorite()
    routes = {OCSP_URL: (500, {}, ""), CRL_URL: (200, {}, autorite.crl(revoque=True))}
    resultat, _ = monde(autorite, routes)
    assert resultat["status"] == "revoked" and resultat["crl"]["signature_ok"] is True
    assert resultat["crl"]["reason"] == "key_compromise"
    assert constats(resultat)["finding.cert_revocation.revoked"].severity == "critical"


def test_crl_signee_par_une_autre_cle(monde):
    autorite = Autorite(ocsp=False)
    pirate = ec.generate_private_key(ec.SECP256R1())
    resultat, _ = monde(autorite, {CRL_URL: (200, {}, autorite.crl(revoque=True, cle=pirate))})
    assert resultat["crl"]["signature_ok"] is False
    assert constats(resultat)["finding.cert_revocation.revoked"].severity == "high"


def test_aucune_source_ne_repond(monde):
    autorite = Autorite()
    resultat, _ = monde(autorite, {OCSP_URL: (503, {}, ""), CRL_URL: (404, {}, "")})
    assert resultat["status"] == "unknown"
    assert resultat["ocsp"]["error"] and resultat["crl"]["error"]
    assert "finding.cert_revocation.unverifiable" in constats(resultat)
    assert note(resultat).points == 3


def test_autorite_injoignable(monde):
    autorite = Autorite()
    routes = {OCSP_URL: httpx.ConnectError("refus"), CRL_URL: httpx.ReadTimeout("lent")}
    resultat, _ = monde(autorite, routes)
    assert resultat["status"] == "unknown" and resultat["measured"] is True
    texte = json.dumps(resultat, default=str)
    assert "refus" not in texte and "lent" not in texte  # jamais le texte brut d'une erreur httpx


def test_reponse_perimee_ne_prouve_rien(monde):
    autorite = Autorite(crl=False)
    resultat, _ = monde(autorite, ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD, ancien=True)))
    assert resultat["ocsp"]["stale"] is True and resultat["ocsp"]["status"] == "unknown"
    assert resultat["status"] == "unknown"


def test_crl_perimee_ne_prouve_rien(monde):
    autorite = Autorite(ocsp=False)
    resultat, _ = monde(autorite, {CRL_URL: (200, {}, autorite.crl(ancienne=True))})
    assert resultat["crl"]["stale"] is True and resultat["status"] == "unknown"


def test_reponse_ocsp_pour_un_autre_certificat(monde):
    autorite = Autorite(crl=False)
    contenu = autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD, serie=12345)
    resultat, _ = monde(autorite, ocsp_ok(contenu))
    assert resultat["ocsp"]["status"] == "error" and resultat["status"] == "unknown"


def test_reponse_illisible(monde):
    autorite = Autorite(crl=False)
    resultat, _ = monde(autorite, ocsp_ok(b"ceci n'est pas de l'ASN.1"))
    assert resultat["ocsp"]["status"] == "error" and is_msg(resultat["ocsp"]["error"])


def test_crl_trop_volumineuse(monde, monkeypatch):
    monkeypatch.setattr(revocation, "MAX_CRL_BYTES", 50)
    autorite = Autorite(ocsp=False)
    resultat, _ = monde(autorite, {CRL_URL: (200, {}, autorite.crl())})
    assert resultat["crl"]["status"] == "error" and resultat["status"] == "unknown"


def test_url_non_http_ignoree(monde, monkeypatch):
    autorite = Autorite()
    monkeypatch.setattr(tls_x509, "ocsp_urls", lambda cert: ["ldap://ocsp.test/", "file:///etc/passwd"])
    monkeypatch.setattr(tls_x509, "crl_urls", lambda cert: [])
    resultat, requetes = monde(autorite)
    assert requetes == [] and resultat["ocsp"]["checked"] is False


# --- Agrafe, Must-Staple ---------------------------------------------------------------------------


def test_must_staple_sans_agrafe(monde):
    autorite = Autorite(must_staple=True)
    resultat, _ = monde(
        autorite, ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD)), agrafe={"supported": False}
    )
    assert resultat["must_staple"] is True
    assert "finding.cert_revocation.must_staple_missing" in constats(resultat)
    assert note(resultat).points == 1


def test_must_staple_avec_agrafe(monde):
    autorite = Autorite(must_staple=True)
    agrafe = {"supported": True, "status": "good", "stale": False}
    resultat, _ = monde(autorite, ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD)), agrafe=agrafe)
    assert "finding.cert_revocation.must_staple_missing" not in constats(resultat)


def test_must_staple_ne_conclut_pas_si_tls13_masque_l_agrafe(monde):
    """supported=None (serveur TLS 1.3 seul : agrafe chiffrée) n'est pas une absence d'agrafe."""
    autorite = Autorite(must_staple=True)
    resultat, _ = monde(
        autorite, ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD)), agrafe={"supported": None}
    )
    assert "finding.cert_revocation.must_staple_missing" not in constats(resultat)


def test_agrafe_perimee(monde):
    autorite = Autorite()
    agrafe = {"supported": True, "status": "unknown", "stale": True}
    resultat, _ = monde(autorite, ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD)), agrafe=agrafe)
    assert "finding.cert_revocation.stale_staple" in constats(resultat)


def test_agrafe_revoquee_suffit(monde):
    autorite = Autorite(ocsp=False, crl=False)
    resultat, _ = monde(autorite, agrafe={"supported": True, "status": "revoked", "stale": False})
    assert resultat["status"] == "revoked"
    assert constats(resultat)["finding.cert_revocation.revoked"].severity == "critical"


def staple(autorite: Autorite, etat=ocsp.OCSPCertStatus.GOOD) -> bytes:
    return autorite.reponse_ocsp(etat)


def test_sonde_d_agrafe(monkeypatch):
    autorite = Autorite()
    vol = tls_hello.ServerFlight("hello", version=tls_hello.TLS12, stapled=staple(autorite))
    monkeypatch.setattr(tls_hello, "probe", lambda *args, **kwargs: vol)
    resultat = revocation.probe_stapling("93.184.216.34", 443, "example.com", autorite.site)
    assert resultat["supported"] is True and resultat["status"] == "good" and resultat["stale"] is False


def test_sonde_d_agrafe_absente_ou_masquee(monkeypatch):
    autorite = Autorite()
    sans = tls_hello.ServerFlight("hello", version=tls_hello.TLS12)
    monkeypatch.setattr(tls_hello, "probe", lambda *args, **kwargs: sans)
    assert revocation.probe_stapling("93.184.216.34", 443, "x", autorite.site) == {"supported": False}
    alerte = tls_hello.ServerFlight("alert", alert=70)
    monkeypatch.setattr(tls_hello, "probe", lambda *args, **kwargs: alerte)
    assert revocation.probe_stapling("93.184.216.34", 443, "x", autorite.site) == {"supported": None}


def test_agrafe_illisible(monkeypatch):
    autorite = Autorite()
    vol = tls_hello.ServerFlight("hello", version=tls_hello.TLS12, stapled=b"xx")
    monkeypatch.setattr(tls_hello, "probe", lambda *args, **kwargs: vol)
    resultat = revocation.probe_stapling("93.184.216.34", 443, "x", autorite.site)
    assert resultat["supported"] is True and resultat["status"] == "error"


# --- Informations absentes, certificats hors sujet ---------------------------------------------------


def test_aucune_information_de_revocation(monde):
    autorite = Autorite(ocsp=False, crl=False)
    resultat, requetes = monde(autorite)
    assert requetes == []
    assert "finding.cert_revocation.no_revocation_info" in constats(resultat)
    assert note(resultat).points == 3


def test_certificat_a_duree_de_vie_courte_dispense(monde):
    """Faux positif évité : la révocation n'est plus exigée pour les certificats de 10 jours ou moins."""
    autorite = Autorite(ocsp=False, crl=False, jours=7)
    resultat, _ = monde(autorite)
    assert resultat["short_lived"] is True and constats(resultat) == {}


def test_chaine_non_approuvee_pas_de_constat_d_absence(monde):
    autorite = Autorite(ocsp=False, crl=False)
    resultat, _ = monde(autorite, verifie=False)
    assert constats(resultat) == {}


def test_crl_seule_sans_ocsp_est_normale(monde):
    """Let's Encrypt a arrêté OCSP en 2025 : une CRL suffit, aucun constat."""
    autorite = Autorite(ocsp=False)
    resultat, _ = monde(autorite, {CRL_URL: (200, {}, autorite.crl())})
    assert resultat["status"] == "good" and constats(resultat) == {}
    assert note(resultat).points == 5


def test_certificat_expire_sans_interrogation(monde):
    autorite = Autorite(debut=MAINTENANT - dt.timedelta(days=100), jours=30)
    resultat, requetes = monde(autorite, {})
    assert requetes == [] and resultat["expired"] is True
    assert constats(resultat) == {} and note(resultat).applicable is False


def test_certificat_autosigne_sans_interrogation(monkeypatch, contexte, http_simule, outils):
    cle = ec.generate_private_key(ec.SECP256R1())
    auto = (
        x509.CertificateBuilder()
        .subject_name(nom("example.com"))
        .issuer_name(nom("example.com"))
        .public_key(cle.public_key())
        .serial_number(1)
        .not_valid_before(MAINTENANT - dt.timedelta(days=1))
        .not_valid_after(MAINTENANT + dt.timedelta(days=300))
        .sign(cle, hashes.SHA256())
    )
    fetched = {"served": [auto.public_bytes(Encoding.DER)], "verified": False, "source": "ssl"}
    monkeypatch.setattr(tls_x509, "fetch_chain", lambda *args: fetched)
    monkeypatch.setattr(revocation, "probe_stapling", lambda *args: {"supported": False})
    requetes = http_simule({})
    resultat = outils.executer(SPEC, contexte())
    assert requetes == [] and resultat["self_signed"] is True and note(resultat).applicable is False


# --- Émetteur manquant (AIA) ------------------------------------------------------------------------------


def test_emetteur_recupere_par_aia(monde):
    autorite = Autorite(crl=False, ca_issuers=True)
    routes = {
        ISSUER_URL: (200, {}, autorite.cert.public_bytes(Encoding.DER)),
        **ocsp_ok(autorite.reponse_ocsp(ocsp.OCSPCertStatus.GOOD)),
    }
    resultat, requetes = monde(autorite, routes, avec_ac=False)
    assert resultat["status"] == "good" and [r.method for r in requetes] == ["GET", "POST"]


def test_emetteur_introuvable(monde):
    autorite = Autorite(ca_issuers=True)
    resultat, _ = monde(autorite, {ISSUER_URL: (404, {}, "")}, avec_ac=False)
    assert resultat.get("issuer_missing") is True and resultat["status"] == "unknown"


# --- Module ---------------------------------------------------------------------------------------------------


def test_pas_de_https_sans_objet(monkeypatch, contexte, outils):
    def refus(*args):
        raise tls_x509.ChainFetchError("refused")

    monkeypatch.setattr(tls_x509, "fetch_chain", refus)
    with pytest.raises(ModuleSkipped):
        outils.executer(SPEC, contexte())


def test_delai_depasse(monkeypatch, contexte, outils):
    def lent(*args):
        raise tls_x509.ChainFetchError("timeout")

    monkeypatch.setattr(tls_x509, "fetch_chain", lent)
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_chaine_illisible(monkeypatch, contexte, outils):
    monkeypatch.setattr(tls_x509, "fetch_chain", lambda *args: {"served": [b"x"], "verified": False})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_sans_client_http(monkeypatch, contexte, outils):
    monkeypatch.setattr(tls_x509, "fetch_chain", lambda *args: Autorite().servie())
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte(http=None))


def test_donnees_inattendues_ne_levent_pas():
    for valeur in (None, [], "x", {"ocsp": 3, "stapling": [], "status": "revoked"}, {"measured": False}):
        constats(valeur)
        if isinstance(valeur, dict):
            note(valeur)


def test_declaration():
    assert SPEC.category == "passif" and SPEC.family == "tls" and SPEC.optional and not SPEC.keys
