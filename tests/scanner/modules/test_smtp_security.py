# =============================================================================
# DomainRecon - Tests du module « smtp_security » (serveur SMTP simulé en local, sans réseau)
# =============================================================================
# Un petit serveur SMTP écoute sur 127.0.0.1 (seul accès réseau permis aux tests de
# modules) ; connect_socket, point d'injection du module, y renvoie toutes les connexions.
# =============================================================================

import datetime as dt
import socket
import ssl
import threading

import dns.exception
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from domainrecon.i18n import render
from domainrecon.scanner import targets
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import smtp_security as impl
from domainrecon.scanner.modules.smtp_security import SPEC
from domainrecon.scanner.rules import FindingInput

HOTE = "mx.example.com"


# --- Certificat et serveur simulés ---------------------------------------------------


def _certificat(tmp_path, noms=(HOTE,), jours_apres=90):
    cle = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, noms[0])])
    maintenant = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - dt.timedelta(days=1))
        .not_valid_after(maintenant + dt.timedelta(days=jours_apres))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in noms]), critical=False)
        .sign(cle, hashes.SHA256())
    )
    fichier_cert, fichier_cle = tmp_path / "cert.pem", tmp_path / "cle.pem"
    fichier_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fichier_cle.write_bytes(
        cle.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexte.load_cert_chain(fichier_cert, fichier_cle)
    return contexte, cert


class ServeurSmtp:
    """Serveur SMTP minimal et scénarisé ; `commandes` garde ce qu'il a reçu."""

    def __init__(
        self,
        *,
        banniere="220 mx.example.com ESMTP Postfix",
        extensions=("PIPELINING", "SIZE 52428800", "STARTTLS"),
        apres_tls=("PIPELINING", "SIZE 52428800"),
        tls=None,
        tls_en_echec=False,
        rcpt=None,
        mail=250,
        muet=False,
        refuse_ehlo=False,
        ferme_apres_banniere=False,
    ):
        self.banniere, self.extensions, self.apres_tls = banniere, extensions, apres_tls
        self.tls, self.tls_en_echec, self.mail, self.muet = tls, tls_en_echec, mail, muet
        self.refuse_ehlo, self.ferme_apres_banniere = refuse_ehlo, ferme_apres_banniere
        self.rcpt = rcpt or (lambda adresse: 250)
        self.commandes: list[str] = []
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.actif = True
        self.fil = threading.Thread(target=self._boucle, daemon=True)
        self.fil.start()

    def arreter(self):
        self.actif = False
        self.fil.join(timeout=3)
        self.socket.close()

    def _boucle(self):
        while self.actif:
            try:
                client, _ = self.socket.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._servir, args=(client,), daemon=True).start()

    def _servir(self, client):
        client.settimeout(5)
        try:
            if self.muet:
                while self.actif:
                    threading.Event().wait(0.05)
                return
            client.sendall(self.banniere.encode() + b"\r\n")
            if self.ferme_apres_banniere:
                return
            chiffre = False
            tampon = b""
            while True:
                while b"\n" not in tampon:
                    morceau = client.recv(4096)
                    if not morceau:
                        return
                    tampon += morceau
                ligne, _, tampon = tampon.partition(b"\n")
                commande = ligne.decode().strip()
                self.commandes.append(commande)
                haut = commande.upper()
                if haut.startswith(("EHLO", "HELO")) and self.refuse_ehlo:
                    client.sendall(b"502 5.5.1 commande non implementee\r\n")
                elif haut.startswith(("EHLO", "HELO")):
                    exts = self.apres_tls if chiffre else self.extensions
                    lignes = [HOTE, *exts]
                    corps = "".join(f"250-{x}\r\n" for x in lignes[:-1]) + f"250 {lignes[-1]}\r\n"
                    client.sendall(corps.encode())
                elif haut == "STARTTLS":
                    client.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                    if self.tls_en_echec or self.tls is None:
                        return  # annonce STARTTLS puis coupe : négociation en échec
                    client = self.tls.wrap_socket(client, server_side=True)
                    chiffre = True
                    tampon = b""
                elif haut.startswith("MAIL FROM"):
                    client.sendall(f"{self.mail} 2.1.0 Ok\r\n".encode())
                elif haut.startswith("RCPT TO"):
                    adresse = commande[commande.index("<") + 1 : commande.rindex(">")]
                    code = self.rcpt(adresse)
                    client.sendall(f"{code} 2.1.5 reponse\r\n".encode())
                elif haut == "RSET":
                    client.sendall(b"250 2.0.0 Ok\r\n")
                elif haut == "QUIT":
                    client.sendall(b"221 2.0.0 Bye\r\n")
                    return
                else:
                    client.sendall(b"502 5.5.2 commande inconnue\r\n")
        except (OSError, ssl.SSLError):
            return
        finally:
            try:
                client.close()
            except OSError:
                pass


@pytest.fixture
def serveur():
    """Fabrique de serveurs simulés, arrêtés en fin de test."""
    crees: list[ServeurSmtp] = []

    def fabrique(**options) -> ServeurSmtp:
        crees.append(ServeurSmtp(**options))
        return crees[-1]

    yield fabrique
    for s in crees:
        s.arreter()


@pytest.fixture
def vers_serveur(monkeypatch):
    """Redirige connect_socket vers un serveur local ; rend la liste des (ip, port) demandés."""
    demandes: list[tuple[str, int]] = []

    def installer(port: int | None = None, erreur: type[Exception] | None = None):
        def connexion(ip, port_demande, timeout):
            demandes.append((ip, port_demande))
            if erreur is not None:
                raise erreur()
            s = socket.socket()
            s.settimeout(timeout)
            s.connect(("127.0.0.1", port))
            return s

        monkeypatch.setattr(impl, "connect_socket", connexion)
        return demandes

    return installer


@pytest.fixture
def delais_courts(monkeypatch):
    monkeypatch.setattr(impl, "IO_TIMEOUT", 0.4)
    monkeypatch.setattr(impl, "HOST_BUDGET", 1.5)
    monkeypatch.setattr(impl, "CONNECT_TIMEOUT", 0.4)


def _sonde(port, **options):
    return impl.probe_host(HOTE, "93.184.216.34", 25, "example.com", 10, **options)


def _constat(code, hotes, **extra):
    rule = next(r for r in SPEC.findings if r.code == code)
    donnees = {"hosts": hotes, **extra}
    return rule.check(
        FindingInput({"smtp_security": donnees}, "smtp_security", lambda s, m: s[m], lambda s, m: True)
    )


def _score(hotes, **extra):
    return SPEC.score_rules[0].evaluate({"smtp_security": {"hosts": hotes, **extra}})


# --- Analyse de texte ----------------------------------------------------------------


def test_declaration_active_et_autorisation():
    assert SPEC.category == "actif" and SPEC.requires_authorization and not SPEC.quick
    assert SPEC.wave == 3 and SPEC.family == "email" and SPEC.keys == ()


def test_ehlo_extensions_auth_et_taille():
    ehlo = impl.parse_ehlo(
        ["mx.example.com", "PIPELINING", "SIZE 35882577", "STARTTLS", "AUTH PLAIN LOGIN", "AUTH=CRAM-MD5"]
    )
    assert ehlo["starttls"] and ehlo["size"] == 35882577
    assert ehlo["auth"] == ["CRAM-MD5", "LOGIN", "PLAIN"]
    assert not impl.parse_ehlo(["mx.example.com", "8BITMIME"])["starttls"]


@pytest.mark.parametrize(
    ("banniere", "logiciel", "version"),
    [
        ("mx.example.com ESMTP Postfix (Ubuntu)", "Postfix", None),
        ("mx ESMTP Exim 4.96 Mon, 13 Oct 2026", "Exim", "4.96"),
        ("mx ESMTP Sendmail 8.15.2/8.15.2; Mon", "Sendmail", "8.15.2/8.15.2"),
        ("mx Microsoft ESMTP MAIL Service, Version: 15.2.1118.7 ready", "Microsoft Exchange", "15.2.1118.7"),
        ("mx.google.com ESMTP abc - gsmtp", "Google", None),
        ("serveur anonyme", None, None),
    ],
)
def test_banniere(banniere, logiciel, version):
    assert impl.parse_banner(banniere) == {"software": logiciel, "version": version}


def test_raisons_d_echec_de_verification():
    def erreur(code):
        e = ssl.SSLCertVerificationError(1, "x")
        e.verify_code = code
        return e

    assert [impl.verify_reason(erreur(c)) for c in (10, 18, 19, 20, 21, 62, 99)] == [
        "expired", "self_signed", "self_signed", "untrusted", "untrusted", "hostname", "other",
    ]  # fmt: skip


def test_description_du_certificat(tmp_path):
    _, cert = _certificat(tmp_path)
    der = cert.public_bytes(serialization.Encoding.DER)
    info = impl.describe_certificate(der, HOTE)
    assert info["subject"] == HOTE and info["self_signed"] is True and info["name_matches"] is True
    assert impl.describe_certificate(der, "autre.example.net")["name_matches"] is False
    assert impl.describe_certificate(b"pas un certificat", HOTE) == {}
    _, joker = _certificat(tmp_path, noms=("*.example.com",))
    assert impl.describe_certificate(joker.public_bytes(serialization.Encoding.DER), "mx1.example.com")[
        "name_matches"
    ]
    assert not impl.describe_certificate(joker.public_bytes(serialization.Encoding.DER), "a.b.example.com")[
        "name_matches"
    ]


def test_synthese_ignore_le_catch_all_d_une_passerelle():
    """Faux positif évité : une passerelle (Mimecast…) accepte tout destinataire par construction."""
    passerelle = _hote(host="eu-smtp-inbound-1.mimecast.com", catch_all=True)
    propre = _hote(host="mail.example.com", catch_all=False)
    resume = impl.summarize([passerelle, propre])
    assert passerelle["gateway"] == "mimecast" and propre["gateway"] is None
    assert resume["catch_all"] is False and resume["examined"] == 2
    seule = impl.summarize([_hote(host="mx.cf-emailsecurity.net", catch_all=True)])
    assert seule["catch_all"] is None


def test_verification_du_certificat_avec_le_magasin_du_projet():
    from domainrecon.scanner import common

    assert impl._ssl_context(True) is common._verified_ssl_context()
    sans = impl._ssl_context(False)
    assert sans.verify_mode == ssl.CERT_NONE and sans.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_choix_de_l_adresse_ipv4_en_priorite():
    assert impl.pick_address(["2606:4700::1", "93.184.216.34"]) == "93.184.216.34"
    assert impl.pick_address([]) is None


def test_relais_desactive_par_defaut(monkeypatch):
    monkeypatch.delenv(impl.RELAY_TEST_ENV, raising=False)
    assert impl.relay_test_enabled() is False
    monkeypatch.setenv(impl.RELAY_TEST_ENV, "1")
    assert impl.relay_test_enabled() is True
    monkeypatch.setenv(impl.RELAY_TEST_ENV, "non")
    assert impl.relay_test_enabled() is False


# --- Sonde d'un serveur ----------------------------------------------------------------


def test_serveur_avec_starttls_et_certificat_auto_signe(tmp_path, serveur, vers_serveur):
    contexte_tls, _ = _certificat(tmp_path)
    s = serveur(
        tls=contexte_tls, extensions=("STARTTLS", "AUTH PLAIN LOGIN"), apres_tls=("AUTH PLAIN LOGIN",)
    )
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["reachable"] and hote["error_code"] is None and hote["starttls"] is True
    assert hote["banner"] == "mx.example.com ESMTP Postfix" and hote["software"] == "Postfix"
    assert hote["tls"]["version"] in ("TLSv1.2", "TLSv1.3") and hote["tls"]["cipher"]
    # Certificat refusé à la vérification, puis seconde connexion pour poursuivre l'examen.
    assert hote["tls"]["verified"] is False and hote["tls"]["verify_error"] == "self_signed"
    assert hote["tls"]["certificate"]["subject"] == HOTE and hote["tls"]["certificate"]["self_signed"]
    assert hote["auth_before_tls"] == ["LOGIN", "PLAIN"] and hote["auth_after_tls"] == ["LOGIN", "PLAIN"]
    assert "_verify_failed" not in hote
    assert _constat("finding.smtp_security.cert_untrusted", [hote]) == {"hosts": [HOTE]}
    assert _constat("finding.smtp_security.auth_cleartext", [hote]) == {"hosts": [HOTE]}
    assert not _constat("finding.smtp_security.cert_expired", [hote])
    assert not _constat("finding.smtp_security.no_starttls", [hote])
    assert _score([hote]).points == 3  # 5 - 1 (certificat) - 1 (AUTH en clair)


def test_sans_starttls(serveur, vers_serveur):
    s = serveur(extensions=("PIPELINING",))
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["starttls"] is False and hote["tls"] is None
    assert not any(c.upper() == "STARTTLS" for c in s.commandes)
    assert _constat("finding.smtp_security.no_starttls", [hote]) == {"hosts": [HOTE]}
    assert _score([hote]).points == 0


def test_starttls_annonce_mais_negociation_en_echec(serveur, vers_serveur):
    s = serveur(tls_en_echec=True)
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["tls"]["error"] == "handshake_failed" and hote["catch_all"] is None
    assert _constat("finding.smtp_security.tls_failed", [hote]) == {"hosts": [HOTE]}
    assert _score([hote]).points == 1


def test_banniere_avec_version_divulguee(serveur, vers_serveur):
    s = serveur(banniere="220 mx.example.com ESMTP Exim 4.96", extensions=("PIPELINING",))
    vers_serveur(s.port)
    hote = _sonde(s.port)
    hits = _constat("finding.smtp_security.banner_version", [hote])
    assert [h.params for h in hits] == [{"host": HOTE, "software": "Exim", "version": "4.96"}]
    sans = serveur(extensions=("PIPELINING",))
    vers_serveur(sans.port)
    assert not _constat("finding.smtp_security.banner_version", [_sonde(sans.port)])


def test_banniere_refusee_n_est_pas_un_defaut_du_domaine(serveur, vers_serveur):
    """Faux positif évité : un 554 à la bannière refuse NOTRE adresse, il n'accuse pas le serveur."""
    s = serveur(banniere="554 5.7.1 Service refused, your IP is blocklisted")
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["reachable"] and hote["error_code"] == "banner_refused"
    assert hote["starttls"] is None
    for rule in SPEC.findings:
        assert not _constat(rule.code, [hote]), rule.code
    assert _score([hote]).measured is False


def test_catch_all_confirme_par_deux_adresses(serveur, vers_serveur):
    s = serveur(extensions=("PIPELINING",), rcpt=lambda a: 250)
    vers_serveur(s.port)
    hote = _sonde(s.port)
    rcpts = [c for c in s.commandes if c.upper().startswith("RCPT")]
    assert hote["catch_all"] is True and len(rcpts) == 2 and rcpts[0] != rcpts[1]
    assert "@example.com>" in rcpts[0] and any(c == "MAIL FROM:<>" for c in s.commandes)
    assert _constat("finding.smtp_security.catch_all", [], catch_all=True) is True


def test_destinataire_inconnu_refuse_pas_de_catch_all(serveur, vers_serveur):
    s = serveur(extensions=("PIPELINING",), rcpt=lambda a: 550)
    vers_serveur(s.port)
    assert _sonde(s.port)["catch_all"] is False


def test_liste_grise_donne_indetermine(serveur, vers_serveur):
    """Faux positif évité : une réponse temporaire (4xx) ne prouve ni catch-all ni son contraire."""
    s = serveur(extensions=("PIPELINING",), rcpt=lambda a: 451)
    vers_serveur(s.port)
    assert _sonde(s.port)["catch_all"] is None
    s2 = serveur(extensions=("PIPELINING",), mail=550)
    vers_serveur(s2.port)
    assert _sonde(s2.port)["catch_all"] is None
    # Une adresse acceptée, l'autre refusée : pas de conclusion non plus.
    reponses = iter([250, 550])
    s3 = serveur(extensions=("PIPELINING",), rcpt=lambda a: next(reponses))
    vers_serveur(s3.port)
    assert _sonde(s3.port)["catch_all"] is None


def test_test_de_relais_jamais_lance_par_defaut(serveur, vers_serveur):
    s = serveur(extensions=("PIPELINING",))
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["relay"] is None
    assert not any(
        "example.net" in c or "example.org" in c
        for c in s.commandes
        if c.upper().startswith(("MAIL", "RCPT"))
    )
    assert not any(c.upper() == "DATA" for c in s.commandes)


def test_test_de_relais_active(serveur, vers_serveur):
    ouvert = serveur(extensions=("PIPELINING",), rcpt=lambda a: 250)
    vers_serveur(ouvert.port)
    hote = _sonde(ouvert.port, relay_test=True)
    assert hote["relay"] == "open"
    assert any(c == f"MAIL FROM:<{impl.RELAY_SENDER}>" for c in ouvert.commandes)
    assert not any(c.upper() == "DATA" for c in ouvert.commandes)
    assert _constat("finding.smtp_security.open_relay", [hote]) == {"hosts": [HOTE]}
    assert _score([hote]).points == 0
    ferme = serveur(extensions=("PIPELINING",), rcpt=lambda a: 550 if "example.net" in a else 250)
    vers_serveur(ferme.port)
    assert _sonde(ferme.port, relay_test=True)["relay"] == "closed"


def test_connexion_refusee_et_delai(serveur, vers_serveur, delais_courts):
    vers_serveur(1, erreur=ConnectionRefusedError)
    assert _sonde(1)["error_code"] == "refused"
    vers_serveur(1, erreur=TimeoutError)
    hote = _sonde(1)
    assert hote["error_code"] == "timeout" and hote["reachable"] is False
    vers_serveur(1, erreur=OSError)
    assert _sonde(1)["error_code"] == "unreachable"


def test_serveur_muet_delai_depasse(serveur, vers_serveur, delais_courts):
    s = serveur(muet=True)
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["reachable"] and hote["error_code"] == "timeout"
    assert "délai" in render(hote["error"], "fr")


def test_ehlo_et_helo_refuses(serveur, vers_serveur):
    s = serveur(refuse_ehlo=True)
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["reachable"] and hote["error_code"] == "ehlo_rejected" and hote["starttls"] is None
    assert [c.split()[0] for c in s.commandes] == ["EHLO", "HELO"]


def test_connexion_fermee_apres_la_banniere(serveur, vers_serveur):
    s = serveur(ferme_apres_banniere=True)
    vers_serveur(s.port)
    hote = _sonde(s.port)
    assert hote["banner"] and hote["error_code"] == "closed"


# --- Score -----------------------------------------------------------------------------


def _hote(**champs):
    base = {
        "host": HOTE,
        "reachable": True,
        "error_code": None,
        "starttls": True,
        "auth_before_tls": [],
        "tls": {"verified": True},
    }
    return {**base, **champs}


def test_score_serveur_irreprochable():
    note = _score([_hote()])
    assert note.points == 5 and note.measured and note.counted


def test_score_certificat_expire_et_auth_en_clair():
    expire = _hote(tls={"verified": False, "verify_error": "expired"}, auth_before_tls=["PLAIN"])
    assert _score([expire]).points == 2


def test_score_sans_serveur_examine_hors_calcul():
    assert _score([{"host": HOTE, "reachable": False, "error_code": "timeout"}]).measured is False
    assert _score([]).measured is False


def test_regles_resistent_aux_donnees_inattendues():
    for data in (None, [], "x", {"hosts": "x"}, {"hosts": [None, 3, {"tls": 4, "auth_before_tls": 7}]}):
        for rule in SPEC.findings:
            rule.check(
                FindingInput({"smtp_security": data}, "smtp_security", lambda s, m: s[m], lambda s, m: True)
            )
        SPEC.score_rules[0].evaluate({"smtp_security": data})


# --- Module (run) ------------------------------------------------------------------------


@pytest.fixture
def adresses(monkeypatch):
    """Résolution des MX : par défaut une adresse publique ; modifiable par test."""
    table: dict[str, list[str]] = {}

    async def resoudre(hote, *args, **kwargs):
        return table.get(hote, ["93.184.216.34"])

    monkeypatch.setattr(targets, "resolve_addresses", resoudre)
    return table


def _mx(outils, *valeurs):
    return [outils.rdata("MX", v) for v in valeurs]


def test_run_succes_deux_mx(tmp_path, outils, contexte, dns_simule, serveur, vers_serveur, adresses):
    contexte_tls, _ = _certificat(tmp_path)
    s = serveur(tls=contexte_tls)
    vers_serveur(s.port)
    dns_simule({("example.com", "MX"): _mx(outils, "10 mx.example.com.", "20 mx2.example.com.")})
    resultat = outils.executer(SPEC, contexte())
    outils.verifier_sortie(resultat)
    assert resultat["tested"] == 2 and resultat["examined"] == 2 and resultat["starttls_all"] is True
    assert [h["host"] for h in resultat["hosts"]] == ["mx.example.com", "mx2.example.com"]
    assert resultat["relay_test"] is False and resultat["catch_all"] is True
    assert resultat["hosts"][0]["tls"]["version"]


def test_run_limite_le_nombre_de_serveurs(outils, contexte, dns_simule, serveur, vers_serveur, adresses):
    s = serveur(extensions=("STARTTLS",), tls_en_echec=True)
    demandes = vers_serveur(s.port)
    dns_simule(
        {("example.com", "MX"): _mx(outils, *[f"{10 * (i + 1)} mx{i}.example.com." for i in range(6)])}
    )
    resultat = outils.executer(SPEC, contexte())
    assert resultat["tested"] == impl.MAX_HOSTS == 3
    assert len(demandes) == 3  # une seule connexion par serveur : pas de seconde tentative sans cause


def test_run_port_25_filtre_essaie_587_puis_echoue(outils, contexte, dns_simule, vers_serveur, adresses):
    demandes = vers_serveur(1, erreur=TimeoutError)
    dns_simule({("example.com", "MX"): _mx(outils, "10 mx.example.com.")})
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    texte = render(erreur.value.message, "fr")
    assert "port 25" in texte and "bloqué" in texte and "587" in texte
    assert {port for _, port in demandes} == {25, 587}


def test_run_adresse_privee_jamais_contactee(outils, contexte, dns_simule, vers_serveur, adresses):
    demandes = vers_serveur(1)
    adresses["mx.example.com"] = ["10.0.0.5"]
    dns_simule({("example.com", "MX"): _mx(outils, "10 mx.example.com.")})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())
    assert demandes == []  # politique anti-SSRF : aucune connexion vers une adresse privée


def test_run_mx_sans_adresse(outils, contexte, dns_simule, vers_serveur, adresses):
    vers_serveur(1)
    adresses["mx.example.com"] = []
    dns_simule({("example.com", "MX"): _mx(outils, "10 mx.example.com.")})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_run_mx_nul_et_sans_mx(outils, contexte, dns_simule):
    dns_simule({("example.com", "MX"): _mx(outils, "0 .")})
    with pytest.raises(ModuleSkipped) as erreur:
        outils.executer(SPEC, contexte())
    assert "RFC 7505" in render(erreur.value.message, "fr")
    dns_simule({})
    with pytest.raises(ModuleSkipped):
        outils.executer(SPEC, contexte())


def test_run_echec_dns_des_mx(outils, contexte, dns_simule):
    dns_simule({("example.com", "MX"): dns.exception.Timeout})
    with pytest.raises(ModuleError):
        outils.executer(SPEC, contexte())


def test_run_relais_active_par_l_environnement(
    monkeypatch, outils, contexte, dns_simule, serveur, vers_serveur, adresses
):
    monkeypatch.setenv(impl.RELAY_TEST_ENV, "1")
    s = serveur(extensions=("PIPELINING",), rcpt=lambda a: 550 if "example.net" in a else 250)
    vers_serveur(s.port)
    dns_simule({("example.com", "MX"): _mx(outils, "10 mx.example.com.")})
    resultat = outils.executer(SPEC, contexte())
    assert resultat["relay_test"] is True and resultat["hosts"][0]["relay"] == "closed"
    assert resultat["relay_open"] is False


def test_sans_objet_adresse_ip_et_plateforme(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
    assert (
        SPEC.skip_reason(contexte(domain="mon-site.github.io", apex="github.io", site="mon-site.github.io"))
        is not None
    )
    assert SPEC.skip_reason(contexte()) is None
