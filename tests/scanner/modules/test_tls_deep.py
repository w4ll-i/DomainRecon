# =============================================================================
# DomainRecon - Tests du module « tls_deep » (sans réseau)
# =============================================================================
# Le serveur TLS est simulé en remplaçant `tls_hello.probe` : la fonction lit le
# ClientHello réellement construit par le module (version, suites, compression),
# puis répond comme le ferait le serveur configuré. L'analyse du vol serveur
# (ServerHello, certificats, agrafe, DH) est testée sur des octets écrits à la main.
# =============================================================================

import json
import struct

import pytest

from domainrecon.i18n import is_msg
from domainrecon.scanner.errors import ModuleError, ModuleSkipped
from domainrecon.scanner.impl import tls_deep as analysis
from domainrecon.scanner.impl import tls_hello as hello
from domainrecon.scanner.modules import tls_deep
from domainrecon.scanner.rules import FindingInput, Hit

SPEC = tls_deep.SPEC

GCM = [0xC02F, 0xC030, 0xCCA8]
TLS13 = [0x1301, 0x1302, 0x1303]


def lire_hello(paquet: bytes) -> dict:
    """Décode le ClientHello forgé : version, suites, compression, extensions présentes."""
    assert paquet[0] == 22
    corps = paquet[9:]
    version = struct.unpack(">H", corps[0:2])[0]
    position = 34
    position += 1 + corps[position]
    nb = struct.unpack(">H", corps[position : position + 2])[0]
    suites = [struct.unpack(">H", corps[position + 2 + i : position + 4 + i])[0] for i in range(0, nb, 2)]
    position += 2 + nb
    compression = list(corps[position + 1 : position + 1 + corps[position]])
    position += 1 + corps[position]
    extensions = set()
    if len(corps) > position + 2:
        fin = position + 2 + struct.unpack(">H", corps[position : position + 2])[0]
        position += 2
        while position + 4 <= fin:
            type_, longueur = struct.unpack(">HH", corps[position : position + 4])
            extensions.add(type_)
            position += 4 + longueur
    return {"version": version, "suites": suites, "compression": compression, "extensions": extensions}


class Serveur:
    """Serveur TLS simulé : {version: suites dans l'ordre de préférence du serveur}."""

    def __init__(self, versions, *, compression=False, dh_bits=None, client_order=False, hors_ligne=None):
        self.versions = versions
        self.compression = compression
        self.dh_bits = dh_bits
        self.client_order = client_order
        self.hors_ligne = hors_ligne  # None ou issue imposée à toutes les sondes
        self.sondes = 0

    def probe(self, address, port, paquet, *, timeout=5.0, read_flight=False):
        self.sondes += 1
        if self.hors_ligne:
            return hello.ServerFlight(self.hors_ligne)
        demande = lire_hello(paquet)
        if hello.TLS13 in demande["extensions"] or 43 in demande["extensions"]:
            voulue = hello.TLS13
        else:
            voulue = demande["version"]
        # Le serveur retient la plus haute version qu'il connaît, au plus égale à celle demandée.
        possibles = [v for v in self.versions if v <= voulue]
        if not possibles:
            return hello.ServerFlight("alert", alert=70)
        version = max(possibles)
        ordre = demande["suites"] if self.client_order else self.versions[version]
        communes = [s for s in ordre if s in demande["suites"] and s in self.versions[version]]
        if not communes:
            return hello.ServerFlight("alert", alert=40)
        suite = communes[0]
        compression = 1 if self.compression and 1 in demande["compression"] else 0
        vol = hello.ServerFlight("hello", version=version, suite=suite, compression=compression)
        if read_flight and "_DHE_" in hello.suite_name(suite):
            vol.dh_bits = self.dh_bits
        return vol


@pytest.fixture
def serveur(monkeypatch):
    def installer(*args, **kwargs) -> Serveur:
        simule = Serveur(*args, **kwargs)
        monkeypatch.setattr(hello, "probe", simule.probe)
        return simule

    return installer


MODERNE = {hello.TLS12: [0xC02F, 0xC030, 0xCCA8, 0xC02B], hello.TLS13: TLS13}
ANCIEN = {
    hello.SSL3: [0x0005, 0x000A],
    hello.TLS10: [0x0005, 0x000A, 0x002F, 0x0001],
    hello.TLS12: [0xC02F, 0x0005, 0x0033],
}


def donnees(valeur: dict) -> FindingInput:
    return FindingInput({}, "tls_deep", lambda scan, module: valeur, lambda scan, module: True)


def constats(valeur: dict) -> dict[str, object]:
    """Codes de constats déclenchés -> résultat de la règle (gravité éventuelle dans un Hit)."""
    trouves = {}
    for regle in SPEC.findings:
        resultat = regle.check(donnees(valeur))
        if resultat:
            trouves[regle.code] = resultat
    return trouves


# --- Suites -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "force", "pfs"),
    [
        (0xC02F, "ok", True),
        (0x1301, "ok", True),
        (0x002F, "ok", False),
        (0x0005, "weak", False),
        (0x000A, "weak", False),
        (0xC012, "weak", True),
        (0x0001, "broken", False),
        (0x0003, "broken", False),
        (0x0018, "broken", False),
        (0xC006, "broken", True),
        (0x0009, "weak", False),
    ],
)
def test_classement_des_suites(code, force, pfs):
    info = hello.classify_suite(hello.suite_name(code))
    assert (info["strength"], info["pfs"]) == (force, pfs)


def test_suite_inconnue_nommee_en_hexadecimal():
    assert hello.suite_name(0xFFFF) == "0xFFFF"


# --- ClientHello et lecture du vol serveur ------------------------------------------


def test_clienthello_sslv3_sans_extensions():
    lu = lire_hello(hello.build_client_hello(hello.SSL3, [0x0005], "example.com"))
    assert lu["version"] == hello.SSL3 and lu["extensions"] == set() and lu["suites"] == [0x0005]


def test_clienthello_tls13_annonce_la_version_et_le_partage_de_cle():
    lu = lire_hello(hello.build_client_hello(hello.TLS13, TLS13, "example.com"))
    assert lu["version"] == hello.TLS12  # version historique du champ
    assert {43, 51} <= lu["extensions"]


def test_clienthello_sans_sni_pour_une_adresse_ip():
    assert 0 not in lire_hello(hello.build_client_hello(hello.TLS12, GCM, "93.184.216.34"))["extensions"]
    assert 0 in lire_hello(hello.build_client_hello(hello.TLS12, GCM, "example.com"))["extensions"]


def test_clienthello_demande_agrafe_et_compression():
    lu = lire_hello(
        hello.build_client_hello(hello.TLS12, GCM, "example.com", status_request=True, compression=(1, 0))
    )
    assert 5 in lu["extensions"] and lu["compression"] == [1, 0]


def enregistrement(type_: int, charge: bytes, version: int = 0x0303) -> bytes:
    return bytes([type_]) + struct.pack(">H", version) + struct.pack(">H", len(charge)) + charge


def message(type_: int, corps: bytes) -> bytes:
    return bytes([type_]) + len(corps).to_bytes(3, "big") + corps


def server_hello(suite: int, version: int = 0x0303, compression: int = 0, extensions: bytes = b"") -> bytes:
    corps = struct.pack(">H", version) + bytes(32) + b"\x00" + struct.pack(">H", suite) + bytes([compression])
    if extensions:
        corps += struct.pack(">H", len(extensions)) + extensions
    return message(2, corps)


class FausseConnexion:
    """Socket simulé qui rend les octets donnés, puis la fermeture."""

    def __init__(self, octets: bytes):
        self.reste = octets
        self.envoye = b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, valeur):
        pass

    def sendall(self, donnees_):
        self.envoye += donnees_

    def recv(self, taille):
        morceau, self.reste = self.reste[:taille], self.reste[taille:]
        return morceau


def sonder(monkeypatch, octets: bytes, **options) -> hello.ServerFlight:
    monkeypatch.setattr(hello.socket, "create_connection", lambda *a, **k: FausseConnexion(octets))
    return hello.probe("93.184.216.34", 443, hello.build_client_hello(hello.TLS12, GCM, "x.test"), **options)


def test_lecture_serverhello(monkeypatch):
    vol = sonder(monkeypatch, enregistrement(22, server_hello(0xC02F)))
    assert (vol.outcome, vol.version, vol.suite, vol.compression) == ("hello", hello.TLS12, 0xC02F, 0)


def test_lecture_serverhello_tls13_via_supported_versions(monkeypatch):
    extension = struct.pack(">HH", 43, 2) + struct.pack(">H", 0x0304)
    vol = sonder(monkeypatch, enregistrement(22, server_hello(0x1301, extensions=extension)))
    assert vol.version == hello.TLS13 and vol.suite == 0x1301


def test_alerte_protocol_version(monkeypatch):
    vol = sonder(monkeypatch, enregistrement(21, bytes([2, 70])))
    assert (vol.outcome, vol.alert) == ("alert", 70)


def test_fermeture_sans_reponse(monkeypatch):
    assert sonder(monkeypatch, b"").outcome == "closed"


def test_reponse_qui_n_est_pas_du_tls(monkeypatch):
    assert sonder(monkeypatch, b"HTTP/1.1 400 Bad Request\r\n\r\n").outcome == "garbage"


def test_vol_complet_certificats_agrafe_et_dh(monkeypatch):
    certificats = b"".join(len(c).to_bytes(3, "big") + c for c in (b"AAA", b"BBBB"))
    certificat = message(11, len(certificats).to_bytes(3, "big") + certificats)
    agrafe = message(22, b"\x01" + len(b"REPONSE").to_bytes(3, "big") + b"REPONSE")
    premier = (0xD).to_bytes(2, "big")  # p de 13 bits : 0x1FFF
    echange = message(12, struct.pack(">H", 2) + b"\x1f\xff" + premier)
    octets = enregistrement(22, server_hello(0x009E) + certificat + agrafe + echange + message(14, b""))
    vol = sonder(monkeypatch, octets, read_flight=True)
    assert vol.certificates == [b"AAA", b"BBBB"]
    assert vol.stapled == b"REPONSE"
    assert vol.dh_bits == 13


def test_connexion_refusee(monkeypatch):
    def refuse(*args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr(hello.socket, "create_connection", refuse)
    vol = hello.probe("93.184.216.34", 443, b"x")
    assert vol.outcome == "refused"


def test_delai_de_connexion(monkeypatch):
    def lent(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr(hello.socket, "create_connection", lent)
    assert hello.probe("93.184.216.34", 443, b"x").outcome == "timeout"


# --- Analyse -------------------------------------------------------------------------


def lancer(contexte, outils, **champs):
    return outils.executer(SPEC, contexte(**champs))


def test_serveur_moderne(serveur, contexte, outils):
    serveur(MODERNE)
    resultat = lancer(contexte, outils)
    outils.verifier_sortie(resultat)
    assert resultat["protocols"] == {
        "SSLv3": False,
        "TLSv1.0": False,
        "TLSv1.1": False,
        "TLSv1.2": True,
        "TLSv1.3": True,
    }
    assert resultat["grade"] == "A"
    assert resultat["suite_count"] == 7
    assert resultat["weak_ciphers"] == [] and resultat["broken_ciphers"] == []
    assert constats(resultat) == {}
    note = SPEC.score_rules[0].evaluate({"tls_deep": resultat})
    assert note.points == 10 and note.cap_reason is None and note.measured


def test_enumeration_complete_des_suites(serveur, contexte, outils):
    serveur({hello.TLS12: [0xC02F, 0xC030, 0xCCA8, 0xC013, 0x002F]})
    resultat = lancer(contexte, outils)
    noms = [s["name"] for s in resultat["suites"]]
    assert noms == [hello.suite_name(c) for c in (0xC02F, 0xC030, 0xCCA8, 0xC013, 0x002F)]
    assert resultat["server_preference"] is True


def test_preference_du_client(serveur, contexte, outils):
    serveur({hello.TLS12: [0xC02F, 0xC030]}, client_order=True)
    assert lancer(contexte, outils)["server_preference"] is False


def test_serveur_ancien(serveur, contexte, outils):
    serveur(ANCIEN, compression=True, dh_bits=1024)
    resultat = lancer(contexte, outils)
    outils.verifier_sortie(resultat)
    assert resultat["protocols"]["SSLv3"] is True
    assert resultat["protocols"]["TLSv1.0"] is True
    assert resultat["protocols"]["TLSv1.1"] is False
    assert resultat["compression"] is True and resultat["dh_bits"] == 1024
    assert "TLS_RSA_WITH_RC4_128_SHA" in resultat["weak_ciphers"]
    assert "TLS_RSA_WITH_NULL_MD5" in resultat["broken_ciphers"]
    assert resultat["grade"] == "F"
    trouves = constats(resultat)
    assert set(trouves) == {
        "finding.tls_deep.broken_ciphers",
        "finding.tls_deep.sslv3",
        "finding.tls_deep.weak_ciphers",
        "finding.tls_deep.weak_dh",
        "finding.tls_deep.legacy_protocols",
        "finding.tls_deep.compression",
        "finding.tls_deep.no_pfs",
        "finding.tls_deep.no_tls13",
    }
    assert trouves["finding.tls_deep.legacy_protocols"] == {"protocols": "TLSv1.0"}
    assert isinstance(trouves["finding.tls_deep.weak_dh"], Hit)
    assert trouves["finding.tls_deep.weak_dh"].severity == "high"
    note = SPEC.score_rules[0].evaluate({"tls_deep": resultat})
    assert note.points == 0 and is_msg(note.cap_reason)


def test_retrogradation_n_est_pas_un_support(serveur, contexte, outils):
    """Faux positif évité : un serveur TLS 1.0 qui répond « 1.0 » à un ClientHello 1.2 ne prend pas en charge TLS 1.2."""
    serveur({hello.TLS10: [0x002F, 0xC013]})
    resultat = lancer(contexte, outils)
    assert resultat["protocols"]["TLSv1.0"] is True
    assert resultat["protocols"]["TLSv1.1"] is False
    assert resultat["protocols"]["TLSv1.2"] is False
    trouves = constats(resultat)
    assert "finding.tls_deep.no_modern_protocol" in trouves
    assert SPEC.score_rules[0].evaluate({"tls_deep": resultat}).points == 0


def test_dh_2048_ou_plus_sans_constat(serveur, contexte, outils):
    serveur({hello.TLS12: [0x009E, 0xC02F], hello.TLS13: TLS13}, dh_bits=2048)
    resultat = lancer(contexte, outils)
    assert resultat["dh_bits"] == 2048
    assert "finding.tls_deep.weak_dh" not in constats(resultat)


def test_protocole_indetermine_n_est_pas_signale_absent(serveur, contexte, outils, monkeypatch):
    """Une sonde TLS 1.3 sans réponse (délai) laisse None : pas de constat « TLS 1.3 absent »."""
    simule = serveur(MODERNE)
    original = simule.probe

    def sonde(address, port, paquet, **options):
        if 43 in lire_hello(paquet)["extensions"]:
            return hello.ServerFlight("timeout")
        return original(address, port, paquet, **options)

    monkeypatch.setattr(hello, "probe", sonde)
    resultat = lancer(contexte, outils)
    assert resultat["protocols"]["TLSv1.3"] is None
    assert "finding.tls_deep.no_tls13" not in constats(resultat)


def test_port_ferme_sans_objet(serveur, contexte, outils):
    serveur(MODERNE, hors_ligne="refused")
    with pytest.raises(ModuleSkipped) as erreur:
        lancer(contexte, outils)
    assert is_msg(erreur.value.message)


def test_delai_depasse(serveur, contexte, outils):
    serveur(MODERNE, hors_ligne="timeout")
    with pytest.raises(ModuleError):
        lancer(contexte, outils)


def test_service_qui_n_est_pas_tls(serveur, contexte, outils):
    serveur(MODERNE, hors_ligne="garbage")
    with pytest.raises(ModuleSkipped):
        lancer(contexte, outils)


def test_sans_adresse_le_module_est_sans_objet(contexte):
    assert is_msg(SPEC.skip_reason(contexte(addresses=[])))


def test_cible_ip_sans_sni(serveur, contexte, outils, monkeypatch):
    vus = []
    simule = serveur(MODERNE)
    original = simule.probe

    def sonde(address, port, paquet, **options):
        vus.append(0 in lire_hello(paquet)["extensions"])
        return original(address, port, paquet, **options)

    monkeypatch.setattr(hello, "probe", sonde)
    lancer(contexte, outils, domain="93.184.216.34")
    assert vus and not any(vus)


def test_categorie_active_et_hors_profil_complet():
    assert SPEC.category == "actif" and SPEC.requires_authorization and not SPEC.quick


def test_sortie_json_et_aucune_cle(serveur, contexte, outils):
    serveur(ANCIEN)
    resultat = lancer(contexte, outils)
    json.dumps(resultat)
    outils.verifier_sortie(resultat, secrets=())


def test_donnees_inattendues_ne_levent_pas():
    for valeur in (None, [], "texte", {"protocols": "x", "suites": 3, "dh_bits": "abc"}, {"measured": False}):
        assert constats(valeur) == {}
        if isinstance(valeur, dict):
            SPEC.score_rules[0].evaluate({"tls_deep": valeur})


def test_note_degradee_sans_plafond_pour_tls10_seul_avec_tls12(serveur, contexte, outils):
    serveur({hello.TLS10: [0xC013], hello.TLS12: [0xC02F], hello.TLS13: TLS13})
    resultat = lancer(contexte, outils)
    note = SPEC.score_rules[0].evaluate({"tls_deep": resultat})
    assert note.points == 8 and note.cap_reason is None
    assert resultat["grade"] == "C"


def test_budget_et_tours_bornes(monkeypatch):
    """Un serveur qui accepte « tout » ne fait pas boucler l'énumération au-delà de MAX_ROUNDS."""
    appels = []

    def toujours(address, port, paquet, **options):
        lu = lire_hello(paquet)
        appels.append(1)
        return hello.ServerFlight("hello", version=lu["version"], suite=lu["suites"][0])

    monkeypatch.setattr(hello, "probe", toujours)
    monkeypatch.setattr(analysis, "MAX_ROUNDS", 5)
    rapport = analysis.scan_sync("93.184.216.34", 443, "example.com", budget=30)
    assert rapport["measured"] is True
    assert len(appels) < 80
