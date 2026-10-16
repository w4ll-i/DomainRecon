# =============================================================================
# DomainRecon - Tests du module « dnssec_data » (sans réseau, réponses DNS fabriquées)
# =============================================================================

import base64

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.impl import dnssec as engine
from domainrecon.scanner.modules import dnssec_data
from domainrecon.scanner.rules import FindingInput

SPEC = dnssec_data.SPEC
ZONE = "example.com"


def _b64(octets: bytes) -> str:
    return base64.b64encode(octets).decode()


def _dnskey(flags=257, algorithm=13, key=None):
    key = key if key is not None else bytes(range(64))
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, f"{flags} 3 {algorithm} {_b64(key)}")


def _ds_de(key, digest="SHA256"):
    return dns.dnssec.make_ds(dns.name.from_text(ZONE), key, digest)


def _rrsig(couvert="A", algorithm=13, expiration="20991231235959"):
    return (
        f"{ZONE}. 300 IN RRSIG {couvert} {algorithm} 2 300 {expiration} 20260101000000 2371 {ZONE}. "
        + _b64(bytes(64))
    )


def _reponse(nom, type_, answer=(), authority=(), rcode="NOERROR", ad=False):
    flags = "QR RD RA" + (" AD" if ad else "")
    lignes = ["id 1", "opcode QUERY", f"rcode {rcode}", f"flags {flags}", ";QUESTION", f"{nom}. IN {type_}"]
    if answer:
        lignes += [";ANSWER", *answer]
    if authority:
        lignes += [";AUTHORITY", *authority]
    texte = chr(10).join(lignes) + chr(10)
    return dns.message.from_text(texte)


class Zone:
    """Serveur simulé : réponses d'une zone signée, modifiables par options."""

    def __init__(
        self,
        *,
        signee=True,
        ds=True,
        ds_faux=False,
        algorithm=13,
        key=None,
        ad=True,
        nsec3=None,
        bogus=False,
        rrsig=True,
        expiration="20991231235959",
        resolveurs_muets=(),
    ):
        self.signee, self.ds, self.ds_faux, self.ad, self.nsec3 = signee, ds, ds_faux, ad, nsec3
        self.bogus, self.rrsig, self.expiration = bogus, rrsig, expiration
        self.ksk = _dnskey(257, algorithm, key)
        self.zsk = _dnskey(256, algorithm, bytes(reversed(range(64))) if key is None else key + b"\x01")
        self.muets = resolveurs_muets
        self.serveurs: list[str] = []

    def __call__(self, query, server, timeout):
        self.serveurs.append(server)
        if server in self.muets:
            raise dns.exception.Timeout
        nom = str(query.question[0].name).rstrip(".")
        type_ = dns.rdatatype.to_text(query.question[0].rdtype)
        cd = bool(query.flags & dns.flags.CD)
        if type_ == "DNSKEY" and self.signee:
            if self.bogus and not cd:
                return _reponse(nom, type_, rcode="SERVFAIL")
            lignes = [f"{ZONE}. 3600 IN DNSKEY {k.to_text()}" for k in (self.ksk, self.zsk)]
            return _reponse(nom, type_, lignes, ad=self.ad and not cd)
        if type_ == "DS" and self.ds:
            ds = _ds_de(self.ksk)
            if self.ds_faux:
                ds = dns.rdata.from_text(
                    dns.rdataclass.IN, dns.rdatatype.DS, f"{ds.key_tag} 13 2 {'00' * 32}"
                )
            return _reponse(nom, type_, [f"{ZONE}. 3600 IN DS {ds.to_text()}"], ad=self.ad)
        if type_ == "A" and nom == ZONE:
            lignes = [f"{ZONE}. 300 IN A 93.184.216.34"]
            if self.signee and self.rrsig:
                lignes.append(_rrsig("A", expiration=self.expiration))
            return _reponse(nom, type_, lignes, ad=self.ad and self.signee)
        if type_ == "A" and nom.startswith("dr-") and self.signee:
            if self.nsec3 is not None:
                return _reponse(
                    nom,
                    type_,
                    authority=[
                        f"abcdef.{ZONE}. 300 IN NSEC3 1 0 {self.nsec3} AB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A"
                    ],
                    rcode="NXDOMAIN",
                )
            return _reponse(
                nom, type_, authority=[f"a.{ZONE}. 300 IN NSEC b.{ZONE}. A RRSIG NSEC"], rcode="NXDOMAIN"
            )
        return _reponse(nom, type_)


@pytest.fixture
def serveur(monkeypatch):
    def installer(**options):
        zone = Zone(**options)
        monkeypatch.setattr(engine, "_send", zone)
        return zone

    return installer


def _finding(data):
    return FindingInput({}, "dnssec_data", lambda scan, name: data, lambda scan, name: True)


def _constats(sortie):
    return {rule.code.rsplit(".", 1)[1]: rule.check(_finding(sortie)) for rule in SPEC.findings}


def _codes(sortie):
    return [issue["$t"] for issue in sortie["issues"]]


def test_zone_signee_et_validee_note_a(contexte, outils, serveur):
    serveur()
    sortie = outils.executer(SPEC, contexte())
    outils.verifier_sortie(sortie)
    assert sortie["status"] == "signed" and sortie["grade"] == "A" and sortie["issues"] == []
    assert (
        sortie["dnskey_found"]
        and sortie["ds_found"]
        and sortie["rrsig_found"]
        and sortie["validated"] is True
    )
    assert sortie["ds_match"] is True and sortie["nsec_type"] == "NSEC" and sortie["bogus"] is False
    assert [k["role"] for k in sortie["keys"]] == ["KSK", "ZSK"]
    assert sortie["algorithms"] == [{"id": 13, "name": "ECDSAP256SHA256", "weak": False}]
    assert sortie["days_left"] > 0 and sortie["resolver"] == "1.1.1.1"
    assert all(v is None or v is False for v in _constats(sortie).values())
    resultat = SPEC.score_rules[0].evaluate({"dnssec_data": sortie})
    assert resultat.points == 5 and resultat.cap_reason is None


def test_zone_non_signee(contexte, outils, serveur):
    serveur(signee=False, ds=False)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["status"] == "unsigned" and sortie["grade"] == "F" and sortie["signed"] is False
    assert _codes(sortie) == ["dnssec_data.issue_unsigned"]
    assert _constats(sortie)["unsigned"] is True and _constats(sortie)["broken"] is False
    assert SPEC.score_rules[0].evaluate({"dnssec_data": sortie}).points == 0


def test_dnskey_sans_ds_chaine_incomplete(contexte, outils, serveur):
    serveur(ds=False)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["status"] == "incomplete" and sortie["grade"] == "D"
    assert "dnssec_data.issue_no_ds" in _codes(sortie)
    assert _constats(sortie)["no_ds"] is True and _constats(sortie)["unsigned"] is False


def test_ds_qui_ne_correspond_pas_chaine_cassee(contexte, outils, serveur):
    serveur(ds_faux=True)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["ds_match"] is False and sortie["status"] == "broken" and sortie["grade"] == "F"
    assert "dnssec_data.issue_ds_mismatch" in _codes(sortie)
    assert _constats(sortie)["broken"] is True
    assert SPEC.score_rules[0].evaluate({"dnssec_data": sortie}).cap_reason is not None


def test_validation_en_echec_detectee_avec_cd(contexte, outils, serveur):
    """SERVFAIL avec validation mais données présentes avec CD=1 : la chaîne est cassée (domaine inaccessible)."""
    serveur(bogus=True)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["bogus"] is True and sortie["status"] == "broken" and sortie["validated"] is False
    assert "dnssec_data.issue_bogus" in _codes(sortie) and _constats(sortie)["broken"] is True


def test_non_valide_par_le_resolveur(contexte, outils, serveur):
    serveur(ad=False)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["validated"] is False and sortie["grade"] == "C"
    assert "dnssec_data.issue_unvalidated" in _codes(sortie)


def test_algorithme_et_cle_faibles(contexte, outils, serveur):
    # RSA/SHA-1 (algorithme 5, déconseillé) avec un module de 512 bits : exposant 3 octets + module 64 octets.
    cle = bytes([3, 1, 0, 1]) + bytes(range(1, 65))
    serveur(algorithm=5, key=cle)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["grade"] == "B"
    assert {"dnssec_data.issue_weak_algorithm", "dnssec_data.issue_short_key"} <= set(_codes(sortie))
    assert _constats(sortie)["weak_algorithm"] == {"algorithms": ["RSASHA1"]}
    assert sortie["keys"][0]["bits"] == 512


def test_nsec3_avec_iterations(contexte, outils, serveur):
    serveur(nsec3=10)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["nsec_type"] == "NSEC3" and sortie["nsec3_iterations"] == 10 and sortie["grade"] == "B"
    assert "dnssec_data.issue_nsec3_iterations" in _codes(sortie)
    serveur(nsec3=0)
    assert outils.executer(SPEC, contexte())["grade"] == "A"


def test_signature_echue(contexte, outils, serveur):
    serveur(expiration="20200101000000")
    sortie = outils.executer(SPEC, contexte())
    assert sortie["days_left"] < 0 and sortie["status"] == "broken"
    assert "dnssec_data.issue_sig_expired" in _codes(sortie)


def test_signature_proche_de_l_echeance_normale(contexte, outils, serveur):
    """Faux positif évité : les signeurs automatiques renouvellent avant l'échéance (Cloudflare : 1 à 2 jours restants)."""
    import time

    demain = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() + 36 * 3600))
    serveur(expiration=demain)
    sortie = outils.executer(SPEC, contexte())
    assert sortie["status"] == "signed" and sortie["grade"] == "A" and sortie["days_left"] in (0, 1)


def test_repli_sur_le_resolveur_suivant(contexte, outils, serveur):
    zone = serveur(resolveurs_muets=("1.1.1.1",))
    sortie = outils.executer(SPEC, contexte())
    assert sortie["resolver"] == "8.8.8.8" and sortie["grade"] == "A" and "9.9.9.9" not in zone.serveurs


def test_aucun_resolveur_ne_repond(contexte, outils, serveur):
    serveur(resolveurs_muets=engine.RESOLVERS)
    with pytest.raises(ModuleError) as erreur:
        outils.executer(SPEC, contexte())
    assert erreur.value.message["$t"] == "dnssec_data.unavailable"


def test_donnees_inattendues_ne_levent_pas():
    for data in (None, [], "x", {"algorithms": "oops"}, {"algorithms": [None, 3]}, {"status": 5}):
        for regle in SPEC.findings:
            regle.check(_finding(data))
    assert SPEC.score_rules[0].evaluate({"dnssec_data": None}).points == 0


def test_taille_des_cles_rsa():
    assert engine._rsa_bits(bytes([3, 1, 0, 1]) + bytes(256)) == 2048
    assert engine._rsa_bits(b"") is None and engine._rsa_bits(bytes([0, 1])) is None


def test_adresse_ip_sans_objet(contexte):
    assert SPEC.skip_reason(contexte(domain="93.184.216.34")) is not None
