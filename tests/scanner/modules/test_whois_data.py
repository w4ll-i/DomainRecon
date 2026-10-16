# =============================================================================
# DomainRecon - Tests du module « whois_data » (RDAP puis WHOIS, sans réseau)
# =============================================================================

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from domainrecon.scanner import whois_lookup
from domainrecon.scanner.impl import whois_rdap
from domainrecon.scanner.modules import whois_data
from domainrecon.scanner.rules import FindingInput

SPEC = whois_data.SPEC
BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
REGISTRE = "https://rdap.verisign.com/com/v1/domain/example.com"
BUREAU = "https://rdap.registrar.example/domain/EXAMPLE.COM"

TABLE = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]],
        [["fr"], ["http://rdap.nic.fr/"]],
    ]
}


def _vcard(**champs):
    return ["vcard", [["version", {}, "text", "4.0"], *[[k, {}, "text", v] for k, v in champs.items()]]]


def _domaine(expiration="2030-08-13T04:00:00Z", **extra):
    """Réponse conforme à l'objet « domain » de la RFC 9083 (registre léger, comme Verisign)."""
    data = {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": expiration},
            {"eventAction": "last changed", "eventDate": "2026-08-14T08:01:43.123Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-10-15T12:00:00Z"},
        ],
        "nameservers": [{"ldhName": "ELLIOTT.NS.CLOUDFLARE.COM"}, {"ldhName": "hera.ns.cloudflare.com"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {
                "objectClassName": "entity",
                "roles": ["registrar"],
                "vcardArray": _vcard(fn="Registrar Example Inc."),
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": _vcard(email="abuse@registrar.example", fn="Abuse"),
                    }
                ],
            }
        ],
        "links": [{"rel": "related", "type": "application/rdap+json", "href": BUREAU}],
    }
    data.update(extra)
    return data


def _bureau():
    return {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "entities": [{"roles": ["registrant"], "vcardArray": _vcard(fn="Jean Dupont", org="Example SA")}],
    }


def _whois(**champs):
    base = {
        "queried_domain": "example.com",
        "registrar": "Registrar WHOIS Inc.",
        "whois_server": "whois.registrar.example",
        "creation_date": "2000-01-01 00:00:00+00:00",
        "expiration_date": "2031-01-01 00:00:00+00:00",
        "updated_date": None,
        "name_servers": ["ns1.example.net"],
        "status": ["clientTransferProhibited"],
        "dnssec": "unsigned",
        "registrant": None,
        "emails": [],
        "registered": True,
        "measured": True,
        "error": None,
    }
    base.update(champs)
    return base


class _Appels(list):
    """Domaines interrogés ; `reponse` : ce que le faux WHOIS rend (dict, exception ou objet)."""

    reponse: dict


@pytest.fixture
def whois_simule(monkeypatch):
    """Remplace le WHOIS (python-whois) ; rend la liste des domaines interrogés."""
    appels = _Appels()
    reponse = {"valeur": _whois()}

    async def faux(domain):
        appels.append(domain)
        valeur = reponse["valeur"]
        if isinstance(valeur, BaseException):
            raise valeur
        return dict(valeur) if isinstance(valeur, dict) else valeur

    monkeypatch.setattr(whois_lookup, "get_whois_data", faux)
    appels.reponse = reponse
    return appels


def _lancer(contexte, outils, http_simule, routes, **champs):
    requetes = http_simule(routes)
    return outils.executer(SPEC, contexte(**champs)), requetes


# --- RDAP en priorité ----------------------------------------------------------


def test_rdap_complet_sans_whois(contexte, outils, http_simule, whois_simule):
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: _domaine(), BUREAU: _bureau()}
    )
    outils.verifier_sortie(sortie)
    assert whois_simule == []  # le WHOIS n'est pas interrogé
    assert sortie["source"] == "rdap" and sortie["measured"] is True and sortie["registered"] is True
    assert sortie["registrar"] == "Registrar Example Inc."
    assert sortie["registrant"] == "Example SA"  # lu chez le bureau d'enregistrement (registre léger)
    assert sortie["emails"] == ["abuse@registrar.example"]
    assert sortie["name_servers"] == ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
    # Codes EPP comme le WHOIS, dates sans fraction de seconde, DNSSEC au vocabulaire WHOIS.
    assert sortie["status"] == [
        "clientDeleteProhibited",
        "clientTransferProhibited",
        "clientUpdateProhibited",
    ]
    assert sortie["creation_date"] == "1995-08-14 04:00:00+00:00"
    assert sortie["expiration_date"] == "2030-08-13 04:00:00+00:00"
    assert sortie["updated_date"] == "2026-08-14 08:01:43+00:00"
    assert sortie["dnssec"] == "signedDelegation"
    assert sortie["queried_domain"] == "example.com" and sortie["days_to_expiry"] > 0
    assert [str(r.url) for r in requetes][:2] == [BOOTSTRAP, REGISTRE]
    assert requetes[1].headers["accept"].startswith("application/rdap+json")


def test_rdap_champ_serveur_whois(contexte, outils, http_simule, whois_simule):
    routes = {BOOTSTRAP: TABLE, REGISTRE: _domaine(port43="WHOIS.Registrar.example"), BUREAU: _bureau()}
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["whois_server"] == "whois.registrar.example"


def test_rdap_incomplet_complete_par_whois(contexte, outils, http_simule, whois_simule):
    data = _domaine(nameservers=[])
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: data, BUREAU: _bureau()})
    assert whois_simule == ["example.com"]
    assert sortie["source"] == "rdap+whois"
    assert sortie["name_servers"] == ["ns1.example.net"]  # champ vide complété
    assert sortie["registrar"] == "Registrar Example Inc."  # le RDAP fait foi quand il répond


def test_rdap_incomplet_et_whois_en_echec_garde_le_rdap(contexte, outils, http_simule, whois_simule):
    whois_simule.reponse["valeur"] = _whois(measured=False, registered=None, error="WHOIS indisponible")
    sortie, _ = _lancer(
        contexte,
        outils,
        http_simule,
        {BOOTSTRAP: TABLE, REGISTRE: _domaine(nameservers=[]), BUREAU: _bureau()},
    )
    assert sortie["source"] == "rdap" and sortie["measured"] is True and sortie["name_servers"] == []


def test_redirection_https_suivie_et_redirection_http_refusee(contexte, outils, http_simule, whois_simule):
    suivie = "https://rdap.autre.example/domain/example.com"
    routes = {
        BOOTSTRAP: TABLE,
        REGISTRE: lambda r: httpx.Response(302, headers={"location": suivie}),
        suivie: _domaine(),
        BUREAU: _bureau(),
    }
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["source"] == "rdap" and whois_simule == []
    routes[REGISTRE] = lambda r: httpx.Response(302, headers={"location": "http://rdap.autre.example/x"})
    sortie, _ = _lancer(contexte, outils, http_simule, routes)
    assert sortie["source"] == "whois"  # redirection vers http refusée : repli WHOIS


# --- Repli WHOIS ---------------------------------------------------------------


def test_extension_absente_de_la_table_utilise_le_whois(contexte, outils, http_simule, whois_simule):
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {BOOTSTRAP: TABLE}, domain="zonetransfer.me", apex="zonetransfer.me"
    )
    outils.verifier_sortie(sortie)
    assert whois_simule == ["zonetransfer.me"]
    assert sortie["source"] == "whois" and sortie["whois_server"] == "whois.registrar.example"
    assert [str(r.url) for r in requetes] == [BOOTSTRAP]


def test_serveur_rdap_http_seul_est_ignore(contexte, outils, http_simule, whois_simule):
    """La table ne donne que http:// pour .fr : jamais de RDAP en clair, repli WHOIS."""
    sortie, requetes = _lancer(
        contexte, outils, http_simule, {BOOTSTRAP: TABLE}, domain="exemple.fr", apex="exemple.fr"
    )
    assert sortie["source"] == "whois" and len(requetes) == 1


@pytest.mark.parametrize(
    "reponse",
    [
        httpx.ReadTimeout("délai"),
        httpx.ConnectError("refusé"),
        (500, {}, "erreur"),
        (200, {}, "pas du json"),
        ["liste", "inattendue"],
    ],
)
def test_rdap_en_panne_repli_whois(contexte, outils, http_simule, whois_simule, reponse):
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: reponse})
    assert sortie["source"] == "whois" and sortie["measured"] is True
    assert whois_simule == ["example.com"]


def test_table_d_amorcage_illisible_repli_whois(contexte, outils, http_simule, whois_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: (200, {}, "<html>")})
    assert sortie["source"] == "whois"


def test_quota_rdap_repli_whois(contexte, outils, http_simule, whois_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: (429, {}, "")})
    assert sortie["source"] == "whois"


def test_rdap_et_whois_en_echec_sortie_non_mesuree(contexte, outils, http_simule, whois_simule):
    whois_simule.reponse["valeur"] = _whois(
        measured=False, registered=None, error="WHOIS : délai dépassé (10 s)"
    )
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: httpx.ConnectError("x")})
    outils.verifier_sortie(sortie)
    assert sortie["measured"] is False and sortie["error"]


def test_sans_client_http_whois_seul(contexte, outils, http_simule, whois_simule):
    http_simule({})
    context = contexte()
    context.http = None
    sortie = outils.executer(SPEC, context)
    assert sortie["source"] == "whois" and whois_simule == ["example.com"]


# --- Faux positif évité : un 404 n'est cru qu'après le WHOIS ------------------


def test_404_rdap_contredit_par_le_whois(contexte, outils, http_simule, whois_simule):
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: (404, {}, "")})
    assert sortie["registered"] is True and sortie["source"] == "whois"


def test_404_rdap_confirme_par_le_whois(contexte, outils, http_simule, whois_simule):
    whois_simule.reponse["valeur"] = _whois(
        registered=False, registrar=None, expiration_date=None, name_servers=[], status=[]
    )
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: (404, {}, "")})
    assert sortie["registered"] is False and sortie["measured"] is True


def test_404_rdap_sans_reponse_whois_fait_foi(contexte, outils, http_simule, whois_simule):
    whois_simule.reponse["valeur"] = _whois(
        measured=False, registered=None, registrar=None, error="WHOIS indisponible"
    )
    sortie, _ = _lancer(contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: (404, {}, "")})
    assert sortie["registered"] is False and sortie["measured"] is True and sortie["error"] is None


# --- Sans objet et contrat -----------------------------------------------------


def test_sans_objet_pour_une_adresse_ip(contexte):
    context = contexte(domain="93.184.216.34")
    assert SPEC.skip_reason(context) is not None
    assert SPEC.skip_reason(contexte()) is None


def test_adaptateur_renvoie_l_objet_du_whois_s_il_n_est_pas_un_dict(
    contexte, outils, http_simule, whois_simule
):
    sentinelle = object()
    whois_simule.reponse["valeur"] = sentinelle
    http_simule({})
    context = contexte()
    context.http = None
    assert outils.executer(SPEC, context) is sentinelle


def test_aucune_cle_ni_url_dans_la_sortie(contexte, outils, http_simule, whois_simule):
    sortie, _ = _lancer(
        contexte, outils, http_simule, {BOOTSTRAP: TABLE, REGISTRE: _domaine(), BUREAU: _bureau()}
    )
    outils.verifier_sortie(sortie, ["secret"])
    assert "http" not in " ".join(str(s) for s in sortie["status"])


# --- Outils RDAP ---------------------------------------------------------------


@pytest.mark.parametrize(
    "texte, code",
    [
        ("client delete prohibited", "clientDeleteProhibited"),
        ("server transfer prohibited", "serverTransferProhibited"),
        ("active", "active"),
        ("ok", "ok"),
        ("pending delete", "pendingDelete"),
        ("clientHold", "clientHold"),
    ],
)
def test_codes_epp(texte, code):
    assert whois_rdap.epp_code(texte) == code


def test_dates_et_jours():
    now = datetime(2026, 10, 15, tzinfo=timezone.utc)
    assert whois_rdap.days_until("2026-10-25 00:00:00+00:00", now) == 10
    assert whois_rdap.days_until("2026-10-05T00:00:00Z", now) == -10
    assert whois_rdap.days_until("2026-10-25", now) == 10  # sans fuseau : UTC
    assert whois_rdap.days_until("pas une date", now) is None
    assert whois_rdap.days_until(None, now) is None


def test_base_url_suffixe_le_plus_long():
    table = {"tlds": {"uk": ["https://a/"], "co.uk": ["https://b"]}}
    assert whois_rdap.base_url(table, "exemple.co.uk") == "https://b/"
    assert whois_rdap.base_url(table, "exemple.uk") == "https://a/"
    assert whois_rdap.base_url(table, "exemple.zz") is None


# --- Constats et score ---------------------------------------------------------


def _dans(jours: int) -> str:
    return str((datetime.now(timezone.utc) + timedelta(days=jours)).replace(microsecond=0))


def _constats(data: dict) -> dict:
    """Code du constat -> paramètres, pour les règles du module."""
    entree = FindingInput({"whois_data": data}, "whois_data", lambda s, m: s[m], lambda s, m: True)
    trouves = {}
    for regle in SPEC.findings:
        resultat = regle.check(entree)
        if resultat:
            trouves[regle.code] = resultat
    return trouves


LOCKS = ["clientDeleteProhibited", "clientTransferProhibited"]


def test_constat_domaine_expire():
    assert "finding.whois_data.expired" in _constats({"expiration_date": _dans(-3), "status": LOCKS})


@pytest.mark.parametrize("jours, gravite", [(5, "high"), (20, "medium"), (50, "low")])
def test_constat_expiration_proche(jours, gravite):
    trouves = _constats({"expiration_date": _dans(jours), "status": LOCKS})
    assert trouves["finding.whois_data.expires_soon"].severity == gravite
    assert trouves["finding.whois_data.expires_soon"].params["days"] in (jours, jours - 1)


def test_pas_de_constat_si_tout_va_bien():
    assert _constats({"expiration_date": _dans(400), "status": LOCKS}) == {}


def test_absence_de_verrou_de_transfert():
    assert "finding.whois_data.no_transfer_lock" in _constats(
        {"status": ["ok"], "expiration_date": _dans(400)}
    )
    # Faux positif évité : statuts sans EPP (ccTLD), ou aucun statut publié.
    assert _constats({"status": ["ACTIVE"], "expiration_date": _dans(400)}) == {}
    assert _constats({"status": [], "expiration_date": _dans(400)}) == {}


def test_domaine_non_enregistre_aucun_constat():
    assert _constats({"registered": False, "expiration_date": _dans(-3), "status": ["ok"]}) == {}


@pytest.mark.parametrize("donnee", [None, "texte", [], {"expiration_date": 12, "status": "ok"}])
def test_regles_defensives(donnee):
    assert _constats(donnee if isinstance(donnee, dict) else {}) is not None
    entree = FindingInput({"whois_data": donnee}, "whois_data", lambda s, m: s[m], lambda s, m: True)
    for regle in SPEC.findings:
        regle.check(entree)  # ne lève jamais


def test_critere_de_score():
    regle = whois_data.WHOIS_SCORE_RULE
    assert regle.criterion == "whois" and regle.weight == 5

    def points(**champs):
        return regle.evaluate({"whois_data": champs})

    assert points(expiration_date=_dans(400), status=LOCKS).points == 5
    assert points(expiration_date=_dans(400), status=["ok"]).points == 4
    assert points(expiration_date=_dans(20), status=LOCKS).points == 3
    assert points(expiration_date=_dans(5), status=LOCKS).points == 1
    assert points(expiration_date=_dans(-5), status=LOCKS).points == 0
    sans_date = points(status=LOCKS)
    assert sans_date.applicable is False
    assert points(registered=False).applicable is False
    assert regle.evaluate({}).applicable is False  # donnée absente : jamais d'exception
