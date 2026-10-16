# =============================================================================
# DomainRecon - Tests des familles (scanner/families.py)
# =============================================================================

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import families as families_module
from domainrecon.scanner.families import (
    FAMILY_KEYS,
    NOT_LAUNCHED,
    compute_families,
    module_run_status,
)
from domainrecon.scanner.findings import compute_findings
from domainrecon.scanner.orchestrator import MODULE_NAMES
from domainrecon.scanner.registry import PROFILE_QUICK, get_modules
from domainrecon.scanner.score import EMAIL_POINTS, compute_security_score
from rendu import en, fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")


def _breakdown(**overrides) -> dict:
    criteres = {
        "headers": {"score": 25, "max": 25, "measured": True, "counted": True},
        "tls": {"score": 20, "max": 20, "measured": True, "counted": True},
        "email": {"score": 15, "max": 15, "measured": True, "counted": True},
        "waf": {"score": 0, "max": 10, "measured": True, "counted": False},
        "cookies": {"score": 10, "max": 10, "measured": True, "counted": True},
        "cors": {"score": 10, "max": 10, "measured": True, "counted": True},
        "https_redirect": {"score": 5, "max": 5, "measured": True, "counted": True},
        "takeover": {"score": 5, "max": 5, "measured": True, "counted": True},
    }
    for cle, valeurs in overrides.items():
        criteres[cle] = {**criteres[cle], **valeurs}
    return criteres


def scan_note(**breakdown) -> dict:
    """Scan noté A partout, sans constat ; `breakdown` modifie des critères du barème."""
    return {
        "module_status": {name: {"status": "ok", "error": None} for name in MODULE_NAMES},
        "security_score": {"breakdown": _breakdown(**breakdown)},
        "tls_certificate": {
            "measured": True,
            "https": True,
            "valid": True,
            "days_remaining": 200,
            "protocol": "TLSv1.3",
        },
        "open_ports": [{"port": 443, "state": "open"}],
        "subdomain_takeover": [],
    }


def test_constantes():
    assert FAMILY_KEYS == ("web", "tls", "email", "dns", "network", "identity", "reputation", "leaks")
    assert sorted(families_module.MODULE_FAMILY) == sorted(MODULE_NAMES)
    assert families_module.MODULE_FAMILY["screenshot"] == "identity"
    assert families_module.MODULE_FAMILY["open_ports"] == "network"
    # Ordre du registre (ModuleSpec.order).
    assert families_module.FAMILY_MODULES["dns"] == (
        "dns_records",
        "subdomains",
        "reverse_dns",
        "subdomain_takeover",
    )
    # Réputation et fuites : aucun des 18 modules historiques n'y appartient.
    for famille in ("reputation", "leaks"):
        assert families_module.FAMILY_MODULES[famille] == ()
        assert (
            families_module.FAMILY_CRITERIA[famille] == ()
            and families_module.FAMILY_VERDICT_MODULES[famille] == ()
        )
    assert list(families_module.FAMILY_MODULES) == list(families_module.FAMILY_CRITERIA) == list(FAMILY_KEYS)


def test_modules_de_verdict_par_famille():
    assert list(families_module.FAMILY_VERDICT_MODULES) == list(FAMILY_KEYS)
    for famille, modules in families_module.FAMILY_VERDICT_MODULES.items():
        assert set(modules) <= set(families_module.FAMILY_MODULES[famille]), famille
    # Les modules descriptifs ne fondent aucun verdict.
    verdict = {module for modules in families_module.FAMILY_VERDICT_MODULES.values() for module in modules}
    assert not {"geo_data", "network_extended", "reverse_dns", "dns_records", "screenshot"} & verdict


def test_scan_sain():
    familles = compute_families(scan_note())
    assert list(familles) == list(FAMILY_KEYS)
    assert {cle: f["state"] for cle, f in familles.items()} == {
        "web": "ok",
        "tls": "ok",
        "email": "ok",
        "dns": "ok",
        "network": "ok",
        "identity": "info",
        "reputation": "unmeasured",
        "leaks": "unmeasured",
    }
    assert {cle: f["grade"] for cle, f in familles.items()} == {
        "web": "A",
        "tls": "A",
        "email": "A",
        "dns": "A",
        "network": None,
        "identity": None,
        "reputation": None,
        "leaks": None,
    }
    assert fr(familles["web"]["summary"]) == "Aucun point à corriger"
    assert en(familles["identity"]["summary"]) == "Descriptive information, not graded"


def test_note_de_famille_sur_les_criteres_comptes():
    sans_cookies = {"score": 0, "counted": False, "measured": False}
    # Web : (25 + 10 + 0) / (25 + 10 + 5) = 87,5 % → 88 → B (cookies sans objet, pas de WAF).
    familles = compute_families(scan_note(cookies=sans_cookies, https_redirect={"score": 0}))
    assert familles["web"]["grade"] == "B"
    # Bonus WAF obtenu : (35 + 10) / (40 + 10) = 90 % → A.
    familles = compute_families(
        scan_note(cookies=sans_cookies, https_redirect={"score": 0}, waf={"score": 10, "counted": True})
    )
    assert familles["web"]["grade"] == "A"


def test_etat_le_plus_grave_entre_note_et_constats():
    scan = scan_note()
    scan["tls_certificate"]["days_remaining"] = 5  # constat « high »
    tls = compute_families(scan)["tls"]
    assert (tls["grade"], tls["state"]) == ("A", "warning")
    assert en(tls["summary"]) == "1 issue(s) to fix"

    scan = scan_note(tls={"score": 0})
    scan["tls_certificate"]["valid"] = False
    tls = compute_families(scan)["tls"]
    assert (tls["grade"], tls["state"]) == ("F", "critical")


def test_reseau_selon_les_ports_exposes():
    scan = scan_note()
    scan["open_ports"].append({"port": 6379, "state": "open"})
    assert compute_families(scan)["network"]["state"] == "critical"
    scan = scan_note()
    scan["open_ports"].append({"port": 3306, "state": "open"})
    assert compute_families(scan)["network"]["state"] == "warning"


def test_famille_sans_objet_et_non_mesuree():
    scan = scan_note(email={"score": 0, "counted": False, "measured": False})
    scan["module_status"]["email_security"] = {
        "status": "skipped",
        "error": msg("orchestrator.skip_ip_target"),
    }
    scan["module_status"]["tls_certificate"] = {"status": "failed", "error": "x"}
    familles = compute_families(scan)
    assert (familles["email"]["state"], familles["email"]["grade"]) == ("skipped", None)
    assert en(familles["email"]["summary"]) == "Not applicable to this target"
    assert (familles["tls"]["state"], familles["tls"]["grade"]) == ("unmeasured", None)
    assert en(familles["tls"]["summary"]) == "Not measured (1 module(s) failed or timed out)"


def test_mesure_partielle():
    # Réseau : ports hors délai, géolocalisation mesurée : aucun verdict possible.
    scan = scan_note()
    scan["module_status"]["open_ports"] = {"status": "timeout", "error": None}
    assert compute_families(scan)["network"]["state"] == "unmeasured"
    # Web : un module en échec, les autres notés : verdict, résumé partiel.
    scan = scan_note()
    scan["module_status"]["cors"] = {"status": "failed", "error": None}
    web = compute_families(scan)["web"]
    assert web["state"] == "ok"
    assert fr(web["summary"]) == "Aucun point à corriger parmi les mesures ; 1 module(s) non mesuré(s)"
    # Identité : une capture en échec reste informative.
    scan = scan_note()
    scan["module_status"]["screenshot"] = {"status": "failed", "error": None}
    assert compute_families(scan)["identity"]["state"] == "info"


def test_module_informatif_en_echec_ne_rend_pas_la_famille_non_mesuree():
    # Réseau : géolocalisation indisponible, ports mesurés sans port sensible.
    scan = scan_note()
    scan["module_status"]["geo_data"] = {"status": "failed", "error": "429"}
    scan["module_status"]["network_extended"] = {"status": "timeout", "error": None}
    reseau = compute_families(scan)["network"]
    assert reseau["state"] == "ok"
    assert en(reseau["summary"]) == "No issues among the measurements; 2 module(s) not measured"
    # Un port sensible reste un constat, malgré les modules en échec.
    scan["open_ports"].append({"port": 6379, "state": "open"})
    reseau = compute_families(scan)["network"]
    assert reseau["state"] == "critical"
    assert en(reseau["summary"]) == "1 issue(s) to fix; 2 module(s) not measured"

    # DNS : DNS inverse hors délai, aucun sous-domaine à tester (takeover sans objet).
    scan = scan_note(takeover={"score": 0, "counted": False, "measured": False})
    scan["module_status"]["reverse_dns"] = {"status": "timeout", "error": None}
    scan["module_status"]["subdomain_takeover"] = {"status": "skipped", "error": None}
    dns = compute_families(scan)["dns"]
    assert (dns["state"], dns["grade"]) == ("ok", None)
    assert fr(dns["summary"]) == "Aucun point à corriger parmi les mesures ; 1 module(s) non mesuré(s)"
    # Enregistrements DNS en échec : le takeover mesuré garde son verdict.
    scan = scan_note()
    scan["module_status"]["dns_records"] = {"status": "failed", "error": None}
    dns = compute_families(scan)["dns"]
    assert (dns["state"], dns["grade"]) == ("ok", "A")


@pytest.mark.parametrize(
    ("famille", "modules_en_echec"),
    [
        ("network", ["open_ports"]),
        ("dns", ["subdomain_takeover"]),
        # L'orchestrateur marque le takeover « failed » quand l'énumération échoue.
        ("dns", ["subdomains", "subdomain_takeover"]),
        ("web", ["security_headers", "cookie_security", "cors", "redirect_chain", "web_files"]),
    ],
)
def test_module_de_verdict_en_echec_rend_la_famille_non_mesuree(famille, modules_en_echec):
    non_note = {"score": 0, "counted": False, "measured": False}
    criteres = {
        "network": {},
        "dns": {"takeover": non_note},
        "web": {cle: non_note for cle in ("headers", "cookies", "cors", "https_redirect")},
    }[famille]
    scan = scan_note(**criteres)
    for module in modules_en_echec:
        scan["module_status"][module] = {"status": "failed", "error": None}
    resultat = compute_families(scan)[famille]
    assert (resultat["state"], resultat["grade"]) == ("unmeasured", None)
    assert en(resultat["summary"]).startswith("Not measured (")


def test_dns_sans_sous_domaine_teste():
    scan = scan_note(takeover={"score": 0, "counted": False, "measured": False})
    scan["module_status"]["subdomain_takeover"] = {"status": "skipped", "error": None}
    dns_famille = compute_families(scan)["dns"]
    assert (dns_famille["state"], dns_famille["grade"]) == ("ok", None)


def test_ancien_scan_sans_module_status_ni_bareme_v3():
    familles = compute_families(
        {
            "security_headers": {"headers_found": {"X-Frame-Options": "DENY"}, "score": "2/6"},
            "security_score": {"breakdown": {"headers": {"score": 10, "max": 25, "detail": "2/6 conformes"}}},
        }
    )
    assert list(familles) == list(FAMILY_KEYS)
    # 10 / 25 = 40 % → D.
    assert (familles["web"]["grade"], familles["web"]["state"]) == ("D", "warning")
    assert list(compute_families(None)) == list(FAMILY_KEYS)


def _ancien_scan(statut: str, **colonnes) -> dict:
    """Ligne d'un ancien scan (sans module_status) : colonnes vides sauf celles données."""
    scan = {nom: None for nom in MODULE_NAMES if nom != "screenshot"}
    scan.update(status=statut, security_score=None, module_status=None, screenshot_path=None)
    scan.update(colonnes)
    return scan


def test_ancien_scan_en_erreur_sans_donnees_n_est_pas_sain():
    familles = compute_families(_ancien_scan("error"))
    assert {cle: f["state"] for cle, f in familles.items()} == dict.fromkeys(FAMILY_KEYS, "unmeasured")
    assert all(f["grade"] is None for f in familles.values())
    # Même statut « error » avec des résultats enregistrés : rien n'est fiable.
    familles = compute_families(_ancien_scan("error", security_headers={"headers_found": {"X": "y"}}))
    assert familles["web"]["state"] == "unmeasured"
    # Ni constat non plus : une famille « non mesurée » n'affiche jamais de constat.
    scan = _ancien_scan(
        "error",
        whois_data={"registrar": "x"},
        subdomains=[{"subdomain": "shop.example.com"}],
        subdomain_takeover=[{"subdomain": "shop.example.com", "provider": "Heroku", "risk": "high"}],
        open_ports=[3306],
    )
    assert compute_findings(scan) == []
    familles = compute_families(scan)
    assert (familles["dns"]["state"], familles["network"]["state"]) == ("unmeasured", "unmeasured")


# Critère takeover d'un ancien scan : la vérification a eu lieu.
_TAKEOVER_VERIFIE = {"breakdown": {"takeover": {"score": 5, "max": 5, "measured": True}}}


def test_ancien_scan_module_sans_resultat_non_mesure():
    scan = _ancien_scan(
        "partial",
        tls_certificate={"error": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"},
        email_security={"error": "Délai dépassé"},
        open_ports=[],
        subdomains=[],
        subdomain_takeover=[],
        security_score=_TAKEOVER_VERIFIE,
        dns_records={"A": ["93.184.216.34"]},
        whois_data={"registrar": "x"},
        geo_data={"country": "FR"},
    )
    familles = compute_families(scan)
    # Certificat refusé : constat critique, pas un module en échec.
    assert (familles["tls"]["state"], en(familles["tls"]["summary"])) == ("critical", "1 issue(s) to fix")
    # Erreur enregistrée : e-mail non mesuré.
    assert familles["email"]["state"] == "unmeasured"
    # Listes vides : rien trouvé, donc mesuré (takeover vérifié selon le barème).
    assert familles["dns"]["state"] == "ok"
    assert familles["network"]["state"] == "ok"
    assert familles["identity"]["state"] == "info"
    # Aucun module web enregistré : non mesuré, jamais « aucun point à corriger ».
    assert familles["web"]["state"] == "unmeasured"


@pytest.mark.parametrize(
    "bareme",
    [
        None,
        {"breakdown": {"headers": {"score": 25, "max": 25}}},
        {"breakdown": {"takeover": {"score": 0, "max": 5, "measured": False, "counted": False}}},
    ],
)
@pytest.mark.parametrize("takeover", [[], None])
def test_ancien_scan_takeover_jamais_verifie_non_mesure(bareme, takeover):
    """Colonne ajoutée à NULL aux anciens scans, relue en [] : seul le barème dit si
    la vérification a eu lieu (même règle que l'interface, takeoverNeverChecked)."""
    scan = _ancien_scan(
        "success",
        dns_records={"A": ["93.184.216.34"]},
        subdomains=[{"subdomain": "www.example.com"}],
        reverse_dns={"ptr": "x.example.net"},
        subdomain_takeover=takeover,
        security_score=bareme,
    )
    dns = compute_families(scan)["dns"]
    assert (dns["state"], dns["grade"]) == ("unmeasured", None)
    assert en(dns["summary"]) == "Not measured (1 module(s) failed or timed out)"
    # Takeover vérifié au barème : « rien trouvé », la famille garde son verdict.
    scan["subdomain_takeover"] = []
    scan["security_score"] = _TAKEOVER_VERIFIE
    assert compute_families(scan)["dns"]["state"] == "ok"
    # Takeover trouvé : le résultat lui-même prouve la vérification, constat affiché.
    scan["subdomain_takeover"] = [{"subdomain": "www.example.com", "provider": "Heroku", "risk": "high"}]
    scan["security_score"] = bareme
    assert compute_families(scan)["dns"]["state"] == "critical"


@pytest.mark.parametrize("valeur", [float("nan"), float("inf"), float("-inf")])
def test_note_ignore_les_nombres_non_finis(valeur):
    scan = scan_note(headers={"score": valeur})
    assert compute_families(scan)["web"]["grade"] == "A"  # critère illisible ignoré
    scan = scan_note(headers={"max": valeur})
    assert compute_families(scan)["web"]["grade"] == "A"
    scan = scan_note(tls={"score": valeur})
    assert compute_families(scan)["tls"]["grade"] is None


@pytest.mark.parametrize("poids", [0, -20])
def test_note_ignore_un_poids_nul_ou_negatif(poids):
    assert compute_families(scan_note(tls={"max": poids}))["tls"]["grade"] is None


# --- Note de la famille E-mail = note du module e-mail -----------------------


def test_points_email_distincts_par_note():
    assert len(set(EMAIL_POINTS.values())) == len(EMAIL_POINTS)


@pytest.mark.parametrize("note", sorted(EMAIL_POINTS))
def test_note_de_la_famille_email_egale_celle_du_module(note):
    """Garde la cohérence barème / famille : C reste C, D reste D (et non D, F)."""
    scan = scan_note()
    scan["email_security"] = {"measured": True, "overall_grade": note}
    scan["security_score"] = compute_security_score(scan)
    assert scan["security_score"]["breakdown"]["email"]["score"] == EMAIL_POINTS[note]
    email = compute_families(scan)["email"]
    assert email["grade"] == note
    assert email["state"] == {"A": "ok", "B": "ok", "C": "warning", "D": "warning", "F": "critical"}[note]


def test_note_email_sur_un_autre_poids_retombe_sur_les_seuils_globaux():
    # Poids différent du barème v3 : pas de correspondance exacte avec EMAIL_POINTS.
    scan = scan_note(email={"score": 8, "max": 20})
    assert compute_families(scan)["email"]["grade"] == "D"  # 40 %


# --- Réputation (7e famille) et modules non lancés ---------------------------------

SANS_CRITERE = {"score": 0, "counted": False, "measured": False, "launched": False}


def scan_v4(lances=MODULE_NAMES, **breakdown) -> dict:
    """Scan noté au barème v4 : module_status ne liste que les modules lancés."""
    scan = scan_note(**breakdown)
    scan["security_score"]["version"] = 4
    scan["module_status"] = {name: {"status": "ok", "error": None} for name in MODULE_NAMES if name in lances}
    return scan


def test_famille_reputation_vide_non_mesuree():
    """Famille sans module : jamais « sans objet » (all() d'une liste vide), jamais un verdict."""
    for scan in (scan_note(), scan_v4(), _ancien_scan("success")):
        reputation = compute_families(scan)["reputation"]
        assert (reputation["state"], reputation["grade"]) == ("unmeasured", None)
        assert fr(reputation["summary"]) == "Non mesuré : modules non lancés"
        assert en(reputation["summary"]) == "Not measured: modules not run"
    assert compute_families(None)["reputation"]["state"] == "unmeasured"
    assert [finding for finding in compute_findings(scan_v4()) if finding["family"] == "reputation"] == []


def test_module_non_lance_n_est_jamais_ok():
    scan = scan_v4(lances={"cors", "tls_certificate"})
    assert module_run_status(scan, "cors") == "ok"
    assert module_run_status(scan, "waf") == NOT_LAUNCHED == "not_launched"
    # Un module déclaré lancé (modules_launched) sans statut garde la règle d'avant : « ok ».
    scan["modules_launched"] = ["waf"]
    assert module_run_status(scan, "waf") == "ok"
    assert module_run_status(scan, "cookie_security") == NOT_LAUNCHED
    # Statut enregistré tel quel, y compris « not_launched ».
    scan["module_status"]["cors"] = {"status": "not_launched", "error": None}
    assert module_run_status(scan, "cors") == NOT_LAUNCHED
    scan["module_status"]["cors"] = {"status": "failed", "error": None}
    assert module_run_status(scan, "cors") == "failed"


def test_module_status_dit_les_modules_lances_sans_liste_declaree():
    """Sans modules_launched (NULL, ou scan d'avant les profils), module_status liste les modules lancés."""
    for version in (None, 3, 4):
        scan = scan_note()
        if version:
            scan["security_score"]["version"] = version
        scan["module_status"] = {"cors": {"status": "failed", "error": None}}
        # Clé absente, puis NULL en base.
        for declared in ({}, {"modules_launched": None}):
            lu = {**scan, **declared}
            assert module_run_status(lu, "cors") == "failed"
            assert module_run_status(lu, "waf") == NOT_LAUNCHED


def test_scan_sans_module_status_garde_les_statuts_deduits_des_resultats():
    """Un scan d'avant module_status n'a pas de liste de modules lancés : rien n'est « non lancé »."""
    scan = _ancien_scan("success", cors={"measured": True, "reflects_origin": False})
    assert module_run_status(scan, "cors") == "ok"
    assert module_run_status(scan, "waf") == "failed"  # aucun résultat enregistré
    scan["modules_launched"] = None
    assert module_run_status(scan, "waf") == "failed"


def test_profil_rapide_signale_les_modules_non_lances_par_famille():
    lances = {spec.name for spec in get_modules(PROFILE_QUICK)}
    scan = scan_v4(lances, takeover=SANS_CRITERE)
    familles = compute_families(scan)

    # Web, TLS, e-mail : tous leurs modules sont lancés, verdict complet.
    assert (familles["web"]["state"], fr(familles["web"]["summary"])) == ("ok", "Aucun point à corriger")
    assert (familles["tls"]["grade"], familles["email"]["grade"]) == ("A", "A")
    # Réseau : le scan de ports (actif, hors profil rapide) fonde le verdict ; géolocalisation et DNS inverse
    # ne suffisent pas, la famille est non mesurée plutôt que « sans problème ».
    assert (familles["network"]["state"], familles["network"]["grade"]) == ("unmeasured", None)
    assert fr(familles["network"]["summary"]) == "Non mesuré : modules non lancés"
    assert en(familles["network"]["summary"]) == "Not measured: modules not run"
    # DNS : ni sous-domaines ni takeover lancés, aucune note : aucun verdict honnête.
    assert (familles["dns"]["state"], familles["dns"]["grade"]) == ("unmeasured", None)
    assert fr(familles["dns"]["summary"]) == "Non mesuré : modules non lancés"
    # Identité : aucun de ses modules n'a été lancé.
    assert (familles["identity"]["state"], familles["identity"]["grade"]) == ("unmeasured", None)
    assert en(familles["identity"]["summary"]) == "Not measured: modules not run"
    assert familles["reputation"]["state"] == "unmeasured"
    assert list(familles) == list(FAMILY_KEYS)


def test_module_de_verdict_non_lance_rend_la_famille_non_mesuree():
    # Réseau : géolocalisation et réseau étendu lancés, pas les ports (module de verdict).
    scan = scan_v4(set(MODULE_NAMES) - {"open_ports"})
    reseau = compute_families(scan)["network"]
    assert (reseau["state"], reseau["grade"]) == ("unmeasured", None)
    assert en(reseau["summary"]) == "Not measured: modules not run"
    # Web : des critères notés (en-têtes, TLS…) donnent un verdict malgré les modules non lancés.
    scan = scan_v4(
        set(MODULE_NAMES) - {"cookie_security", "cors"},
        cookies=SANS_CRITERE,
        cors=SANS_CRITERE,
    )
    web = compute_families(scan)["web"]
    assert (web["state"], web["grade"]) == ("ok", "A")
    assert en(web["summary"]) == "No issues found; 2 module(s) not run"


def test_modules_non_lances_et_en_echec_signales_ensemble():
    scan = scan_v4(set(MODULE_NAMES) - {"network_extended"})
    scan["module_status"]["geo_data"] = {"status": "failed", "error": "429"}
    reseau = compute_families(scan)["network"]
    assert reseau["state"] == "ok"
    assert en(reseau["summary"]) == (
        "No issues among the measurements; 1 module(s) not measured; 1 module(s) not run"
    )
    assert fr(reseau["summary"]) == (
        "Aucun point à corriger parmi les mesures ; 1 module(s) non mesuré(s) ; 1 module(s) non lancé(s)"
    )
    # Un constat reste signalé, avec les deux réserves.
    scan["open_ports"].append({"port": 6379, "state": "open"})
    reseau = compute_families(scan)["network"]
    assert reseau["state"] == "critical"
    assert en(reseau["summary"]) == "1 issue(s) to fix; 1 module(s) not measured; 1 module(s) not run"


def test_modules_lances_tous_sans_objet_et_un_non_lance():
    scan = scan_v4(set(MODULE_NAMES) - {"reverse_dns"}, takeover=SANS_CRITERE)
    for module in ("dns_records", "subdomains", "subdomain_takeover"):
        scan["module_status"][module] = {"status": "skipped", "error": None}
    dns = compute_families(scan)["dns"]
    assert (dns["state"], dns["grade"]) == ("skipped", None)
    assert en(dns["summary"]) == "Not applicable to this target; 1 module(s) not run"


def test_module_non_lance_sans_constat_ni_verdict():
    """Les données enregistrées d'un module non lancé ne disent rien : jamais de constat."""
    scan = scan_v4(set(MODULE_NAMES) - {"open_ports", "tls_certificate"})
    scan["open_ports"].append({"port": 6379, "state": "open"})
    scan["tls_certificate"]["valid"] = False
    assert compute_findings(scan) == []
    familles = compute_families(scan)
    assert (familles["network"]["state"], familles["tls"]["state"]) == ("unmeasured", "unmeasured")
    # Lancés, les mêmes données font leurs constats.
    scan = scan_v4()
    scan["open_ports"].append({"port": 6379, "state": "open"})
    assert [finding["module"] for finding in compute_findings(scan)] == ["open_ports"]


def test_scan_v3_garde_ses_familles_et_son_bareme():
    """Un scan v3 (18 modules lancés, aucune liste déclarée) est relu comme avant, avec son barème."""
    scan = scan_note()
    scan["security_score"]["version"] = 3
    assert "modules_launched" not in scan
    familles = compute_families(scan)
    assert {cle: f["state"] for cle, f in familles.items()} == {
        "web": "ok",
        "tls": "ok",
        "email": "ok",
        "dns": "ok",
        "network": "ok",
        "identity": "info",
        "reputation": "unmeasured",
        "leaks": "unmeasured",
    }
    assert familles["web"]["grade"] == "A"
