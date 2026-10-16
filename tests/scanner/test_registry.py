# =============================================================================
# DomainRecon - Tests du registre des modules (registry.py et modules/)
# =============================================================================
# Les 18 modules actuels sont enregistrés par des adaptateurs (un fichier par
# module) qui appellent les fonctions de scan existantes. Les règles de
# filtrage de get_modules (profils, clés API, autorisation, dépendances) sont
# éprouvées sur un registre de démonstration qui remplace MODULES le temps du
# test : elles ne dépendent pas des modules réels.
# =============================================================================

import asyncio
import inspect
from dataclasses import FrozenInstanceError

import pytest

from domainrecon.i18n import msg
from domainrecon.scanner import (
    cookies,
    cors,
    dns,
    email_security,
    headers,
    modules,
    redirects,
    registry,
    screenshot,
    takeover,
    technologies,
    tls,
    waf,
    web_files,
    whois_lookup,
)
from domainrecon.scanner import families as families_module
from domainrecon.scanner.errors import ModuleError
from domainrecon.scanner.families import FAMILY_KEYS
from domainrecon.scanner.impl import geo_data as impl_geo_data
from domainrecon.scanner.impl import network_extended as impl_network_extended
from domainrecon.scanner.impl import open_ports as impl_open_ports
from domainrecon.scanner.registry import ModuleSpec, ScanContext
from rendu import fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

# Les 18 modules de la v1, dans l'ordre de orchestrator.MODULE_NAMES.
LEGACY_MODULES = (
    "dns_records",
    "subdomains",
    "security_headers",
    "tls_certificate",
    "technologies",
    "geo_data",
    "whois_data",
    "open_ports",
    "email_security",
    "waf",
    "redirect_chain",
    "web_files",
    "cookie_security",
    "cors",
    "reverse_dns",
    "network_extended",
    "screenshot",
    "subdomain_takeover",
)

# Profil « rapide » : sans l'énumération des sous-domaines (et le takeover qui
# en dépend), le WHOIS, les voisins réseau et la capture d'écran, trop lents.
QUICK_MODULES = (
    "dns_records",
    "security_headers",
    "tls_certificate",
    "technologies",
    "geo_data",
    "email_security",
    "waf",
    "redirect_chain",
    "web_files",
    "cookie_security",
    "cors",
    "reverse_dns",
)

# Modules actifs : sonde envoyée à la cible, donc personnalisé et autorisation seulement.
ACTIVE_MODULES = ("open_ports", "subdomain_takeover")
# Profil « complet » : les 16 modules passifs.
COMPLETE_MODULES = tuple(name for name in LEGACY_MODULES if name not in ACTIVE_MODULES)

PUBLIC_IPV4 = "93.184.216.34"
PUBLIC_IPV6 = "2606:2800:220:1:248:1893:25c8:1946"
SUBDOMAINS = [{"subdomain": "www.example.com", "ip": PUBLIC_IPV4}]


def names(specs) -> list[str]:
    return [spec.name for spec in specs]


# =============================================================================
# Les 18 modules actuels
# =============================================================================


def test_le_registre_contient_les_18_modules():
    assert len(LEGACY_MODULES) == 18
    assert set(LEGACY_MODULES) <= set(registry.MODULES)
    # Même ordre que celui de l'enregistrement : c'est celui de module_status.
    assert [name for name in registry.MODULES if name in LEGACY_MODULES] == list(LEGACY_MODULES)


def test_noms_coherents_avec_l_orchestrateur():
    """Un seul inventaire : MODULE_NAMES et le registre désignent les mêmes modules, dans le même ordre."""
    from domainrecon.scanner import orchestrator

    assert tuple(orchestrator.MODULE_NAMES) == LEGACY_MODULES
    assert set(orchestrator.MODULE_NAMES) <= set(registry.MODULES)
    assert [name for name in registry.MODULES if name in orchestrator.MODULE_NAMES] == list(
        orchestrator.MODULE_NAMES
    )


def test_delais_coherents_avec_l_orchestrateur():
    from domainrecon.scanner import orchestrator

    assert registry.DEFAULT_TIMEOUT == orchestrator.MODULE_TIMEOUT
    for name in LEGACY_MODULES:
        # Délai propre du takeover ; les autres prennent celui du profil (Réglages).
        expected = orchestrator.TAKEOVER_TIMEOUT if name == "subdomain_takeover" else None
        assert registry.MODULES[name].timeout == expected, name


@pytest.mark.parametrize("name", LEGACY_MODULES)
def test_champs_de_chaque_module(name):
    spec = registry.MODULES[name]
    assert spec.name == name
    # Famille : celle des familles de l'écran « Résultat ».
    assert spec.family == families_module.MODULE_FAMILY[name]
    assert spec.category == ("actif" if name in ACTIVE_MODULES else "passif")
    assert spec.requires_authorization is (name in ACTIVE_MODULES)
    assert spec.quick is (name in QUICK_MODULES)
    assert spec.api_key is None
    assert spec.wave == 1
    assert spec.depends_on == (("subdomains",) if name == "subdomain_takeover" else ())
    assert spec.timeout == (30 if name == "subdomain_takeover" else None)
    assert spec.column == ("screenshot_path" if name == "screenshot" else name)
    assert spec.quick is (name in QUICK_MODULES)
    assert inspect.iscoroutinefunction(spec.run)
    assert callable(spec.skip_reason)


@pytest.mark.parametrize("name", LEGACY_MODULES)
def test_un_fichier_par_module(name):
    """modules/<nom>.py déclare le ModuleSpec enregistré sous ce nom."""
    adapter = getattr(modules, name)

    assert adapter.__name__ == f"domainrecon.scanner.modules.{name}"
    assert adapter.SPEC is registry.MODULES[name]


def test_familles_du_registre():
    assert len(registry.FAMILIES) == 8
    assert set(FAMILY_KEYS) <= set(registry.FAMILIES)
    # Les mêmes huit familles, dans le même ordre, que l'écran « Résultat » (réputation et fuites comprises).
    assert registry.FAMILIES == FAMILY_KEYS
    assert {spec.family for spec in registry.MODULES.values()} <= set(registry.FAMILIES)


def test_le_registre_est_coherent():
    registry.validate_registry()


# =============================================================================
# Les adaptateurs appellent la fonction de scan existante, avec les bons arguments
# =============================================================================

# Cible www.example.com sur un site example.com, résolue en IPv6 puis IPv4 :
# l'adresse transmise aux modules réseau est l'IPv4 (adresse principale).
CONTEXT = ScanContext(
    domain="www.example.com",
    apex="example.com",
    site="example.com",
    addresses=[PUBLIC_IPV6, PUBLIC_IPV4],
    results={"subdomains": SUBDOMAINS},
)

# Module -> (module du scanner, fonction appelée, arguments, arguments nommés).
CALLS = {
    "dns_records": (dns, "scan_dns_records", ("www.example.com",), {}),
    "subdomains": (dns, "find_subdomains", ("example.com",), {}),
    "security_headers": (headers, "check_security_headers", ("www.example.com",), {}),
    "tls_certificate": (tls, "check_tls_certificate", ("www.example.com",), {}),
    "technologies": (technologies, "detect_technologies", ("www.example.com",), {}),
    "geo_data": (impl_geo_data, "get_geo_data", (PUBLIC_IPV4,), {"token": None, "client": None}),
    "whois_data": (whois_lookup, "get_whois_data", ("example.com",), {}),
    "open_ports": (impl_open_ports, "scan_ports", (PUBLIC_IPV4,), {}),
    "email_security": (
        email_security,
        "analyze_email_security",
        ("example.com",),
        {"dmarc_domain": "www.example.com"},
    ),
    "waf": (waf, "detect_waf", ("www.example.com",), {}),
    "redirect_chain": (redirects, "trace_redirects", ("www.example.com",), {}),
    "web_files": (web_files, "check_web_files", ("www.example.com",), {}),
    "cookie_security": (cookies, "analyze_cookies", ("www.example.com",), {}),
    "cors": (cors, "check_cors", ("www.example.com",), {}),
    "reverse_dns": (dns, "reverse_dns", (PUBLIC_IPV4,), {}),
    "network_extended": (
        impl_network_extended,
        "extended_network_scan",
        (PUBLIC_IPV4, "www.example.com"),
        {"token": None, "client": None},
    ),
    "screenshot": (
        screenshot,
        "capture_screenshot",
        ("www.example.com", str(screenshot.SCREENSHOTS_DIR)),
        {},
    ),
    "subdomain_takeover": (takeover, "check_subdomain_takeover", (SUBDOMAINS,), {}),
}


def test_chaque_module_a_son_appel():
    assert set(CALLS) == set(LEGACY_MODULES)


@pytest.mark.parametrize("name", LEGACY_MODULES)
def test_l_adaptateur_appelle_la_fonction_existante(name, monkeypatch):
    module, function, args, kwargs = CALLS[name]
    received = []
    result = object()

    async def fake(*a, **kw):
        received.append((a, kw))
        return result

    monkeypatch.setattr(module, function, fake)

    # Le résultat est celui de la fonction, sans transformation.
    assert asyncio.run(registry.MODULES[name].run(CONTEXT)) is result
    assert received == [(args, kwargs)]


@pytest.mark.parametrize("name", LEGACY_MODULES)
def test_l_adaptateur_laisse_remonter_les_erreurs(name, monkeypatch):
    """Statut et message d'un échec sont l'affaire de l'orchestrateur : l'adaptateur n'avale rien."""
    module, function, _, _ = CALLS[name]

    async def fails(*a, **kw):
        raise ModuleError(msg("orchestrator.module_failed"))

    monkeypatch.setattr(module, function, fails)

    with pytest.raises(ModuleError) as error:
        asyncio.run(registry.MODULES[name].run(CONTEXT))
    assert error.value.message == msg("orchestrator.module_failed")


# =============================================================================
# Modules sans objet pour une cible
# =============================================================================

NOT_FOR_IP = ("dns_records", "subdomains", "whois_data", "email_security", "subdomain_takeover")
NEEDS_ADDRESS = ("geo_data", "open_ports", "reverse_dns", "network_extended", "screenshot")


def skip_reasons(context: ScanContext) -> dict:
    """Raison d'ignorer chacun des 18 modules pour ce contexte (None : il s'exécute)."""
    return {name: registry.MODULES[name].skip_reason(context) for name in LEGACY_MODULES}


def test_aucun_module_ignore_pour_un_domaine_resolu():
    assert set(skip_reasons(CONTEXT).values()) == {None}


def test_modules_sans_objet_pour_une_adresse_ip():
    context = ScanContext(domain=PUBLIC_IPV4, addresses=[PUBLIC_IPV4])

    assert context.is_ip_target
    reasons = skip_reasons(context)
    for name in LEGACY_MODULES:
        expected = msg("orchestrator.skip_ip_target") if name in NOT_FOR_IP else None
        assert reasons[name] == expected, name
    assert fr(reasons["whois_data"]) == "Sans objet pour une adresse IP"


def test_modules_sans_adresse_ip():
    """Cible qui n'a pas résolu : seuls les modules qui travaillent sur l'adresse sont sans objet."""
    context = ScanContext(domain="example.com")

    assert context.ip_address is None
    reasons = skip_reasons(context)
    for name in LEGACY_MODULES:
        expected = msg("orchestrator.no_address") if name in NEEDS_ADDRESS else None
        assert reasons[name] == expected, name


def test_email_sans_objet_pour_une_plateforme_mutualisee():
    context = ScanContext(
        domain="alice.github.io", apex="github.io", site="alice.github.io", addresses=[PUBLIC_IPV4]
    )

    assert context.shared_platform
    reasons = skip_reasons(context)
    assert reasons["email_security"] == msg("orchestrator.skip_shared_platform")
    assert {name for name, reason in reasons.items() if reason} == {"email_security"}


def test_email_plateforme_mutualisee_avant_adresse_ip():
    """Même ordre que l'ancien orchestrateur : la plateforme mutualisée prime sur l'adresse IP."""
    context = ScanContext(domain=PUBLIC_IPV4, apex="a", site="b", addresses=[PUBLIC_IPV4])

    assert registry.MODULES["email_security"].skip_reason(context) == msg("orchestrator.skip_shared_platform")


# --- Takeover : dépend du résultat de l'énumération des sous-domaines ---------


def takeover_spec() -> ModuleSpec:
    return registry.MODULES["subdomain_takeover"]


def test_takeover_sans_sous_domaine_est_sans_objet():
    context = ScanContext(domain="example.com", addresses=[PUBLIC_IPV4], results={"subdomains": []})

    assert takeover_spec().skip_reason(context) == msg("orchestrator.skip_no_subdomains")


def test_takeover_non_verifie_si_l_enumeration_a_echoue():
    """Énumération en échec ou hors délai : son résultat est absent du contexte, le takeover est « non vérifié »."""
    context = ScanContext(domain="example.com", addresses=[PUBLIC_IPV4])

    assert takeover_spec().skip_reason(context) is None  # il se lance, puis échoue :
    with pytest.raises(ModuleError) as error:
        asyncio.run(takeover_spec().run(context))
    assert error.value.message == msg("orchestrator.takeover_not_checked")
    assert fr(error.value.message) == "Non vérifié : énumération des sous-domaines en échec"


def test_takeover_recoit_les_sous_domaines(monkeypatch):
    seen = []

    async def fake(subdomains):
        seen.append(subdomains)
        return []

    monkeypatch.setattr(takeover, "check_subdomain_takeover", fake)
    context = ScanContext(domain="example.com", addresses=[PUBLIC_IPV4], results={"subdomains": SUBDOMAINS})

    assert takeover_spec().skip_reason(context) is None
    assert asyncio.run(takeover_spec().run(context)) == []
    assert seen == [SUBDOMAINS]


# =============================================================================
# ScanContext
# =============================================================================


def test_contexte_par_defaut():
    context = ScanContext(domain="www.example.com")

    # Sans précision, le domaine enregistrable et celui du site sont la cible.
    assert (context.domain, context.apex, context.site) == ("www.example.com",) * 3
    assert context.addresses == [] and context.results == {}
    assert context.ip_address is None
    assert not context.is_ip_target and not context.shared_platform
    assert context.proxy is None and context.http is None
    assert context.logger.name == "domainrecon.scanner"


def test_contextes_independants():
    """Les dictionnaires et listes par défaut ne sont pas partagés d'un scan à l'autre."""
    first, second = ScanContext(domain="a.example"), ScanContext(domain="b.example")
    first.results["dns_records"] = {}
    first.addresses.append(PUBLIC_IPV4)

    assert second.results == {} and second.addresses == []


def test_adresse_principale_ipv4_d_abord():
    assert ScanContext(domain="example.com", addresses=[PUBLIC_IPV6, PUBLIC_IPV4]).ip_address == PUBLIC_IPV4
    assert ScanContext(domain="example.com", addresses=[PUBLIC_IPV6]).ip_address == PUBLIC_IPV6


def test_cible_adresse_ip():
    assert ScanContext(domain=PUBLIC_IPV4).is_ip_target
    assert ScanContext(domain=PUBLIC_IPV6).is_ip_target
    assert not ScanContext(domain="example.com").is_ip_target


# =============================================================================
# ModuleSpec et register()
# =============================================================================


async def _run(context):
    return {"measured": True, "error": None}


def make_spec(name="demo", **fields) -> ModuleSpec:
    fields = {"family": "web", "category": "passif", "run": _run, **fields}
    return ModuleSpec(name=name, **fields)


def test_valeurs_par_defaut_d_un_module():
    spec = make_spec()

    assert (spec.api_key, spec.wave, spec.depends_on) == (None, 1, ())
    # Sans délai propre : celui du profil (Réglages), 60 s par défaut.
    assert spec.timeout is None and registry.DEFAULT_TIMEOUT == 60
    assert spec.keys == () and spec.required_keys == () and spec.optional_keys == ()
    assert spec.findings == () and spec.score_rules == () and spec.optional is False
    assert spec.order == registry.DEFAULT_ORDER and spec.column is None
    assert spec.quick is False
    assert spec.skip_reason(ScanContext(domain="example.com")) is None
    assert not spec.requires_authorization


def test_un_module_est_immuable():
    spec = make_spec(depends_on=["autre"])

    assert spec.depends_on == ("autre",)  # liste convertie en tuple
    with pytest.raises(FrozenInstanceError):
        spec.wave = 2
    assert hash(spec)


def test_delai_en_secondes_entier_ou_decimal():
    assert make_spec(timeout=5).timeout == 5
    assert make_spec(timeout=0.05).timeout == 0.05


@pytest.mark.parametrize(
    "fields",
    [
        {"name": ""},
        {"name": "Majuscule"},
        {"name": "avec-tiret"},
        {"name": "1chiffre"},
        {"name": 12},
        {"family": "inconnue"},
        {"category": "agressif"},
        {"category": "api_key"},  # sans nom de clé
        {"api_key": ""},
        {"api_key": 5},
        {"wave": 0},
        {"wave": 4},
        {"wave": True},
        {"wave": "1"},
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": True},
        {"timeout": "60"},
        {"depends_on": "autre"},
        {"depends_on": ("demo",)},  # dépend de lui-même
        {"quick": True, "category": "actif"},  # seul un module passif peut être rapide
        {"quick": True, "category": "api_key", "api_key": "cle"},
        {"run": None},
        {"skip_reason": "non"},
    ],
    ids=repr,
)
def test_module_invalide_refuse(fields):
    with pytest.raises(ValueError):
        make_spec(**fields)


@pytest.mark.parametrize(
    ("category", "needs"),
    [("passif", False), ("api_key", False), ("actif", True), ("sensible", True)],
)
def test_autorisation_requise_pour_les_modules_actifs_et_sensibles(category, needs):
    spec = make_spec(category=category, api_key="cle" if category == "api_key" else None)

    assert spec.requires_authorization is needs


@pytest.fixture
def empty_registry(monkeypatch):
    """Registre vide à la place de MODULES (register et get_modules le lisent à chaque appel)."""
    registered: dict[str, ModuleSpec] = {}
    monkeypatch.setattr(registry, "MODULES", registered)
    return registered


def test_register_enregistre_et_renvoie_le_module(empty_registry):
    spec = make_spec("premier")

    assert registry.register(spec) is spec
    assert empty_registry == {"premier": spec}


def test_register_refuse_un_nom_deja_pris(empty_registry):
    registry.register(make_spec("premier"))

    with pytest.raises(ValueError, match="déjà enregistré"):
        registry.register(make_spec("premier", family="tls"))
    assert empty_registry["premier"].family == "web"


# --- validate_registry --------------------------------------------------------


def test_dependance_inconnue_refusee(empty_registry):
    registry.register(make_spec("a", depends_on=("absent",)))

    with pytest.raises(ValueError, match="dépendance inconnue"):
        registry.validate_registry()


def test_dependance_d_une_vague_plus_tardive_refusee(empty_registry):
    registry.register(make_spec("tard", wave=3))
    registry.register(make_spec("tot", wave=2, depends_on=("tard",)))

    with pytest.raises(ValueError, match="vague"):
        registry.validate_registry()


def test_module_rapide_dont_la_dependance_ne_l_est_pas_refuse(empty_registry):
    registry.register(make_spec("lent"))
    registry.register(make_spec("vite", quick=True, depends_on=("lent",)))

    with pytest.raises(ValueError, match="rapide"):
        registry.validate_registry()


def test_cycle_de_dependances_refuse(empty_registry):
    registry.register(make_spec("a", depends_on=("b",)))
    registry.register(make_spec("b", depends_on=("c",)))
    registry.register(make_spec("c", depends_on=("a",)))

    with pytest.raises(ValueError, match="Cycle"):
        registry.validate_registry()


def test_dependances_valides(empty_registry):
    registry.register(make_spec("a", quick=True))
    registry.register(make_spec("b", quick=True, depends_on=("a",)))  # même vague
    registry.register(make_spec("c", wave=2, depends_on=("a", "b")))

    registry.validate_registry()


# =============================================================================
# get_modules sur les modules actuels
# =============================================================================


def test_profil_rapide_des_modules_actuels():
    chosen = registry.get_modules("rapide")

    assert names(chosen) == list(QUICK_MODULES)
    assert all(spec.category == "passif" for spec in chosen)
    # Le profil rapide évite les modules lents (sous-domaines, WHOIS, réseau étendu, capture) et les actifs.
    assert {"subdomains", "whois_data", "network_extended", "screenshot", *ACTIVE_MODULES}.isdisjoint(
        names(chosen)
    )


def test_profil_complet_des_modules_actuels():
    assert names(registry.get_modules("complet")) == list(COMPLETE_MODULES)
    # Même autorisée, la cible ne fait pas entrer les modules actifs dans le profil complet.
    assert names(registry.get_modules("complet", authorized=True)) == list(COMPLETE_MODULES)


def test_profil_personnalise_des_modules_actuels():
    # Ordre du registre, quel que soit l'ordre de la sélection ; doublons ignorés.
    chosen = registry.get_modules("personnalise", selected=["waf", "dns_records", "waf"])

    assert names(chosen) == ["dns_records", "waf"]
    assert registry.get_modules("personnalise", selected=[]) == []
    assert registry.get_modules("personnalise") == []


def test_le_takeover_entraine_l_enumeration_des_sous_domaines():
    chosen = registry.get_modules("personnalise", selected=["subdomain_takeover"], authorized=True)

    assert names(chosen) == ["subdomains", "subdomain_takeover"]


def test_modules_actifs_ecartes_sans_autorisation():
    """Sans autorisation, ports et takeover ne sont pas lancés (même sélectionnés), sans erreur."""
    assert registry.get_modules("personnalise", selected=["subdomain_takeover", "open_ports"]) == []
    chosen = registry.get_modules("personnalise", selected=["open_ports", "waf"], authorized=True)
    assert names(chosen) == ["open_ports", "waf"]
    assert names(registry.get_modules("personnalise", selected=["open_ports", "waf"])) == ["waf"]


def test_modules_actuels_independants_des_cles_et_de_l_autorisation():
    """Les modules actuels sont sans clé et les actifs n'entrent dans aucun profil automatique : ni l'autorisation
    ni les clés ne changent rien aux profils rapide et complet."""
    for profile, expected in (("rapide", QUICK_MODULES), ("complet", COMPLETE_MODULES)):
        for authorized in (False, True):
            chosen = registry.get_modules(profile, ["virustotal"], authorized)
            assert [name for name in names(chosen) if name in LEGACY_MODULES] == list(expected)


def test_profil_inconnu_refuse():
    with pytest.raises(ValueError, match="Profil inconnu"):
        registry.get_modules("agressif")


def test_module_inconnu_refuse_dans_une_selection():
    with pytest.raises(ValueError, match="inexistant"):
        registry.get_modules("personnalise", selected=["waf", "inexistant"])


def test_selection_ignoree_hors_profil_personnalise():
    assert names(registry.get_modules("rapide", selected=["subdomains"])) == list(QUICK_MODULES)
    assert names(registry.get_modules("complet", selected=["waf", "inexistant"])) == list(COMPLETE_MODULES)


def test_get_modules_renvoie_une_nouvelle_liste():
    first = registry.get_modules("complet")
    first.clear()

    assert len(registry.get_modules("complet")) == len(COMPLETE_MODULES)


# =============================================================================
# get_modules : profils, clés API, autorisation, dépendances (registre de démonstration)
# =============================================================================


@pytest.fixture
def demo(empty_registry):
    """Un module de chaque sorte, enregistrés dans le désordre des vagues."""
    for spec in (
        make_spec("passif_rapide", quick=True),
        make_spec("passif_lent"),
        make_spec("passif_dependant", wave=2, quick=True, depends_on=("passif_rapide",)),
        make_spec("virustotal", category="api_key", api_key="virustotal", wave=2),
        make_spec("shodan", category="api_key", api_key="shodan", wave=2, depends_on=("passif_rapide",)),
        make_spec("nuclei", category="actif", wave=3),
        make_spec("intelx", category="sensible", api_key="intelx", wave=3),
        make_spec("apres_nuclei", wave=3, depends_on=("nuclei",)),
        make_spec("tot", wave=1, quick=True),
    ):
        registry.register(spec)
    registry.validate_registry()
    return empty_registry


def pick(profile, keys=(), authorized=False, selected=None) -> list[str]:
    return names(registry.get_modules(profile, keys, authorized, selected))


def test_rapide_prend_les_modules_passifs_marques(demo):
    # Les modules à clé, actifs ou sensibles n'en font jamais partie, même autorisés ou dotés de leur clé.
    expected = ["passif_rapide", "tot", "passif_dependant"]

    assert pick("rapide") == expected
    assert pick("rapide", ["virustotal", "shodan", "intelx"], authorized=True) == expected


def test_complet_prend_les_passifs_et_les_modules_a_cle_renseignee(demo):
    passifs = ["passif_rapide", "passif_lent", "tot", "passif_dependant"]

    assert pick("complet") == passifs
    assert pick("complet", ["virustotal"]) == [*passifs, "virustotal"]
    assert pick("complet", ["virustotal", "shodan"]) == [*passifs, "virustotal", "shodan"]
    assert pick("complet", ["shodan", "inconnue"]) == [*passifs, "shodan"]


def test_complet_n_ajoute_jamais_les_modules_actifs_ou_sensibles(demo):
    # Ils se choisissent un à un (profil personnalisé), avec l'autorisation de tester la cible.
    keys = ["virustotal", "shodan", "intelx"]

    assert pick("complet", keys, authorized=True) == pick("complet", keys)
    assert {"nuclei", "intelx"}.isdisjoint(pick("complet", keys, authorized=True))


def test_complet_ecarte_un_module_passif_qui_depend_d_un_module_actif(demo):
    # « apres_nuclei » est passif, mais « nuclei » est actif : le profil complet ne le lance jamais.
    assert "apres_nuclei" not in pick("complet")
    assert "apres_nuclei" not in pick("complet", authorized=True)


def test_modules_dans_l_ordre_des_vagues_puis_de_l_enregistrement(demo):
    selected = ["shodan", "nuclei", "tot", "passif_lent", "virustotal"]

    result = pick("personnalise", ["virustotal", "shodan"], True, selected)

    # « passif_rapide » (vague 1) est la dépendance de « shodan » ; « tot » est enregistré après lui.
    assert result == ["passif_rapide", "passif_lent", "tot", "virustotal", "shodan", "nuclei"]


def test_module_actif_exige_l_autorisation(demo):
    assert pick("personnalise", selected=["nuclei"]) == []
    assert pick("personnalise", selected=["nuclei"], authorized=False) == []
    assert pick("personnalise", selected=["nuclei"], authorized=True) == ["nuclei"]


def test_autorisation_ecarte_seulement_les_modules_actifs_et_sensibles(demo):
    selected = ["passif_lent", "nuclei", "virustotal"]

    assert pick("personnalise", ["virustotal"], False, selected) == ["passif_lent", "virustotal"]
    assert pick("personnalise", ["virustotal"], True, selected) == ["passif_lent", "virustotal", "nuclei"]


def test_module_a_cle_exige_la_cle(demo):
    assert pick("personnalise", selected=["virustotal"]) == []
    assert pick("personnalise", ["shodan"], selected=["virustotal"]) == []
    assert pick("personnalise", ["virustotal"], selected=["virustotal"]) == ["virustotal"]


def test_module_sensible_exige_la_cle_et_l_autorisation(demo):
    assert pick("personnalise", ["intelx"], False, ["intelx"]) == []
    assert pick("personnalise", [], True, ["intelx"]) == []
    assert pick("personnalise", ["intelx"], True, ["intelx"]) == ["intelx"]


@pytest.mark.parametrize("keys", [None, (), [], set(), iter(())])
def test_aucune_cle_disponible(demo, keys):
    assert "virustotal" not in pick("complet", keys)


def test_cles_donnees_en_dictionnaire_ou_en_generateur(demo):
    # Les noms des clés renseignées : un dictionnaire {nom: valeur}, un ensemble, un générateur…
    assert "virustotal" in pick("complet", {"virustotal": "secret"})
    assert "virustotal" in pick("complet", (name for name in ("virustotal",)))


def test_les_dependances_sont_ajoutees_a_la_selection(demo):
    assert pick("personnalise", selected=["passif_dependant"]) == ["passif_rapide", "passif_dependant"]
    assert pick("personnalise", ["shodan"], selected=["shodan"]) == ["passif_rapide", "shodan"]


def test_module_dont_la_dependance_ne_peut_pas_tourner_est_ecarte(demo):
    # « apres_nuclei » dépend du module actif « nuclei » : sans autorisation, ni l'un ni l'autre.
    assert pick("personnalise", selected=["apres_nuclei"]) == []
    assert pick("personnalise", selected=["apres_nuclei"], authorized=True) == ["nuclei", "apres_nuclei"]
    # Même chose pour une dépendance dont la clé manque.
    registry.register(make_spec("apres_shodan", wave=3, depends_on=("shodan",)))
    assert pick("personnalise", selected=["apres_shodan"]) == []
    assert pick("personnalise", ["shodan"], selected=["apres_shodan"]) == [
        "passif_rapide",
        "shodan",
        "apres_shodan",
    ]


def test_dependance_transitive(demo):
    registry.register(make_spec("derniere", wave=3, depends_on=("passif_dependant",)))
    registry.register(make_spec("chaine", wave=3, depends_on=("apres_nuclei",)))

    assert pick("personnalise", selected=["derniere"]) == ["passif_rapide", "passif_dependant", "derniere"]
    # Elle s'écarte aussi quand la dépendance de sa dépendance ne peut pas tourner.
    assert pick("personnalise", selected=["chaine"]) == []
    assert pick("personnalise", selected=["chaine"], authorized=True) == ["nuclei", "apres_nuclei", "chaine"]


def test_dependance_inconnue_n_entraine_pas_d_erreur_a_la_selection(demo):
    registry.register(make_spec("orphelin", depends_on=("absent",)))

    assert "orphelin" not in pick("complet")
    assert pick("personnalise", selected=["orphelin"]) == []
