# =============================================================================
# DomainRecon - Tests du cache à durée de vie limitée (@cached)
# =============================================================================
# Horloge simulée : aucun test n'attend réellement l'expiration d'une entrée.
# Les fonctions décorées sont définies dans chaque test : chacune a son cache.
# =============================================================================

import asyncio
import contextvars
import gc
import inspect
import logging
import threading

import pytest

from domainrecon.scanner import cache


class Clock:
    """Horloge simulée, avancée à la main."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(cache, "_clock", fake)
    return fake


@pytest.fixture(autouse=True)
def cache_vide():
    cache.clear_cache()
    yield
    cache.clear_cache()


def test_durees_usuelles():
    assert cache.SHORT_TTL == 300  # 5 min : données volatiles
    assert cache.MEDIUM_TTL == 3600  # 1 h : sous-domaines, DNS
    assert cache.LONG_TTL == 86400  # 24 h : WHOIS, certificats


# =============================================================================
# Mise en cache et expiration
# =============================================================================


def test_resultat_garde_par_arguments(clock):
    calls = []

    @cache.cached(cache.SHORT_TTL)
    async def lookup(domain):
        calls.append(domain)
        return {"domain": domain, "rank": len(calls)}

    async def scenario():
        return [await lookup("example.com"), await lookup("example.com"), await lookup("example.org")]

    first, second, other = asyncio.run(scenario())

    assert calls == ["example.com", "example.org"]
    assert first == second == {"domain": "example.com", "rank": 1}
    assert other == {"domain": "example.org", "rank": 2}


def test_resultat_valable_jusqu_a_l_echeance(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        return len(calls)

    async def at(delay):
        clock.advance(delay)
        return await lookup("example.com")

    async def scenario():
        return [await at(0), await at(59), await at(1), await at(59), await at(1)]

    # Garde jusqu'à 60 s (exclu) après le calcul ; l'échéance repart du nouveau calcul.
    assert asyncio.run(scenario()) == [1, 1, 2, 2, 3]
    assert calls == ["example.com"] * 3


def test_echeance_propre_a_chaque_fonction(clock):
    calls = []

    @cache.cached(cache.SHORT_TTL)
    async def volatile(key):
        calls.append(("volatile", key))

    @cache.cached(cache.LONG_TTL)
    async def stable(key):
        calls.append(("stable", key))

    async def scenario():
        await volatile("a")
        await stable("a")
        clock.advance(cache.SHORT_TTL)
        await volatile("a")
        await stable("a")

    asyncio.run(scenario())

    assert calls == [("volatile", "a"), ("stable", "a"), ("volatile", "a")]


# =============================================================================
# Ce qui n'est pas gardé
# =============================================================================


def test_exception_non_gardee(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        if len(calls) == 1:
            raise ConnectionError("API injoignable")
        return "ok"

    async def scenario():
        with pytest.raises(ConnectionError):
            await lookup("example.com")
        return [await lookup("example.com"), await lookup("example.com")]

    assert asyncio.run(scenario()) == ["ok", "ok"]
    # Premier appel en échec, deuxième exécuté et gardé, troisième servi par le cache.
    assert len(calls) == 2


@pytest.mark.parametrize(
    "failure",
    [
        {"measured": False, "error": "délai dépassé"},
        {"error": "HTTP 503"},
        {"measured": False},
    ],
)
def test_resultat_en_erreur_non_garde(clock, failure):
    """Contrat des modules : un dict dont `error` est renseigné ou `measured` faux est un échec."""
    results = iter([failure, {"measured": True, "error": None, "ports": [443]}])
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        return next(results)

    async def scenario():
        return [await lookup("example.com"), await lookup("example.com"), await lookup("example.com")]

    first, second, third = asyncio.run(scenario())

    assert first == failure
    assert second == third == {"measured": True, "error": None, "ports": [443]}
    assert len(calls) == 2


@pytest.mark.parametrize("value", [None, 0, "", [], {}, {"measured": True, "error": None}, {"error": ""}])
def test_resultats_vides_ou_sans_erreur_gardes(clock, value):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        return value

    async def scenario():
        return [await lookup("example.com"), await lookup("example.com")]

    assert asyncio.run(scenario()) == [value, value]
    assert len(calls) == 1


def test_resultat_non_copiable_non_garde(clock):
    """Un objet qu'on ne peut pas copier n'est jamais partagé entre appelants : rien n'est gardé."""
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        return threading.Lock()

    async def scenario():
        return [await lookup("example.com"), await lookup("example.com")]

    first, second = asyncio.run(scenario())

    assert len(calls) == 2
    assert first is not second


# =============================================================================
# Vidage
# =============================================================================


def test_clear_cache_vide_toutes_les_fonctions(clock):
    calls = []

    @cache.cached(60)
    async def first(key):
        calls.append(("first", key))

    @cache.cached(60)
    async def second(key):
        calls.append(("second", key))

    async def scenario():
        for _ in range(2):
            await first("a")
            await second("a")
        cache.clear_cache()
        await first("a")
        await second("a")

    asyncio.run(scenario())

    assert calls == [("first", "a"), ("second", "a")] * 2


def test_cache_clear_d_une_seule_fonction(clock):
    calls = []

    @cache.cached(60)
    async def first(key):
        calls.append(("first", key))

    @cache.cached(60)
    async def second(key):
        calls.append(("second", key))

    async def scenario():
        await first("a")
        await second("a")
        first.cache_clear()
        await first("a")
        await second("a")

    asyncio.run(scenario())

    assert calls == [("first", "a"), ("second", "a"), ("first", "a")]


def test_vidage_pendant_un_calcul_le_resultat_n_est_pas_garde(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        await gate.wait()
        return len(calls)

    async def scenario():
        nonlocal gate
        gate = asyncio.Event()
        running = asyncio.ensure_future(lookup("example.com"))
        await asyncio.sleep(0)
        cache.clear_cache()
        gate.set()
        first = await running
        return first, await lookup("example.com")

    gate = None
    # Le premier calcul a démarré avant le vidage : son résultat est rendu mais pas gardé.
    assert asyncio.run(scenario()) == (1, 2)


# =============================================================================
# Clé : arguments
# =============================================================================


def test_cle_selon_la_signature(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain, timeout=None):
        calls.append((domain, timeout))

    async def scenario():
        await lookup("example.com")
        await lookup(domain="example.com")
        await lookup("example.com", None)
        await lookup("example.com", timeout=None)
        await lookup("example.com", timeout=5)

    asyncio.run(scenario())

    assert calls == [("example.com", None), ("example.com", 5)]


def test_cle_distingue_les_types(clock):
    """1, 1.0 et True sont égaux pour Python : pas pour le cache."""
    calls = []

    @cache.cached(60)
    async def lookup(value):
        calls.append(value)

    async def scenario():
        for value in (1, True, 1.0, "1", b"1", 1):
            await lookup(value)

    asyncio.run(scenario())

    assert calls == [1, True, 1.0, "1", b"1"]


def test_arguments_conteneurs_hachables_apres_conversion(clock):
    calls = []

    @cache.cached(60)
    async def lookup(names, options):
        calls.append((names, options))

    async def scenario():
        await lookup(["a", "b"], {"deep": [1, 2], "ports": {80, 443}})
        await lookup(["a", "b"], {"ports": {443, 80}, "deep": [1, 2]})  # même contenu, autre ordre
        await lookup(("a", "b"), {"deep": [1, 2], "ports": {80, 443}})  # tuple, pas liste
        await lookup(["a", "b", "c"], {})

    asyncio.run(scenario())

    assert len(calls) == 3


def test_arguments_sans_forme_hachable_appel_direct(clock):
    class Unhashable:
        __hash__ = None

    calls = []

    @cache.cached(60)
    async def lookup(value):
        calls.append(value)
        return len(calls)

    async def scenario():
        return [await lookup(Unhashable()), await lookup(Unhashable())]

    # Aucune erreur : la fonction s'exécute à chaque fois, rien n'est gardé.
    assert asyncio.run(scenario()) == [1, 2]


def test_appel_invalide_signale_par_la_fonction(clock):
    @cache.cached(60)
    async def lookup(domain):
        return domain

    async def scenario():
        with pytest.raises(TypeError, match="lookup"):
            await lookup()
        with pytest.raises(TypeError, match="lookup"):
            await lookup("a", "b")

    asyncio.run(scenario())


def test_ignore_ecarte_des_parametres_de_la_cle(clock):
    class Client:
        pass

    calls = []

    @cache.cached(60, ignore=("client",))
    async def lookup(client, domain):
        calls.append(client)
        return domain

    async def scenario():
        first, second = Client(), Client()
        await lookup(first, "example.com")
        await lookup(second, "example.com")
        await lookup(second, "example.org")

    asyncio.run(scenario())

    assert len(calls) == 2  # un client différent ne change pas la clé


def test_ignore_invalide():
    async def lookup(domain):
        return domain

    with pytest.raises(ValueError, match="inconnu.*client"):
        cache.cached(60, ignore=("client",))(lookup)
    with pytest.raises(ValueError, match="tuple"):
        cache.cached(60, ignore="domain")


def test_scope_ajoute_une_valeur_lue_a_chaque_appel_a_la_cle(clock):
    """Même argument, contexte différent : deux entrées ; même contexte : une seule."""
    scope = ["a"]
    calls = []

    @cache.cached(60, scope=lambda: scope[0])
    async def lookup(domain):
        calls.append((scope[0], domain))
        return len(calls)

    async def scenario():
        first = await lookup("example.com")
        again = await lookup("example.com")
        scope[0] = "b"
        other = await lookup("example.com")
        scope[0] = "a"
        back = await lookup("example.com")  # l'entrée du premier contexte est toujours là
        return first, again, other, back

    assert asyncio.run(scenario()) == (1, 1, 2, 1)
    assert calls == [("a", "example.com"), ("b", "example.com")]


def test_scope_calculs_en_cours_distincts(clock):
    """Un calcul lancé dans un contexte n'est jamais repris par un appel d'un autre contexte (il garde le sien)."""
    context = contextvars.ContextVar("contexte", default="sans proxy")
    started = []

    @cache.cached(60, scope=context.get)
    async def lookup(domain):
        started.append(context.get())
        await asyncio.sleep(0.01)
        return context.get()

    async def call_in(value):
        context.set(value)  # propre à la tâche : gather en crée une par appel
        return await lookup("example.com")

    async def scenario():
        return await asyncio.gather(call_in("sans proxy"), call_in("avec proxy"), call_in("avec proxy"))

    results = asyncio.run(scenario())

    assert results == ["sans proxy", "avec proxy", "avec proxy"]
    # Un calcul par contexte : le troisième appel rejoint celui du deuxième.
    assert sorted(started) == ["avec proxy", "sans proxy"]


def test_scope_sans_forme_hachable_appel_direct(clock):
    calls = []

    @cache.cached(60, scope=lambda: bytearray(b"proxy"))  # un bytearray n'est pas hachable
    async def lookup(domain):
        calls.append(domain)

    async def scenario():
        await lookup("example.com")
        await lookup("example.com")

    asyncio.run(scenario())

    assert calls == ["example.com", "example.com"]  # contexte non hachable : jamais de cache


def test_scope_invalide():
    async def lookup(domain):
        return domain

    with pytest.raises(ValueError, match="scope"):
        cache.cached(60, scope="proxy")(lookup)


# =============================================================================
# Résultats indépendants
# =============================================================================


def test_chaque_appelant_recoit_sa_copie(clock):
    @cache.cached(60)
    async def lookup(domain):
        return {"domain": domain, "records": ["A"]}

    async def scenario():
        first = await lookup("example.com")
        first["records"].append("modifié par l'appelant")
        first["extra"] = True
        second = await lookup("example.com")
        second["records"].clear()
        return first, second, await lookup("example.com")

    first, second, third = asyncio.run(scenario())

    assert third == {"domain": "example.com", "records": ["A"]}
    assert first["extra"] is True and second == {"domain": "example.com", "records": []}


# =============================================================================
# Appels simultanés, annulation
# =============================================================================


def test_appels_simultanes_un_seul_calcul(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        rank = len(calls)
        await asyncio.sleep(0.05)
        return {"domain": domain, "rank": rank}

    async def scenario():
        return await asyncio.gather(*(lookup("example.com") for _ in range(8)), lookup("example.org"))

    results = asyncio.run(scenario())

    assert calls == ["example.com", "example.org"]
    assert results[:8] == [{"domain": "example.com", "rank": 1}] * 8
    # Copies distinctes, pas un même objet partagé.
    assert len({id(result) for result in results[:8]}) == 8


def test_echec_partage_puis_nouvel_essai(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        await asyncio.sleep(0.02)
        if len(calls) == 1:
            raise ConnectionError("API injoignable")
        return "ok"

    async def scenario():
        failed = await asyncio.gather(*(lookup("example.com") for _ in range(3)), return_exceptions=True)
        return failed, await lookup("example.com")

    failed, retry = asyncio.run(scenario())

    assert all(isinstance(error, ConnectionError) for error in failed)
    assert retry == "ok"
    assert len(calls) == 2  # un seul calcul pour les trois appelants, puis une nouvelle tentative


def test_annuler_un_appelant_n_interrompt_pas_les_autres(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        await asyncio.sleep(0.05)
        return "ok"

    async def scenario():
        first = asyncio.ensure_future(lookup("example.com"))
        second = asyncio.ensure_future(lookup("example.com"))
        await asyncio.sleep(0.01)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        return await second

    assert asyncio.run(scenario()) == "ok"
    assert calls == ["example.com"]


def test_calcul_termine_et_garde_meme_si_tous_les_appelants_sont_annules(clock):
    calls = []

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        await asyncio.sleep(0.05)
        return "ok"

    async def scenario():
        caller = asyncio.ensure_future(lookup("example.com"))
        await asyncio.sleep(0.01)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        await asyncio.sleep(0.1)  # le calcul s'achève et garde son résultat
        return await lookup("example.com")

    assert asyncio.run(scenario()) == "ok"
    assert calls == ["example.com"]


def test_exception_d_un_calcul_abandonne_n_est_pas_signalee(clock, caplog):
    """Sans appelant pour la lire, l'exception ne doit pas finir en « Task exception was never retrieved »."""

    @cache.cached(60)
    async def lookup(domain):
        await asyncio.sleep(0.02)
        raise ConnectionError("API injoignable")

    async def scenario():
        caller = asyncio.ensure_future(lookup("example.com"))
        await asyncio.sleep(0.005)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        await asyncio.sleep(0.05)

    with caplog.at_level(logging.ERROR, logger="asyncio"):
        asyncio.run(scenario())
        gc.collect()
    assert "never retrieved" not in caplog.text


def test_threads_et_boucles_distinctes(clock):
    """Chaque thread a sa boucle : pas de verrou asyncio partagé, aucun conflit."""
    calls = []
    errors = []
    start = threading.Barrier(6)

    @cache.cached(60)
    async def lookup(domain):
        calls.append(domain)
        await asyncio.sleep(0.02)
        return {"domain": domain}

    def worker():
        try:
            start.wait(timeout=5)
            for _ in range(3):
                assert asyncio.run(lookup("example.com")) == {"domain": "example.com"}
        except BaseException as e:  # remonté au thread principal
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    executed = len(calls)
    assert 1 <= executed <= 6  # au plus un calcul par thread, les boucles ne se partagent rien
    assert asyncio.run(lookup("example.com")) == {"domain": "example.com"}
    assert len(calls) == executed  # désormais servi par le cache


# =============================================================================
# Borne du cache
# =============================================================================


def test_borne_retire_l_entree_la_plus_proche_de_l_echeance(clock):
    calls = []

    @cache.cached(100, max_entries=2)
    async def lookup(key):
        calls.append(key)

    async def scenario():
        await lookup("a")
        clock.advance(10)
        await lookup("b")
        clock.advance(10)
        await lookup("c")  # plein : « a » (échéance la plus proche) part
        calls.clear()
        await lookup("b")
        await lookup("c")
        await lookup("a")

    asyncio.run(scenario())

    assert calls == ["a"]


def test_borne_retire_d_abord_les_entrees_expirees(clock):
    calls = []

    @cache.cached(100, max_entries=2)
    async def lookup(key):
        calls.append(key)

    async def scenario():
        await lookup("a")
        clock.advance(50)
        await lookup("b")
        clock.advance(70)  # « a » est expiré, « b » valable encore 30 s
        await lookup("c")
        calls.clear()
        await lookup("b")
        await lookup("c")

    asyncio.run(scenario())

    assert calls == []


# =============================================================================
# Validation
# =============================================================================


@pytest.mark.parametrize("ttl", [0, -1, True, False, None, "60", float("inf"), float("nan"), [60]])
def test_duree_invalide(ttl):
    with pytest.raises(ValueError, match="Durée de cache invalide"):
        cache.cached(ttl)


@pytest.mark.parametrize("max_entries", [0, -3, True, 2.5, None])
def test_borne_invalide(max_entries):
    with pytest.raises(ValueError, match="Borne du cache invalide"):
        cache.cached(60, max_entries=max_entries)


def test_fonction_synchrone_refusee():
    with pytest.raises(TypeError, match="async"):
        cache.cached(60)(lambda domain: domain)


def test_metadonnees_conservees():
    @cache.cached(60)
    async def lookup(domain):
        """Interroge l'API."""

    assert lookup.__name__ == "lookup"
    assert lookup.__doc__ == "Interroge l'API."
    assert inspect.iscoroutinefunction(lookup)
    assert lookup.__wrapped__.__name__ == "lookup"
