# =============================================================================
# DomainRecon - Scanner : cache en mémoire à durée de vie limitée
# =============================================================================
# @cached(ttl) garde le résultat d'une fonction async pendant `ttl` secondes,
# pour les appels aux API tierces dont la réponse change peu : plusieurs scans
# d'une même cible (ou de cibles voisines) partagent la même requête au lieu de
# la répéter, au risque de dépasser le quota du service.
#
#   SHORT_TTL  (5 min) : données volatiles (réputation) ;
#   MEDIUM_TTL (1 h)   : sous-domaines, DNS ;
#   LONG_TTL   (24 h)  : WHOIS, certificats.
#
# Règles :
#   - la clé est formée des arguments de l'appel (valeur et type), rangés selon
#     la signature de la fonction : f("a"), f(domain="a") et f("a", None) avec
#     None par défaut ne font qu'une entrée. `ignore` écarte de la clé les
#     paramètres qui ne sont pas des données (client HTTP, contexte du scan) ;
#     des arguments sans forme hachable n'empêchent pas l'appel : il se fait
#     sans cache ;
#   - `scope` ajoute à la clé une valeur lue à CHAQUE appel (et non passée en
#     argument) : le contexte du scan dont dépend la requête, tel le proxy
#     sortant (common.proxy_scope). Deux appels ne partagent un résultat, ni un
#     calcul en cours, que si leur contexte est le même ;
#   - seul un résultat sans erreur est gardé : ni une exception, ni un résultat
#     qui porte lui-même une erreur (dict dont `error` est renseigné ou dont
#     `measured` est faux, voir le contrat des modules dans orchestrator.py) ;
#   - chaque appelant reçoit sa propre copie du résultat : modifier ce qu'on
#     reçoit ne change pas ce que les suivants recevront ;
#   - des appels simultanés avec la même clé, dans une même boucle d'événements,
#     n'exécutent la fonction qu'une fois ; annuler l'un d'eux n'interrompt pas
#     le calcul des autres ;
#   - le cache vit en mémoire, par processus : vidé au redémarrage, borné
#     (`max_entries` par fonction), sûr à partir de plusieurs threads et de
#     plusieurs boucles d'événements (verrou de threading, jamais tenu pendant
#     un await : un asyncio.Lock est lié à une seule boucle).
#
# Pour des fonctions de module : sur une méthode, `self` ferait partie de la clé.
# =============================================================================

import asyncio
import copy
import functools
import inspect
import math
import threading
import time
import weakref
from collections.abc import Awaitable, Callable, Hashable
from typing import TypeVar

from .common import logger

# Durées usuelles, en secondes.
SHORT_TTL = 300
MEDIUM_TTL = 3600
LONG_TTL = 86400

# Nombre maximal de résultats gardés par fonction décorée.
DEFAULT_MAX_ENTRIES = 256

# Horloge des échéances : monotone (insensible aux changements d'heure du
# système). Les tests la remplacent pour avancer le temps.
_clock = time.monotonic

# Un seul verrou pour tous les caches : les sections critiques ne font que lire
# ou écrire des dict, en quelques microsecondes.
_lock = threading.Lock()
# Caches des fonctions décorées (références faibles : celui d'une fonction disparue disparaît).
_caches: "weakref.WeakSet[_Cache]" = weakref.WeakSet()

T = TypeVar("T")


# =============================================================================
# Clés et résultats
# =============================================================================


def _freeze(value: object) -> Hashable:
    """Forme hachable d'un argument (valeur et type) ; lève TypeError s'il n'en a pas."""
    if isinstance(value, (list, tuple)):
        return (type(value), tuple(_freeze(item) for item in value))
    if isinstance(value, (set, frozenset)):
        return (type(value), frozenset(_freeze(item) for item in value))
    if isinstance(value, dict):
        return (dict, frozenset((_freeze(name), _freeze(item)) for name, item in value.items()))
    hash(value)
    # Le type fait partie de la clé : 1, 1.0 et True sont égaux pour Python, pas pour l'appelant.
    return (type(value), value)


def _make_key(
    signature: inspect.Signature, args: tuple, kwargs: dict, ignore: frozenset[str]
) -> Hashable | None:
    """Clé d'un appel, ou None s'il n'est pas cachable (arguments invalides ou sans forme hachable)."""
    try:
        bound = signature.bind(*args, **kwargs)
    except TypeError:
        return None  # appel invalide : la fonction elle-même le signalera
    bound.apply_defaults()
    try:
        return _freeze({name: value for name, value in bound.arguments.items() if name not in ignore})
    except (TypeError, RecursionError):
        return None


def _is_failure(value: object) -> bool:
    """Résultat qui porte une erreur (contrat des modules : `error` renseigné ou `measured` faux)."""
    return isinstance(value, dict) and bool(value.get("error") or value.get("measured") is False)


def _isolate(value: object) -> object:
    """Copie indépendante d'un résultat gardé ; le résultat lui-même si l'objet ne se copie pas."""
    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _consume_exception(task: asyncio.Task) -> None:
    """Exception d'un calcul que plus personne n'attend : lue, pour qu'elle ne soit pas signalée à la fermeture.

    asyncio.shield ne s'en charge pas avant Python 3.11 (il se détache du calcul dès que son appelant est annulé).
    """
    if not task.cancelled():
        task.exception()


# =============================================================================
# Cache d'une fonction
# =============================================================================


class _Cache:
    """Résultats gardés et calculs en cours d'une fonction décorée."""

    def __init__(self, ttl: float, max_entries: int) -> None:
        self.ttl = ttl
        self.max_entries = max_entries
        # clé -> (échéance, résultat)
        self.entries: dict[Hashable, tuple[float, object]] = {}
        # clé -> calcul en cours (une tâche, liée à la boucle qui l'a lancée)
        self.pending: dict[Hashable, asyncio.Task] = {}
        # Incrémentée à chaque vidage : un calcul lancé avant ne garde pas son résultat.
        self.generation = 0

    def lookup(
        self, key: Hashable, loop: asyncio.AbstractEventLoop, start: Callable[[int], asyncio.Task]
    ) -> tuple[bool, object]:
        """(True, résultat gardé) ; sinon (False, tâche) : calcul en cours dans `loop`, ou lancé par `start`."""
        with _lock:
            entry = self.entries.get(key)
            if entry is not None:
                if _clock() < entry[0]:
                    return True, entry[1]
                del self.entries[key]
            task = self.pending.get(key)
            if task is not None and (task.done() or task.get_loop().is_closed()):
                # Reste d'une boucle fermée sans avoir fini : à oublier.
                del self.pending[key]
                task = None
            if task is not None and task.get_loop() is loop:
                return False, task
            started = start(self.generation)
            if task is None:
                self.pending[key] = started
            # Sinon le calcul d'une autre boucle reste enregistré : celui-ci se fait à part.
            return False, started

    def store(self, key: Hashable, value: object, generation: int) -> None:
        """Garde `value` jusqu'à l'échéance, sauf si le cache a été vidé depuis le début du calcul."""
        try:
            private = copy.deepcopy(value)
        except Exception as e:
            logger.debug("Cache : résultat non copiable, non gardé (%s)", type(e).__name__)
            return
        with _lock:
            if generation != self.generation:
                return
            now = _clock()
            if key not in self.entries and len(self.entries) >= self.max_entries:
                for name in [name for name, (expires, _) in self.entries.items() if expires <= now]:
                    del self.entries[name]
                if len(self.entries) >= self.max_entries:
                    # Toujours plein : la plus proche de l'échéance part.
                    del self.entries[min(self.entries, key=lambda name: self.entries[name][0])]
            self.entries[key] = (now + self.ttl, private)

    def forget(self, key: Hashable, task: asyncio.Task | None) -> None:
        """Oublie le calcul `task` de `key`, s'il est encore celui qui est enregistré."""
        with _lock:
            if self.pending.get(key) is task:
                del self.pending[key]

    def clear(self) -> None:
        with _lock:
            self.generation += 1
            self.entries.clear()
            self.pending.clear()


# =============================================================================
# Décorateur
# =============================================================================


def cached(
    ttl_seconds: float,
    *,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    ignore: tuple[str, ...] = (),
    scope: Callable[[], Hashable] | None = None,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """Décorateur : garde le résultat d'une fonction async `ttl_seconds` secondes (voir l'en-tête).

    `ignore` : noms de paramètres écartés de la clé. `scope` : fonction sans
    argument dont la valeur (hachable) s'ajoute à la clé de chaque appel.
    `wrapper.cache_clear()` vide le cache de cette seule fonction ;
    clear_cache() vide tous les caches.
    Lève ValueError si la durée, la borne, un nom de `ignore` ou `scope` est
    invalide, TypeError si la fonction décorée n'est pas async.
    """
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, (int, float))
        or not math.isfinite(ttl_seconds)
        or ttl_seconds <= 0
    ):
        raise ValueError(f"Durée de cache invalide : {ttl_seconds!r} (secondes, nombre fini > 0)")
    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
        raise ValueError(f"Borne du cache invalide : {max_entries!r} (entier >= 1)")
    if isinstance(ignore, str):
        raise ValueError(f"ignore est un tuple de noms de paramètres, pas un texte : {ignore!r}")
    if scope is not None and not callable(scope):
        raise ValueError(f"scope est une fonction sans argument, pas {scope!r}")

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        if not inspect.iscoroutinefunction(func):
            raise TypeError(f"@cached décore une fonction async, pas {func!r}")
        signature = inspect.signature(func)
        if unknown := sorted(set(ignore) - signature.parameters.keys()):
            raise ValueError(f"@cached : paramètre inconnu dans ignore : {', '.join(unknown)}")
        ignored = frozenset(ignore)
        cache = _Cache(float(ttl_seconds), max_entries)
        with _lock:
            _caches.add(cache)

        async def compute(key: Hashable, args: tuple, kwargs: dict, generation: int) -> object:
            task = asyncio.current_task()
            try:
                value = await func(*args, **kwargs)
                if not _is_failure(value):
                    cache.store(key, value, generation)
                return value
            finally:
                cache.forget(key, task)

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            key = _make_key(signature, args, kwargs, ignored)
            if key is not None and scope is not None:
                try:
                    key = (_freeze(scope()), key)
                except (TypeError, RecursionError):
                    key = None
            if key is None:
                return await func(*args, **kwargs)
            loop = asyncio.get_running_loop()

            def start(generation: int) -> asyncio.Task:
                task = loop.create_task(compute(key, args, kwargs, generation))
                task.add_done_callback(_consume_exception)
                return task

            hit, found = cache.lookup(key, loop, start)
            if hit:
                return _isolate(found)
            # shield : annuler cet appelant n'interrompt pas le calcul que d'autres attendent.
            return _isolate(await asyncio.shield(found))

        wrapper.cache_clear = cache.clear
        return wrapper

    return decorator


def clear_cache() -> None:
    """Vide les caches de toutes les fonctions décorées (tests). Un calcul en cours ne garde pas son résultat."""
    with _lock:
        caches = list(_caches)
    for cache in caches:
        cache.clear()
