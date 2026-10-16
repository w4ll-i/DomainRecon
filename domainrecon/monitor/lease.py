# =============================================================================
# DomainRecon - Surveillance : bail d'exécution d'une surveillance
# =============================================================================
# Une surveillance ne doit jamais être scannée deux fois en même temps, même par
# deux processus : le planificateur intégré du serveur (scheduler.py) et la
# commande `domainrecon monitor run-due` (tâche système) passent tous deux par
# run_due (service.py) et se partagent la même base. La réservation de l'échéance
# (schedule.claim) n'écarte que le doublon d'une même échéance : « Lancer
# maintenant » ou une échéance modifiée pendant un scan rendent la surveillance
# de nouveau échue, et un second processus la lançait alors en parallèle.
#
# Le bail est une ligne de la table watch_leases, une par surveillance :
#   - prise atomique : mise à jour conditionnelle d'un bail expiré, sinon
#     insertion ; la clé primaire départage deux processus simultanés ;
#   - expiration : un processus arrêté sans libérer son bail (plantage, arrêt
#     brutal) ne bloque la surveillance que pendant LEASE_TTL ; le bail expiré
#     est repris par le suivant ;
#   - renouvellement : tant que le scan court, hold() prolonge le bail toutes les
#     RENEW_EVERY secondes, de sorte qu'un scan long garde son bail ;
#   - libération en fin d'exécution, qu'elle réussisse, échoue ou soit annulée.
# Chaque exécution a son propre identifiant (`holder`) : elle ne renouvelle ni ne
# libère que son propre bail, jamais celui qu'une autre a repris après expiration.
# L'horloge est celle de run_due (injectable pour les tests).
# =============================================================================

import asyncio
import contextlib
import logging
import os
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from ..core.database import SessionLocal
from .models import WatchLease

logger = logging.getLogger(__name__)

# Validité d'un bail non renouvelé, et période de son renouvellement (secondes) :
# cinq renouvellements manqués avant qu'un autre processus puisse le reprendre.
LEASE_TTL = timedelta(minutes=5)
RENEW_EVERY = 60.0

Clock = Callable[[], datetime]


def new_holder() -> str:
    """Identifiant d'une exécution : numéro du processus et jeton aléatoire (deux exécutions d'un même processus diffèrent)."""
    return f"{os.getpid()}-{uuid.uuid4().hex[:24]}"


# =============================================================================
# Accès base
# =============================================================================


def acquire(db: Session, watch_id: int, holder: str, now: datetime, ttl: timedelta = LEASE_TTL) -> bool:
    """Prend le bail de la surveillance pour `holder` : vrai s'il était libre ou expiré à `now`."""
    expires_at = now + ttl
    # Bail expiré : repris par une mise à jour conditionnelle. Deux concurrents ne la gagnent
    # pas tous les deux : une fois la ligne mise à jour, elle n'est plus expirée.
    taken = (
        db.query(WatchLease)
        .filter(WatchLease.watch_id == watch_id, WatchLease.expires_at <= now)
        .update(
            {WatchLease.holder: holder, WatchLease.acquired_at: now, WatchLease.expires_at: expires_at},
            synchronize_session=False,
        )
    )
    if taken:
        db.commit()
        return True
    # Aucun bail : insertion. Si un autre l'a pris entre-temps, la clé primaire refuse la seconde.
    db.add(WatchLease(watch_id=watch_id, holder=holder, acquired_at=now, expires_at=expires_at))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return False
    return True


def renew(db: Session, watch_id: int, holder: str, now: datetime, ttl: timedelta = LEASE_TTL) -> bool:
    """Prolonge le bail de `holder` : faux s'il ne le tient plus (repris après expiration, ou supprimé)."""
    updated = (
        db.query(WatchLease)
        .filter(WatchLease.watch_id == watch_id, WatchLease.holder == holder)
        .update({WatchLease.expires_at: now + ttl}, synchronize_session=False)
    )
    db.commit()
    return updated == 1


def release(db: Session, watch_id: int, holder: str) -> bool:
    """Libère le bail de `holder` : faux s'il ne le tient plus (celui d'un autre n'est jamais touché)."""
    deleted = (
        db.query(WatchLease)
        .filter(WatchLease.watch_id == watch_id, WatchLease.holder == holder)
        .delete(synchronize_session=False)
    )
    db.commit()
    return deleted == 1


def _acquire(watch_id: int, holder: str, now: datetime, ttl: timedelta) -> bool:
    with SessionLocal() as db:
        return acquire(db, watch_id, holder, now, ttl)


def _renew(watch_id: int, holder: str, now: datetime, ttl: timedelta) -> bool:
    with SessionLocal() as db:
        return renew(db, watch_id, holder, now, ttl)


def _release(watch_id: int, holder: str) -> bool:
    with SessionLocal() as db:
        return release(db, watch_id, holder)


# =============================================================================
# Exécution : prise, renouvellement et libération
# =============================================================================


async def _renew_loop(watch_id: int, holder: str, clock: Clock, ttl: timedelta, every: float) -> None:
    """Prolonge le bail toutes les `every` secondes, jusqu'à l'annulation de la tâche ou la perte du bail."""
    while True:
        await asyncio.sleep(every)
        try:
            alive = await asyncio.to_thread(_renew, watch_id, holder, clock(), ttl)
        except Exception as exc:
            # Base occupée : le bail dure encore, nouvel essai à la période suivante.
            logger.warning(
                "Bail de la surveillance %s : renouvellement impossible (%s)", watch_id, type(exc).__name__
            )
            continue
        if not alive:
            logger.warning(
                "Bail de la surveillance %s perdu (expiré et repris, ou surveillance supprimée)", watch_id
            )
            return


async def _release_quietly(watch_id: int, holder: str) -> None:
    """Libère le bail à l'abri d'une annulation ; un échec n'est pas fatal : le bail expirera de lui-même."""
    try:
        await asyncio.shield(asyncio.to_thread(_release, watch_id, holder))
    except Exception as exc:  # jamais d'exception ici : elle masquerait l'issue de l'exécution
        logger.warning(
            "Bail de la surveillance %s : libération impossible (%s), il expirera de lui-même",
            watch_id,
            type(exc).__name__,
        )


@contextlib.asynccontextmanager
async def hold(
    watch_id: int,
    clock: Clock,
    *,
    ttl: timedelta = LEASE_TTL,
    renew_every: float = RENEW_EVERY,
) -> AsyncIterator[bool]:
    """`async with hold(id, clock) as acquired:` tient le bail de la surveillance le temps du bloc.

    `acquired` est faux si une autre exécution (de ce processus ou d'un autre) le tient : le
    bloc ne doit alors rien lancer. Tant que le bloc court, le bail est renouvelé en tâche
    de fond ; il est libéré à la sortie, quelle qu'elle soit (succès, exception, annulation).
    """
    holder = new_holder()
    acquisition = asyncio.ensure_future(asyncio.to_thread(_acquire, watch_id, holder, clock(), ttl))
    try:
        acquired = await asyncio.shield(acquisition)
    except asyncio.CancelledError:
        # Annulé pendant la prise (quelques millisecondes) : elle va au bout dans son fil, et
        # si elle aboutit, le bail est rendu tout de suite au lieu d'attendre son expiration.
        with contextlib.suppress(Exception):
            if await asyncio.shield(acquisition):
                await _release_quietly(watch_id, holder)
        raise
    except SQLAlchemyError as exc:
        # Sans bail, rien ne prouve que la surveillance est libre : elle n'est pas lancée,
        # et reste échue pour le prochain passage.
        logger.warning("Bail de la surveillance %s : prise impossible (%s)", watch_id, type(exc).__name__)
        acquired = False
    if not acquired:
        yield False
        return
    renewer = asyncio.get_running_loop().create_task(
        _renew_loop(watch_id, holder, clock, ttl, renew_every), name=f"domainrecon-lease-{watch_id}"
    )
    try:
        yield True
    finally:
        renewer.cancel()
        await _release_quietly(watch_id, holder)
