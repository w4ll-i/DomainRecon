# =============================================================================
# DomainRecon - Surveillance : tableau de bord, comparaison, scans en lot, planification
# =============================================================================
# Modules :
#   models.py     table des surveillances ;
#   scorefmt.py   note et score tels que l'interface les affiche ;
#   compare.py    différences entre deux scans d'un même domaine ;
#   dashboard.py  vue d'ensemble : un élément par domaine ;
#   batches.py    scans en lot (file, concurrence limitée) ;
#   alerts.py     règles d'alerte (changement d'état seulement) ;
#   schedule.py   fréquences, échéances, réservation d'une échéance ;
#   lease.py      bail d'exécution : une surveillance n'est jamais scannée deux fois en même temps ;
#   service.py    exécution des surveillances échues (application et ligne de commande) ;
#   scheduler.py  planificateur intégré (tourne tant que l'application est ouverte) ;
#   systask.py    tâche système (schtasks / minuteur systemd --user) ;
#   routes.py     routes /api (tableau de bord, comparaison, lots, surveillances).
# Les canaux et le centre de notifications sont dans domainrecon/notify.
# =============================================================================
