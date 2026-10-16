# =============================================================================
# DomainRecon - Notifications : centre, canaux externes et envoi des alertes
# =============================================================================
# Modules :
#   models.py    tables « notifications » (centre) et « notify_channels » ;
#   channels.py  canaux : Discord, Slack, Teams, webhook JSON, e-mail SMTP, bureau ;
#   store.py     configuration des canaux (secrets chiffrés) et centre de notifications ;
#   dispatch.py  envoi d'une alerte au centre et aux canaux choisis ;
#   routes.py    routes /api/notifications et /api/notify.
# =============================================================================
