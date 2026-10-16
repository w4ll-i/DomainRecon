# =============================================================================
# DomainRecon - Modèles SQLAlchemy
# =============================================================================

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, CheckConstraint, Column, DateTime, Float, Integer, String, Text, true

from .database import Base


def utcnow() -> datetime:
    """Horodatage UTC naïf, le format de stockage de la base.

    La colonne est un DateTime sans fuseau : on y écrit toujours de l'UTC naïf.
    Une valeur avec fuseau serait convertie par PostgreSQL dans le fuseau de la
    session avant d'être tronquée, d'où des heures décalées. L'API remet le
    fuseau UTC à la lecture (voir `main.as_utc`).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Scan(Base):
    """Table des scans de domaines."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    dns_records = Column(JSON, nullable=True)
    subdomains = Column(JSON, nullable=True)
    security_headers = Column(JSON, nullable=True)
    whois_data = Column(JSON, nullable=True)
    geo_data = Column(JSON, nullable=True)
    tls_certificate = Column(JSON, nullable=True)
    open_ports = Column(JSON, nullable=True)
    technologies = Column(JSON, nullable=True)
    email_security = Column(JSON, nullable=True)
    waf = Column(JSON, nullable=True)
    redirect_chain = Column(JSON, nullable=True)
    web_files = Column(JSON, nullable=True)
    cookie_security = Column(JSON, nullable=True)
    cors = Column(JSON, nullable=True)
    # Attribut aligné sur la clé du résultat de scan et de l'API ; la colonne
    # garde son nom historique pour les bases existantes.
    reverse_dns = Column("reverse_dns_data", JSON, nullable=True)
    subdomain_takeover = Column(JSON, nullable=True)
    # v3.1 — Réseau étendu et score de sécurité
    network_extended = Column(JSON, nullable=True)
    security_score = Column(JSON, nullable=True)
    # v2 — Stockage générique : {nom_module: {status, data, duration, error}} pour
    # les modules du registre, qui n'écrivent que dans cette colonne. NULL pour un
    # scan d'avant la v2 : ses résultats sont dans les colonnes ci-dessus, lues en
    # priorité. none_as_null : None s'enregistre en NULL SQL, pas en JSON « null ».
    # Ajoutée aux bases existantes au démarrage (database.sync_schema).
    modules = Column(JSON(none_as_null=True), nullable=True)
    # v2 — Profil du scan (rapide, complet ou personnalise : scanner/registry.py) et noms
    # des modules lancés, dans l'ordre d'exécution. NULL pour un scan d'avant la v2 (ou
    # lancé sans profil, par POST /api/scan) : la liste des modules est alors inconnue.
    # Ajoutées aux bases existantes au démarrage (database.sync_schema).
    profile = Column(Text, nullable=True)
    modules_launched = Column(JSON(none_as_null=True), nullable=True)
    # v3.1 — Traçabilité de l'exécution du scan
    module_status = Column(JSON, nullable=True)
    scan_duration = Column(Float, nullable=True)
    screenshot_path = Column(String(500), nullable=True)
    tags = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    # Indexé : l'historique et la timeline trient sur cette colonne.
    scan_timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)
    status = Column(String(50), default="success", nullable=False)
    error_message = Column(Text, nullable=True)

    def __repr__(self):
        return f"<Scan(id={self.id}, domain='{self.domain}')>"


# Délais par défaut (secondes) des profils « complet » et « rapide ».
DEFAULT_SCAN_TIMEOUT = 60
DEFAULT_QUICK_TIMEOUT = 30

# Colonnes de Settings qui portent une clé API (ou l'identifiant qui l'accompagne) :
# toujours chiffrées (core/crypto.py) avant d'être enregistrées. Ces noms sont
# ceux que les modules à clé API déclarent (ModuleSpec.keys). Toute autre clé
# déclarée par un module est rangée, chiffrée elle aussi, dans extra_secrets.
SECRET_FIELDS = (
    "shodan_key",
    "virustotal_key",
    "censys_id",
    "censys_secret",
    "abuseipdb_key",
    "urlscan_key",
    "otx_key",
    "safebrowsing_key",
    "securitytrails_key",
    "builtwith_key",
    "circl_user",
    "circl_password",
    "intelx_key",
    "github_token",
)


class Settings(Base):
    """Réglages de l'application : table à une seule ligne (id = 1)."""

    __tablename__ = "settings"
    # Une seule ligne : la base refuse elle-même un autre identifiant.
    __table_args__ = (CheckConstraint("id = 1", name="ck_settings_singleton"),)

    id = Column(Integer, primary_key=True, autoincrement=False, default=1)

    # Clés API, chiffrées (voir SECRET_FIELDS) ; NULL : non renseignée.
    shodan_key = Column(Text, nullable=True)
    virustotal_key = Column(Text, nullable=True)
    censys_id = Column(Text, nullable=True)
    censys_secret = Column(Text, nullable=True)
    abuseipdb_key = Column(Text, nullable=True)
    urlscan_key = Column(Text, nullable=True)
    otx_key = Column(Text, nullable=True)
    safebrowsing_key = Column(Text, nullable=True)
    securitytrails_key = Column(Text, nullable=True)
    builtwith_key = Column(Text, nullable=True)
    circl_user = Column(Text, nullable=True)
    circl_password = Column(Text, nullable=True)
    intelx_key = Column(Text, nullable=True)
    github_token = Column(Text, nullable=True)

    # Délais (secondes) des profils « complet » et « rapide » : l'orchestrateur en
    # borne le délai de chaque module ; les valeurs par défaut côté base permettent
    # d'ajouter ces colonnes à une table existante.
    scan_timeout = Column(
        Integer, nullable=False, default=DEFAULT_SCAN_TIMEOUT, server_default=str(DEFAULT_SCAN_TIMEOUT)
    )
    quick_timeout = Column(
        Integer, nullable=False, default=DEFAULT_QUICK_TIMEOUT, server_default=str(DEFAULT_QUICK_TIMEOUT)
    )
    # Capture d'écran de la cible (Chromium) activée.
    screenshot_enabled = Column(Boolean, nullable=False, default=True, server_default=true())
    # Proxy sortant (http://, https://, socks5://, socks5h://), chiffré comme les clés
    # API (il peut porter des identifiants : http://utilisateur:mdp@hôte) ; NULL : aucun.
    # Une valeur sans préfixe « enc:v1: » est un ancien texte en clair, encore lisible.
    proxy_url = Column(Text, nullable=True)
    # Clés API déclarées par les modules hors des 14 colonnes ci-dessus (ApiKey de
    # scanner/keys.py) : {nom: valeur chiffrée « enc:v1:… »} ; NULL : aucune.
    # Ajoutée aux bases existantes au démarrage (database.sync_schema).
    extra_secrets = Column(JSON(none_as_null=True), nullable=True)

    def __repr__(self):
        # Jamais les clés, même chiffrées.
        return f"<Settings(id={self.id})>"
