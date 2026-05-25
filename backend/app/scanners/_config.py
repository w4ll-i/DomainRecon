# backend/app/scanners/_config.py

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    465, 587, 993, 995,                          # Mail TLS
    1433, 1521,                                   # MSSQL, Oracle
    2375, 2376,                                   # Docker (cleartext/TLS)
    3000, 3001,                                   # Node.js / Grafana
    3306, 3389,                                   # MySQL, RDP
    4848,                                         # GlassFish admin
    5000, 5001,                                   # Flask / Docker registry
    5432, 5900,                                   # PostgreSQL, VNC
    6379, 6380,                                   # Redis
    7001, 7002,                                   # WebLogic
    8000, 8001, 8080, 8081, 8443, 8888,          # Alt-HTTP
    8500,                                         # Consul
    9000, 9200, 9300,                             # PHP-FPM, Elasticsearch
    11211,                                        # Memcached
    27017, 27018,                                 # MongoDB
    50000,                                        # SAP / Jenkins
]

DKIM_SELECTORS = [
    # Generic
    "default", "dkim", "mail", "email", "key1", "key2",
    # Google Workspace
    "google", "google2048",
    # Microsoft 365
    "selector1", "selector2",
    # SendGrid
    "s1", "s2", "sm",
    # Mailchimp / Mandrill
    "k1", "k2", "mandrill",
    # Mailgun
    "mg", "mta",
    # Amazon SES
    "amazonses",
    # Other providers
    "sendgrid", "smtp", "zoho", "pm", "mxvault",
    "sig1", "sig2", "mimecast", "protonmail",
]

JS_SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}",
    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}",
    r"(?i)(secret|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}",
    r"(?i)Bearer\s+[a-zA-Z0-9\-_\.]{20,}",
]

DNSBL_SERVERS = [
    # Spamhaus
    "zen.spamhaus.org",
    "sbl.spamhaus.org",
    "xbl.spamhaus.org",
    "pbl.spamhaus.org",
    "dbl.spamhaus.org",
    # SpamCop
    "bl.spamcop.net",
    # SORBS
    "dnsbl.sorbs.net",
    "spam.sorbs.net",
    "http.dnsbl.sorbs.net",
    # Barracuda
    "b.barracudacentral.org",
    # UCEPROTECT
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    # Passive Spam Block List
    "psbl.surriel.com",
    # Mailspike (reputation - also whitelist)
    "bl.mailspike.net",
    # NordSpam
    "ix.dnsbl.manitu.net",
    # DRONEBL
    "dnsbl.dronebl.org",
]

SUBDOMAIN_WORDLIST = [
    # Common services
    "www", "www2", "www3", "mail", "webmail", "smtp", "pop", "imap",
    "ftp", "sftp", "ssh", "vpn", "remote",
    # Infrastructure
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay", "gateway", "proxy",
    # CDN / assets
    "cdn", "static", "media", "img", "images", "assets", "files",
    "download", "upload", "storage", "s3", "blob",
    # Environments
    "dev", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "prod", "production", "beta", "alpha", "demo", "sandbox",
    "preview", "preprod", "pre-prod",
    # Applications
    "app", "app1", "app2", "api", "api2", "v1", "v2", "v3",
    "mobile", "m", "ios", "android",
    # Admin / management
    "admin", "administrator", "portal", "manage", "management",
    "dashboard", "panel", "control", "console",
    "cpanel", "whm", "plesk", "webdisk", "directadmin",
    # Monitoring / ops
    "monitor", "monitoring", "status", "health", "metrics",
    "logs", "log", "analytics", "grafana", "kibana",
    "prometheus", "elastic", "elasticsearch", "logstash",
    # CI/CD / DevOps
    "git", "gitlab", "github", "bitbucket",
    "jenkins", "ci", "cd", "build", "deploy", "runner",
    "registry", "docker", "k8s", "kubernetes", "cluster",
    "vault", "consul", "nomad",
    # Database
    "db", "database", "mysql", "postgres", "redis",
    "mongo", "mongodb", "sql", "oracle",
    # Communication
    "chat", "slack", "jira", "confluence", "wiki", "docs",
    "forum", "blog", "news", "support", "help", "desk", "ticket",
    # E-commerce
    "shop", "store", "cart", "checkout", "payment", "billing",
    "pay", "order", "orders",
    # Auth
    "auth", "login", "signin", "sso", "oauth", "id", "accounts",
    "identity", "idp", "saml",
    # Exchange / email
    "exchange", "owa", "autodiscover", "autoconfig",
    # Geographic / misc
    "corp", "office", "intranet", "internal", "external",
    "en", "fr", "de", "es", "jp", "cn", "us", "uk", "eu",
    "old", "new", "backup", "bak",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/wp-admin", "/wp-login.php", "/backend", "/manage",
    "/dashboard", "/panel", "/control", "/cpanel",
    "/phpmyadmin", "/pma", "/myadmin", "/dbadmin",
    "/manager", "/management", "/console", "/system",
    "/login", "/signin", "/auth/login", "/user/login",
    "/cms", "/joomla/administrator", "/drupal/admin",
    "/api/v1/admin", "/api/admin",
    "/sitemanager", "/filemanager", "/webadmin",
    "/adm", "/adm/", "/administration",
    # NOTE: /.env, /.git/config, /config, /settings are sensitive files, NOT admin panels.
    # They are probed by check_web_files() in web.py - do NOT duplicate here.
]

WEAK_CIPHERS = [
    "RC4", "RC2", "DES", "3DES", "NULL",
    "EXPORT", "anon", "ADH", "AECDH",
    "MD5", "SHA1",   # SHA1 in cipher name (not cert sig)
    "PSK", "SRP",    # legacy key exchange
]

TYPO_SUBSTITUTIONS = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
}

TYPO_TLDS = [".com", ".net", ".org", ".info", ".biz", ".co"]

PRIVATE_IP_PATTERNS = [
    r"^10\.",
    r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"^192\.168\.",
    r"^127\.",
    r"^::1$",
    r"^fc",
    r"^fd",
    r"^169\.254\.",   # link-local
    r"^0\.",          # this network
]
