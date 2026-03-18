# backend/app/scanners/_config.py

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 6379, 8080, 8443, 27017,
]

DKIM_SELECTORS = [
    "default", "google", "mail", "dkim",
    "selector1", "selector2", "k1", "smtp",
]

JS_SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}",
    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}",
    r"(?i)(secret|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}",
    r"(?i)Bearer\s+[a-zA-Z0-9\-_\.]{20,}",
]

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "portal",
    "api", "dev", "staging", "test", "beta", "demo", "app", "mobile", "secure",
    "vpn", "remote", "cdn", "static", "media", "img", "images", "assets",
    "blog", "shop", "store", "help", "support", "docs", "wiki", "forum",
    "git", "gitlab", "jenkins", "ci", "build", "deploy", "monitor",
    "grafana", "kibana", "elastic", "redis", "mysql", "db", "database",
    "ns", "ns1", "ns2", "dns", "mx", "mx1", "mx2", "relay", "gateway",
    "backup", "old", "new", "v1", "v2", "internal", "external", "intranet",
    "corp", "office", "owa", "exchange", "autodiscover", "autoconfig",
    "cpanel", "whm", "plesk", "webdisk", "ftp2", "ssh", "sftp",
    "status", "health", "metrics", "logs", "analytics",
    "search", "map", "auth", "login", "sso", "oauth", "id", "accounts",
    "payment", "billing", "pay", "checkout", "cart", "order",
    "download", "upload", "files", "storage",
    "m", "en", "fr", "de", "es", "www2",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/wp-admin", "/wp-login.php", "/backend", "/manage",
    "/dashboard", "/panel", "/control", "/cpanel",
    "/phpmyadmin", "/pma", "/myadmin", "/dbadmin",
    "/manager", "/management", "/console", "/system",
    "/login", "/signin", "/auth/login", "/user/login",
    "/cms", "/joomla/administrator", "/drupal/admin",
    "/.env", "/.git/config", "/config", "/settings",
    "/api/v1/admin", "/api/admin",
]

WEAK_CIPHERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"]

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
]
