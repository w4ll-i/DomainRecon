# backend/app/scanners/subdomain_bruteforce.py
"""
Active subdomain enumeration via DNS brute-force.

Uses dnspython (dns.resolver) with Google and Cloudflare public nameservers.
DNS lookups are blocking calls run inside a thread-pool executor in batches
of 50 to avoid overwhelming the resolver or the event loop.

No external API required.
"""
import asyncio
import dns.resolver

_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
_TIMEOUT = 3      # seconds per query attempt
_LIFETIME = 5     # total seconds before giving up on a query
_BATCH_SIZE = 50  # concurrent queries per asyncio.gather batch

_WORDLIST = [
    "www", "mail", "ftp", "remote", "vpn", "api", "dev", "staging", "test",
    "beta", "cdn", "static", "assets", "admin", "portal", "webmail", "blog",
    "shop", "store", "help", "support", "docs", "auth", "login", "dashboard",
    "app", "mobile", "m", "img", "images", "media", "files", "backup", "db",
    "mysql", "ns1", "ns2", "mx", "smtp", "pop", "imap", "autodiscover",
    "autoconfig", "cpanel", "whm", "plesk", "git", "gitlab", "jenkins",
    "jira", "confluence", "grafana", "kibana", "elasticsearch", "redis",
    "mongo", "postgres", "phpmyadmin", "adminer", "api-dev", "api-staging",
    "api-v1", "api-v2", "dev-api", "staging-api", "test-api", "internal",
    "intranet", "vpn2", "office", "remote2", "cloud", "cdn2", "media2",
    "static2", "new", "old", "v1", "v2", "beta2", "alpha", "preview", "demo",
    "sandbox", "local", "prod", "production", "stage", "preprod", "qa", "uat",
    "review", "web", "www2", "web2", "monitoring", "nagios", "zabbix",
    "netdata", "prometheus", "alertmanager", "wiki", "forum", "forum2",
    "community", "social", "video", "live", "stream", "download", "downloads",
    "update", "updates", "releases", "assets2", "resources", "payment", "pay",
    "checkout", "cart", "invoice", "billing", "account", "accounts", "secure",
    "safe", "trust", "policy", "legal", "terms", "privacy", "status",
    "statuspage", "uptime", "health", "ping", "heartbeat", "test2", "testing",
    "develop", "development", "developer", "developers", "eng", "engineering",
    "data", "analytics", "reports", "stats", "metrics", "logs", "logger",
    "search", "index", "home", "welcome", "landing", "contact", "about",
    "news", "events", "calendar", "schedule", "booking", "reservation", "hr",
    "erp", "crm", "helpdesk", "ticket", "tickets", "service", "services",
    "sharepoint", "exchange", "teams", "skype", "zoom", "docker", "k8s",
    "kubernetes", "registry", "nexus", "sonar", "sonarqube", "proxy",
    "gateway", "lb", "loadbalancer", "balancer", "haproxy", "nginx", "fw",
    "firewall", "switch", "router", "wap", "wireless", "hidden", "secret",
    "private", "restricted", "protected", "locked", "owa", "autodiscover",
    "lyncdiscover", "origin", "edge", "relay", "bounce", "outbound", "inbound",
]

_CLOUD_NATIVE = [
    "eks", "gke", "aks", "lambda", "functions", "serverless",
    "eu", "us-east", "ap", "us-west", "eu-west", "ap-southeast",
    "microservice", "svc", "ingress", "proxy2", "lb2",
    "argocd", "helm", "harbor", "nexus", "artifactory", "sonar2",
    "vault", "consul", "nomad", "terraform", "ansible",
    "celery", "rabbitmq", "kafka", "nats",
    "payments", "billing2", "invoicing", "subscriptions",
    "notifications", "alerts", "webhooks", "callbacks",
    "onboarding", "signup", "oauth", "sso2",
    "profile", "account2", "preferences",
]


# ─── DNS probe ───────────────────────────────────────────────────────────────

def _resolve_a(fqdn: str) -> dict | None:
    """
    Synchronous A-record lookup for *fqdn*.
    Returns {"subdomain": fqdn, "ips": [...]} on success, None otherwise.
    Designed to run inside a thread-pool executor.
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = _NAMESERVERS
    resolver.timeout = _TIMEOUT
    resolver.lifetime = _LIFETIME

    try:
        answers = resolver.resolve(fqdn, "A")
        ips = [rdata.address for rdata in answers]
        if ips:
            return {"subdomain": fqdn, "ips": ips}
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        Exception,
    ):
        pass
    return None


# ─── Batch executor ──────────────────────────────────────────────────────────

async def _probe_batch(loop: asyncio.AbstractEventLoop, fqdns: list[str]) -> list[dict]:
    """Resolve a batch of FQDNs concurrently using the thread pool."""
    tasks = [loop.run_in_executor(None, _resolve_a, fqdn) for fqdn in fqdns]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    found = []
    for r in results:
        if isinstance(r, dict) and r is not None:
            found.append(r)
    return found


# ─── Main scanner ────────────────────────────────────────────────────────────

async def bruteforce_subdomains(domain: str) -> dict:
    """
    Brute-force subdomain enumeration for *domain* using the embedded wordlist.

    DNS queries run in a thread-pool executor in batches of _BATCH_SIZE to
    avoid overwhelming the resolver. Never raises — all exceptions are caught.

    Returns a dict with subdomains_found, count, and wordlist_size.
    Deduplication against passive-scan results is expected to happen upstream
    in scanner.py.
    """
    empty: dict = {
        "enriched": False,
        "subdomains_found": [],
        "count": 0,
        "wordlist_size": len(_WORDLIST),
    }

    try:
        loop = asyncio.get_event_loop()
        domain = domain.strip().lower()

        # Wildcard pre-check: if random label resolves, DNS wildcards are enabled
        import random
        import string
        rand_label = "".join(random.choices(string.ascii_lowercase, k=32))
        try:
            probe_result = await asyncio.wait_for(
                loop.run_in_executor(None, _resolve_a, f"{rand_label}.{domain}"),
                timeout=5.0
            )
            if probe_result is not None:
                return {
                    "enriched": False,
                    "wildcard_detected": True,
                    "subdomains_found": [],
                    "count": 0,
                    "wordlist_size": 0,
                }
        except Exception:
            pass

        # Build the full candidate list (deduplicate wordlist entries)
        name = domain.split(".")[0]
        _dynamic = [
            f"api-{name}", f"{name}-api", f"{name}-dev", f"{name}-staging",
            f"{name}-prod", f"v2-{name}", f"{name}-app", f"{name}-web",
            f"{name}-service", f"{name}-internal",
        ]
        seen_words: set[str] = set()
        candidates: list[str] = []
        for word in _WORDLIST + _CLOUD_NATIVE:
            word = word.strip()
            if word and word not in seen_words:
                seen_words.add(word)
                candidates.append(f"{word}.{domain}")
        for fqdn in _dynamic:
            if fqdn not in seen_words:
                seen_words.add(fqdn)
                candidates.append(fqdn)

        found: list[dict] = []

        # Process in batches
        for start in range(0, len(candidates), _BATCH_SIZE):
            batch = candidates[start: start + _BATCH_SIZE]
            batch_results = await _probe_batch(loop, batch)
            found.extend(batch_results)

        return {
            "enriched": len(found) > 0,
            "subdomains_found": found,
            "count": len(found),
            "wordlist_size": len(candidates),
        }

    except Exception:
        return empty
