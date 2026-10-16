# =============================================================================
# DomainRecon - Module « sensitive_files » : fichiers sensibles exposés
# =============================================================================
# Recherche des fichiers qui ne devraient jamais être servis : dépôt de code
# (.git/HEAD, .git/config, .svn/entries), secrets d'environnement (.env et ses
# variantes), sauvegardes de configuration (wp-config.php.bak, config.php.bak,
# .env.bak), vidages SQL, .htaccess, phpinfo. Un simple
# code 200 ne suffit pas (faux positifs massifs sur les serveurs « fourre-tout » et
# les applications monopage), et les fichiers informatifs (humans.txt, ads.txt,
# manifest.json) relèvent de « web_files_extra ».
# Ici, un fichier n'est retenu que si son CONTENU a la signature attendue ET qu'il
# diffère de la page « introuvable » de référence. Le contenu des secrets n'est
# JAMAIS recopié dans le résultat (seule sa taille). Catégorie « actif » : chemins
# forgés au-delà d'une visite normale, autorisation de la cible requise.
# =============================================================================

import re

from ...i18n import msg
from ..impl import web_exposure as probe
from ..registry import ModuleSpec, ScanContext
from ..rules import FindingInput, FindingRule, Outcome, ScoreRule, hit
from ..score import as_dict, as_list

_GIT_HEAD = re.compile(r"^\s*(ref:\s+refs/|[0-9a-f]{40}\b)", re.IGNORECASE)
_PHP_OPEN = re.compile(r"<\?php", re.IGNORECASE)
_SQL_DUMP = re.compile(r"\b(insert\s+into|create\s+table|mysqldump|drop\s+table)\b", re.IGNORECASE)
_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.MULTILINE)
_HTACCESS = re.compile(r"\b(rewriterule|rewriteengine|<files|order\s+(allow|deny)|require\s)", re.IGNORECASE)


def _git_head(text: str) -> bool:
    return bool(_GIT_HEAD.search(text))


def _git_config(text: str) -> bool:
    return "[core]" in text.lower() or "[remote" in text.lower()


def _env(text: str) -> bool:
    # Au moins deux affectations VAR=... et pas une page HTML.
    return len(_ENV_LINE.findall(text)) >= 2 and "<html" not in text[:200].lower()


def _php_source(text: str) -> bool:
    return bool(_PHP_OPEN.search(text))


def _sql(text: str) -> bool:
    return bool(_SQL_DUMP.search(text))


def _htaccess(text: str) -> bool:
    return bool(_HTACCESS.search(text))


def _phpinfo(text: str) -> bool:
    return "phpinfo()" in text.lower() or "php version" in text.lower()


def _svn(text: str) -> bool:
    return text.lstrip()[:3].isdigit() or "svn:" in text.lower() or "dir\n" in text.lower()


def _ds_store(text: str) -> bool:
    return text[:4] == "\x00\x00\x00\x01" or "Bud1" in text[:16]


# (clé, chemin, validateur, gravité). La gravité dit l'enjeu si le fichier est lisible.
FILES: tuple[tuple[str, str, object, str], ...] = (
    ("git_head", "/.git/HEAD", _git_head, "critical"),
    ("git_config", "/.git/config", _git_config, "critical"),
    ("svn_entries", "/.svn/entries", _svn, "high"),
    ("env", "/.env", _env, "critical"),
    ("env_local", "/.env.local", _env, "critical"),
    ("env_production", "/.env.production", _env, "critical"),
    ("env_bak", "/.env.bak", _env, "critical"),
    ("wp_config_bak", "/wp-config.php.bak", _php_source, "critical"),
    ("config_php_bak", "/config.php.bak", _php_source, "high"),
    ("htaccess", "/.htaccess", _htaccess, "medium"),
    ("backup_sql", "/backup.sql", _sql, "critical"),
    ("dump_sql", "/dump.sql", _sql, "critical"),
    ("database_sql", "/database.sql", _sql, "critical"),
    ("phpinfo", "/phpinfo.php", _phpinfo, "high"),
    ("info_php", "/info.php", _phpinfo, "high"),
    ("ds_store", "/.DS_Store", _ds_store, "low"),
)

_SEVERITY = {key: severity for key, _, _, severity in FILES}
_PATH = {key: path for key, path, _, _ in FILES}


async def run(context: ScanContext) -> dict:
    home = await probe.homepage_or_fail(context)
    host = context.domain
    origin = probe.origin_of(home, host)

    async with await probe.open_client() as client:
        baseline = await probe.measure_baseline(client, origin, host)

        def handle(path, fetched, error):
            key = next(k for k, p, _, _ in FILES if p == path)
            if fetched is None:
                return {"key": key, "path": path, "found": None, "error": error}
            if fetched.status_code != 200:
                return {"key": key, "path": path, "found": False, "status_code": fetched.status_code}
            text = fetched.text
            validator = next(v for k, _, v, _ in FILES if k == key)
            if not text.strip() or baseline.same_page(text, len(fetched.body)) or not validator(text):
                return {"key": key, "path": path, "found": False, "status_code": 200}
            return {
                "key": key,
                "path": path,
                "found": True,
                "status_code": 200,
                "size": len(fetched.body),
                "severity": _SEVERITY[key],
            }

        entries = await probe.probe_paths(client, origin, host, [p for _, p, _, _ in FILES], handle)

    found = [e for e in entries if e["found"] is True]
    unverified = sum(1 for e in entries if e["found"] is None)
    return {
        "measured": True,
        "error": None,
        "url": home.url,
        "exposed": found,
        "exposed_count": len(found),
        "checked": len(FILES),
        "unverified": unverified,
        "catch_all": baseline.catch_all,
        "has_critical": any(e["severity"] == "critical" for e in found),
    }


def _exposed(f: FindingInput, severity: str) -> object:
    data = as_dict(f.data)
    files = [
        str(e.get("path"))
        for e in as_list(data.get("exposed"))
        if isinstance(e, dict) and e.get("severity") == severity
    ]
    return hit(files=", ".join(files)) if files else None


def _score(data: dict) -> Outcome:
    result = as_dict(data.get("sensitive_files"))
    exposed = as_list(result.get("exposed"))
    if not exposed:
        return Outcome(8, msg("sensitive_files.score_clean"), True)
    if result.get("has_critical") is True:
        return Outcome(0, msg("sensitive_files.score_critical"), True, cap_reason=msg("sensitive_files.cap"))
    return Outcome(3, msg("sensitive_files.score_exposed", count=len(exposed)), True)


SPEC = ModuleSpec(
    name="sensitive_files",
    family="web",
    category="actif",
    run=run,
    order=140,
    timeout=60,
    findings=(
        FindingRule(
            code="finding.sensitive_files.critical",
            severity="critical",
            check=lambda f: _exposed(f, "critical"),
        ),
        FindingRule(
            code="finding.sensitive_files.high", severity="high", check=lambda f: _exposed(f, "high")
        ),
        FindingRule(
            code="finding.sensitive_files.medium", severity="medium", check=lambda f: _exposed(f, "medium")
        ),
        FindingRule(code="finding.sensitive_files.low", severity="low", check=lambda f: _exposed(f, "low")),
    ),
    score_rules=(ScoreRule(criterion="sensitive_files", weight=8, evaluate=_score),),
)
