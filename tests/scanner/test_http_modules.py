# =============================================================================
# DomainRecon - Tests des modules HTTP du scanner
# =============================================================================
# Aucun trafic réseau réel : httpx.MockTransport pour les réponses HTTP, DNS
# simulé pour le takeover, et un serveur local 127.0.0.1 pour la lecture bornée.
# =============================================================================

import asyncio
import time

import httpx
import pytest

from domainrecon.scanner import (
    ModuleError,
    TargetNotAllowedError,
    analyze_cookies,
    check_cors,
    check_security_headers,
    check_subdomain_takeover,
    check_web_files,
    compute_security_score,
    detect_technologies,
    detect_waf,
    evaluate_security_headers,
    trace_redirects,
)
from domainrecon.scanner import common as common_module
from domainrecon.scanner import cookies as cookies_module
from domainrecon.scanner import cors as cors_module
from domainrecon.scanner import headers as headers_module
from domainrecon.scanner import redirects as redirects_module
from domainrecon.scanner import takeover as takeover_module
from domainrecon.scanner import technologies as technologies_module
from domainrecon.scanner import tls as tls_module
from domainrecon.scanner import waf as waf_module
from domainrecon.scanner import web_files as web_files_module
from domainrecon.scanner.cookies import analyze_cookie_headers, parse_cookie_date, parse_set_cookie
from domainrecon.scanner.headers import apply_tls_verdict
from domainrecon.scanner.http_utils import MAX_REDIRECTS, describe_error, fetch, redirect_target, same_site
from rendu import fr

# Comportement des 18 modules historiques : registre ramené à eux (tests/conftest.py).
pytestmark = pytest.mark.usefixtures("registre_historique")

# =============================================================================
# Outils de test
# =============================================================================


def make_handler(routes: dict, calls: list | None = None):
    """Transport simulé : `routes` associe « schéma://hôte/chemin » à une réponse.

    Valeurs possibles : (statut, en-têtes, corps), une exception, ou une
    fonction (request) -> httpx.Response. Route absente : connexion refusée.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        key = f"{request.url.scheme}://{request.url.host}{request.url.path}"
        if calls is not None:
            calls.append((key, dict(request.headers)))
        action = routes.get(key)
        if action is None:
            raise httpx.ConnectError("Connexion refusée", request=request)
        if isinstance(action, BaseException):
            raise action
        if callable(action):
            return action(request)
        status, headers, body = action
        return httpx.Response(status, headers=headers, content=body)

    return handler


def use_transport(monkeypatch, handler, *modules):
    """Remplace le client HTTP des modules par un client sur transport simulé."""

    def factory(timeout=10.0, follow_redirects=True):
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    for module in modules:
        monkeypatch.setattr(module, "_http_client", factory)


def redirect(location: str, status: int = 301, headers: list | None = None):
    return (status, [("location", location), *(headers or [])], b"")


def run(coro):
    return asyncio.run(coro)


# =============================================================================
# http_utils : résolution des redirections, même site, lecture bornée
# =============================================================================


@pytest.mark.parametrize(
    "base, location, expected",
    [
        ("http://example.com/a/b", "//www.example.com/", "http://www.example.com/"),
        ("https://example.com/a/b", "//www.example.com/x", "https://www.example.com/x"),
        ("http://example.com/a/b", "login", "http://example.com/a/login"),
        ("http://example.com/a/b", "../x?y=1", "http://example.com/x?y=1"),
        ("http://example.com/a/b", "?page=2", "http://example.com/a/b?page=2"),
        ("http://example.com/", "https://example.com/", "https://example.com/"),
        ("http://example.com/", "  /home  ", "http://example.com/home"),
        ("http://example.com/", "javascript:alert(1)", None),
        ("http://example.com/", "ftp://example.com/f", None),
        ("http://example.com/", "", None),
        ("http://example.com/", None, None),
        ("http://example.com/", "http://[invalid/", None),
    ],
)
def test_redirect_target(base, location, expected):
    assert redirect_target(base, location) == expected


@pytest.mark.parametrize(
    "host, target, expected",
    [
        ("example.com", "example.com", True),
        ("www.example.com", "example.com", True),
        ("example.com", "blog.example.com", True),
        ("a.b.example.co.uk", "example.co.uk", True),
        ("example.com.evil.net", "example.com", False),
        ("evilexample.com", "example.com", False),
        ("example.co.uk", "other.co.uk", False),
        ("127.0.0.1", "127.0.0.1", True),
        ("127.0.0.2", "127.0.0.1", False),
        ("a.localhost", "localhost", False),
        # Section privée de la PSL : deux comptes GitHub Pages sont deux sites.
        ("bob.github.io", "alice.github.io", False),
        ("www.alice.github.io", "alice.github.io", True),
        ("", "example.com", False),
    ],
)
def test_same_site(host, target, expected):
    assert same_site(host, target) is expected


def test_fetch_corps_infini_lu_de_facon_bornee():
    """Un flux sans fin ne doit ni saturer la mémoire ni bloquer le module."""
    produced = []

    async def endless():
        while True:
            produced.append(1)
            yield b"x" * 65536

    def handler(request):
        return httpx.Response(200, content=endless())

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://example.com/", max_bytes=100_000)

    result = run(scenario())
    assert len(result.body) == 100_000
    assert result.truncated is True
    assert len(produced) <= 3


def test_fetch_redirection_hors_site_non_suivie():
    calls = []
    handler = make_handler(
        {
            "http://example.com/": redirect("https://market.example.net/lander", 302),
            "https://market.example.net/lander": (200, {}, b"parking"),
        },
        calls,
    )

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://example.com/", site="example.com")

    result = run(scenario())
    assert result.status_code == 302
    assert result.off_site_url == "https://market.example.net/lander"
    # Aucune requête n'est partie vers le site tiers.
    assert [key for key, _ in calls] == ["http://example.com/"]


def test_fetch_suit_les_redirections_relatives_du_meme_site():
    handler = make_handler(
        {
            "http://example.com/": redirect("//www.example.com/start"),
            "http://www.example.com/start": redirect("login", 302),
            "http://www.example.com/login": (200, {}, b"ok"),
        }
    )

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://example.com/", site="example.com")

    result = run(scenario())
    assert result.url == "http://www.example.com/login"
    assert result.text == "ok"
    assert [str(r.url) for r in result.history] == ["http://example.com/", "http://www.example.com/start"]


def test_fetch_boucle_de_redirections_interrompue():
    handler = make_handler({"http://example.com/": redirect("/")})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://example.com/", max_redirects=3)

    result = run(scenario())
    assert fr(result.redirect_error) == "Trop de redirections (plus de 3)"
    assert len(result.history) == 3


def test_fetch_redirection_refusee_garde_la_derniere_reponse():
    handler = make_handler(
        {
            "http://example.com/": redirect("http://intranet.example.com/", 302),
            "http://intranet.example.com/": TargetNotAllowedError("adresse privée"),
        }
    )

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://example.com/", site="example.com")

    result = run(scenario())
    assert result.status_code == 302
    assert result.history == []
    assert fr(result.redirect_error) == (
        "Redirection non suivie (http://intranet.example.com/) : adresse privée"
    )


@pytest.mark.parametrize("location", ["javascript:alert(1)", "mailto:a@example.com", "ftp://example.com/f"])
def test_fetch_location_inexploitable_ne_fait_pas_echouer_la_requete(location):
    """httpx lève InvalidURL sur ces Location, même sans suivre la redirection."""
    handler = make_handler({"http://example.com/": redirect(location, headers=[("set-cookie", "sid=1")])})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://example.com/", site="example.com")

    result = run(scenario())
    assert result.status_code == 301
    assert fr(result.redirect_error) == "Redirection vers une URL invalide ou un schéma non pris en charge"
    assert result.headers.get_list("set-cookie") == ["sid=1"]


def test_fetch_premiere_requete_en_echec_leve():
    handler = make_handler({})

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch(client, "http://example.com/")

    with pytest.raises(httpx.ConnectError):
        run(scenario())


def test_fetch_lecture_bornee_sur_serveur_local(monkeypatch):
    """Serveur local 127.0.0.1 qui envoie un corps sans fin, avec le vrai client HTTP."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n")
            while True:
                writer.write(b"<p>" + b"a" * 65536 + b"</p>")
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def scenario():
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with common_module._http_client(timeout=5.0) as client:
                return await asyncio.wait_for(
                    fetch(client, f"http://127.0.0.1:{port}/", max_bytes=200_000),
                    timeout=10,
                )
        finally:
            server.close()

    result = run(scenario())
    assert len(result.body) == 200_000
    assert result.truncated is True


# =============================================================================
# check_security_headers
# =============================================================================

STRONG_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}
WITHOUT_HSTS = {k: v for k, v in STRONG_HEADERS.items() if k != "Strict-Transport-Security"}


@pytest.mark.parametrize("headers", [STRONG_HEADERS, WITHOUT_HSTS])
def test_hsts_sans_objet_pour_une_cible_ip(headers):
    """RFC 6797 §8.1 : HSTS est ignoré pour une adresse IP, présent ou absent il n'est pas noté."""
    evaluation = evaluate_security_headers(headers, https=True, ip_target=True)

    hsts = evaluation["checks"]["Strict-Transport-Security"]
    assert hsts["status"] == "info"
    assert "adresse IP" in fr(hsts["detail"])
    assert hsts["value"] == headers.get("Strict-Transport-Security")
    assert evaluation["counts"] == {"ok": 5, "weak": 0, "invalid": 0, "missing": 0, "total": 5}


def test_hsts_toujours_note_pour_un_nom_de_domaine():
    evaluation = evaluate_security_headers(WITHOUT_HSTS, https=True)

    assert evaluation["checks"]["Strict-Transport-Security"]["status"] == "missing"
    assert fr(evaluation["checks"]["Strict-Transport-Security"]) == {
        "value": None,
        "status": "missing",
        "detail": "Absent",
    }
    assert evaluation["counts"]["total"] == 6


@pytest.mark.parametrize(
    "target, total, score",
    [("203.0.113.10", 5, "5/5"), ("2001:db8::1", 5, "5/5"), ("example.com", 6, "5/6")],
)
def test_module_en_tetes_hsts_hors_bareme_sur_cible_ip(monkeypatch, target, total, score):
    use_transport(monkeypatch, lambda request: httpx.Response(200, headers=WITHOUT_HSTS), headers_module)

    result = run(check_security_headers(target))

    assert result["measured"] is True and result["https"] is True
    assert result["counts"]["total"] == total
    assert result["score"] == score
    # headers_missing ne liste que les en-têtes notés : pas HSTS sur une IP.
    assert result["headers_missing"] == ([] if total == 5 else ["Strict-Transport-Security"])
    breakdown = compute_security_score({"security_headers": result})["breakdown"]["headers"]
    assert breakdown["score"] == round(25 * 5 / total)


def test_module_en_tetes_erreurs_https_et_http_conservees(monkeypatch):
    """Régression : seule la dernière tentative (HTTP) restait dans le message d'erreur."""

    def handler(request):
        if request.url.scheme == "https":
            raise httpx.RemoteProtocolError(
                "Server disconnected without sending a response.", request=request
            )
        raise httpx.ReadTimeout("", request=request)

    use_transport(monkeypatch, handler, headers_module)

    result = run(check_security_headers("example.com"))

    assert result["measured"] is False
    assert "HTTPS : connexion fermée par le serveur sans réponse" in fr(result["error"])
    assert "HTTP : délai dépassé" in fr(result["error"])


@pytest.mark.parametrize(
    "routes, downgrade",
    [
        # http.badssl.com : HTTPS renvoie vers HTTP, dont la réponse est notée.
        (
            {
                "https://example.com/": redirect("http://example.com/"),
                "http://example.com/": (200, STRONG_HEADERS, b""),
            },
            True,
        ),
        ({"https://example.com/": (200, STRONG_HEADERS, b"")}, False),
        # HTTPS injoignable, repli sur HTTP : pas de redirection, pas de downgrade.
        ({"http://example.com/": (200, STRONG_HEADERS, b"")}, False),
    ],
)
def test_module_en_tetes_signale_https_redirige_vers_http(monkeypatch, routes, downgrade):
    use_transport(monkeypatch, make_handler(routes), headers_module)

    result = run(check_security_headers("example.com"))

    assert result["measured"] is True
    assert result["https_downgrade"] is downgrade
    if downgrade:
        assert result["https"] is False
        assert result["checks"]["Strict-Transport-Security"]["status"] == "invalid"


def test_hsts_avec_certificat_invalide_ignore():
    """RFC 6797 §8.1 : un HSTS reçu avec un certificat invalide est ignoré par le navigateur."""
    evaluation = evaluate_security_headers(STRONG_HEADERS, https=True, cert_valid=False)

    assert evaluation["checks"]["Strict-Transport-Security"]["status"] == "invalid"
    assert "Certificat TLS invalide" in fr(evaluation["checks"]["Strict-Transport-Security"]["detail"])
    assert evaluation["counts"]["ok"] == 5


@pytest.mark.parametrize(
    "url, valid, hsts",
    [
        ("https://example.com", False, "invalid"),
        ("https://example.com/accueil", False, "invalid"),
        ("https://example.com", True, "ok"),
        # Réponse notée venue d'un autre hôte : le verdict TLS de la cible ne la concerne pas.
        ("https://www.example.com/", False, "ok"),
    ],
)
def test_verdict_tls_recoupe_hsts(url, valid, hsts):
    evaluation = evaluate_security_headers(STRONG_HEADERS, https=True)
    result = {
        "measured": True,
        "https": True,
        "url": url,
        "checks": evaluation["checks"],
        "counts": evaluation["counts"],
        "score": "6/6",
    }

    apply_tls_verdict(result, {"measured": True, "https": True, "valid": valid}, "example.com")

    assert result["checks"]["Strict-Transport-Security"]["status"] == hsts
    assert result["score"] == ("5/6" if hsts == "invalid" else "6/6")
    assert result["counts"]["ok"] == (5 if hsts == "invalid" else 6)


# =============================================================================
# trace_redirects
# =============================================================================


def test_redirects_location_protocol_relative_et_relative(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("//www.example.com/"),
                "http://www.example.com/": redirect("https://www.example.com/start"),
                "https://www.example.com/start": redirect("login", 302),
                "https://www.example.com/login": (200, {"server": "nginx"}, b""),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert [hop["url"] for hop in result["chain"]] == [
        "http://example.com",
        "http://www.example.com/",
        "https://www.example.com/start",
        "https://www.example.com/login",
    ]
    assert result["final_url"] == "https://www.example.com/login"
    assert result["forces_https"] is True
    assert result["measured"] is True and result["error"] is None


def test_redirects_https_dans_la_query_ne_compte_pas(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("/login?next=https://example.com/"),
                "http://example.com/login": (200, {}, b""),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["final_url"] == "http://example.com/login?next=https://example.com/"
    assert result["forces_https"] is False


def test_redirects_vers_un_autre_site_ne_compte_pas(monkeypatch):
    calls = []
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("https://parking.example.net/lander"),
                "https://parking.example.net/lander": redirect("https://parking.example.net/other"),
            },
            calls,
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["forces_https"] is False
    assert result["leaves_site"] is True
    assert fr(result["warnings"]) == [
        "La chaîne quitte le site ciblé vers https://parking.example.net/lander"
    ]
    # La chaîne s'arrête au premier saut hors site (https://example.com/ : chaîne HTTPS).
    assert [key for key, _ in calls if key != "https://example.com/"] == [
        "http://example.com/",
        "https://parking.example.net/lander",
    ]


def test_redirects_retour_en_http(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("https://example.com/"),
                "https://example.com/": redirect("http://example.com/home"),
                "http://example.com/home": (200, {}, b""),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["forces_https"] is False
    assert result["https_downgrade"] is True
    # Même saut vu dans les deux chaînes : un seul avertissement.
    assert [w for w in fr(result["warnings"]) if "HTTPS redirige vers HTTP" in w] == [
        "HTTPS redirige vers HTTP (https://example.com/ → http://example.com/home) : "
        "la connexion chiffrée est abandonnée"
    ]


def test_redirects_https_redirige_vers_http_downgrade(monkeypatch):
    """Régression (http.badssl.com) : HTTP sert la page, HTTPS renvoie vers HTTP."""
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": (200, {"server": "nginx"}, b""),
                "https://example.com/": redirect("http://example.com/"),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["measured"] is True
    assert result["https_downgrade"] is True
    assert result["forces_https"] is False
    assert result["https_available"] is True
    assert [hop["url"] for hop in result["https_chain"]] == ["https://example.com", "http://example.com/"]
    assert any("HTTPS redirige vers HTTP" in w for w in fr(result["warnings"]))
    breakdown = compute_security_score({"redirect_chain": result})["breakdown"]["https_redirect"]
    assert breakdown["measured"] is True and breakdown["score"] == 0


def test_redirects_https_vers_un_autre_site_en_http_n_est_pas_un_downgrade(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("https://example.com/"),
                "https://example.com/": redirect("http://parking.example.net/"),
                "http://parking.example.net/": (200, {}, b""),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["https_downgrade"] is False


def test_redirects_boucle(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("https://example.com/"),
                "https://example.com/": redirect("https://example.com/"),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["forces_https"] is False
    assert fr(result["warnings"]) == [f"Plus de {MAX_REDIRECTS} redirections : boucle probable"]


def test_redirects_schema_non_pris_en_charge(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("javascript:alert(1)"),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["measured"] is True
    assert result["forces_https"] is False
    assert result["total_hops"] == 0
    assert fr(result["warnings"]) == [
        "Redirection vers une URL invalide ou un schéma non pris en charge : chaîne interrompue"
    ]


@pytest.mark.parametrize(
    "http_failure, reason",
    [
        (httpx.ConnectTimeout("délai"), "délai dépassé"),
        (httpx.ConnectError("Connexion refusée"), "connexion impossible (Connexion refusée)"),
    ],
    ids=["delai", "refus"],
)
def test_redirects_http_sans_reponse_n_est_pas_https_force(monkeypatch, http_failure, reason):
    """Régression (neverssl.com) : un délai dépassé sur le port 80 valait « HTTPS seulement », 5/5."""
    use_transport(
        monkeypatch,
        make_handler({"http://example.com/": http_failure, "https://example.com/": (200, {}, b"")}),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["measured"] is False
    assert result["forces_https"] is None
    assert result["http_available"] is False
    assert result["https_available"] is True
    assert fr(result["error"]) == (
        "Redirection HTTP → HTTPS non vérifiable : http://example.com sans réponse depuis le scanner "
        f"({reason}), alors que HTTPS répond"
    )
    # Un HTTP muet n'est pas un verdict : aucun avertissement du type « servi qu'en HTTPS ».
    assert fr(result["warnings"]) == []
    breakdown = compute_security_score({"redirect_chain": result})["breakdown"]["https_redirect"]
    assert breakdown["measured"] is False and breakdown["score"] == 0


def test_redirects_saut_https_sans_reponse_non_conclu(monkeypatch):
    """La redirection vers HTTPS reste sans réponse : destination finale inconnue, pas « Non »."""
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("https://www.example.com/"),
                "https://www.example.com/": httpx.ReadTimeout("délai"),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["measured"] is False
    assert result["forces_https"] is None
    assert fr(result["error"]) == (
        "Redirection vers https://www.example.com/ sans réponse (délai dépassé) : chaîne incomplète, "
        "redirection vers HTTPS non vérifiable"
    )


def test_redirects_saut_sans_reponse_apres_un_downgrade(monkeypatch):
    """Un downgrade avéré suffit à mesurer : le saut du site resté sans réponse n'est qu'un avertissement."""
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/": redirect("https://example.com/"),
                "https://example.com/": redirect("http://example.com/home"),
                "http://example.com/home": redirect("http://www.example.com/x"),
                "http://www.example.com/x": httpx.ReadTimeout("délai"),
            }
        ),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["measured"] is True and result["https_downgrade"] is True and result["error"] is None
    assert fr(result["warnings"]) == [
        "HTTPS redirige vers HTTP (https://example.com/ → http://example.com/home) : "
        "la connexion chiffrée est abandonnée",
        "Redirection vers http://www.example.com/x sans réponse (délai dépassé) : chaîne incomplète",
    ]


def test_redirects_saut_hors_site_sans_reponse(monkeypatch):
    """Le premier saut hors du site ne répond pas : avertissement, la mesure reste valable."""
    use_transport(
        monkeypatch,
        make_handler({"http://example.com/": redirect("https://parking.example.net/lander")}),
        redirects_module,
    )

    result = run(trace_redirects("example.com"))

    assert result["measured"] is True and result["forces_https"] is False
    assert fr(result["warnings"]) == [
        "La chaîne quitte le site ciblé vers https://parking.example.net/lander",
        "Redirection vers https://parking.example.net/lander sans réponse : "
        "connexion impossible (Connexion refusée)",
    ]


def test_redirects_site_injoignable(monkeypatch):
    use_transport(monkeypatch, make_handler({}), redirects_module)

    result = run(trace_redirects("example.com"))

    assert result["measured"] is False
    assert fr(result["error"]) == (
        "Site injoignable en HTTP et en HTTPS (HTTP : connexion impossible (Connexion refusée) ; "
        "HTTPS : connexion impossible (Connexion refusée))"
    )
    assert result["forces_https"] is None


# =============================================================================
# detect_waf
# =============================================================================


@pytest.mark.parametrize(
    "headers, cdn",
    [
        ({"via": "1.1 varnish (Varnish/6.0)", "server": "nginx"}, "Varnish"),
        # Proxy Cloudflare (example.com) : server et cf-ray figurent sur toute réponse du CDN.
        ({"server": "cloudflare", "cf-ray": "8a1b-CDG", "cf-cache-status": "HIT"}, "Cloudflare"),
        ({"server": "cloudflare", "cf-ray": "8a1b-CDG"}, "Cloudflare"),
        ({"server": "GitHub.com", "x-fastly-request-id": "abc", "x-served-by": "cache-par-1-PAR"}, "Fastly"),
        ({"via": "1.1 google", "server": "Google Frontend"}, "Google Cloud (Google Frontend)"),
        ({"x-amz-cf-id": "abc", "server": "AmazonS3"}, "Amazon CloudFront"),
        ({"x-amzn-requestid": "abc"}, None),
        ({"server": "nginx"}, None),
    ],
)
def test_waf_en_tetes_de_cdn_ne_sont_pas_un_waf(monkeypatch, headers, cdn):
    use_transport(monkeypatch, make_handler({"https://example.com/": (200, headers, b"")}), waf_module)

    result = run(detect_waf("example.com"))

    assert result["detected"] is False
    assert result["waf_name"] is None
    assert result["cdn_name"] == cdn
    assert result["measured"] is True and result["error"] is None
    # Le bonus WAF du score suit waf.detected seulement.
    assert compute_security_score({"waf": result})["breakdown"]["waf"]["counted"] is False


@pytest.mark.parametrize(
    "headers, evidence",
    [
        (
            [("server", "cloudflare"), ("cf-ray", "x"), ("set-cookie", "__cf_bm=abc; path=/; HttpOnly")],
            ["Cookie: __cf_bm"],
        ),
        (
            [("server", "cloudflare"), ("cf-ray", "x"), ("cf-mitigated", "challenge")],
            ["Header: cf-mitigated"],
        ),
        (
            [("cf-mitigated", "challenge"), ("set-cookie", "cf_clearance=abc; path=/")],
            ["Header: cf-mitigated", "Cookie: cf_clearance"],
        ),
    ],
)
def test_waf_cloudflare_sur_preuve_propre_confiance_moyenne(monkeypatch, headers, evidence):
    """Un WAF Cloudflare ne se déduit que de preuves propres, et jamais avec une confiance « high »."""
    use_transport(monkeypatch, make_handler({"https://example.com/": (403, headers, b"")}), waf_module)

    result = run(detect_waf("example.com"))

    assert result["detected"] is True
    assert result["waf_name"] == "Cloudflare"
    assert result["evidence"] == evidence
    assert result["confidence"] == "medium"
    if any(name == "server" for name, _ in headers):
        assert result["cdn_detected"] is True and result["cdn_name"] == "Cloudflare"


def test_waf_cookie_pose_sur_la_redirection(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": redirect("/home", 302, [("set-cookie", "incap_ses_123=abc; path=/")]),
                "https://example.com/home": (200, {}, b""),
            }
        ),
        waf_module,
    )

    result = run(detect_waf("example.com"))

    assert result["waf_name"] == "Imperva/Incapsula"


def test_waf_redirection_hors_site_non_attribuee(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": redirect("https://market.example.net/", 302),
                "https://market.example.net/": (200, {"server": "cloudflare", "cf-ray": "x"}, b""),
            }
        ),
        waf_module,
    )

    result = run(detect_waf("example.com"))

    assert result["detected"] is False
    assert result["off_site_redirect"] == "https://market.example.net/"


def test_waf_site_injoignable(monkeypatch):
    use_transport(monkeypatch, make_handler({}), waf_module)

    result = run(detect_waf("example.com"))

    assert result["measured"] is False
    assert fr(result["error"]) == (
        "Site injoignable (HTTPS : connexion impossible (Connexion refusée) ; "
        "HTTP : connexion impossible (Connexion refusée))"
    )


# =============================================================================
# analyze_cookies
# =============================================================================


@pytest.mark.parametrize(
    "raw, secure, httponly, samesite, path",
    [
        ("secure_session=abc; Path=/", False, False, None, "/"),
        ("pref=httponly_mode; Path=/", False, False, None, "/"),
        ("sid=insecure-token-httponly; Path=/; SameSite=Lax", False, False, "lax", "/"),
        ("sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/app", True, True, "strict", "/app"),
        ("sid=abc;secure;httponly;samesite=None", True, True, "none", "/"),
        ("sid=abc; SameSite=Invalide", False, False, None, "/"),
    ],
)
def test_parse_set_cookie_attributs_exacts(raw, secure, httponly, samesite, path):
    cookie = parse_set_cookie(raw)
    assert cookie["name"] == raw.split("=", 1)[0]
    assert (cookie["secure"], cookie["httponly"], cookie["samesite"], cookie["path"]) == (
        secure,
        httponly,
        samesite,
        path,
    )


def test_cookies_poses_sur_la_redirection_sont_analyses(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": redirect(
                    "/fr/", 302, [("set-cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")]
                ),
                "https://example.com/fr/": (
                    200,
                    [("set-cookie", "lang=fr; Secure; HttpOnly; SameSite=Lax")],
                    b"",
                ),
            }
        ),
        cookies_module,
    )

    result = run(analyze_cookies("example.com"))

    assert result["cookies_present"] is True
    assert sorted(c["name"] for c in result["cookies"]) == ["lang", "sid"]
    assert result["score"] == "A"


def test_cookies_sans_aucun_flag_note_f(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": (200, [("set-cookie", "a=1"), ("set-cookie", "b=2")], b""),
            }
        ),
        cookies_module,
    )

    result = run(analyze_cookies("example.com"))

    assert result["score"] == "F"
    assert fr(result["cookies"][0]["issues"]) == [
        "Pas de flag Secure",
        "Pas de flag HttpOnly",
        "Pas de SameSite",
    ]


def test_cookies_d_un_autre_site_ignores(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": redirect("https://market.example.net/", 302),
                "https://market.example.net/": (200, [("set-cookie", "tracker=1")], b""),
            }
        ),
        cookies_module,
    )

    result = run(analyze_cookies("example.com"))

    assert result["cookies_present"] is False
    assert result["score"] == "N/A"
    assert result["off_site_redirect"] == "https://market.example.net/"


def test_cookies_site_injoignable(monkeypatch):
    use_transport(monkeypatch, make_handler({}), cookies_module)

    result = run(analyze_cookies("example.com"))

    assert result["measured"] is False
    assert fr(result["error"]) == (
        "Site injoignable (HTTPS : connexion impossible (Connexion refusée) ; "
        "HTTP : connexion impossible (Connexion refusée))"
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
        ("Thu, 01-Jan-1970 00:00:01 GMT", 1),
        # Année sur deux chiffres : 70-99 → 19xx (http2time y voyait 2070).
        ("Thursday, 01-Jan-70 00:00:01 GMT", 1),
        ("Sat, 31-Dec-37 23:55:55 GMT", 2145916555),
        ("Thu Jan  1 00:00:01 1970", 1),
        ("Wed, 21 Oct 2099 07:28:00 GMT", 4096250880),
        # Dates que les navigateurs rejettent : l'attribut Expires est ignoré.
        ("2020-01-01", None),
        ("Thu, 32 Jan 2020 00:00:00 GMT", None),
        ("Thu, 01 Jan 2020 24:00:00 GMT", None),
        ("demain", None),
        ("", None),
    ],
)
def test_parse_cookie_date_rfc_6265(value, expected):
    assert parse_cookie_date(value) == expected


@pytest.mark.parametrize(
    "raw, expired",
    [
        ("sid=deleted; Max-Age=0; Path=/", True),
        ("sid=deleted; Max-Age=-1", True),
        ("sid=abc; Max-Age=3600", False),
        ("sid=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/", True),
        ("sid=deleted; expires=Thu, 01-Jan-70 00:00:01 GMT", True),
        ("sid=abc; Expires=Wed, 21 Oct 2099 07:28:00 GMT", False),
        # Max-Age prime sur Expires…
        ("sid=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=3600", False),
        ("sid=deleted; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Max-Age=0", True),
        # … sauf s'il est invalide : il est alors ignoré.
        ("sid=deleted; Max-Age=bientot; Expires=Thu, 01 Jan 1970 00:00:00 GMT", True),
        ("sid=abc; Max-Age=-", False),
        # Date illisible : cookie de session, bien vivant.
        ("sid=abc; Expires=2020-01-01", False),
        ("sid=abc", False),
    ],
)
def test_parse_set_cookie_suppression(raw, expired):
    assert parse_set_cookie(raw)["expired"] is expired


def test_cookies_suppression_non_notee():
    """Régression : une ligne qui efface un cookie était notée comme un cookie non sécurisé."""
    result = analyze_cookie_headers(
        [
            "sid=abc; Secure; HttpOnly; SameSite=Lax",
            "PHPSESSID=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/",
        ]
    )

    assert [c["name"] for c in result["cookies"]] == ["sid"]
    assert result["score"] == "A"
    assert result["cookies_present"] is True


def test_cookies_uniquement_des_suppressions_non_applicable():
    result = analyze_cookie_headers(["PHPSESSID=deleted; Max-Age=0; path=/"])

    assert result["cookies_present"] is False
    assert result["cookies"] == []
    assert result["score"] == "N/A"


def test_cookies_suppression_efface_le_cookie_pose_plus_tot(monkeypatch):
    """Le navigateur efface le cookie reposé expiré : il n'expose plus rien."""
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": redirect("/fr/", 302, [("set-cookie", "sid=1; Path=/")]),
                "https://example.com/fr/": (
                    200,
                    [
                        ("set-cookie", "sid=; Max-Age=0; Path=/"),
                        ("set-cookie", "lang=fr; Secure; HttpOnly; SameSite=Lax"),
                    ],
                    b"",
                ),
            }
        ),
        cookies_module,
    )

    result = run(analyze_cookies("example.com"))

    assert [c["name"] for c in result["cookies"]] == ["lang"]
    assert result["score"] == "A"


def test_cookies_repose_apres_suppression_est_note():
    result = analyze_cookie_headers(["sid=; Max-Age=0; Path=/", "sid=2; Path=/"])

    assert [c["name"] for c in result["cookies"]] == ["sid"]
    assert result["cookies"][0]["expired"] is False
    assert result["score"] == "F"


# =============================================================================
# check_cors
# =============================================================================


def cors_server(
    reflect=lambda origin: True, credentials=False, base_acao=None, base_acac=False, drop=lambda origin: False
):
    """Serveur CORS simulé : reflète l'Origin selon `reflect` ; coupe la connexion selon `drop`."""

    def respond(request):
        headers = {}
        origin = request.headers.get("origin")
        if origin is not None and drop(origin):
            raise httpx.RemoteProtocolError(
                "Server disconnected without sending a response.", request=request
            )
        if origin is None:
            if base_acao:
                headers["access-control-allow-origin"] = base_acao
                if base_acac:
                    headers["access-control-allow-credentials"] = "true"
        elif reflect(origin):
            headers["access-control-allow-origin"] = origin
            if credentials:
                headers["access-control-allow-credentials"] = "true"
        return httpx.Response(200, headers=headers)

    return make_handler({"https://example.com/": respond})


def test_cors_reflet_sans_credentials_mal_configure(monkeypatch):
    """Une origine arbitraire reflétée est une erreur de configuration, même sans credentials."""
    use_transport(monkeypatch, cors_server(), cors_module)

    result = run(check_cors("example.com"))

    assert result["reflects_origin"] is True
    assert result["misconfigured"] is True
    assert result["severity"] == "low"
    # Pas de « * » littéral : le reflet a son propre drapeau.
    assert result["allows_any_origin"] is False
    assert result["measured"] is True


def test_cors_wildcard_sans_credentials_acceptable(monkeypatch):
    """« * » sans credentials : ressources publiques, simple information."""
    use_transport(monkeypatch, cors_server(reflect=lambda o: False, base_acao="*"), cors_module)

    result = run(check_cors("example.com"))

    assert result["allows_any_origin"] is True
    assert result["misconfigured"] is False
    assert result["severity"] == "info"
    assert result["measured"] is True and result["partial"] is False
    assert result["origin_tests"] == {"total": 4, "succeeded": 4, "errors": []}
    assert "acceptable" in fr(result["details"][0])


def test_cors_reflet_avec_credentials_critique(monkeypatch):
    use_transport(monkeypatch, cors_server(credentials=True), cors_module)

    result = run(check_cors("example.com"))

    assert result["misconfigured"] is True
    assert result["reflects_with_credentials"] is True
    assert result["severity"] == "critical"
    assert any("CRITIQUE" in detail for detail in fr(result["details"]))


def test_cors_wildcard_avec_credentials_non_critique(monkeypatch):
    use_transport(
        monkeypatch, cors_server(reflect=lambda o: False, base_acao="*", base_acac=True), cors_module
    )

    result = run(check_cors("example.com"))

    assert result["allows_credentials_with_wildcard"] is True
    # Credentials avec une origine permissive : mal configuré, mais non exploitable.
    assert result["misconfigured"] is True
    assert result["severity"] == "low"
    # Rendus avant de comparer : sur des messages, « in » ne cherche que dans les clés.
    assert fr(result["details"])[0].startswith("Incohérent")
    assert not any("CRITIQUE" in detail for detail in fr(result["details"]))


def test_cors_origine_null_avec_credentials(monkeypatch):
    use_transport(monkeypatch, cors_server(reflect=lambda o: o == "null", credentials=True), cors_module)

    result = run(check_cors("example.com"))

    assert result["misconfigured"] is True
    assert result["reflected_origin"] == "null"


def test_cors_contournement_par_suffixe(monkeypatch):
    use_transport(
        monkeypatch,
        cors_server(reflect=lambda o: o.endswith("example.com"), credentials=True),
        cors_module,
    )

    result = run(check_cors("example.com"))

    assert result["misconfigured"] is True
    assert result["reflected_origin"] == "https://evilexample.com"


def test_cors_sans_reflet(monkeypatch):
    use_transport(monkeypatch, cors_server(reflect=lambda o: False), cors_module)

    result = run(check_cors("example.com"))

    assert result["measured"] is True
    assert result["misconfigured"] is False
    assert result["reflects_origin"] is False
    assert result["cors_enabled"] is False


def test_cors_site_injoignable(monkeypatch):
    use_transport(monkeypatch, make_handler({}), cors_module)

    result = run(check_cors("example.com"))

    assert result["measured"] is False
    assert fr(result["error"]) == (
        "Site injoignable (HTTPS : connexion impossible (Connexion refusée) ; "
        "HTTP : connexion impossible (Connexion refusée))"
    )


def test_cors_tests_d_origine_en_echec_non_mesure(monkeypatch):
    """Régression (neverssl.com) : les tests Origin en échec étaient ignorés, et le module concluait « OK » 10/10.

    Serveur qui reflète l'Origin avec credentials, mais coupe toute requête qui en porte une.
    """
    use_transport(monkeypatch, cors_server(credentials=True, drop=lambda o: True), cors_module)

    result = run(check_cors("example.com"))

    assert result["measured"] is False
    assert result["misconfigured"] is False
    assert result["origin_tests"]["succeeded"] == 0
    assert len(result["origin_tests"]["errors"]) == 4
    assert fr(result["error"]).startswith("Tests CORS impossibles")
    assert "connexion fermée par le serveur sans réponse" in fr(result["error"])
    breakdown = compute_security_score({"cors": result})["breakdown"]["cors"]
    assert breakdown["measured"] is False and breakdown["score"] == 0


def test_cors_un_test_d_origine_en_echec_ne_conclut_pas(monkeypatch):
    """Le test en échec (null) aurait pu révéler un reflet : pas de verdict « OK »."""
    use_transport(
        monkeypatch,
        cors_server(reflect=lambda o: o == "null", credentials=True, drop=lambda o: o == "null"),
        cors_module,
    )

    result = run(check_cors("example.com"))

    assert result["measured"] is False
    assert result["partial"] is True
    assert result["origin_tests"]["succeeded"] == 3
    assert fr(result["origin_tests"]["errors"]) == ["null : connexion fermée par le serveur sans réponse"]
    assert fr(result["error"]).startswith("Tests CORS incomplets : 1 test(s) d'origine sur 4 en échec")


def test_cors_faille_etablie_malgre_des_tests_en_echec(monkeypatch):
    """Un reflet avec credentials observé reste un verdict, même si d'autres tests échouent."""
    use_transport(
        monkeypatch,
        cors_server(credentials=True, drop=lambda o: o == "https://evil.com"),
        cors_module,
    )

    result = run(check_cors("example.com"))

    assert result["measured"] is True
    assert result["partial"] is True
    assert result["misconfigured"] is True
    assert result["severity"] == "critical"


# =============================================================================
# detect_technologies
# =============================================================================


def _names(technologies):
    return {tech["name"] for tech in technologies}


def test_technologies_pas_de_detection_sur_simple_mention(monkeypatch):
    page = b"""<html><head>
    <meta content="WordPress 6.4" name="generator">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
    </head><body>
    <p>omega(3) et saga(2)</p><p>Un guide bootstrap, pas sur shopify, ni tailwind.</p>
    <p>Nous aimons react et angular.</p>
    </body></html>"""
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": (200, {"server": "nginx", "content-type": "text/html"}, page),
            }
        ),
        technologies_module,
    )

    technologies = run(detect_technologies("example.com"))

    assert _names(technologies) == {"Nginx", "WordPress 6.4", "cdnjs"}
    assert {tech["name"]: tech["category"] for tech in fr(technologies)} == {
        "Nginx": "Serveur Web",
        "WordPress 6.4": "Générateur",
        "cdnjs": "CDN",
    }


def test_technologies_marqueurs_structurels(monkeypatch):
    page = b"""<html ng-version="17.0.0"><head>
    <link rel="stylesheet" href="/css/bootstrap.min.css">
    <script src="/js/jquery-3.7.1.min.js"></script>
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-XYZ"></script>
    <script>gtag('config', 'G-XYZ');</script>
    </head><body><div data-v-1a2b3c4d></div>
    <img src="/wp-content/uploads/logo.png"></body></html>"""
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": (
                    200,
                    {"server": "Apache/2.4", "x-powered-by": "PHP/8.2", "cf-ray": "x"},
                    page,
                ),
            }
        ),
        technologies_module,
    )

    technologies = run(detect_technologies("example.com"))
    names = _names(technologies)

    assert {
        "Apache",
        "PHP",
        "Cloudflare",
        "Bootstrap",
        "jQuery",
        "Google Analytics",
        "Angular",
        "Vue.js",
        "WordPress",
    } <= names
    assert "Google Tag Manager" not in names
    categories = {tech["name"]: tech["category"] for tech in fr(technologies)}
    assert categories == {
        "Apache": "Serveur Web",
        "PHP": "Framework",
        "Cloudflare": "CDN",
        "Bootstrap": "Framework CSS",
        "jQuery": "Librairie JS",
        "Google Analytics": "Analytics",
        "Angular": "Framework JS",
        "Vue.js": "Framework JS",
        "WordPress": "CMS",
    }


def test_technologies_redirection_hors_site_non_attribuee(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/": redirect("https://shop.example.net/", 302, [("server", "nginx")]),
                "https://shop.example.net/": (
                    200,
                    {"x-powered-by": "PHP"},
                    b'<script src="//cdn.shopify.com/s.js"></script>',
                ),
            }
        ),
        technologies_module,
    )

    names = _names(run(detect_technologies("example.com")))

    assert names == {"Nginx"}


@pytest.mark.parametrize(
    "headers, expected",
    [
        # example.com / cloudflare.com : proxy Cloudflare, catégorie CDN (et non « Serveur Web »).
        (
            {"server": "cloudflare", "cf-ray": "8a1b-CDG", "cf-cache-status": "HIT"},
            [{"name": "Cloudflare", "category": "CDN"}],
        ),
        # octocat.github.io : GitHub Pages derrière Fastly (Varnish).
        (
            {
                "server": "GitHub.com",
                "x-github-request-id": "456C:247D4C",
                "via": "1.1 varnish",
                "x-served-by": "cache-par-lfpg1960091-PAR",
                "x-fastly-request-id": "aa5907d5",
            },
            [
                {"name": "GitHub Pages", "category": "Hébergement"},
                {"name": "Fastly", "category": "CDN"},
                {"name": "Varnish Cache", "category": "Reverse proxy"},
            ],
        ),
        # github.com (sans Fastly) n'est pas GitHub Pages : Server rapporté tel quel.
        (
            {"server": "github.com", "x-github-request-id": "725B:126DAD"},
            [{"name": "github.com", "category": "Serveur Web"}],
        ),
        ({"server": "Varnish", "x-varnish": "123"}, [{"name": "Varnish Cache", "category": "Reverse proxy"}]),
    ],
)
def test_technologies_cdn_et_hebergement_depuis_les_en_tetes(monkeypatch, headers, expected):
    use_transport(
        monkeypatch, make_handler({"https://example.com/": (200, headers, b"")}), technologies_module
    )

    assert fr(run(detect_technologies("example.com"))) == expected


def test_technologies_site_injoignable_leve_module_error(monkeypatch):
    use_transport(monkeypatch, make_handler({}), technologies_module)

    with pytest.raises(ModuleError):
        run(detect_technologies("example.com"))


# =============================================================================
# check_web_files
# =============================================================================

ROBOTS = b"User-agent: *\nDisallow: /admin\nDisallow: /tmp # temporaire\nSitemap: https://example.com/sitemap.xml\n"
SITEMAP = b'<?xml version="1.0"?><urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/a</loc></url></urlset>'
SECURITY = b"Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\n"


def test_web_files_trouves_en_https(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/robots.txt": (200, {}, ROBOTS),
                "https://example.com/sitemap.xml": (200, {}, SITEMAP),
                "https://example.com/.well-known/security.txt": (200, {}, SECURITY),
                "https://example.com/security.txt": (404, {}, b""),
            }
        ),
        web_files_module,
    )

    result = run(check_web_files("example.com"))

    assert result["measured"] is True and result["error"] is None
    assert result["robots_txt"]["found"] is True
    assert result["robots_txt"]["disallowed"] == ["/admin", "/tmp"]
    assert result["robots_txt"]["sitemaps"] == ["https://example.com/sitemap.xml"]
    assert result["sitemap_xml"]["url_count"] == 2
    assert result["security_txt"]["contact"] == "mailto:security@example.com"
    assert result["security_txt"]["url"] == "https://example.com/.well-known/security.txt"


def test_web_files_repli_http_et_page_html_ignoree(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://example.com/robots.txt": (200, {}, ROBOTS),
                "http://example.com/sitemap.xml": (
                    200,
                    {"content-type": "text/html"},
                    b"<html>Page introuvable</html>",
                ),
                "http://example.com/.well-known/security.txt": (404, {}, b""),
                "http://example.com/security.txt": (200, {}, SECURITY),
            }
        ),
        web_files_module,
    )

    result = run(check_web_files("example.com"))

    assert result["robots_txt"]["found"] is True
    assert result["sitemap_xml"]["found"] is False
    assert result["security_txt"]["found"] is True
    assert result["security_txt"]["url"] == "http://example.com/security.txt"


def test_web_files_redirection_hors_site_non_retenue(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/robots.txt": redirect("https://parking.example.net/robots.txt", 302),
                "https://parking.example.net/robots.txt": (200, {}, ROBOTS),
                "https://example.com/sitemap.xml": (404, {}, b""),
                "https://example.com/.well-known/security.txt": (404, {}, b""),
                "https://example.com/security.txt": (404, {}, b""),
            }
        ),
        web_files_module,
    )

    result = run(check_web_files("example.com"))

    assert result["robots_txt"]["found"] is False


def test_web_files_requetes_paralleles_et_hote_filtre(monkeypatch):
    """Hôte filtré : les requêtes partent en parallèle et le module rend une erreur."""
    in_flight = 0
    peak = 0
    calls = 0

    async def handler(request):
        nonlocal in_flight, peak, calls
        calls += 1
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            await asyncio.sleep(0.05)
        finally:
            in_flight -= 1
        raise httpx.ConnectTimeout("délai", request=request)

    use_transport(monkeypatch, handler, web_files_module)

    result = run(check_web_files("example.com"))

    assert result["measured"] is False
    assert fr(result["error"]) == "Site injoignable (HTTPS : délai dépassé ; HTTP : délai dépassé)"
    assert calls == 8
    assert peak >= 4


def test_web_files_budget_depasse_garde_les_resultats_partiels(monkeypatch):
    """Régression : un module trop lent perdait aussi les fichiers déjà trouvés."""
    monkeypatch.setattr(web_files_module, "WEB_FILES_ROUND_BUDGET", 0.2)

    async def handler(request):
        if request.url.path == "/robots.txt":
            return httpx.Response(200, content=ROBOTS)
        await asyncio.sleep(5)
        return httpx.Response(404)

    use_transport(monkeypatch, handler, web_files_module)

    async def scenario():
        start = time.perf_counter()
        result = await check_web_files("example.com")
        return result, time.perf_counter() - start

    result, elapsed = run(scenario())
    assert result["robots_txt"]["found"] is True
    # Jamais obtenus : non vérifiés, et non « absents ».
    assert result["sitemap_xml"]["found"] is None
    assert "délai dépassé" in fr(result["sitemap_xml"]["error"])
    assert result["security_txt"]["found"] is None
    assert result["measured"] is True and result["partial"] is True
    assert elapsed < 2


def test_web_files_fichier_jamais_obtenu_non_verifie(monkeypatch):
    """Régression (neverssl.com) : seul robots.txt répondait (404 en HTTP), les autres fichiers
    passaient pour « absents » et le module pour mesuré sans réserve."""

    def handler(request):
        if request.url.scheme == "http" and request.url.path == "/robots.txt":
            return httpx.Response(404)
        raise httpx.ReadTimeout("délai", request=request)

    use_transport(monkeypatch, handler, web_files_module)

    result = run(check_web_files("example.com"))

    assert result["measured"] is True and result["partial"] is True
    assert result["error"] is None
    assert result["robots_txt"]["found"] is False
    assert result["robots_txt"]["error"] is None
    assert result["sitemap_xml"]["found"] is None
    assert (
        fr(result["sitemap_xml"]["error"])
        == "HTTPS /sitemap.xml : délai dépassé ; HTTP /sitemap.xml : délai dépassé"
    )
    assert result["security_txt"]["found"] is None
    assert "/.well-known/security.txt" in fr(result["security_txt"]["error"])


def test_web_files_aucun_fichier_verifie(monkeypatch):
    """Un emplacement répond (404) mais aucun fichier n'a un état connu : ce n'est pas « injoignable »."""

    def handler(request):
        if request.url.path == "/.well-known/security.txt":
            return httpx.Response(404)
        raise httpx.ReadTimeout("délai", request=request)

    use_transport(monkeypatch, handler, web_files_module)

    result = run(check_web_files("example.com"))

    assert result["measured"] is False and result["partial"] is False
    assert fr(result["error"]) == "Aucun fichier vérifié (HTTPS : délai dépassé ; HTTP : délai dépassé)"


@pytest.mark.parametrize(
    "answer, reason",
    [
        ((503, {}, b"Service Unavailable"), "réponse HTTP 503"),
        ((429, {}, b""), "réponse HTTP 429"),
        # Redirection du site vers un hôte qui ne répond pas.
        (
            redirect("https://www.example.com/sitemap.xml"),
            "Redirection non suivie (https://www.example.com/sitemap.xml)",
        ),
    ],
    ids=["503", "429", "redirection-sans-reponse"],
)
def test_web_files_reponse_non_probante_non_verifiee(monkeypatch, answer, reason):
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/robots.txt": (404, {}, b""),
                "https://example.com/sitemap.xml": answer,
                "https://example.com/.well-known/security.txt": (404, {}, b""),
                "https://example.com/security.txt": (404, {}, b""),
            }
        ),
        web_files_module,
    )

    result = run(check_web_files("example.com"))

    assert result["robots_txt"]["found"] is False
    assert result["security_txt"]["found"] is False
    assert result["sitemap_xml"]["found"] is None
    assert fr(result["sitemap_xml"]["error"]).startswith(f"HTTPS /sitemap.xml : {reason}")
    assert result["partial"] is True


def test_web_files_tous_absents_mesure_complete(monkeypatch):
    use_transport(
        monkeypatch,
        make_handler(
            {f"https://example.com{path}": (404, {}, b"") for _, path, _ in web_files_module._WEB_FILES}
        ),
        web_files_module,
    )

    result = run(check_web_files("example.com"))

    assert result["measured"] is True and result["partial"] is False
    assert [result[key]["found"] for key in ("robots_txt", "sitemap_xml", "security_txt")] == [False] * 3


def test_web_files_sitemap_de_plus_d_un_mio_compte_en_entier(monkeypatch):
    """Régression (cloudflare.com) : 682 <loc> comptées sur le premier Mio d'un sitemap qui en contient 910."""
    entry = b"<url><loc>https://example.com/" + b"p" * 1500 + b"</loc></url>"
    count = 910
    sitemap = b'<?xml version="1.0"?><urlset>' + entry * count + b"</urlset>"
    assert len(sitemap) > 1024 * 1024
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/robots.txt": (404, {}, b""),
                "https://example.com/sitemap.xml": (200, {"content-type": "application/xml"}, sitemap),
                "https://example.com/.well-known/security.txt": (404, {}, b""),
                "https://example.com/security.txt": (404, {}, b""),
            }
        ),
        web_files_module,
    )

    result = run(check_web_files("example.com"))

    assert result["sitemap_xml"]["found"] is True
    assert result["sitemap_xml"]["url_count"] == count
    assert result["sitemap_xml"]["truncated"] is False


@pytest.mark.parametrize(
    "content_type", ["text/plain; charset=utf-8", "text/plain", "text/plain; charset=iso-8859-1"]
)
def test_web_files_bom_utf8_initial_ignore(monkeypatch, content_type):
    """Régression : un BOM UTF-8 masquait la première ligne (seul User-agent ou Contact)."""
    bom = b"\xef\xbb\xbf"
    headers = {"content-type": content_type}
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://example.com/robots.txt": (200, headers, bom + b"User-agent: *\nDisallow: /admin\n"),
                "https://example.com/sitemap.xml": (404, {}, b""),
                "https://example.com/.well-known/security.txt": (200, headers, bom + SECURITY),
                "https://example.com/security.txt": (404, {}, b""),
            }
        ),
        web_files_module,
    )

    result = run(check_web_files("example.com"))

    assert result["robots_txt"]["found"] is True
    assert result["robots_txt"]["disallowed"] == ["/admin"]
    assert result["robots_txt"]["content"].startswith("User-agent")
    assert result["security_txt"]["found"] is True
    assert result["security_txt"]["contact"] == "mailto:security@example.com"


# =============================================================================
# check_subdomain_takeover
# =============================================================================


def fake_dns(
    monkeypatch, cnames: dict, nxdomain: set = frozenset(), delay: float = 0.0, errors: set = frozenset()
):
    """DNS simulé : `cnames` associe un sous-domaine à la cible de son CNAME."""
    import dns.exception

    async def resolve_cname(resolver, name):
        if delay:
            await asyncio.sleep(delay)
        if name in errors:
            raise dns.exception.Timeout()
        return cnames.get(name)

    async def target_state(resolver, name):
        return "nxdomain" if name in nxdomain else "exists"

    monkeypatch.setattr(takeover_module, "_make_resolver", lambda: object())
    monkeypatch.setattr(takeover_module, "_resolve_cname", resolve_cname)
    monkeypatch.setattr(takeover_module, "_cname_target_state", target_state)


def subs(*names):
    return [{"subdomain": name} for name in names]


def test_takeover_pas_de_faux_positif_sur_404_ou_texte_generique(monkeypatch):
    fake_dns(
        monkeypatch,
        {
            "app.example.com": "cname.vercel-dns.com",
            "cdn.example.com": "d111.cloudfront.net",
            "api.example.com": "api-prod.azurewebsites.net",
            "docs.example.com": "live.github.io",
            "blog.example.com": "live-site.netlify.app",
        },
    )
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://app.example.com/": (200, {}, b'<img src="hero-404x300.png">'),
                "https://cdn.example.com/": (200, {}, b"<p>400 Bad Request</p>"),
                "https://api.example.com/": (404, {}, b"Error 404"),
                "https://docs.example.com/": (404, {}, b"custom 404 of a live site"),
                "https://blog.example.com/": (200, {}, b"nothing not found here"),
            }
        ),
        takeover_module,
    )

    result = run(
        check_subdomain_takeover(
            subs(
                "app.example.com",
                "cdn.example.com",
                "api.example.com",
                "docs.example.com",
                "blog.example.com",
            )
        )
    )

    assert result == []


def test_takeover_empreinte_ngrok_regex(monkeypatch):
    fake_dns(monkeypatch, {"tun.example.com": "abc.ngrok.io"})
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://tun.example.com/": (404, {}, b"Tunnel abc.ngrok.io not found"),
            }
        ),
        takeover_module,
    )

    result = run(check_subdomain_takeover(subs("tun.example.com")))

    assert len(result) == 1
    entry = result[0]
    assert entry["provider"] == "ngrok"
    assert entry["risk"] == "high"
    assert entry["confirmed"] is True
    assert entry["fingerprint_matched"] is True


def test_takeover_bucket_s3_website(monkeypatch):
    fake_dns(monkeypatch, {"static.example.com": "static.example.com.s3-website-eu-west-1.amazonaws.com"})
    use_transport(
        monkeypatch,
        make_handler(
            {
                "http://static.example.com/": (404, {}, b"<Code>NoSuchBucket</Code>"),
            }
        ),
        takeover_module,
    )

    result = run(check_subdomain_takeover(subs("static.example.com")))

    assert [e["provider"] for e in result] == ["AWS S3"]
    assert result[0]["confirmed"] is True


def test_takeover_azure_nxdomain_confirme(monkeypatch):
    fake_dns(
        monkeypatch,
        {"old.example.com": "old-app.azurewebsites.net"},
        nxdomain={"old-app.azurewebsites.net"},
    )
    use_transport(monkeypatch, make_handler({}), takeover_module)

    result = run(check_subdomain_takeover(subs("old.example.com")))

    assert len(result) == 1
    assert result[0]["cname_nxdomain"] is True
    assert result[0]["risk"] == "high"
    assert result[0]["confirmed"] is True


def test_takeover_cname_pendant_service_inconnu_a_verifier(monkeypatch):
    fake_dns(
        monkeypatch, {"x.example.com": "host.unknown-provider.net"}, nxdomain={"host.unknown-provider.net"}
    )
    use_transport(monkeypatch, make_handler({}), takeover_module)

    result = run(check_subdomain_takeover(subs("x.example.com")))

    assert len(result) == 1
    assert result[0]["risk"] == "medium"
    assert result[0]["confirmed"] is False


def test_takeover_fournisseur_avec_preuve_de_propriete(monkeypatch):
    fake_dns(monkeypatch, {"shop.example.com": "old-app.herokuapp.com"})
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://shop.example.com/": (404, {}, b"<title>No such app</title>"),
            }
        ),
        takeover_module,
    )

    result = run(check_subdomain_takeover(subs("shop.example.com")))

    assert result[0]["fingerprint_matched"] is True
    assert result[0]["confirmed"] is False
    assert result[0]["risk"] == "medium"


def test_takeover_service_injoignable_a_verifier(monkeypatch):
    fake_dns(monkeypatch, {"docs.example.com": "gone.github.io"})
    use_transport(monkeypatch, make_handler({}), takeover_module)

    result = run(check_subdomain_takeover(subs("docs.example.com")))

    assert len(result) == 1
    assert result[0]["risk"] == "low"
    assert result[0]["confirmed"] is False
    assert result[0]["fingerprint_matched"] is False


def test_takeover_cible_refusee_ignoree(monkeypatch):
    fake_dns(monkeypatch, {"intra.example.com": "intra.github.io"})
    use_transport(
        monkeypatch,
        make_handler(
            {
                "https://intra.example.com/": TargetNotAllowedError("adresse privée"),
            }
        ),
        takeover_module,
    )

    assert run(check_subdomain_takeover(subs("intra.example.com"))) == []


def test_takeover_respecte_le_delai_d_annulation(monkeypatch):
    """Régression : CancelledError était avalée, le délai n'était pas respecté."""
    fake_dns(monkeypatch, {}, delay=1.0)
    use_transport(monkeypatch, make_handler({}), takeover_module)
    names = subs(*(f"s{i}.example.com" for i in range(15)))

    async def scenario():
        start = time.perf_counter()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(check_subdomain_takeover(names), timeout=0.2)
        return time.perf_counter() - start

    assert run(scenario()) < 0.9


def test_takeover_dns_totalement_en_echec_leve_module_error(monkeypatch):
    names = ("a.example.com", "b.example.com")
    fake_dns(monkeypatch, {}, errors=set(names))
    use_transport(monkeypatch, make_handler({}), takeover_module)

    with pytest.raises(ModuleError):
        run(check_subdomain_takeover(subs(*names)))


def test_takeover_entrees_invalides_ignorees(monkeypatch):
    fake_dns(monkeypatch, {})
    use_transport(monkeypatch, make_handler({}), takeover_module)

    assert run(check_subdomain_takeover(subs("contact@example.com", "*.example.com", "", "a b"))) == []
    assert run(check_subdomain_takeover([])) == []


def test_takeover_regex_s3_sans_backtracking_catastrophique():
    hostile = "x.s3" + "-a" * 120 + ".amazonaws.org"
    start = time.perf_counter()
    assert takeover_module.match_service(hostile) is None
    assert time.perf_counter() - start < 0.5


@pytest.mark.parametrize(
    "error, expected",
    [
        (TimeoutError("timed out"), "délai dépassé"),
        (ConnectionRefusedError(10061, "refused"), "connexion refusée"),
        (ConnectionResetError(10054, "reset"), "connexion réinitialisée par l'hôte"),
    ],
)
def test_tls_erreur_reseau_en_francais(monkeypatch, error, expected):
    """Régression (testphp.vulnweb.com) : « Hôte injoignable sur le port 443 : timed out »."""

    def connect(host, port, timeout, addresses):
        raise error

    monkeypatch.setattr(tls_module, "_connect", connect)

    result = tls_module._check_tls_sync("example.com", addresses=["203.0.113.10"])

    assert result["measured"] is False
    assert fr(result["error"]) == f"Hôte injoignable sur le port 443 : {expected}"


def test_tls_reinitialisation_passagere_refaite_une_fois(monkeypatch):
    """Régression (self-signed.badssl.com) : un RST isolé ne fait pas conclure « HTTPS fermé »."""
    calls = []

    def handshake(domain, port, context, timeout, addresses):
        calls.append(port)
        if len(calls) == 1:
            raise ConnectionResetError(10054, "reset")
        return {}, b"", "TLSv1.3", ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    monkeypatch.setattr(tls_module, "_handshake", handshake)
    monkeypatch.setattr(tls_module, "_http_port_responds", lambda *a: True)

    result = tls_module._check_tls_sync("example.com", addresses=["203.0.113.10"])

    assert len(calls) == 2
    assert result["https"] is True and result["valid"] is True and result["protocol"] == "TLSv1.3"


def test_tls_deux_reinitialisations_https_ferme(monkeypatch):
    def handshake(domain, port, context, timeout, addresses):
        raise ConnectionResetError(10054, "reset")

    monkeypatch.setattr(tls_module, "_handshake", handshake)
    monkeypatch.setattr(tls_module, "_http_port_responds", lambda *a: True)

    result = tls_module._check_tls_sync("example.com", addresses=["203.0.113.10"])

    assert result["https"] is False and result["measured"] is True


def test_http_utils_describe_error():
    request = httpx.Request("GET", "http://example.com/")
    assert fr(describe_error(httpx.ConnectTimeout("x", request=request))) == "délai dépassé"
    assert fr(describe_error(httpx.ReadTimeout("", request=request))) == "délai dépassé"
    assert fr(describe_error(TargetNotAllowedError("Cible non autorisée"))) == "Cible non autorisée"
    # Sans texte : message par défaut.
    assert fr(describe_error(TargetNotAllowedError())) == "cible non autorisée"


def test_http_utils_describe_error_en_francais():
    """Régression : le texte anglais de httpx remontait tel quel dans les messages."""
    request = httpx.Request("GET", "http://example.com/")
    disconnected = httpx.RemoteProtocolError(
        "Server disconnected without sending a response.", request=request
    )
    assert fr(describe_error(disconnected)) == "connexion fermée par le serveur sans réponse"
    illegal = httpx.RemoteProtocolError("illegal header line", request=request)
    assert fr(describe_error(illegal)) == "réponse HTTP non conforme (illegal header line)"
    assert fr(describe_error(httpx.RemoteProtocolError("", request=request))) == "réponse HTTP non conforme"
    assert fr(describe_error(httpx.ReadError("", request=request))) == "connexion interrompue"
    write_error = httpx.WriteError("[WinError 10054]", request=request)
    assert fr(describe_error(write_error)) == "connexion interrompue"


def test_http_utils_describe_error_connexion_et_autres_erreurs():
    request = httpx.Request("GET", "http://example.com/")
    assert fr(describe_error(httpx.ConnectError("refus", request=request))) == "connexion impossible (refus)"
    assert fr(describe_error(httpx.ConnectError("", request=request))) == "connexion impossible"
    # Erreur sans traitement particulier : nom du type et texte, ou le nom seul.
    assert fr(describe_error(httpx.InvalidURL("URL illisible"))) == "InvalidURL: URL illisible"
    assert describe_error(httpx.LocalProtocolError("", request=request)) == "LocalProtocolError"
    assert describe_error(RuntimeError()) == "RuntimeError"


@pytest.mark.parametrize(
    "headers, name",
    [
        ([("set-cookie", "FORTIWAFSID=abc; Path=/")], "Fortinet FortiWeb"),
        ([("x-pan-rematch", "1")], "Palo Alto Networks"),
        ([("set-cookie", "NSC_vserver=ffff; Path=/")], "Citrix NetScaler AppFirewall"),
        ([("server", "nginx-wallarm")], "Wallarm"),
        ([("set-cookie", "rbzid=1; Path=/")], "Reblaze"),
        ([("set-cookie", "aliyungf_tc=1; Path=/")], "Alibaba Cloud WAF"),
        ([("set-cookie", "wfwaf-authcookie-1234=x; Path=/")], "Wordfence"),
    ],
)
def test_waf_signatures_complementaires(headers, name):
    """Signatures passives complémentaires (en-têtes, cookies)."""
    result = waf_module.analyze_waf_responses([httpx.Response(200, headers=headers)])
    assert result["detected"] is True and result["waf_name"] == name
