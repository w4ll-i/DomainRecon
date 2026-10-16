import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { ScanResponse } from "../../../api/types";
import { HOSTILE, makeScan } from "../../../test/fixtures";
import {
  CookiesModule,
  CorsModule,
  HeadersModule,
  RedirectsModule,
  TechnologiesModule,
  WafModule,
  WebFilesModule,
} from "./web";

const region = (name: string) => screen.getByRole("region", { name });

describe("famille Web", () => {
  it("en-têtes : décompte, verdict par en-tête, valeur et détail", () => {
    render(<HeadersModule scan={makeScan()} />);
    const card = region("En-têtes de sécurité");
    expect(card).toHaveTextContent("4/6 conforme(s) · 1 partiel(s) · 1 absent(s)");
    const referrer = within(card).getByText("Referrer-Policy").closest("li") as HTMLElement;
    expect(referrer).toHaveTextContent("Partiel");
    expect(referrer).toHaveTextContent("Valeur permissive");
    expect(referrer).toHaveTextContent("unsafe-url");
  });

  it("en-têtes : signale la rétrogradation HTTPS → HTTP", () => {
    const scan = makeScan();
    render(<HeadersModule scan={{ ...scan, security_headers: { ...scan.security_headers, https_downgrade: true } }} />);
    expect(screen.getByText("HTTPS redirige vers HTTP : en-têtes lus sur la réponse servie en clair.")).toBeInTheDocument();
  });

  it("cookies : note, drapeaux et problèmes ; une donnée hostile reste du texte", () => {
    const scan = makeScan();
    const cookies = [{ ...scan.cookie_security.cookies![0], name: HOSTILE }];
    render(<CookiesModule scan={{ ...scan, cookie_security: { ...scan.cookie_security, cookies } }} />);
    const card = region("Cookies");
    expect(within(card).getByRole("img", { name: "Note C" })).toBeInTheDocument();
    expect(card).toHaveTextContent("1 cookie(s) analysé(s)");
    expect(card).toHaveTextContent("1 problème(s)");
    expect(card).toHaveTextContent("HttpOnly : non");
    expect(card).toHaveTextContent("HttpOnly absent");
    expect(within(card).getByText(HOSTILE)).toBeInTheDocument();
    expect(card.querySelector("img")).toBeNull();
  });

  it("CORS : verdict critique quand l'origine est reflétée avec credentials", () => {
    const scan = makeScan({
      cors: { measured: true, cors_enabled: true, misconfigured: true, reflects_origin: true, reflects_with_credentials: true, severity: "critical" },
    });
    render(<CorsModule scan={scan} />);
    expect(screen.getByText("Misconfiguration CORS critique : origine arbitraire acceptée avec credentials")).toBeInTheDocument();
    const reflects = screen.getByText("Reflète l'origine avec credentials").closest("li") as HTMLElement;
    expect(reflects).toHaveTextContent("Oui");
  });

  it("CORS en échec : jamais « CORS non activé »", () => {
    const base = makeScan();
    const scan = makeScan({
      module_status: { ...base.module_status, cors: { status: "failed", error: "Site injoignable" } },
      cors: { measured: false, error: "Site injoignable" },
    });
    render(<CorsModule scan={scan} />);
    expect(screen.queryByText("CORS non activé")).not.toBeInTheDocument();
    expect(screen.getByText("Site injoignable")).toBeInTheDocument();
  });

  it("redirections : synthèse et étapes ; chaîne partielle gardée sous l'avertissement", () => {
    render(<RedirectsModule scan={makeScan()} />);
    const card = region("Redirections");
    expect(within(card).getByText("Force HTTPS").nextElementSibling).toHaveTextContent("Oui");
    expect(card).toHaveTextContent("https://example.com/");
    expect(within(card).getAllByRole("listitem")).toHaveLength(2);
  });

  it("redirections en échec avec une chaîne : avertissement et chaîne", () => {
    const base = makeScan();
    const scan = makeScan({
      module_status: { ...base.module_status, redirect_chain: { status: "failed", error: "HTTPS injoignable" } },
      redirect_chain: { measured: false, error: "HTTPS injoignable", chain: [{ url: "http://example.com/", status_code: 0, error: "Connexion refusée" }] },
    });
    render(<RedirectsModule scan={scan} />);
    expect(screen.getByText("HTTPS injoignable")).toBeInTheDocument();
    expect(screen.getByText("Connexion refusée")).toBeInTheDocument();
  });

  it("fichiers web : trouvé, absent, non vérifié", () => {
    render(<WebFilesModule scan={makeScan()} />);
    const card = region("Fichiers web");
    expect(within(card).getByText("robots.txt").closest("div")).toHaveTextContent("Trouvé");
    expect(card).toHaveTextContent("/admin");
    expect(within(card).getByText("sitemap.xml").closest("div")).toHaveTextContent("Absent");
    expect(within(card).getByText("security.txt").closest("div")).toHaveTextContent("Non vérifié");
    expect(card).toHaveTextContent("Délai dépassé");
  });

  it("technologies et WAF/CDN", () => {
    render(
      <>
        <TechnologiesModule scan={makeScan()} />
        <WafModule scan={makeScan()} />
      </>,
    );
    expect(region("Technologies")).toHaveTextContent("Nginx");
    expect(region("Technologies")).toHaveTextContent("Serveur Web");
    const waf = region("WAF / CDN");
    expect(waf).toHaveTextContent("Aucun WAF détecté");
    expect(waf).toHaveTextContent("CDN : Edgecast");
    expect(waf).toHaveTextContent("Un CDN n'est pas un WAF");
  });

  it("WAF détecté derrière un CDN : garde la mention du CDN, sans libellé générique « WAF » ni « CDN : ? »", () => {
    const { unmount } = render(
      <WafModule scan={makeScan({ waf: { measured: true, detected: true, waf_name: "Cloudflare", confidence: "high", cdn_detected: true, cdn_name: "Cloudflare" } })} />,
    );
    const named = region("WAF / CDN");
    expect(named).toHaveTextContent("Cloudflare");
    expect(named).toHaveTextContent("CDN : Cloudflare");
    unmount();
    render(
      <WafModule scan={makeScan({ waf: { measured: true, detected: true, waf_name: null, confidence: "low", cdn_detected: true, cdn_name: null } })} />,
    );
    const anonymous = region("WAF / CDN");
    expect(anonymous).toHaveTextContent("WAF non identifié");
    expect(anonymous).toHaveTextContent("CDN détecté");
    expect(anonymous).not.toHaveTextContent("CDN : ?");
  });

  it("en-têtes d'un ancien scan : présence seulement, jamais un verdict « Conforme »", () => {
    const scan = makeScan({ security_headers: { headers_found: { "X-Frame-Options": "DENY" } } });
    render(<HeadersModule scan={scan} />);
    const card = region("En-têtes de sécurité");
    const present = within(card).getByText("X-Frame-Options").closest("li") as HTMLElement;
    expect(present).toHaveTextContent("Présent (valeur non évaluée : scan antérieur)");
    expect(present).not.toHaveTextContent("Conforme");
    expect(within(card).getByText("Content-Security-Policy").closest("li")).toHaveTextContent("Absent");
  });

  it("CORS partiel sans reflet avéré : bandeau non concluant, pas de ligne verte « Reflète l'origine »", () => {
    const scan = makeScan({
      cors: {
        measured: true,
        cors_enabled: true,
        misconfigured: false,
        reflects_origin: false,
        reflects_with_credentials: false,
        partial: true,
        origin_tests: { total: 3, succeeded: 2, errors: ["Origine https://evil.example : délai dépassé"] },
      },
    });
    render(<CorsModule scan={scan} />);
    const banner = screen.getByText(/Résultat non concluant/);
    expect(banner).toHaveAttribute("data-tone", "warning");
    expect(screen.queryByText("CORS activé et correctement configuré")).not.toBeInTheDocument();
    expect(screen.queryByText("Reflète l'origine")).not.toBeInTheDocument();
    expect(screen.queryByText("Reflète l'origine avec credentials")).not.toBeInTheDocument();
    expect(screen.getByText("Origine https://evil.example : délai dépassé")).toBeInTheDocument();
  });

  it("CORS non activé : « Non » en ton neutre, jamais rouge", () => {
    render(<CorsModule scan={makeScan()} />);
    const pill = within(screen.getByText("CORS activé").closest("li") as HTMLElement).getByText("Non");
    expect(pill).toHaveAttribute("data-tone", "neutral");
  });

  it("redirections : nombre de sauts absent affiché N/A, pas 0", () => {
    const base = makeScan();
    render(<RedirectsModule scan={makeScan({ redirect_chain: { ...base.redirect_chain, total_hops: undefined } })} />);
    expect(within(region("Redirections")).getByText("Sauts").nextElementSibling).toHaveTextContent("N/A");
  });

  it("fichiers web : un fichier absent n'est pas une alerte rouge", () => {
    render(<WebFilesModule scan={makeScan()} />);
    const pill = within(region("Fichiers web")).getByText("sitemap.xml").closest("div")?.querySelector("[data-tone]");
    expect(pill).toHaveAttribute("data-tone", "neutral");
  });

  it("WAF : un nom non textuel ne fait pas planter la carte", () => {
    const waf = { measured: true, detected: true, waf_name: 42, cdn_detected: true, cdn_name: 7 } as unknown as ScanResponse["waf"];
    render(<WafModule scan={makeScan({ waf })} />);
    expect(region("WAF / CDN")).toHaveTextContent("WAF non identifié");
    expect(region("WAF / CDN")).toHaveTextContent("CDN détecté");
  });

  it("modules vides d'un ancien scan : non mesurés, pas « Mesuré » ni six « Absent » rouges", () => {
    const scan = makeScan({ cors: {}, security_headers: {}, cookie_security: {}, waf: {}, web_files: {}, redirect_chain: {} });
    render(
      <>
        <HeadersModule scan={scan} />
        <CorsModule scan={scan} />
        <CookiesModule scan={scan} />
        <WafModule scan={scan} />
        <WebFilesModule scan={scan} />
        <RedirectsModule scan={scan} />
      </>,
    );
    for (const name of ["En-têtes de sécurité", "CORS", "Cookies", "WAF / CDN", "Fichiers web", "Redirections"]) {
      expect(region(name)).toHaveTextContent("Non mesuré");
      expect(region(name)).not.toHaveTextContent("Mesuré");
    }
    expect(screen.queryByText("Absent")).not.toBeInTheDocument();
    expect(screen.queryByText("CORS non activé")).not.toBeInTheDocument();
    expect(screen.queryByText("Aucun WAF détecté")).not.toBeInTheDocument();
  });
});
