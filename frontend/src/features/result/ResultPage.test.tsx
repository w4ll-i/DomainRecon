import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { allOk, makeLegacyScan, makeScan } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { ResultPage } from "./ResultPage";


function renderResult(route = "/scans/42") {
  return renderWithProviders(<ResultPage />, { route, path: "/scans/:id" });
}

describe("écran Résultat", () => {
  it("met le verdict en tête : note, domaine, score, couverture, statut", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    expect(await screen.findByRole("heading", { level: 1, name: "example.com" })).toBeInTheDocument();
    // La jauge dit la note, le score et la couverture ; le score en chiffres n'est écrit qu'une fois.
    expect(screen.getByRole("img", { name: "Note B, score 78 sur 100, couverture 90 %" })).toHaveTextContent("B");
    expect(screen.getByText("78/100")).toBeInTheDocument();
    expect(screen.getByText("90 % du barème mesuré · confiance élevée")).toBeInTheDocument();
    expect(screen.getByText("Réussi")).toBeInTheDocument();
    expect(window.localStorage.getItem("domainrecon.lastScan")).toBe("42");
    expect(document.title).toBe("Résultat de example.com · DomainRecon");
  });

  it("liste « À corriger » avec la gravité et un lien vers la famille", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    const list = await screen.findByRole("list", { name: "À corriger" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("Élevée");
    expect(items[0]).toHaveTextContent("Port 3306 (MySQL) exposé");
    // Le lien mène droit à l'onglet du module du constat (ici les ports ouverts).
    expect(within(items[0]).getByRole("link", { name: "Voir la famille Réseau" })).toHaveAttribute(
      "href",
      "/scans/42/network/open_ports",
    );
  });

  it("affiche huit tuiles de familles accessibles", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    const network = await screen.findByRole("link", { name: "Réseau : Critique, note N/A. 1 port sensible exposé" });
    expect(network).toHaveAttribute("href", "/scans/42/network");
    expect(screen.getByRole("link", { name: "Web : Attention, note C. 2 points à revoir" })).toHaveAttribute(
      "href",
      "/scans/42/web",
    );
    // Six familles du scan, plus la réputation et les fuites (sans module dans le repli statique : non mesurées).
    expect(screen.getByRole("list", { name: "Familles" }).children).toHaveLength(8);
  });

  it("ne présente jamais un scan en échec comme « rien à corriger »", async () => {
    mockFetch({
      "GET /api/scan/42": makeScan({
        status: "error",
        error_message: "Cible injoignable : aucune résolution DNS ni réponse HTTP",
        findings: [],
        security_score: { score: 0, grade: "N/A", coverage: 0, grade_reason: "Aucun critère du score n'a pu être mesuré" },
        module_status: { ...allOk(), geo_data: { status: "timeout", error: "Délai dépassé (60 s)" } },
      }),
    });
    renderResult();
    expect(await screen.findByText("Aucune conclusion possible : l'analyse a échoué.")).toBeInTheDocument();
    expect(screen.queryByText("Aucun point à corriger parmi les critères mesurés.")).not.toBeInTheDocument();
    const banner = screen.getByRole("alert");
    expect(banner).toHaveTextContent("L'analyse a échoué");
    expect(banner).toHaveTextContent("Cible injoignable : aucune résolution DNS ni réponse HTTP");
    expect(banner).toHaveTextContent("Géolocalisation (délai dépassé)");
    // Motif visible (pas seulement en infobulle) ; pastille neutre : le texte secondaire
    // ne se pose pas sur le fond teinté du bandeau (contraste).
    expect(banner).toHaveTextContent("Délai dépassé (60 s)");
    expect(within(banner).getByText("Géolocalisation (délai dépassé)")).toHaveAttribute("data-tone", "neutral");
    expect(screen.getByText("Pas de note")).toBeInTheDocument();
    expect(screen.getByText("Aucun critère du score n'a pu être mesuré")).toBeInTheDocument();
  });

  it("scan en erreur ou partiel sans message ni module en échec : le bandeau le dit quand même", async () => {
    mockFetch({
      "GET /api/scan/42": makeScan({ status: "error", error_message: null, module_status: allOk() }),
      "GET /api/scan/43": makeScan({ id: 43, status: "partial", error_message: null, module_status: allOk() }),
    });
    const first = renderResult();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("L'analyse a échoué");
    expect(alert).toHaveTextContent("Le serveur n'a fourni aucun détail sur cet état.");
    first.unmount();
    renderResult("/scans/43");
    const status = await screen.findByText("Analyse incomplète");
    expect(status.closest("[role=status]")).toHaveTextContent("Le serveur n'a fourni aucun détail sur cet état.");
  });

  it("couverture insuffisante : score indicatif et message prudent", async () => {
    mockFetch({
      "GET /api/scan/42": makeScan({
        status: "partial",
        findings: [],
        security_score: { score: 50, grade: "N/A", coverage: 30, measured_max: 40, confidence: "low" },
      }),
    });
    renderResult();
    expect(await screen.findByText("Score indicatif 50/100")).toBeInTheDocument();
    expect(
      screen.getByText("Aucun point à corriger parmi les critères mesurés, mais la couverture est insuffisante pour conclure."),
    ).toBeInTheDocument();
    // La jauge n'invente pas de note : score indicatif, couverture, et « N/A » en grand.
    const gauge = screen.getByRole("img", { name: "Score indicatif 50 sur 100, sans note (couverture insuffisante), couverture 30 %" });
    expect(gauge).toHaveAttribute("data-state", "indicative");
    expect(gauge).toHaveTextContent("N/A");
  });

  it("scan introuvable (supprimé) : message, lien de sortie, dernier scan oublié", async () => {
    window.localStorage.setItem("domainrecon.lastScan", "42");
    mockFetch({ "GET /api/scan/42": () => jsonResponse({ detail: "Scan non trouvé", code: null, params: {} }, 404) });
    renderResult();
    expect(await screen.findByText("Scan introuvable")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Voir l'historique" })).toHaveAttribute("href", "/history");
    await waitFor(() => expect(window.localStorage.getItem("domainrecon.lastScan")).toBeNull());
  });

  it("identifiant non numérique : message sans appel à l'API", async () => {
    const { calls } = mockFetch({});
    renderResult("/scans/abc");
    expect(await screen.findByText("Identifiant de scan invalide.")).toBeInTheDocument();
    // Aucune lecture de scan (le catalogue des modules, lui, peut être demandé).
    expect(calls.filter((call) => call.url.pathname.startsWith("/api/scan"))).toHaveLength(0);
  });

  it("affiche un ancien scan sans planter", async () => {
    mockFetch({ "GET /api/scan/7": makeLegacyScan() });
    renderResult("/scans/7");
    expect(await screen.findByRole("heading", { level: 1, name: "legacy.example.org" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Familles" }).children).toHaveLength(8);
    expect(screen.getAllByText("Non mesuré").length).toBeGreaterThanOrEqual(6);
  });

  it("exporte par le serveur, relance et ouvre la timeline", async () => {
    const download = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:test");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const { calls } = mockFetch({
      "GET /api/scan/42": makeScan(),
      "GET /api/scan/42/export": () =>
        new Response("%PDF", { status: 200, headers: { "Content-Disposition": 'attachment; filename="rapport_example.pdf"' } }),
      "POST /api/scans": () => jsonResponse({ id: "job9", status: "running" }, 202),
    });
    const { user } = renderResult();
    await screen.findByRole("heading", { level: 1, name: "example.com" });
    expect(screen.getByRole("link", { name: "Timeline" })).toHaveAttribute("href", "/history/example.com");
    await user.click(screen.getByRole("button", { name: /Exporter/ }));
    expect(screen.getAllByRole("menuitem").map((item) => item.querySelector("span")?.textContent)).toEqual([
      "PDF",
      "HTML",
      "Markdown",
      "CSV",
      "JSON",
      "SARIF",
    ]);
    await user.click(screen.getByRole("menuitem", { name: /PDF/ }));
    expect(await screen.findByText("Export PDF téléchargé")).toBeInTheDocument();
    expect(download).toHaveBeenCalledOnce();
    const exportCall = calls.find((call) => call.url.pathname === "/api/scan/42/export");
    expect(exportCall?.url.searchParams.get("format")).toBe("pdf");
    expect(exportCall?.url.searchParams.get("lang")).toBe("fr");
    await user.click(screen.getByRole("button", { name: "Relancer" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/scans/live/job9"));
    expect(JSON.parse(String(calls.find((call) => call.method === "POST")?.init.body))).toEqual({ domain: "example.com" });
  });

  it("signale l'échec d'un export (PDF indisponible)", async () => {
    mockFetch({
      "GET /api/scan/42": makeScan(),
      "GET /api/scan/42/export": () => jsonResponse({ detail: "PDF indisponible : Chromium n'est pas installé" }, 503),
    });
    const { user } = renderResult();
    await screen.findByRole("heading", { level: 1, name: "example.com" });
    await user.click(screen.getByRole("button", { name: /Exporter/ }));
    await user.click(screen.getByRole("menuitem", { name: /PDF/ }));
    expect(await screen.findByText(/Export PDF impossible : PDF indisponible/)).toBeInTheDocument();
  });

  it("détaille le score dans un second onglet : points, bonus, non mesuré, explications, pénalités", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const { user } = renderResult();
    const overview = await screen.findByRole("tab", { name: "Vue d'ensemble" });
    const score = screen.getByRole("tab", { name: "Détail du score" });
    expect(overview).toHaveAttribute("aria-selected", "true");
    expect(score).toHaveAttribute("aria-selected", "false");
    // Le détail n'est pas monté tant que son onglet n'est pas ouvert.
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    await user.click(score);
    expect(score).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("location")).toHaveTextContent("/scans/42?tab=score");
    const panel = screen.getByRole("tabpanel", { name: "Détail du score" });
    const headers = within(panel).getByText("En-têtes").closest("li") as HTMLElement;
    expect(headers).toHaveTextContent("19/25");
    expect(headers).toHaveTextContent("4/6 conformes, 1 partiel(s)");
    expect(within(panel).getByRole("progressbar", { name: "En-têtes" })).toHaveAttribute("value", "19");
    expect(within(panel).getByText("WAF").closest("li")).toHaveTextContent("bonus");
    expect(within(panel).getByText("Takeover").closest("li")).toHaveTextContent("non mesuré");
    expect(within(panel).getByText("Pénalités hors barème : −10 point(s)")).toBeInTheDocument();
    // Retour à la vue d'ensemble : l'adresse perd son paramètre.
    await user.click(overview);
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/scans\/42$/);
    expect(await screen.findByRole("list", { name: "À corriger" })).toBeInTheDocument();
  });

  it("l'onglet « Détail du score » vit dans l'adresse (?tab=score) : lien partageable et rechargement", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult("/scans/42?tab=score");
    const panel = await screen.findByRole("tabpanel", { name: "Détail du score" });
    expect(within(panel).getByRole("progressbar", { name: "TLS" })).toHaveAttribute("value", "20");
    expect(screen.queryByRole("list", { name: "À corriger" })).not.toBeInTheDocument();
  });

  it("détail du score : barre masquée aux lecteurs d'écran pour un critère non mesuré, plafond sans grade inventé", async () => {
    const base = makeScan();
    mockFetch({
      "GET /api/scan/42": makeScan({
        security_score: { ...base.security_score, grade_cap: null, grade_cap_reasons: ["CORS reflète l'origine avec credentials"] },
      }),
    });
    const { user } = renderResult();
    await user.click(await screen.findByRole("tab", { name: "Détail du score" }));
    const panel = screen.getByRole("tabpanel");
    // Mesuré : une vraie barre nommée par son critère ; non mesuré : barre vide, cachée (0 se lirait « 0 point »).
    expect(within(panel).getByRole("progressbar", { name: "En-têtes" })).toHaveAttribute("aria-valuetext", "19/25");
    const takeover = within(panel).getByText("Takeover").closest("li") as HTMLElement;
    const unmeasured = takeover.querySelector("progress");
    expect(unmeasured).toHaveAttribute("aria-hidden", "true");
    expect(unmeasured).not.toHaveAttribute("aria-labelledby");
    expect(within(panel).queryByRole("progressbar", { name: "Takeover" })).not.toBeInTheDocument();
    expect(within(panel).getByText("Grade plafonné (vulnérabilité critique)")).toBeInTheDocument();
    expect(within(panel).queryByText(/plafonné à D/)).not.toBeInTheDocument();
  });

  it("sans détail de score à montrer : pas d'onglets, la vue d'ensemble seule", async () => {
    mockFetch({ "GET /api/scan/7": makeLegacyScan() });
    renderResult("/scans/7");
    await screen.findByRole("heading", { level: 1, name: "legacy.example.org" });
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(screen.queryByRole("tabpanel")).not.toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Familles" })).toBeInTheDocument();
  });

  it("en-tête : domaine, grande note, score sur 100, phrase de résumé et méta (date, durée, modules)", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    const title = await screen.findByRole("heading", { level: 1, name: "example.com" });
    const header = title.closest("header") as HTMLElement;
    // Grande note typographique et score : lettre B, 78/100.
    const grade = within(header).getByRole("img", { name: /^Note B/ });
    expect(grade).toHaveTextContent("B");
    expect(grade).toHaveTextContent("78/100");
    // Une phrase de résumé en langage clair : bonne posture, deux constats dont un sérieux.
    expect(within(header).getByText("Bonne note, mais 1 problème(s) sérieux à corriger en priorité.")).toBeInTheDocument();
    // Méta : statut, date, durée, modules mesurés sur lancés.
    const meta = (label: string) => within(header).getByText(label).nextElementSibling as HTMLElement;
    expect(meta("Date")).toHaveTextContent(/\d{2}\/\d{2}\/\d{4}/);
    expect(meta("Durée")).toHaveTextContent("23,4 s");
    expect(meta("Modules")).toHaveTextContent(/^\d+ mesurés sur \d+ lancés$/);
    // Plus de bandeau de métriques ni de radar.
    expect(screen.queryByRole("list", { name: "Indicateurs du scan" })).not.toBeInTheDocument();
    expect(screen.queryByTestId("radar")).not.toBeInTheDocument();
  });

  it("modules mesurés sur lancés : un module non lancé ne compte pas, un module en échec compte parmi les lancés", async () => {
    mockFetch({
      "GET /api/scan/42": makeScan({
        modules_launched: ["dns_records", "subdomains", "tls_certificate"],
        module_status: {
          dns_records: { status: "ok", error: null },
          subdomains: { status: "timeout", error: "Délai dépassé (60 s)" },
          tls_certificate: { status: "ok", error: null },
        },
      }),
    });
    renderResult();
    const header = (await screen.findByRole("heading", { level: 1, name: "example.com" })).closest("header") as HTMLElement;
    expect(within(header).getByText("Modules").nextElementSibling).toHaveTextContent("2 mesurés sur 3 lancés");
  });

  it("durée absente : « — », jamais un 0 qui se lirait comme une mesure", async () => {
    mockFetch({ "GET /api/scan/42": makeScan({ scan_duration: null }) });
    renderResult();
    const header = (await screen.findByRole("heading", { level: 1, name: "example.com" })).closest("header") as HTMLElement;
    expect(within(header).getByText("Durée").nextElementSibling).toHaveTextContent("—");
  });

  it("phrase de résumé : posture fragile et problèmes sérieux, ou aucun problème", async () => {
    mockFetch({
      "GET /api/scan/42": makeScan({
        security_score: { score: 30, grade: "F", coverage: 90, measured_max: 100 },
      }),
      "GET /api/scan/43": makeScan({
        id: 43,
        findings: [],
        security_score: { score: 96, grade: "A", coverage: 95, measured_max: 100 },
      }),
    });
    const first = renderResult();
    expect(await screen.findByText("Posture fragile : 1 problème(s) sérieux à corriger en priorité.")).toBeInTheDocument();
    first.unmount();
    renderResult("/scans/43");
    expect(await screen.findByText("Bonne posture de sécurité : rien à corriger.")).toBeInTheDocument();
  });

  it("« À corriger » : cinq actions prioritaires d'emblée, le reste se déplie", async () => {
    const severities = ["critical", "high", "high", "medium", "medium", "low", "low"] as const;
    const findings = severities.map((severity, index) => ({
      severity,
      family: "web" as const,
      module: "security_headers" as const,
      message: `Constat numéro ${index + 1}`,
    }));
    mockFetch({ "GET /api/scan/42": makeScan({ findings }) });
    const { user } = renderResult();
    const list = await screen.findByRole("list", { name: "À corriger" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(5);
    // Les plus graves d'abord (ordre de l'API) : le sixième constat n'est pas encore montré.
    expect(within(list).getByText("Constat numéro 1")).toBeInTheDocument();
    expect(within(list).queryByText("Constat numéro 6")).not.toBeInTheDocument();
    const more = screen.getByRole("button", { name: "Voir les 2 autres" });
    expect(more).toHaveAttribute("aria-expanded", "false");
    await user.click(more);
    expect(within(screen.getByRole("list", { name: "À corriger" })).getAllByRole("listitem")).toHaveLength(7);
    const less = screen.getByRole("button", { name: "Réduire la liste" });
    expect(less).toHaveAttribute("aria-expanded", "true");
    await user.click(less);
    expect(within(screen.getByRole("list", { name: "À corriger" })).getAllByRole("listitem")).toHaveLength(5);
  });

  it("jusqu'à cinq constats : aucun bouton de dépliage", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    await screen.findByRole("list", { name: "À corriger" });
    expect(screen.queryByRole("button", { name: /autres|Réduire/ })).not.toBeInTheDocument();
  });

  it("gravité d'un constat : icône et texte, jamais la couleur seule", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    const list = await screen.findByRole("list", { name: "À corriger" });
    const [first] = within(list).getAllByRole("listitem");
    const severity = within(first).getByText("Élevée");
    expect(severity.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it("familles en lignes simples : nom, note, état (icône et texte) et nombre de problèmes", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    const web = await screen.findByRole("link", { name: /^Web :/ });
    expect(web).toHaveAttribute("data-family", "web");
    expect(within(web).getByText("Web")).toBeInTheDocument();
    expect(within(web).getByRole("img", { name: "Note C" })).toBeInTheDocument();
    expect(within(web).getByText("Attention").querySelector("svg")).not.toBeNull();
    // Le nombre de problèmes de la famille vient des constats de l'API.
    const network = screen.getByRole("link", { name: /^Réseau :/ });
    expect(within(network).getByText("1 problème(s)")).toBeInTheDocument();
    expect(within(screen.getByRole("link", { name: /^Réputation :/ })).getByText("Aucun problème")).toBeInTheDocument();
    // Ni carte, ni compteur de modules par famille.
    expect(screen.queryByText("Modules mesurés")).not.toBeInTheDocument();
  });

  it("« À corriger » est mis en avant : titre de section, nombre de constats et ton de la gravité", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderResult();
    const section = await screen.findByRole("region", { name: "À corriger" });
    expect(within(section).getByText("Priorités")).toBeInTheDocument();
    expect(section).toHaveAttribute("data-tone", "critical");
    expect(within(section).getByText("2")).toHaveAttribute("data-tone", "critical");
  });

  it("une liste « À corriger » vide dit pourquoi, avec l'icône de l'état qu'elle exprime", async () => {
    mockFetch({ "GET /api/scan/42": makeScan({ findings: [] }) });
    renderResult();
    const message = await screen.findByText("Aucun point à corriger parmi les critères mesurés.");
    expect(message.closest("p")).toHaveAttribute("data-state", "ok");
    expect(screen.queryByRole("list", { name: "À corriger" })).not.toBeInTheDocument();
  });

  it("aucune animation d'entrée ni cascade, aucun style en ligne", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const { container } = renderResult();
    await screen.findByRole("heading", { level: 1, name: "example.com" });
    expect(container.querySelector("[class*=enter-], [class*=stagger]")).toBeNull();
    expect(container.querySelector("[style]")).toBeNull();
    expect(container.querySelector("style")).toBeNull();
  });
});
