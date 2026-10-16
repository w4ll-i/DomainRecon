import { configure, render, screen, waitFor, within } from "@testing-library/react";
import { useNavigate } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { queryKeys } from "../../api/queries";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { makeLegacyScan, makeScan } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { FamilyPage } from "./FamilyPage";
import { GenericFamilyView } from "./registry";

// Sous la charge de la suite complète, findBy* (1 s par défaut) et les tests (5 s) sont trop justes.
configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20_000 });

// Cytoscape (carte réseau) dessine dans un conteneur mesuré, absent de jsdom :
// il est remplacé par un témoin inerte (la carte de localisation est un SVG).
vi.mock("cytoscape", () => ({
  default: vi.fn(() => ({
    on: vi.fn(),
    destroy: vi.fn(),
    zoom: vi.fn(() => 1),
    width: vi.fn(() => 400),
    height: vi.fn(() => 300),
    fit: vi.fn(),
  })),
}));

function renderFamily(route: string) {
  return renderWithProviders(<FamilyPage />, { route, path: "/scans/:id/:family/:module?" });
}

const tabNames = (list: HTMLElement) => within(list).getAllByRole("tab").map((tab) => tab.textContent);

// Chemin affiché par le témoin du routeur de test (la navigation peut être différée d'une transition).
const expectPath = (path: string) => waitFor(() => expect(screen.getByTestId("location").textContent).toBe(path));

// Bouton qui navigue ailleurs (le routeur en mémoire n'a pas de barre d'adresse).
function GoTo({ to }: { to: string }) {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate(to)}>
      aller
    </button>
  );
}

describe("écran Famille", () => {
  it("présente la famille, sa note, ses constats et la navigation entre familles", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily("/scans/42/web");
    const title = await screen.findByRole("heading", { level: 1, name: "Web" });
    // La note et l'état de la famille sont dans l'en-tête, à côté du titre.
    const header = title.closest("header") as HTMLElement;
    expect(within(header).getByRole("img", { name: "Note C" })).toBeInTheDocument();
    expect(within(header).getByText("Attention")).toBeInTheDocument();
    expect(within(header).getByText("2 points à revoir")).toBeInTheDocument();
    expect(within(header).getByText("Famille")).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Familles du scan" });
    expect(within(nav).getAllByRole("link")).toHaveLength(8);
    // L'état de chaque famille est dit en toutes lettres, pas seulement par la couleur.
    expect(within(nav).getByRole("link", { name: "Web (Attention)" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Réseau (Critique)" })).toHaveAttribute("href", "/scans/42/network");
    expect(within(nav).getByRole("link", { name: "TLS (OK)" })).toBeInTheDocument();
    const findings = screen.getByRole("list", { name: "À corriger dans cette famille" });
    expect(within(findings).getAllByRole("listitem")).toHaveLength(1);
    expect(findings).toHaveTextContent("CSP absente");
    expect(screen.getByRole("link", { name: "Résultat de example.com" })).toHaveAttribute("href", "/scans/42");
    expect(window.localStorage.getItem("domainrecon.lastScan")).toBe("42");
  });

  it("réputation (7e famille, sans module) : non mesurée, sans module ni onglet ni constat à afficher", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily("/scans/42/reputation");
    const title = await screen.findByRole("heading", { level: 1, name: "Réputation" });
    expect(within(title.closest("header") as HTMLElement).getByText("Non mesuré")).toBeInTheDocument();
    expect(screen.getByText("Non mesuré, aucun module lancé")).toBeInTheDocument();
    expect(
      screen.getByText("Aucune conclusion possible : cette famille n'a pas pu être mesurée."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(screen.queryByRole("tabpanel")).not.toBeInTheDocument();
  });

  it("famille inconnue : message et retour au résultat, sans appel à l'API", async () => {
    const { calls } = mockFetch({});
    renderFamily("/scans/42/foo");
    expect(await screen.findByText("Famille inconnue")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Retour au résultat" })).toHaveAttribute("href", "/scans/42");
    // Aucune lecture de scan (le catalogue des modules, lui, peut être demandé).
    expect(calls.filter((call) => call.url.pathname.startsWith("/api/scan"))).toHaveLength(0);
  });

  it("scan introuvable : message et sortie, dernier scan consulté oublié", async () => {
    window.localStorage.setItem("domainrecon.lastScan", "42");
    mockFetch({ "GET /api/scan/42": () => jsonResponse({ detail: "Scan non trouvé", code: null, params: {} }, 404) });
    renderFamily("/scans/42/tls");
    expect(await screen.findByText("Scan introuvable")).toBeInTheDocument();
    await waitFor(() => expect(window.localStorage.getItem("domainrecon.lastScan")).toBeNull());
  });

  it("famille critique ou en attention sans constat : jamais « aucun point à corriger »", async () => {
    const base = makeScan();
    mockFetch({
      "GET /api/scan/42": makeScan({
        findings: [],
        families: { ...base.families, tls: { state: "critical", grade: "F", summary: "Certificat invalide" } },
      }),
    });
    renderFamily("/scans/42/tls");
    expect(
      await screen.findByText("Aucun constat détaillé, mais l'état de cette famille n'est pas sain : voir le détail des modules ci-dessous."),
    ).toBeInTheDocument();
    expect(screen.queryByText("Aucun point à corriger dans cette famille parmi les critères mesurés.")).not.toBeInTheDocument();
  });

  it("famille sans objet : « Sans objet », pas « rien à corriger »", async () => {
    const base = makeScan();
    mockFetch({
      "GET /api/scan/42": makeScan({ findings: [], families: { ...base.families, email: { state: "skipped", grade: null, summary: "" } } }),
    });
    renderFamily("/scans/42/email");
    expect(await screen.findByText("Sans objet pour cette cible : rien à corriger dans cette famille.")).toBeInTheDocument();
  });

  it("famille saine sans constat : « aucun point à corriger »", async () => {
    mockFetch({ "GET /api/scan/42": makeScan({ findings: [] }) });
    renderFamily("/scans/42/tls");
    expect(await screen.findByText("Aucun point à corriger dans cette famille parmi les critères mesurés.")).toBeInTheDocument();
  });

  it("affiche un ancien scan sans planter (en-têtes non évalués)", async () => {
    mockFetch({ "GET /api/scan/7": makeLegacyScan() });
    renderFamily("/scans/7/web");
    expect(await screen.findByRole("heading", { level: 1, name: "Web" })).toBeInTheDocument();
    expect(screen.getByText("Présent (valeur non évaluée : scan antérieur)")).toBeInTheDocument();
    expect(screen.getByText("Non mesuré")).toBeInTheDocument();
  });

  it("ancien scan sans état de famille : « À corriger » ne conclut pas, modules vides non mesurés", async () => {
    mockFetch({ "GET /api/scan/7": { ...makeLegacyScan(), security_headers: {} } });
    const { user } = renderFamily("/scans/7/web");
    await screen.findByRole("heading", { level: 1, name: "Web" });
    expect(screen.getByText("Aucune conclusion possible : cette famille n'a pas pu être mesurée.")).toBeInTheDocument();
    expect(screen.queryByText("Aucun point à corriger dans cette famille parmi les critères mesurés.")).not.toBeInTheDocument();
    // Un module à la fois : chaque onglet montre un module non mesuré, jamais un « Absent » trompeur.
    for (const name of ["En-têtes de sécurité", "CORS", "Cookies", "Fichiers web"]) {
      await user.click(screen.getByRole("tab", { name }));
      expect(screen.getByRole("region", { name })).toHaveTextContent("Non mesuré");
      expect(screen.queryByText("Absent")).not.toBeInTheDocument();
    }
  });

  it("la vue générique affiche une carte honnête par module", () => {
    render(<GenericFamilyView scan={makeScan()} family="identity" />);
    expect(screen.getByRole("heading", { name: "WHOIS" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Capture d'écran" })).toBeInTheDocument();
    expect(screen.getAllByText("Sans objet")).toHaveLength(2);
  });
});

describe("onglets des modules", () => {
  it("un onglet par module, dans l'ordre, le premier affiché par défaut", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily("/scans/42/web");
    const list = await screen.findByRole("tablist", { name: "Modules de la famille Web" });
    // Le premier onglet porte la pastille de son constat (« CSP absente »).
    expect(tabNames(list)).toEqual([
      "En-têtes de sécurité 1",
      "Cookies",
      "CORS",
      "Redirections",
      "Fichiers web",
      "Technologies",
      "WAF / CDN",
    ]);
    expect(within(list).getByRole("tab", { selected: true })).toHaveTextContent("En-têtes de sécurité");
    // Sans module dans l'adresse, l'adresse n'est pas réécrite.
    await expectPath("/scans/42/web");
  });

  it("n'affiche qu'un module à la fois, dans un panneau lié à son onglet", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily("/scans/42/web");
    expect(await screen.findByRole("region", { name: "En-têtes de sécurité" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "CORS" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Cookies" })).not.toBeInTheDocument();
    const tab = screen.getByRole("tab", { selected: true });
    const panel = screen.getByRole("tabpanel");
    expect(tab).toHaveAttribute("aria-controls", panel.id);
    expect(panel).toHaveAttribute("aria-labelledby", tab.id);
    expect(within(panel).getByRole("region", { name: "En-têtes de sécurité" })).toBeInTheDocument();
  });

  it("cliquer un onglet change de module et remplace l'adresse (lien profond)", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const { user } = renderFamily("/scans/42/web");
    await user.click(await screen.findByRole("tab", { name: "CORS" }));
    await expectPath("/scans/42/web/cors");
    expect(await screen.findByRole("region", { name: "CORS" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "En-têtes de sécurité" })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent("CORS");
    // Le titre de la famille et ses constats restent affichés au-dessus.
    expect(screen.getByRole("heading", { level: 1, name: "Web" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "À corriger dans cette famille" })).toBeInTheDocument();
  });

  it("clavier : flèches, Début et Fin déplacent l'onglet actif et l'adresse", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const { user } = renderFamily("/scans/42/web/cors");
    const cors = await screen.findByRole("tab", { name: "CORS" });
    cors.focus();
    await user.keyboard("{ArrowRight}");
    await expectPath("/scans/42/web/redirect_chain");
    expect(await screen.findByRole("region", { name: "Redirections" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Redirections" })).toHaveFocus();
    await user.keyboard("{End}");
    await expectPath("/scans/42/web/waf");
    expect(await screen.findByRole("region", { name: "WAF / CDN" })).toBeInTheDocument();
    await user.keyboard("{ArrowRight}");
    // En boucle : après le dernier, le premier.
    await expectPath("/scans/42/web/security_headers");
    await user.keyboard("{ArrowLeft}");
    await expectPath("/scans/42/web/waf");
    await user.keyboard("{Home}");
    await expectPath("/scans/42/web/security_headers");
    expect(await screen.findByRole("region", { name: "En-têtes de sécurité" })).toBeInTheDocument();
  });

  it("lien profond : /scans/42/web/cors ouvre l'onglet CORS", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily("/scans/42/web/cors");
    expect(await screen.findByRole("region", { name: "CORS" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent("CORS");
    expect(screen.queryByRole("region", { name: "En-têtes de sécurité" })).not.toBeInTheDocument();
    // La pastille de la navigation entre familles reste sur Web.
    expect(within(screen.getByRole("navigation", { name: "Familles du scan" })).getByRole("link", { name: "Web (Attention)" })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it.each([
    ["un module qui n'existe pas", "/scans/42/web/inconnu"],
    ["un module d'une autre famille", "/scans/42/web/open_ports"],
  ])("%s : retombe sur le premier onglet", async (_label, route) => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily(route);
    expect(await screen.findByRole("region", { name: "En-têtes de sécurité" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent("En-têtes de sécurité");
  });

  it("une famille à un seul module (TLS, e-mail) n'a pas de barre d'onglets", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const tls = renderFamily("/scans/42/tls");
    expect(await screen.findByRole("region", { name: "Certificat TLS" })).toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(screen.queryByRole("tabpanel")).not.toBeInTheDocument();
    tls.unmount();
    // Un module d'adresse inutile n'y change rien.
    renderFamily("/scans/42/email/n-importe-quoi");
    expect(await screen.findByRole("region", { name: "Sécurité e-mail" })).toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
  });

  it("pastille de constats sur l'onglet du module : nombre et gravité, rien à zéro", async () => {
    const base = makeScan();
    mockFetch({
      "GET /api/scan/42": makeScan({
        findings: [
          ...base.findings,
          { severity: "low", family: "web", module: "security_headers", message: "Referrer-Policy permissive" },
          { severity: "low", family: "web", module: "cors", message: "CORS ouvert" },
          { severity: "critical", family: "web", module: "cookie_security", message: "Cookie de session sans Secure" },
        ],
      }),
    });
    renderFamily("/scans/42/web");
    const list = await screen.findByRole("tablist");
    // Moyenne + faible : orange ; critique : rouge ; faible seule : neutre ; aucun constat : pas de pastille.
    expect(within(within(list).getByRole("tab", { name: /^En-têtes de sécurité/ })).getByText("2")).toHaveAttribute("data-tone", "warning");
    expect(within(within(list).getByRole("tab", { name: /^Cookies/ })).getByText("1")).toHaveAttribute("data-tone", "critical");
    expect(within(within(list).getByRole("tab", { name: /^CORS/ })).getByText("1")).toHaveAttribute("data-tone", "neutral");
    expect(within(within(list).getByRole("tab", { name: "WAF / CDN" })).queryByText(/\d/)).not.toBeInTheDocument();
  });

  it("réseau : la localisation d'abord, les ports sensibles signalés sur leur onglet", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const { user } = renderFamily("/scans/42/network");
    const list = await screen.findByRole("tablist", { name: "Modules de la famille Réseau" });
    expect(tabNames(list)).toEqual(["Géolocalisation", "Ports ouverts 1", "Réseau étendu"]);
    expect(within(within(list).getByRole("tab", { name: /^Ports ouverts/ })).getByText("1")).toHaveAttribute("data-tone", "critical");
    expect(screen.getByRole("region", { name: "Géolocalisation" })).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: /^Ports ouverts/ }));
    expect(await screen.findByText("3306", { exact: true })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Géolocalisation" })).not.toBeInTheDocument();
  });

  it("DNS : la carte réseau d'abord, puis un onglet par module", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily("/scans/42/dns");
    const list = await screen.findByRole("tablist", { name: "Modules de la famille DNS & sous-domaines" });
    expect(tabNames(list)).toEqual([
      "Carte réseau",
      "Enregistrements DNS",
      "Sous-domaines",
      "Takeover de sous-domaines",
      "DNS inverse (PTR)",
    ]);
    // La carte est chargée à la demande (lazyParts) : elle apparaît après les onglets.
    expect(await screen.findByRole("img", { name: /^Carte réseau de example\.com/ })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Enregistrements DNS" })).not.toBeInTheDocument();
  });

  it("identité : WHOIS, capture d'écran, puis notes et tags dans leur onglet", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const { user } = renderFamily("/scans/42/identity");
    const list = await screen.findByRole("tablist", { name: "Modules de la famille Identité" });
    expect(tabNames(list)).toEqual(["WHOIS", "Capture d'écran", "Notes et tags"]);
    expect(screen.getByRole("region", { name: "WHOIS" })).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Notes et tags" }));
    await expectPath("/scans/42/identity/notes");
    expect(await screen.findByRole("region", { name: "Notes et tags" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retirer le tag prod" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "WHOIS" })).not.toBeInTheDocument();
  });

  it("changer de scan remonte le panneau : les notes en cours de saisie ne passent pas à l'autre scan", async () => {
    const other = makeScan({ id: 43, domain: "shop.example.com", notes: "Autre scan", tags: [] });
    mockFetch({ "GET /api/scan/42": makeScan(), "GET /api/scan/43": other });
    const { user, queryClient } = renderWithProviders(
      <>
        <FamilyPage />
        <GoTo to="/scans/43/identity/notes" />
      </>,
      { route: "/scans/42/identity/notes", path: "/scans/:id/:family/:module?" },
    );
    // Le second scan est déjà en cache : l'écran passe de l'un à l'autre sans état de chargement.
    queryClient.setQueryData(queryKeys.scan(43, "fr"), other);
    const notes = await screen.findByLabelText("Notes d'investigation");
    expect(notes).toHaveValue("Note initiale");
    await user.type(notes, " brouillon");
    expect(notes).toHaveValue("Note initiale brouillon");
    await user.click(screen.getByRole("button", { name: "aller" }));
    await expectPath("/scans/43/identity/notes");
    await waitFor(() => expect(screen.getByLabelText("Notes d'investigation")).toHaveValue("Autre scan"));
  });

  it("aucun attribut style : en-tête, navigation, onglets et module", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    const { container } = renderFamily("/scans/42/web");
    await screen.findByRole("tablist");
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("aucune animation d'entrée sur l'en-tête ni sur le panneau", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderFamily("/scans/42/web");
    const title = await screen.findByRole("heading", { level: 1, name: "Web" });
    expect(title.closest("header")?.className).not.toMatch(/enter-/);
    expect(screen.getByRole("tabpanel").className).not.toMatch(/enter-/);
  });
});
