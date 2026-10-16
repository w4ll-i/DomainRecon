import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import i18n from "../../i18n";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { makeSummary } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { NewScanPage } from "./NewScanPage";

const history = { total: 0, scans: [] };

describe("Nouveau scan", () => {
  it("lance un scan et ouvre le suivi en direct", async () => {
    const { calls } = mockFetch({
      "GET /api/history": history,
      "POST /api/scans": () => jsonResponse({ id: "abc123", status: "running" }, 202),
    });
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    expect(screen.getByLabelText("Domaine ou URL à analyser")).toHaveFocus();
    await user.type(screen.getByLabelText("Domaine ou URL à analyser"), "  example.com ");
    await user.click(screen.getByRole("button", { name: "Scan" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/scans/live/abc123"));
    const post = calls.find((call) => call.method === "POST");
    expect(JSON.parse(String(post?.init.body))).toEqual({ domain: "example.com" });
    expect(document.title).toBe("Nouveau scan · DomainRecon");
  });

  it("présente le héros : étiquette, titre « Analyse de domaine » (niveau 1) et accroche", () => {
    mockFetch({ "GET /api/history": history });
    const { container } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const kicker = screen.getByText("Reconnaissance · OSINT");
    const title = screen.getByRole("heading", { level: 1, name: "Analyse de domaine" });
    // L'étiquette précède le titre ; le dernier mot reste dans le titre.
    expect(kicker.compareDocumentPosition(title) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(title).getByText("domaine")).toBeInTheDocument();
    expect(screen.getByText(/Analysez la sécurité et l'infrastructure publique d'un domaine/)).toBeInTheDocument();
    // Le titre de l'onglet reste « Nouveau scan ».
    expect(document.title).toBe("Nouveau scan · DomainRecon");
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("anglais : étiquette, titre et accent traduits", async () => {
    mockFetch({ "GET /api/history": history });
    await i18n.changeLanguage("en");
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const title = screen.getByRole("heading", { level: 1, name: "Domain analysis" });
    expect(within(title).getByText("analysis")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scan" })).toBeInTheDocument();
  });

  it("le bouton SCAN est le bouton principal (accent plein), et le champ une saisie mono", () => {
    mockFetch({ "GET /api/history": history });
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const button = screen.getByRole("button", { name: "Scan" });
    expect(button).toHaveClass("btn");
    expect(button).toHaveAttribute("data-variant", "primary");
    expect(button).toHaveAttribute("type", "submit");
    const input = screen.getByLabelText("Domaine ou URL à analyser");
    expect(input).toHaveClass("mono");
    expect(input).toHaveAttribute("placeholder", "exemple.com");
  });

  it("propose les trois profils et explique chacun ; « complet » est choisi par défaut", () => {
    mockFetch({ "GET /api/history": history });
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const group = screen.getByRole("group", { name: "Profil du scan" });
    expect(within(group).getByRole("radio", { name: /Rapide/ })).not.toBeChecked();
    expect(within(group).getByRole("radio", { name: /Complet/ })).toBeChecked();
    expect(within(group).getByRole("radio", { name: /Personnalisé/ })).not.toBeChecked();
    expect(within(group).getByText(/Aucun module actif ni sensible/)).toBeInTheDocument();
    expect(within(group).getByText(/modules passifs essentiels/)).toBeInTheDocument();
    // Pas de sélection de modules ni d'autorisation tant que le profil n'est pas personnalisé.
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("refuse un domaine trop court sans appeler l'API", async () => {
    const { calls } = mockFetch({ "GET /api/history": history });
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    await user.type(screen.getByLabelText("Domaine ou URL à analyser"), "ab");
    await user.click(screen.getByRole("button", { name: "Scan" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Le domaine doit faire de 3 à 255 caractères.");
    expect(screen.getByLabelText("Domaine ou URL à analyser")).toHaveAttribute("aria-invalid", "true");
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("affiche le refus du serveur tel qu'il est rendu", async () => {
    mockFetch({
      "GET /api/history": history,
      "POST /api/scans": () =>
        jsonResponse({ detail: "Cible non autorisée : adresse privée", code: "target.not_allowed", params: {} }, 400),
    });
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    await user.type(screen.getByLabelText("Domaine ou URL à analyser"), "192.168.1.1");
    await user.click(screen.getByRole("button", { name: "Scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cible non autorisée : adresse privée");
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/$/);
  });

  it("remplit le champ avec un exemple", async () => {
    mockFetch({ "GET /api/history": history });
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    await user.click(screen.getByRole("button", { name: "wikipedia.org" }));
    expect(screen.getByLabelText("Domaine ou URL à analyser")).toHaveValue("wikipedia.org");
  });

  it("liste les derniers scans avec leur note", async () => {
    mockFetch({
      "GET /api/history": {
        total: 2,
        scans: [
          makeSummary(),
          makeSummary({ id: 7, domain: "legacy.example.org", security_score: { score: 40, grade: "N/A", coverage: 30 } }),
        ],
      },
    });
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const link = await screen.findByRole("link", { name: /example\.com/ });
    expect(link).toHaveAttribute("href", "/scans/42");
    expect(screen.getByRole("link", { name: /legacy\.example\.org/ })).toHaveAttribute("href", "/scans/7");
    expect(screen.getAllByRole("img", { name: "Note N/A" })).toHaveLength(1);
  });

  it("scans récents : cinq cartes au plus, liées, avec note et score", async () => {
    const scans = Array.from({ length: 7 }, (_, index) =>
      makeSummary({ id: 100 + index, domain: `site-${index}.example.org`, scan_timestamp: `2026-09-2${index}T10:05:00Z` }),
    );
    mockFetch({ "GET /api/history": { total: 7, scans } });
    const { container } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    // La région existe avant les données (elle porte le titre) : on attend les cartes.
    await screen.findAllByRole("link", { name: /site-\d\.example\.org/ });
    const region = screen.getByRole("region", { name: "Derniers scans" });
    const links = within(region).getAllByRole("link", { name: /site-\d\.example\.org/ });
    expect(links).toHaveLength(5);
    expect(links.map((link) => link.getAttribute("href"))).toEqual(["/scans/100", "/scans/101", "/scans/102", "/scans/103", "/scans/104"]);
    // Chaque lien enveloppe une petite carte de chiffre clé : note, score et date lisibles.
    const card = within(links[0]).getByText("site-0.example.org").closest("[data-variant]");
    expect(card).toHaveAttribute("data-variant", "secondary");
    expect(card).toHaveAttribute("data-tone", "ok");
    expect(within(links[0]).getByRole("img", { name: "Note B" })).toHaveTextContent("B");
    expect(links[0]).toHaveTextContent("78/100");
    expect(links[0]).toHaveTextContent(/20\/09\/2026/);
    // Aucune cascade d'entrée : la liste est une simple liste de cinq lignes.
    const list = within(region).getByRole("list");
    expect(list.className).not.toMatch(/stagger/);
    expect(Array.from(list.children)).toHaveLength(5);
    expect(within(region).getByRole("link", { name: "Tout l'historique" })).toHaveAttribute("href", "/history");
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("la carte d'un scan récent dit la note en toutes lettres et teinte son ton", async () => {
    mockFetch({
      "GET /api/history": {
        total: 4,
        scans: [
          makeSummary({ id: 1, domain: "bad.example.org", security_score: { score: 34, grade: "F", coverage: 100 } }),
          makeSummary({ id: 2, domain: "mid.example.org", security_score: { score: 62, grade: "C", coverage: 80 } }),
          makeSummary({ id: 3, domain: "indicative.example.org", security_score: { score: 60, grade: "C", coverage: 40, measured_max: 40 } }),
          makeSummary({ id: 4, domain: "none.example.org", security_score: { score: 0, grade: "N/A", coverage: 0 } }),
        ],
      },
    });
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const toneOf = (name: RegExp) => screen.getByRole("link", { name }).querySelector("[data-variant]")?.getAttribute("data-tone");
    await screen.findByRole("link", { name: /bad\.example\.org/ });
    expect(toneOf(/bad\.example\.org/)).toBe("critical");
    expect(toneOf(/mid\.example\.org/)).toBe("warning");
    expect(toneOf(/indicative\.example\.org/)).toBe("na");
    expect(toneOf(/none\.example\.org/)).toBe("na");
    expect(screen.getByRole("link", { name: /bad\.example\.org/ })).toHaveTextContent("34/100");
    // Score indicatif : jamais présenté comme une note ; rien de mesuré : « N/A ».
    expect(screen.getByRole("link", { name: /indicative\.example\.org/ })).toHaveTextContent("60/100 (indicatif)");
    expect(screen.getByRole("link", { name: /none\.example\.org/ })).toHaveTextContent("N/A");
  });

  it("annonce le chargement des scans récents, puis leur indisponibilité", async () => {
    mockFetch({ "GET /api/history": () => jsonResponse({ detail: "Base verrouillée", code: null, params: {} }, 503) });
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    expect(screen.getByRole("status")).toHaveTextContent("Chargement…");
    expect(await screen.findByText(/Derniers scans indisponibles/)).toBeInTheDocument();
  });

  it("invite à lancer un premier scan quand l'historique est vide", async () => {
    mockFetch({ "GET /api/history": history });
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    expect(await screen.findByText("Aucune analyse pour l'instant : lancez votre premier scan.")).toBeInTheDocument();
  });

  it("l'erreur affichée disparaît dès que la saisie change (ou qu'un exemple est choisi)", async () => {
    mockFetch({
      "GET /api/history": history,
      "POST /api/scans": () => jsonResponse({ detail: "Cible non autorisée : adresse privée", code: "target.not_allowed" }, 400),
    });
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const input = screen.getByLabelText("Domaine ou URL à analyser");
    await user.type(input, "192.168.1.1");
    await user.click(screen.getByRole("button", { name: "Scan" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cible non autorisée");
    expect(input).toHaveAttribute("aria-invalid", "true");
    await user.type(input, "0");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(input).not.toHaveAttribute("aria-invalid");
    // Même chose avec un exemple.
    await user.click(screen.getByRole("button", { name: "Scan" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "github.com" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("trop de scans en cours (429) : annoncé une seule fois, par la notification et non par l'alerte du champ", async () => {
    mockFetch({
      "GET /api/history": history,
      "POST /api/scans": () => jsonResponse({ detail: "Trop de scans simultanés (3 au maximum)", code: "api.too_many_scans" }, 429),
    });
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const input = screen.getByLabelText("Domaine ou URL à analyser");
    await user.type(input, "example.com");
    await user.click(screen.getByRole("button", { name: "Scan" }));
    expect(await screen.findByText("Trop de scans simultanés (3 au maximum)")).toBeInTheDocument();
    expect(screen.getAllByText("Trop de scans simultanés (3 au maximum)")).toHaveLength(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    // Ce n'est pas une faute de saisie : le champ n'est pas marqué invalide.
    expect(input).not.toHaveAttribute("aria-invalid");
  });
});
