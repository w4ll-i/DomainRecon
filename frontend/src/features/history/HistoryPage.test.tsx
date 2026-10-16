import { screen, waitFor, within } from "@testing-library/react";
import { useNavigate } from "react-router";
import { describe, expect, it } from "vitest";
import type { ScanSummary } from "../../api/types";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { makeSummary } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { HistoryPage } from "./HistoryPage";

const scans: ScanSummary[] = [
  makeSummary(),
  makeSummary({ id: 43, domain: "shop.example.com", security_score: { score: 34, grade: "F", coverage: 100 }, status: "partial", tags: [] }),
  makeSummary({
    id: 44,
    domain: "legacy.example.org",
    subdomains_count: null,
    security_score: { score: 60, grade: "C", coverage: 40, measured_max: 40 },
  }),
];

// Bouton « retour » : le routeur en mémoire n'a pas de bouton Précédent.
function BackButton() {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate(-1)}>
      retour
    </button>
  );
}

function renderHistory(route = "/history", total = 3) {
  const result = mockFetch({
    "GET /api/history": ({ url }) =>
      jsonResponse({ total, scans: url.searchParams.get("domain") === "shop" ? [scans[1]] : scans }),
    "DELETE /api/scan/42": () => jsonResponse({ message: "Scan supprimé", id: 42 }),
    "DELETE /api/scan/43": () => jsonResponse({ detail: "Scan non trouvé", code: null, params: {} }, 404),
  });
  return { ...renderWithProviders(<HistoryPage />, { route, path: "/history" }), calls: result.calls };
}

describe("écran Historique", () => {
  it("liste les scans : domaine, note, score, statut, sous-domaines, liens", async () => {
    renderHistory();
    const table = await screen.findByRole("table", { name: "Scans enregistrés, du plus récent au plus ancien" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(within(rows[1]).getByRole("link", { name: "example.com" })).toHaveAttribute("href", "/scans/42");
    expect(within(rows[1]).getByRole("img", { name: "Note B" })).toBeInTheDocument();
    expect(rows[1]).toHaveTextContent("78/100");
    expect(within(rows[3]).getByRole("img", { name: "Note N/A" })).toBeInTheDocument();
    // Même règle de score que Résultat et Timeline : couverture insuffisante = score indicatif.
    expect(rows[3]).toHaveTextContent("60/100 (indicatif)");
    const unmeasured = within(rows[3]).getByTitle("Sous-domaines non mesurés (échec, délai dépassé ou sans objet)");
    expect(unmeasured).toHaveTextContent("N/A");
    // Explication visible (légende liée à la cellule), pas seulement en infobulle.
    const note = screen.getByText("N/A : sous-domaines non mesurés (échec, délai dépassé ou sans objet).");
    expect(unmeasured.closest("td")).toHaveAttribute("aria-describedby", note.id);
    expect(within(rows[2]).getByRole("link", { name: "Timeline de shop.example.com" })).toHaveAttribute(
      "href",
      "/history/shop.example.com",
    );
    expect(screen.getByText("1–3 sur 3 scan(s)")).toHaveAttribute("aria-live", "polite");
    // Le défilement horizontal du tableau est atteignable au clavier.
    const region = screen.getByRole("region", { name: "Liste des scans (défilable horizontalement)" });
    expect(region).toHaveAttribute("tabindex", "0");
    expect(within(region).getByRole("table")).toBeInTheDocument();
  });

  it("cherche côté serveur après une pause de saisie et garde l'état dans l'URL", async () => {
    const { user, calls } = renderHistory();
    await screen.findByRole("table");
    await user.type(screen.getByRole("searchbox", { name: "Rechercher un domaine" }), "shop");
    await waitFor(() => expect(calls.some((call) => call.url.searchParams.get("domain") === "shop")).toBe(true));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/history?q=shop"));
    expect(await screen.findByRole("link", { name: "shop.example.com" })).toBeInTheDocument();
  });

  it("le bouton Précédent défait chaque recherche et chaque filtre, et resynchronise le champ", async () => {
    mockFetch({
      "GET /api/history": ({ url }) => jsonResponse({ total: 3, scans: url.searchParams.get("domain") === "shop" ? [scans[1]] : scans }),
    });
    const { user } = renderWithProviders(
      <>
        <HistoryPage />
        <BackButton />
      </>,
      { route: "/history", path: "/history" },
    );
    await screen.findByRole("table");
    const search = screen.getByRole("searchbox", { name: "Rechercher un domaine" });
    await user.type(search, "shop");
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(/^\/history\?q=shop$/));
    await user.selectOptions(screen.getByLabelText("Note"), "F");
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("grade=F"));
    await user.click(screen.getByRole("button", { name: "retour" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(/^\/history\?q=shop$/));
    expect(search).toHaveValue("shop");
    await user.click(screen.getByRole("button", { name: "retour" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(/^\/history$/));
    // L'URL fait foi : le champ suit le retour.
    await waitFor(() => expect(search).toHaveValue(""));
  });

  it("garde un caractère tapé après l'envoi de la recherche (pas de resynchronisation sur sa propre valeur)", async () => {
    const { user } = renderHistory();
    await screen.findByRole("table");
    const search = screen.getByRole("searchbox", { name: "Rechercher un domaine" });
    await user.type(search, "shop");
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/history?q=shop"));
    await user.type(search, "x");
    expect(search).toHaveValue("shopx");
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/history?q=shopx"));
    expect(search).toHaveValue("shopx");
  });

  it("filtre par note et par statut, puis réinitialise", async () => {
    const { user, calls } = renderHistory();
    await screen.findByRole("table");
    await user.selectOptions(screen.getByLabelText("Note"), "F");
    await user.selectOptions(screen.getByLabelText("Statut"), "partial");
    await waitFor(() =>
      expect(calls.some((call) => call.url.searchParams.get("grade") === "F" && call.url.searchParams.get("status") === "partial")).toBe(
        true,
      ),
    );
    expect(screen.getByTestId("location")).toHaveTextContent("grade=F");
    await user.click(screen.getByRole("button", { name: "Réinitialiser les filtres" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(/^\/history$/));
  });

  it("pagine côté serveur (25 par page)", async () => {
    const { user, calls } = renderHistory("/history", 60);
    await screen.findByRole("table");
    expect(screen.getByText("Page 1 sur 3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Page précédente" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Page suivante" }));
    await waitFor(() => expect(calls.some((call) => call.url.searchParams.get("offset") === "25")).toBe(true));
    expect(screen.getByTestId("location")).toHaveTextContent("page=2");
  });

  it("revient à la dernière page existante quand l'URL pointe trop loin", async () => {
    const { calls } = renderHistory("/history?page=9", 30);
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("page=2"));
    await waitFor(() => expect(calls.some((call) => call.url.searchParams.get("offset") === "25")).toBe(true));
    expect(await screen.findByText("Page 2 sur 2")).toBeInTheDocument();
  });

  it("page absurde dans l'URL : le décalage envoyé à l'API reste borné et l'écran revient à la dernière page", async () => {
    const { calls } = renderHistory("/history?page=99999999999999999999", 30);
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("page=2"));
    expect(calls.every((call) => Number(call.url.searchParams.get("offset")) <= 2 ** 31 - 1)).toBe(true);
    expect(await screen.findByText("Page 2 sur 2")).toBeInTheDocument();
  });

  it.each([
    ["sans filtre", "/history?page=9"],
    ["avec une recherche", "/history?q=shop&page=9"],
  ])("retour à la dernière page (%s) : jamais d'état vide entre-temps", async (_, route) => {
    mockFetch({
      "GET /api/history": ({ url }) => jsonResponse({ total: 30, scans: url.searchParams.get("offset") === "200" ? [] : scans }),
    });
    const seen: string[] = [];
    // Les deux textes de l'état vide : historique vide et recherche sans résultat.
    const observer = new MutationObserver(() => {
      const text = document.body.textContent ?? "";
      if (text.includes("Aucun scan") || text.includes("Aucune analyse")) seen.push(text);
    });
    observer.observe(document.body, { subtree: true, childList: true, characterData: true });
    renderWithProviders(<HistoryPage />, { route, path: "/history" });
    expect(await screen.findByText("Page 2 sur 2")).toBeInTheDocument();
    observer.disconnect();
    expect(seen).toEqual([]);
  });

  it("page refusée par le serveur : bouton pour revenir à la première page", async () => {
    mockFetch({
      "GET /api/history": ({ url }) =>
        url.searchParams.get("offset") === "25"
          ? jsonResponse({ detail: "page refusée", code: null, params: {} }, 422)
          : jsonResponse({ total: 60, scans }),
    });
    const { user } = renderWithProviders(<HistoryPage />, { route: "/history?page=2", path: "/history" });
    expect(await screen.findByRole("alert")).toHaveTextContent("page refusée");
    await user.click(screen.getByRole("button", { name: "Revenir à la première page" }));
    expect(await screen.findByRole("table")).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/history$/);
  });

  it("supprime après confirmation ; un scan déjà supprimé n'est pas une erreur", async () => {
    window.localStorage.setItem("domainrecon.lastScan", "42");
    const { user, calls } = renderHistory();
    const table = await screen.findByRole("table");
    await user.click(within(table).getByRole("button", { name: "Supprimer le scan de example.com" }));
    const dialog = screen.getByRole("alertdialog", { name: "Supprimer ce scan ?" });
    expect(dialog).toHaveTextContent("Le scan de example.com du");
    await user.click(within(dialog).getByRole("button", { name: "Supprimer" }));
    expect(await screen.findByText("Scan supprimé")).toBeInTheDocument();
    expect(calls.some((call) => call.method === "DELETE" && call.url.pathname === "/api/scan/42")).toBe(true);
    expect(window.localStorage.getItem("domainrecon.lastScan")).toBeNull();
    // La ligne disparaît : le focus passe au titre, il ne tombe pas sur <body>.
    expect(screen.getByRole("heading", { level: 1, name: "Historique" })).toHaveFocus();
    await user.click(within(table).getByRole("button", { name: "Supprimer le scan de shop.example.com" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Supprimer" }));
    expect(await screen.findByText("Ce scan avait déjà été supprimé")).toBeInTheDocument();
  });

  it("oublie le dernier scan même si l'écran est quitté avant la réponse du serveur", async () => {
    window.localStorage.setItem("domainrecon.lastScan", "42");
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    mockFetch({
      "GET /api/history": { total: 3, scans },
      "DELETE /api/scan/42": async () => {
        await gate;
        return jsonResponse({ message: "Scan supprimé", id: 42 });
      },
    });
    const { user, unmount } = renderWithProviders(<HistoryPage />, { route: "/history", path: "/history" });
    const table = await screen.findByRole("table");
    await user.click(within(table).getByRole("button", { name: "Supprimer le scan de example.com" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Supprimer" }));
    unmount();
    release();
    await waitFor(() => expect(window.localStorage.getItem("domainrecon.lastScan")).toBeNull());
  });

  it("annuler la confirmation ne supprime rien", async () => {
    const { user, calls } = renderHistory();
    const table = await screen.findByRole("table");
    await user.click(within(table).getByRole("button", { name: "Supprimer le scan de example.com" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Annuler" }));
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
  });

  it("historique vide et recherche sans résultat", async () => {
    mockFetch({ "GET /api/history": { total: 0, scans: [] } });
    renderWithProviders(<HistoryPage />, { route: "/history?q=zzz", path: "/history" });
    expect(await screen.findByText("Aucun scan ne correspond à ces critères.")).toBeInTheDocument();
  });

  it("historique vide : invite à lancer un premier scan, avec un lien vers le nouveau scan", async () => {
    mockFetch({ "GET /api/history": { total: 0, scans: [] } });
    renderWithProviders(<HistoryPage />, { route: "/history", path: "/history" });
    expect(await screen.findByText("Aucune analyse effectuée. Lancez votre premier scan.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Nouveau scan" })).toHaveAttribute("href", "/");
  });

  it("refuse une recherche trop longue", async () => {
    const { user } = renderHistory();
    await screen.findByRole("table");
    // Collage plutôt que 256 frappes : la saisie touche par touche dépasse le délai du test.
    await user.click(screen.getByRole("searchbox", { name: "Rechercher un domaine" }));
    await user.paste("a".repeat(256));
    expect(await screen.findByRole("alert")).toHaveTextContent("Recherche trop longue : 255 caractères au maximum.");
  });

  it("présente l'écran avec une étiquette et un titre de niveau 1, sans animation d'entrée", async () => {
    const { container } = renderHistory();
    const table = await screen.findByRole("table");
    expect(screen.getByRole("heading", { level: 1, name: "Historique" })).toBeInTheDocument();
    expect(screen.getByText("Archives")).toBeInTheDocument();
    expect(screen.getByRole("search").className).not.toMatch(/enter-|\bi-\d/);
    expect(table.closest("[role=region]")?.className).not.toMatch(/enter-/);
    // CSP stricte : jamais d'attribut style.
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("colore le filet de chaque ligne par sa note, la lettre du badge restant l'indice premier", async () => {
    renderHistory();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    // Note B, F puis N/A (couverture insuffisante) : data-grade suit le badge affiché.
    expect(rows.slice(1).map((row) => row.getAttribute("data-grade"))).toEqual(["B", "F", "NA"]);
    expect(within(rows[2]).getByRole("img", { name: "Note F" })).toBeInTheDocument();
  });

  it("le titre reste focalisable par programme : le focus lui revient après une suppression (tabindex posé à ce moment)", async () => {
    const { user } = renderHistory();
    const table = await screen.findByRole("table");
    const title = screen.getByRole("heading", { level: 1, name: "Historique" });
    // Pas de tabindex tant que le focus n'est pas rendu au titre : il ne s'ajoute pas à l'ordre de tabulation.
    expect(title).not.toHaveAttribute("tabindex");
    await user.click(within(table).getByRole("button", { name: "Supprimer le scan de example.com" }));
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Supprimer" }));
    await screen.findByText("Scan supprimé");
    expect(title).toHaveAttribute("tabindex", "-1");
    expect(title).toHaveFocus();
  });
});
