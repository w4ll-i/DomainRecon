import { configure, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { jsonResponse, mockFetch } from "../../../test/fetchMock";
import { HOSTILE, makeScan } from "../../../test/fixtures";
import { renderWithProviders } from "../../../test/render";
import { FamilyPage } from "../FamilyPage";

configure({ asyncUtilTimeout: 5000 });
vi.setConfig({ testTimeout: 20_000 });

const catalog = {
  families: ["web", "tls", "email", "dns", "network", "identity", "reputation", "leaks"],
  categories: [],
  profiles: [],
  modules: [
    {
      name: "hibp",
      family: "leaks",
      category: "cle_api",
      requires_authorization: false,
      keys: [{ name: "hibp_key", service: "hibp", label: "Have I Been Pwned", required: true, free_text: false, hidden: false, configured: false }],
      criteria: [{ criterion: "hibp", weight: 5 }],
      help: { title: "Fuites HIBP", checks: "Comptes du domaine dans des fuites publiques.", why: "Des mots de passe réutilisés ouvrent des accès." },
    },
    {
      name: "leakix",
      family: "leaks",
      category: "actif",
      requires_authorization: true,
      help: { title: "LeakIX", checks: "Services exposés.", why: "Surface d'attaque." },
    },
  ],
};

const scan = makeScan({
  families: { leaks: { state: "warning", grade: "C", summary: "1 fuite" } },
  modules: {
    hibp: {
      status: "ok",
      duration: 2.34,
      error: null,
      data: {
        measured: true,
        error: null,
        accounts: 3,
        reached: true,
        breaches: ["Adobe", "LinkedIn", HOSTILE],
        details: [
          { name: "Adobe", year: 2013, verified: true },
          { name: "LinkedIn", year: 2012, verified: false },
        ],
        meta: { source: { name: "hibp", nested: { deep: { deeper: 1 } } } },
      },
    },
  },
  modules_launched: ["hibp"],
});

const route = { path: "/scans/:id/:family/:module?" };

describe("module sans composant dédié", () => {
  it("famille Fuites : onglets pilotés par le catalogue, titre, aide et données principales", async () => {
    mockFetch({ "GET /api/modules": catalog, "GET /api/scan/42": () => jsonResponse(scan) });
    const { user } = renderWithProviders(<FamilyPage />, { route: "/scans/42/leaks", ...route });
    expect(await screen.findByRole("heading", { level: 1, name: "Fuites de données" })).toBeInTheDocument();
    const tabs = await screen.findByRole("tablist");
    await waitFor(() => expect(within(tabs).getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Fuites HIBP", "LeakIX"]));

    const card = screen.getByRole("region", { name: "Fuites HIBP" });
    expect(within(card).getByText("Mesuré")).toBeInTheDocument();
    expect(within(card).getByText("Comptes du domaine dans des fuites publiques.")).toBeInTheDocument();
    expect(within(card).getByText("Des mots de passe réutilisés ouvrent des accès.")).toBeInTheDocument();
    // Valeurs simples en liste clé / valeur, listes en liste, objets en tableau.
    expect(within(card).getByText("Accounts")).toBeInTheDocument();
    expect(within(card).getByText("3")).toBeInTheDocument();
    expect(within(card).getByText("Adobe", { selector: "li" })).toBeInTheDocument();
    expect(within(card).getByRole("table")).toBeInTheDocument();
    expect(within(card).getByText("2013")).toBeInTheDocument();
    // Lignes empilées sur mobile : chaque cellule reprend l'intitulé de sa colonne.
    const table = within(card).getByRole("table");
    const headers = within(table).getAllByRole("columnheader").map((header) => header.textContent);
    const firstRow = within(table).getAllByRole("row")[1];
    expect(within(firstRow).getAllByRole("cell").map((cell) => cell.getAttribute("data-label"))).toEqual(headers);
    // Les clés techniques de la mesure ne sont pas affichées ; une donnée hostile reste du texte.
    expect(within(card).queryByText("Measured")).toBeNull();
    expect(within(card).getByText(HOSTILE)).toBeInTheDocument();
    expect(card.querySelector("img")).toBeNull();

    // Module non lancé : statut honnête, jamais « rien trouvé », avec la raison.
    await user.click(within(tabs).getByRole("tab", { name: "LeakIX" }));
    const second = await screen.findByRole("region", { name: "LeakIX" });
    expect(within(second).getAllByText("Non lancé").length).toBeGreaterThan(0);
    expect(within(second).getByText(/n.est lancé que sur une cible autorisée/)).toBeInTheDocument();
  });

  it("module non lancé faute de clé : dit laquelle manque", async () => {
    mockFetch({ "GET /api/modules": catalog, "GET /api/scan/42": () => jsonResponse({ ...scan, modules: {}, modules_launched: [] }) });
    renderWithProviders(<FamilyPage />, { route: "/scans/42/leaks/hibp", ...route });
    const card = await screen.findByRole("region", { name: "Fuites HIBP" });
    expect(within(card).getAllByText("Non lancé").length).toBeGreaterThan(0);
    expect(await within(card).findByText(/Have I Been Pwned/)).toBeInTheDocument();
  });

  it("sans catalogue (API plus ancienne) : les 18 modules historiques restent affichés", async () => {
    mockFetch({ "GET /api/scan/42": () => jsonResponse(makeScan()) });
    renderWithProviders(<FamilyPage />, { route: "/scans/42/web", ...route });
    expect(await screen.findByRole("heading", { level: 1, name: "Web" })).toBeInTheDocument();
    expect(await screen.findByRole("tab", { name: /En-têtes de sécurité/ })).toBeInTheDocument();
  });
});
