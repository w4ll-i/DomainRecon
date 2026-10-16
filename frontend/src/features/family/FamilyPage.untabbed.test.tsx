import { configure, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { mockFetch } from "../../test/fetchMock";
import { makeScan } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { FamilyPage } from "./FamilyPage";

configure({ asyncUtilTimeout: 5000 });

// Une famille dont les modules n'auraient pas (encore) d'onglet : le registre est ici
// par le registre), mais les composants de module les importent.
vi.mock("cytoscape", () => ({ default: vi.fn() }));
vi.mock("./tabs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./tabs")>();
  return { ...actual, FAMILY_TABS: { ...actual.FAMILY_TABS, identity: [] }, activeFamilyTab: () => undefined };
});

describe("écran Famille : modules sans onglet", () => {
  it("garde une carte honnête par module, sans barre d'onglets", async () => {
    mockFetch({ "GET /api/scan/42": makeScan() });
    renderWithProviders(<FamilyPage />, { route: "/scans/42/identity", path: "/scans/:id/:family/:module?" });
    expect(await screen.findByRole("heading", { level: 1, name: "Identité" })).toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "WHOIS" })).toBeInTheDocument();
    // Capture d'écran non réalisée (sans objet) : dite telle quelle, jamais « rien trouvé ».
    expect(within(screen.getByRole("region", { name: "Capture d'écran" })).getByText("Ce module est sans objet pour cette cible.")).toBeInTheDocument();
  });
});
