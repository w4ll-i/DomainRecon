import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { BatchView } from "../../api/ops";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { BatchPage } from "./BatchPage";
import { batchCsv, parseDomainList } from "./batchList";

const ID = "0123456789abcdef0123456789abcdef";

function view(overrides: Partial<BatchView> = {}): BatchView {
  return {
    id: ID,
    status: "running",
    profile: "complet",
    created_at: "2026-09-18T10:00:00Z",
    total: 3,
    finished: 1,
    counts: { queued: 1, running: 1, done: 1, failed: 0, cancelled: 0 },
    items: [
      { domain: "a.example.com", status: "done", scan_id: 11, job_id: "j1", error: null, grade: "A", score: 95 },
      { domain: "b.example.com", status: "running", scan_id: null, job_id: "j2", error: null, grade: null, score: null },
      { domain: "c.example.com", status: "failed", scan_id: null, job_id: null, error: "Résolution impossible", grade: null, score: null },
    ],
    ...overrides,
  };
}

const catalog = { "GET /api/modules": { modules: [], families: [], categories: [], profiles: [] } };

describe("liste de domaines", () => {
  it("accepte retours à la ligne, virgules, points-virgules, guillemets et supprime les doublons", () => {
    expect(parseDomainList('a.com\nb.com, c.com;"d.com"\n  a.com ')).toEqual(["a.com", "b.com", "c.com", "d.com"]);
    expect(parseDomainList("  \n ")).toEqual([]);
  });

  it("exporte le tableau en CSV en neutralisant les formules", () => {
    const csv = batchCsv(view().items ?? []);
    expect(csv.split("\n")[0]).toBe("domain,status,grade,score,scan_id,error");
    expect(csv).toContain("a.example.com,done,A,95,11,");
    expect(csv).toContain('c.example.com,failed,,,,Résolution impossible');
    expect(batchCsv([{ domain: "=cmd", status: "done", scan_id: null, job_id: null, error: 'a,"b"', grade: null, score: null }])).toContain(
      `'=cmd,done,,,,"a,""b"""`,
    );
  });
});

describe("Scan en lot", () => {
  it("sans lot : explique quoi faire, bouton désactivé sans domaine", () => {
    mockFetch(catalog);
    renderWithProviders(<BatchPage />, { route: "/batch", path: "/batch" });
    expect(screen.getByText("Aucun lot en cours")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Lancer le lot (0)" })).toBeDisabled();
  });

  it("lance le lot, signale refus et doublons, puis suit l'avancement", async () => {
    const { calls } = mockFetch({
      ...catalog,
      "POST /api/batches": () =>
        jsonResponse(
          { ...view({ items: undefined }), rejected: [{ input: "pas un domaine", reason: "Cible invalide" }], duplicates: 1 },
          202,
        ),
      [`GET /api/batches/${ID}`]: () => jsonResponse(view()),
    });
    const { user } = renderWithProviders(<BatchPage />, { route: "/batch", path: "/batch" });
    await user.click(screen.getByLabelText("Liste de domaines"));
    await user.paste("a.example.com\nb.example.com\nc.example.com\na.example.com");
    expect(screen.getByText("3 domaine(s) détecté(s)")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Lancer le lot (3)" }));
    expect(await screen.findByText("1 sur 3 terminé(s)")).toBeInTheDocument();
    const post = calls.find((call) => call.method === "POST" && call.url.pathname === "/api/batches");
    expect(JSON.parse(String(post?.init.body))).toEqual({
      domains: ["a.example.com", "b.example.com", "c.example.com"],
      profile: "complet",
      authorized_target: false,
    });
    expect(screen.getByTestId("location")).toHaveTextContent(`/batch?batch=${ID}`);
    expect(screen.getByText("1 doublon(s) ignoré(s).")).toBeInTheDocument();
    expect(screen.getByText("pas un domaine")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Résultats du lot" });
    const rows = within(table).getAllByRole("row");
    expect(within(rows[1]).getByRole("link", { name: "Ouvrir le résultat" })).toHaveAttribute("href", "/scans/11");
    expect(within(rows[2]).getByText("En cours")).toBeInTheDocument();
    expect(within(rows[3]).getByText("Résolution impossible")).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "Avancement du lot" })).toHaveAttribute("value", "1");
  });

  it("reprend un lot depuis l'adresse, l'annule et exporte en CSV", async () => {
    const create = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:csv");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const { calls } = mockFetch({
      ...catalog,
      [`GET /api/batches/${ID}`]: () => jsonResponse(view()),
      [`POST /api/batches/${ID}/cancel`]: () => jsonResponse({ id: ID, status: "cancelled" }, 202),
    });
    const { user } = renderWithProviders(<BatchPage />, { route: `/batch?batch=${ID}`, path: "/batch" });
    await screen.findByText("1 sur 3 terminé(s)");
    await user.click(screen.getByRole("button", { name: "Exporter en CSV" }));
    expect(create).toHaveBeenCalledOnce();
    const blob = create.mock.calls[0][0] as Blob;
    expect(blob.type).toBe("text/csv;charset=utf-8");
    await user.click(screen.getByRole("button", { name: "Annuler le lot" }));
    await waitFor(() => expect(calls.some((call) => call.url.pathname === `/api/batches/${ID}/cancel`)).toBe(true));
  });

  it("importe un fichier .csv ou .txt dans la liste, refuse un fichier trop gros", async () => {
    mockFetch(catalog);
    const { user } = renderWithProviders(<BatchPage />, { route: "/batch", path: "/batch" });
    const input = screen.getByLabelText("Fichier de domaines (.txt ou .csv)");
    await user.upload(input, new File(["a.example.com,x\nb.example.com,y\n"], "liste.csv", { type: "text/csv" }));
    await waitFor(() => expect(screen.getByLabelText("Liste de domaines")).toHaveValue("a.example.com,x\nb.example.com,y\n"));
    const big = new File(["x"], "gros.txt", { type: "text/plain" });
    Object.defineProperty(big, "size", { value: 600 * 1024 });
    await user.upload(input, big);
    expect(await screen.findByText("Fichier trop volumineux (512 Ko au plus).")).toBeInTheDocument();
  });

  it("un module actif exige l'autorisation pour tous les domaines du lot", async () => {
    mockFetch({
      "GET /api/modules": {
        modules: [
          { name: "open_ports", family: "network", category: "actif", requires_authorization: true, help: { title: "", checks: "", why: "" } },
        ],
        families: ["network"],
      },
    });
    const { user } = renderWithProviders(<BatchPage />, { route: "/batch", path: "/batch" });
    await user.click(screen.getByLabelText("Liste de domaines"));
    await user.paste("a.example.com");
    await user.click(screen.getByRole("radio", { name: /Personnalisé/ }));
    await user.click(await screen.findByRole("checkbox", { name: /Ports ouverts/ }));
    expect(screen.getByRole("checkbox", { name: "J'ai l'autorisation de tester ces cibles" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Lancer le lot (1)" })).toBeDisabled();
  });
});
