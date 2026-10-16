import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { DashboardItem, DashboardResponse } from "../../api/ops";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { DashboardPage } from "./DashboardPage";

function item(overrides: Partial<DashboardItem> = {}): DashboardItem {
  return {
    domain: "example.com",
    scan_id: 42,
    scan_timestamp: "2026-09-18T10:00:00Z",
    status: "success",
    grade: "B",
    score: 81.5,
    coverage: 95,
    scans_count: 3,
    trend: [
      { scan_id: 40, timestamp: "2026-08-29T10:00:00Z", status: "success", score: 60, grade: "C" },
      { scan_id: 41, timestamp: "2026-09-05T10:00:00Z", status: "success", score: 70, grade: "C" },
      { scan_id: 42, timestamp: "2026-09-18T10:00:00Z", status: "success", score: 81.5, grade: "B" },
    ],
    findings: { critical: 1, high: 1, medium: 2, low: 0, total: 4 },
    watch: { id: 1, enabled: true, frequency: "weekly", next_run_at: "2026-09-25T10:00:00Z", last_status: "ok" },
    ...overrides,
  };
}

function dashboard(domains: DashboardItem[]): DashboardResponse {
  return {
    domains,
    totals: {
      domains: domains.length,
      shown: domains.length,
      watched: domains.filter((entry) => entry.watch?.enabled).length,
      average_score: domains.length ? 81.5 : null,
      grades: { B: domains.length },
      findings: { critical: 1, high: 1, medium: 2, low: 0, total: 4 },
      with_critical_or_high: domains.length ? 1 : 0,
    },
  };
}

const render = () => renderWithProviders(<DashboardPage />, { route: "/dashboard", path: "/dashboard" });

describe("Tableau de bord", () => {
  it("sans scan : explique quoi faire et mène au scanner", async () => {
    mockFetch({ "GET /api/dashboard": dashboard([]) });
    render();
    expect(await screen.findByText("Aucun domaine analysé")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Lancer un scan" })).toHaveAttribute("href", "/");
    expect(document.title).toBe("Tableau de bord · DomainRecon");
  });

  it("résume les domaines : chiffres clés, note, tendance, constats, surveillance, comparaison", async () => {
    mockFetch({
      "GET /api/dashboard": dashboard([item(), item({ domain: "solo.org", scan_id: 7, scans_count: 1, watch: null, findings: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }, trend: [] })]),
    });
    render();
    const table = await screen.findByRole("table", { name: "Dernier scan de chaque domaine" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    const first = within(rows[1]);
    expect(first.getByRole("link", { name: "example.com" })).toHaveAttribute("href", "/scans/42");
    expect(first.getByRole("img", { name: /B/ })).toBeInTheDocument();
    expect(first.getByRole("img", { name: "Tendance des scores de example.com" })).toBeInTheDocument();
    expect(first.getByText("4 constat(s) dont 2 urgent(s)")).toBeInTheDocument();
    expect(first.getByText("Hebdomadaire")).toBeInTheDocument();
    expect(first.getByRole("link", { name: "Comparer" })).toHaveAttribute("href", "/compare?domain=example.com");
    const second = within(rows[2]);
    expect(second.getByText("Aucun constat")).toBeInTheDocument();
    // Un seul scan : rien à comparer.
    expect(second.queryByRole("link", { name: "Comparer" })).not.toBeInTheDocument();
    expect(screen.getByText("Score moyen")).toBeInTheDocument();
    expect(screen.getByText("Avec constat urgent")).toBeInTheDocument();
  });

  it("signale l'erreur du serveur et propose de réessayer", async () => {
    mockFetch({ "GET /api/dashboard": () => jsonResponse({ detail: "Base illisible" }, 500) });
    render();
    expect(await screen.findByText("Base illisible")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Réessayer" })).toBeInTheDocument();
  });
});
