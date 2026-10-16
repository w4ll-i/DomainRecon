import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { CompareResponse } from "../../api/ops";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { makeTimeline } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { ComparePage } from "./ComparePage";

function diff(overrides: Partial<CompareResponse> = {}): CompareResponse {
  return {
    domain: "example.com",
    a: { id: 40, timestamp: "2026-08-29T10:00:00Z", status: "success" },
    b: { id: 42, timestamp: "2026-09-18T10:00:00Z", status: "success" },
    comparable: true,
    score: {
      a: { score: 62, grade: "C", coverage: 90 },
      b: { score: 80.5, grade: "B", coverage: 92 },
      delta: 18.5,
      grade_changed: true,
    },
    findings: {
      new: [{ severity: "high", family: "web", module: "security_headers", message: "HSTS absent" }],
      resolved: [{ severity: "medium", family: "tls", module: "tls_certificate", message: "Certificat bientôt expiré" }],
      unchanged: 2,
    },
    dns: { A: { added: ["1.2.3.4"], removed: ["5.6.7.8"] } },
    ports: { opened: [{ port: 8080, service: "http-alt" }], closed: [] },
    subdomains: { added: ["new.example.com"], removed: [] },
    certificate: { changed: true, fields: { not_after: { a: "2026-10-01", b: "2027-01-01" } }, days_remaining: { a: 12, b: 100 } },
    technologies: null,
    changes: ["Note : C vers B (+18.5)", "1 nouveau constat"],
    ...overrides,
  };
}

function renderCompare(route = "/compare?domain=example.com") {
  return renderWithProviders(<ComparePage />, { route, path: "/compare" });
}

const timelineRoute = { "GET /api/dns-timeline/example.com": makeTimeline() };

describe("Comparer", () => {
  it("sans domaine : explique quoi faire", () => {
    mockFetch({ "GET /api/dashboard": { domains: [], totals: {} } });
    renderCompare("/compare");
    expect(screen.getByText("Aucun domaine choisi")).toBeInTheDocument();
    expect(document.title).toBe("Comparer deux scans · DomainRecon");
  });

  it("moins de deux scans : demande d'en relancer un", async () => {
    mockFetch({
      "GET /api/dashboard": { domains: [], totals: {} },
      "GET /api/dns-timeline/example.com": makeTimeline({ timeline: [makeTimeline().timeline[0]], total_scans: 1 }),
    });
    renderCompare();
    expect(await screen.findByText("Deux scans nécessaires")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Lancer un scan" })).toHaveAttribute("href", "/");
  });

  it("compare par défaut les deux derniers scans et montre chaque différence", async () => {
    const { calls } = mockFetch({
      "GET /api/dashboard": { domains: [], totals: {} },
      ...timelineRoute,
      "GET /api/compare": () => jsonResponse(diff()),
    });
    renderCompare();
    expect(await screen.findByText("Note : C vers B (+18.5)")).toBeInTheDocument();
    const compareCall = calls.find((call) => call.url.pathname === "/api/compare");
    expect(compareCall?.url.searchParams.get("a")).toBe("41");
    expect(compareCall?.url.searchParams.get("b")).toBe("42");
    expect(screen.getByText("+18,5 points")).toBeInTheDocument();
    const findings = screen.getByRole("region", { name: "Constats" });
    expect(within(findings).getByText("HSTS absent")).toBeInTheDocument();
    expect(within(findings).getByText("Certificat bientôt expiré")).toBeInTheDocument();
    expect(within(findings).getByText("2 constat(s) inchangé(s).")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Ports ouverts" })).getByText("8080 (http-alt)")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Sous-domaines" })).getByText("new.example.com")).toBeInTheDocument();
    const dns = screen.getByRole("region", { name: "Enregistrements DNS" });
    expect(within(dns).getByText("1.2.3.4")).toBeInTheDocument();
    expect(within(dns).getByText("5.6.7.8")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Certificat TLS" })).getByText("Expire le")).toBeInTheDocument();
    // Rubrique non mesurée par l'un des scans : dite, jamais « aucun changement ».
    expect(
      within(screen.getByRole("region", { name: "Technologies" })).getByText(/Non mesuré dans l'un des deux scans/),
    ).toBeInTheDocument();
    // Les deux listes permettent de choisir d'autres scans.
    expect(screen.getByLabelText("Scan de référence (le plus ancien)")).toHaveValue("41");
    expect(screen.getByLabelText("Scan à comparer (le plus récent)")).toHaveValue("42");
  });

  it("un scan en erreur n'est pas comparable", async () => {
    mockFetch({
      "GET /api/dashboard": { domains: [], totals: {} },
      ...timelineRoute,
      "GET /api/compare": () => jsonResponse(diff({ comparable: false, findings: null, changes: [] })),
    });
    renderCompare();
    expect(await screen.findByText(/n'est pas possible/)).toBeInTheDocument();
  });

  it("deux scans identiques : le dit en clair", async () => {
    mockFetch({
      "GET /api/dashboard": { domains: [], totals: {} },
      ...timelineRoute,
      "GET /api/compare": () =>
        jsonResponse(
          diff({
            changes: [],
            score: { a: { score: 70, grade: "B", coverage: 90 }, b: { score: 70, grade: "B", coverage: 90 }, delta: 0, grade_changed: false },
            findings: { new: [], resolved: [], unchanged: 3 },
            dns: {},
            ports: { opened: [], closed: [] },
            subdomains: { added: [], removed: [] },
            certificate: { changed: false, fields: {}, days_remaining: { a: 50, b: 40 } },
            technologies: { added: [], removed: [] },
          }),
        ),
    });
    renderCompare();
    expect(await screen.findByText("Aucune différence entre ces deux scans.")).toBeInTheDocument();
    expect(screen.getByText("Aucun nouveau constat.")).toBeInTheDocument();
    expect(screen.getAllByText("Aucun changement.").length).toBeGreaterThanOrEqual(4);
  });

  it("choisir un domaine met l'adresse à jour", async () => {
    mockFetch({ "GET /api/dashboard": { domains: [{ domain: "example.com" }], totals: {} }, ...timelineRoute, "GET /api/compare": () => jsonResponse(diff()) });
    const { user } = renderCompare("/compare");
    await user.type(screen.getByLabelText("Domaine"), "example.com");
    await user.click(screen.getByRole("button", { name: "Choisir" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/compare?domain=example.com");
    expect(await screen.findByText("Note : C vers B (+18.5)")).toBeInTheDocument();
  });
});
