import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { CatalogModule } from "../../api/types";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { renderWithProviders } from "../../test/render";
import { NewScanPage } from "./NewScanPage";
import { needsAuthorization, optionsPayload, optionsValid } from "./scanOptions";
import { buildCatalog } from "../../lib/catalog";

function module(name: string, family: string, category: string, extra: Partial<CatalogModule> = {}): CatalogModule {
  return {
    name,
    family,
    category,
    requires_authorization: category === "actif" || category === "sensible",
    quick: category === "passif",
    help: { title: name, checks: `Vérifie ${name} (SPF).`, why: "Parce que." },
    ...extra,
  };
}

const modules = {
  modules: [
    module("dns_records", "dns", "passif"),
    module("security_headers", "web", "passif"),
    module("open_ports", "network", "actif"),
    module("sensitive_files", "web", "sensible"),
    module("shodan", "network", "cle_api", {
      keys: [{ name: "shodan_key", service: "shodan", label: "Shodan", required: true, free_text: false, hidden: false, configured: false }],
    }),
  ],
  families: ["web", "tls", "email", "dns", "network", "identity", "reputation", "leaks"],
  categories: ["passif", "actif", "cle_api", "sensible"],
  profiles: ["rapide", "complet", "personnalise"],
};

const routes = {
  "GET /api/history": { total: 0, scans: [] },
  "GET /api/modules": modules,
  "POST /api/scans": () => jsonResponse({ id: "abc123", status: "running" }, 202),
};

function body(calls: Array<{ method: string; init: RequestInit }>) {
  return JSON.parse(String(calls.find((call) => call.method === "POST")?.init.body));
}

describe("choix du profil de scan", () => {
  it("le nombre de modules rapides n'est annoncé qu'une fois le catalogue du serveur arrivé (jamais « 0 »)", async () => {
    mockFetch({ ...routes, "GET /api/modules": () => new Promise<Response>(() => undefined) });
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const quick = screen.getByRole("radio", { name: /Rapide/ }).closest("label") as HTMLElement;
    expect(quick).toHaveTextContent("Les modules passifs essentiels.");
    expect(quick).not.toHaveTextContent(/Les [0-9]+ modules/);
  });

  it("catalogue arrivé : le nombre de modules rapides vient du catalogue", async () => {
    mockFetch(routes);
    renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    const quick = screen.getByRole("radio", { name: /Rapide/ }).closest("label") as HTMLElement;
    await waitFor(() => expect(quick).toHaveTextContent("Les 2 modules passifs essentiels."));
  });

  it("profil rapide : envoie le profil, sans module ni autorisation", async () => {
    const { calls } = mockFetch(routes);
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    await user.click(screen.getByRole("radio", { name: /Rapide/ }));
    await user.type(screen.getByLabelText("Domaine ou URL à analyser"), "example.com");
    await user.click(screen.getByRole("button", { name: "Scan" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/scans/live/abc123"));
    expect(body(calls)).toEqual({ domain: "example.com", profile: "rapide" });
  });

  it("personnalisé : modules par famille avec badges, passifs présélectionnés", async () => {
    mockFetch(routes);
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    await user.click(screen.getByRole("radio", { name: /Personnalisé/ }));
    expect(await screen.findByText("2 module(s) choisi(s) sur 5")).toBeInTheDocument();
    const security = screen.getByRole("checkbox", { name: /En-têtes de sécurité/ });
    expect(security).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /Ports ouverts/ })).not.toBeChecked();
    // Badges de catégorie : passif, actif, sensible, clé d'API.
    expect(screen.getAllByText("Passif").length).toBeGreaterThanOrEqual(2);
    expect(within(screen.getByRole("checkbox", { name: /Ports ouverts/ }).closest("label") as HTMLElement).getByText("Actif")).toBeInTheDocument();
    expect(within(screen.getByRole("checkbox", { name: /sensitive_files/ }).closest("label") as HTMLElement).getByText("Sensible")).toBeInTheDocument();
    expect(within(screen.getByRole("checkbox", { name: /shodan/ }).closest("label") as HTMLElement).getByText("Clé d'API")).toBeInTheDocument();
    // Le module à clé non renseignée est signalé.
    expect(screen.getByText(/a besoin d'une clé d'API/)).toBeInTheDocument();
    // Les sigles du texte d'aide ont leur infobulle.
    expect(screen.getAllByRole("tooltip")[0]).toHaveTextContent("SPF");
  });

  it("un module actif exige la case d'autorisation avant de pouvoir lancer", async () => {
    const { calls } = mockFetch(routes);
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    await user.click(screen.getByRole("radio", { name: /Personnalisé/ }));
    await user.type(screen.getByLabelText("Domaine ou URL à analyser"), "example.com");
    expect(screen.queryByRole("checkbox", { name: /J'ai l'autorisation/ })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("checkbox", { name: /Ports ouverts/ }));
    const authorization = screen.getByRole("checkbox", { name: "J'ai l'autorisation de tester cette cible" });
    expect(authorization).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Scan" })).toBeDisabled();
    await user.click(authorization);
    expect(screen.getByRole("button", { name: "Scan" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Scan" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/scans/live/abc123"));
    expect(body(calls)).toEqual({
      domain: "example.com",
      profile: "personnalise",
      selected: ["dns_records", "security_headers", "open_ports"],
      authorized_target: true,
    });
  });

  it("choisir ou vider une famille entière, et refuser une sélection vide", async () => {
    mockFetch(routes);
    const { user } = renderWithProviders(<NewScanPage />, { route: "/", path: "/" });
    await user.click(screen.getByRole("radio", { name: /Personnalisé/ }));
    await user.click(await screen.findByRole("button", { name: "Aucun : Web" }));
    expect(screen.getByRole("checkbox", { name: /En-têtes de sécurité/ })).not.toBeChecked();
    await user.click(screen.getByRole("button", { name: "Aucun : DNS & sous-domaines" }));
    expect(screen.getByText("Choisissez au moins un module.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scan" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Tout choisir : Web" }));
    expect(screen.getByRole("checkbox", { name: /sensitive_files/ })).toBeChecked();
    // Un module sensible a rendu l'autorisation obligatoire.
    expect(screen.getByRole("checkbox", { name: /J'ai l'autorisation/ })).toBeInTheDocument();
  });

  it("les règles de validation et de corps sont indépendantes de l'écran", () => {
    const catalog = buildCatalog({ ...modules } as never);
    const base = { profile: "personnalise" as const, selected: ["open_ports"], authorized: false };
    expect(needsAuthorization(catalog, base)).toBe(true);
    expect(optionsValid(catalog, base)).toBe(false);
    expect(optionsValid(catalog, { ...base, authorized: true })).toBe(true);
    expect(optionsValid(catalog, { ...base, selected: [] })).toBe(false);
    expect(optionsPayload(catalog, { ...base, authorized: true })).toEqual({
      profile: "personnalise",
      selected: ["open_ports"],
      authorized_target: true,
    });
    // L'autorisation cochée puis devenue inutile n'est pas transmise.
    expect(optionsPayload(catalog, { profile: "personnalise", selected: ["dns_records"], authorized: true })).toEqual({
      profile: "personnalise",
      selected: ["dns_records"],
    });
    expect(optionsPayload(catalog, { profile: "complet", selected: [], authorized: true })).toEqual({});
  });
});
