import { QueryClient } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { lazy, type ReactElement } from "react";
import { createMemoryRouter, type NonIndexRouteObject, type RouteObject, RouterProvider } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { routes } from "../router";
import { jsonResponse, mockFetch } from "../test/fetchMock";
import { AppProviders } from "./Providers";

const health = { api: "healthy", database: "connected", version: "1.0.0" };
const info = { version: "1.0.0", data_dir: "/tmp/data", portable: false, frozen: false };

function renderApp(path: string, appRoutes: RouteObject[] = routes) {
  const router = createMemoryRouter(appRoutes, { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const utils = render(
    <AppProviders queryClient={client}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
  return { ...utils, router, user: userEvent.setup() };
}

describe("coquille de l'application", () => {
  it("affiche le menu de huit entrées, « Réglages » courant", async () => {
    mockFetch({ "/api/health": health, "/api/system/info": info });
    renderApp("/settings");
    const nav = screen.getByRole("navigation", { name: "Navigation principale" });
    expect(within(nav).getAllByRole("link")).toHaveLength(8);
    expect(within(nav).getByRole("link", { name: "Scanner" })).toHaveAttribute("href", "/");
    expect(within(nav).getByRole("link", { name: "Historique" })).toHaveAttribute("href", "/history");
    expect(within(nav).getByRole("link", { name: "Réglages" })).toHaveAttribute("aria-current", "page");
    expect(await screen.findByRole("heading", { level: 1, name: "Réglages" })).toBeInTheDocument();
    expect(await screen.findByText("Serveur en ligne")).toBeInTheDocument();
  });

  it("la langue se change à un seul endroit : les Réglages", async () => {
    mockFetch({ "/api/health": health, "/api/system/info": info });
    const { user } = renderApp("/settings");
    expect(screen.queryByRole("button", { name: "EN" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "English" }));
    expect(await screen.findByRole("link", { name: "Scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en");
    expect(window.localStorage.getItem("domainrecon.lang")).toBe("en");
  });

  it("signale un serveur dégradé ou injoignable", async () => {
    mockFetch({ "/api/health": () => jsonResponse({ ...health, api: "degraded", database: "read-only" }, 503), "/api/system/info": info });
    const { unmount } = renderApp("/settings");
    expect(await screen.findByText("Serveur dégradé")).toBeInTheDocument();
    unmount();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    renderApp("/settings");
    expect(await screen.findByText("Serveur injoignable")).toBeInTheDocument();
  });

  it("signale l'onglet ouvert au serveur dès l'affichage (battement)", async () => {
    const { calls } = mockFetch({
      "/api/health": health,
      "/api/system/info": info,
      "POST /api/system/heartbeat": () => new Response(null, { status: 204 }),
    });
    renderApp("/settings");
    await waitFor(() =>
      expect(calls.some((call) => call.method === "POST" && call.url.pathname === "/api/system/heartbeat")).toBe(true),
    );
  });

  it("serveur arrêté après avoir répondu au battement : message explicite (relancer, puis recharger)", async () => {
    mockFetch({
      "/api/health": health,
      "/api/system/info": info,
      "POST /api/system/heartbeat": () => new Response(null, { status: 204 }),
    });
    renderApp("/settings");
    expect(await screen.findByText("Serveur en ligne")).toBeInTheDocument();
    expect(screen.queryByText(/ne répond plus/)).not.toBeInTheDocument();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    // Retour sur l'onglet : battement immédiat, qui échoue.
    document.dispatchEvent(new Event("visibilitychange"));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("DomainRecon ne répond plus : il s'est sans doute arrêté automatiquement");
    expect(alert).toHaveTextContent("Relancez DomainRecon, puis rechargez cette page.");
  });

  it("page inconnue : message et retour", async () => {
    mockFetch({ "/api/health": health });
    renderApp("/pas/une/page");
    expect(screen.getByRole("heading", { level: 1, name: "Page introuvable" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Retour au nouveau scan" })).toHaveAttribute("href", "/");
  });

  it("déplace le focus sur le contenu à chaque changement d'écran", async () => {
    mockFetch({ "/api/health": health, "/api/system/info": info, "/api/history": { total: 0, scans: [] } });
    const { user } = renderApp("/settings");
    await user.click(screen.getByRole("link", { name: "Historique" }));
    await waitFor(() => expect(screen.getByRole("main")).toHaveFocus());
    expect(screen.getByRole("heading", { level: 1, name: "Historique" })).toBeInTheDocument();
  });


  it("revenir à « Nouveau scan » par le menu : le champ domaine garde le focus (autoFocus), pas le conteneur", async () => {
    mockFetch({ "/api/health": health, "/api/system/info": info, "/api/history": { total: 0, scans: [] } });
    const { user } = renderApp("/history");
    await user.click(screen.getByRole("link", { name: "Scanner" }));
    const input = await screen.findByLabelText("Domaine ou URL à analyser");
    await waitFor(() => expect(input).toHaveFocus());
    expect(screen.getByRole("main")).not.toHaveFocus();
    // Le premier rendu de « / » garde aussi son autoFocus.
    expect(document.activeElement).toBe(input);
  });

  it("écrans d'erreur : un titre de niveau 1 (identifiant invalide, scan supprimé, famille inconnue)", async () => {
    mockFetch({
      "/api/health": health,
      "GET /api/scan/999": () => jsonResponse({ detail: "Scan non trouvé", code: null, params: {} }, 404),
    });
    const invalid = renderApp("/scans/abc");
    expect(await screen.findByRole("heading", { level: 1, name: "Scan introuvable" })).toBeInTheDocument();
    invalid.unmount();
    const missing = renderApp("/scans/999");
    expect(await screen.findByRole("heading", { level: 1, name: "Scan introuvable" })).toBeInTheDocument();
    missing.unmount();
    renderApp("/scans/42/inconnue");
    expect(await screen.findByRole("heading", { level: 1, name: "Famille inconnue" })).toBeInTheDocument();
  });

  it("connaît toutes les routes de la spec", () => {
    // Les écrans sont sous une route sans chemin (errorElement) qui laisse la coquille en place.
    const children = routes[0].children?.[0]?.children ?? [];
    expect(children.map((route) => (route.index ? "/" : route.path))).toEqual([
      "/",
      "scans/live/:jobId",
      "scans/:id",
      "scans/:id/:family/:module?",
      "history",
      "history/:domain",
      "settings",
      "dashboard",
      "batch",
      "compare",
      "monitoring",
      "help",
      "*",
    ]);
  });
});

function Boom(): never {
  throw new Error("plantage de test");
}

// Même arbre de routes, plus un écran qui plante au rendu.
function routesWithBoom(): RouteObject[] {
  const [root] = routes as [NonIndexRouteObject];
  const [screens] = (root.children ?? []) as [NonIndexRouteObject];
  return [{ ...root, children: [{ ...screens, children: [{ path: "boom", element: <Boom /> }, ...(screens.children ?? [])] }] }];
}

describe("erreur de rendu", () => {
  beforeEach(() => {
    // React et React Router journalisent l'erreur jetée exprès.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  it("un écran qui plante laisse la coquille en place : message, rechargement et sortie", async () => {
    mockFetch({ "/api/health": health });
    renderApp("/boom", routesWithBoom());
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { level: 1, name: "Cet écran n'a pas pu s'afficher" })).toBeInTheDocument();
    expect(within(alert).getByText("plantage de test")).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: "Recharger la page" })).toBeInTheDocument();
    expect(within(alert).getByRole("link", { name: "Nouveau scan" })).toHaveAttribute("href", "/");
    // Menu, bascule de thème et contenu sont toujours là.
    expect(screen.getByRole("navigation", { name: "Navigation principale" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Passer au thème clair" })).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getByRole("alert")).toBe(alert);
  });

  it("naviguer depuis l'écran en erreur affiche à nouveau un écran normal", async () => {
    mockFetch({ "/api/health": health, "/api/history": { total: 0, scans: [] } });
    const { user } = renderApp("/boom", routesWithBoom());
    await screen.findByRole("alert");
    await user.click(screen.getByRole("link", { name: "Historique" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Historique" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("si la coquille elle-même plante, la racine sert de dernier recours", async () => {
    mockFetch({ "/api/health": health });
    renderApp("/", [{ ...routes[0], element: <Boom /> }]);
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("button", { name: "Recharger la page" })).toBeInTheDocument();
    expect(within(alert).getByRole("link", { name: "Nouveau scan" })).toHaveAttribute("href", "/");
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });
});

// Même arbre de routes, avec en tête un écran « bientôt chargé » dont le chargement se contrôle.
function routesWithLazy(load: () => Promise<{ default: () => ReactElement }>): RouteObject[] {
  const [root] = routes as [NonIndexRouteObject];
  const [screens] = (root.children ?? []) as [NonIndexRouteObject];
  const Slow = lazy(load);
  return [{ ...root, children: [{ ...screens, children: [{ path: "lent", element: <Slow /> }, ...(screens.children ?? [])] }] }];
}

describe("écrans chargés à la demande", () => {
  it("tous les écrans, sauf l'accueil et la page inconnue, sont des composants React.lazy", () => {
    const children = routes[0].children?.[0]?.children ?? [];
    const kinds = children.map((route) => [
      route.index ? "/" : route.path,
      (route.element as unknown as { type: { $$typeof?: symbol } }).type.$$typeof === Symbol.for("react.lazy"),
    ]);
    expect(Object.fromEntries(kinds)).toEqual({
      "/": false,
      "scans/live/:jobId": true,
      "scans/:id": true,
      "scans/:id/:family/:module?": true,
      history: true,
      "history/:domain": true,
      settings: true,
      dashboard: true,
      batch: true,
      compare: true,
      monitoring: true,
      help: true,
      "*": false,
    });
  });

  it("pendant le chargement : un état de chargement sobre dans la coquille, qui reste en place ; puis l'écran", async () => {
    mockFetch({ "/api/health": health });
    let release: (module: { default: () => ReactElement }) => void = () => {};
    const loading = new Promise<{ default: () => ReactElement }>((resolve) => {
      release = resolve;
    });
    renderApp("/lent", routesWithLazy(() => loading));
    const main = screen.getByRole("main");
    expect(within(main).getByRole("status")).toHaveTextContent("Chargement");
    expect(screen.getByRole("navigation", { name: "Navigation principale" })).toBeInTheDocument();
    act(() => release({ default: () => <h1>Écran chargé</h1> }));
    expect(await screen.findByRole("heading", { level: 1, name: "Écran chargé" })).toBeInTheDocument();
    expect(within(main).queryByText("Chargement…")).not.toBeInTheDocument();
  });

  it("chargement impossible (fichier introuvable) : message, rechargement et sortie ; la coquille reste en place", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    mockFetch({ "/api/health": health });
    renderApp(
      "/lent",
      routesWithLazy(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module"))),
    );
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("heading", { level: 1, name: "Cet écran n'a pas pu s'afficher" })).toBeInTheDocument();
    expect(within(alert).getByText(/Failed to fetch dynamically imported module/)).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: "Recharger la page" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Navigation principale" })).toBeInTheDocument();
  });
});
