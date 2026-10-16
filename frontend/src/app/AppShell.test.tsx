import { QueryClient } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, type RouteObject, RouterProvider, useLocation } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { jsonResponse, mockFetch } from "../test/fetchMock";
import { routes } from "../router";
import { AppShell } from "./AppShell";
import { AppProviders } from "./Providers";

const health = { api: "healthy", database: "connected", version: "1.0.0" };
const info = { version: "1.0.0", data_dir: "/tmp/data", portable: false, frozen: false };
const base = { "/api/health": health, "/api/system/info": info };
// Identifiant de tâche du serveur : 32 caractères hexadécimaux.
const JOB = "0123456789abcdef0123456789abcdef";

// Écran de remplacement : il montre le chemin et l'état de navigation reçus, sans appeler d'API.
function Probe() {
  const location = useLocation();
  return (
    <>
      <p data-testid="path">{location.pathname}</p>
      <p data-testid="state">{JSON.stringify(location.state)}</p>
      <button type="button" role="tab" aria-selected="true">
        Onglet
      </button>
      <button type="button">Bouton</button>
    </>
  );
}

// La coquille réelle autour d'un écran factice : seul le menu, l'en-tête et leurs réglages sont testés.
const shellRoutes: RouteObject[] = [
  { path: "/", element: <AppShell />, children: [{ index: true, element: <Probe /> }, { path: "*", element: <Probe /> }] },
];

function renderShell(path: string) {
  const router = createMemoryRouter(shellRoutes, { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const utils = render(
    <AppProviders queryClient={client}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
  return { ...utils, router, user: userEvent.setup() };
}

// Lancements de scan parmi les appels (le battement du serveur est aussi un POST).
const launches = (calls: Array<{ method: string; url: URL; init: RequestInit }>) =>
  calls.filter((call) => call.method === "POST" && call.url.pathname === "/api/scans");

describe("menu latéral", () => {
  it("liste les huit écrans dans l'ordre, l'écran courant est marqué", () => {
    mockFetch(base);
    renderShell("/history");
    const nav = screen.getByRole("navigation", { name: "Navigation principale" });
    const links = within(nav).getAllByRole("link");
    expect(links.map((link) => link.textContent)).toEqual([
      "Scanner",
      "Tableau de bord",
      "Historique",
      "Lot",
      "Comparer",
      "Surveillance",
      "Aide",
      "Réglages",
    ]);
    expect(links.map((link) => link.getAttribute("href"))).toEqual([
      "/",
      "/dashboard",
      "/history",
      "/batch",
      "/compare",
      "/monitoring",
      "/help",
      "/settings",
    ]);
    expect(within(nav).getByRole("link", { name: "Historique" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Scanner" })).not.toHaveAttribute("aria-current");
  });

  it("« Scanner » n'est actif que sur la page d'accueil", () => {
    mockFetch(base);
    renderShell("/");
    expect(screen.getByRole("link", { name: "Scanner" })).toHaveAttribute("aria-current", "page");
  });

  it("aucun doublon de contrôle : la langue ne se règle pas dans le menu, ni de badge, ni de champ de scan rapide", async () => {
    mockFetch({ ...base, "/api/history": { total: 37, scans: [] } });
    renderShell("/settings");
    await screen.findByText("Serveur en ligne");
    const nav = screen.getByRole("navigation", { name: "Navigation principale" });
    expect(screen.queryByRole("group", { name: "Langue" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "FR" })).not.toBeInTheDocument();
    expect(nav.querySelector("[data-tone]")).toBeNull();
    expect(screen.queryByRole("textbox", { name: "Scan rapide" })).not.toBeInTheDocument();
  });

  it("les étiquettes du menu ne sont pas des titres : le plan de la page garde son seul niveau 1", () => {
    mockFetch(base);
    renderShell("/history");
    const nav = screen.getByRole("navigation", { name: "Navigation principale" });
    expect(within(nav).queryAllByRole("heading")).toHaveLength(0);
  });
});

describe("écrans de la navigation", () => {
  const dashboard = {
    domains: [],
    totals: { domains: 0, shown: 0, watched: 0, average_score: null, grades: {}, findings: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }, with_critical_or_high: 0 },
  };
  it.each([
    ["/dashboard", "Tableau de bord"],
    ["/batch", "Scan en lot"],
    ["/compare", "Comparer deux scans"],
    ["/monitoring", "Surveillance"],
    ["/help", "Aide"],
  ])("%s : l'écran (chargé à la demande) s'affiche avec son titre", async (path, title) => {
    mockFetch({
      ...base,
      "/api/dashboard": dashboard,
      "/api/watches": { watches: [] },
      "/api/notifications": { total: 0, unread: 0, items: [] },
      "/api/monitor/task": { supported: true, platform: "windows", installed: false, command: "domainrecon monitor run-due" },
    });
    const router = createMemoryRouter(routes, { initialEntries: [path] });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <AppProviders queryClient={client}>
        <RouterProvider router={router} />
      </AppProviders>,
    );
    expect(await screen.findByRole("heading", { level: 1, name: title })).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe(`${title} · DomainRecon`));
  });
});

describe("focus au changement d’écran", () => {
  it("passe au contenu, sauf pour un onglet choisi au clavier (l’adresse change avec lui)", async () => {
    mockFetch(base);
    const { router } = renderShell("/scans/1/web/a");
    const main = screen.getByRole("main");
    screen.getByRole("tab", { name: "Onglet" }).focus();
    await act(async () => {
      await router.navigate("/scans/1/web/b", { replace: true });
    });
    expect(screen.getByTestId("path")).toHaveTextContent("/scans/1/web/b");
    expect(screen.getByRole("tab", { name: "Onglet" })).toHaveFocus();
    // Un simple bouton, lui, laisse le focus au contenu du nouvel écran.
    screen.getByRole("button", { name: "Bouton" }).focus();
    await act(async () => {
      await router.navigate("/history");
    });
    expect(main).toHaveFocus();
  });

  it("une fenêtre modale ouverte (palette) garde le focus quand l'écran change après coup", async () => {
    mockFetch({ ...base, "/api/history": { total: 0, scans: [] } });
    const { router, user } = renderShell("/settings");
    await user.keyboard("{Control>}k{/Control}");
    const input = await screen.findByRole("combobox");
    expect(input).toHaveFocus();
    // L'écran choisi s'affiche alors que la palette est déjà ouverte (chargement à la demande).
    await act(async () => {
      await router.navigate("/history");
    });
    expect(screen.getByTestId("path")).toHaveTextContent("/history");
    expect(input).toHaveFocus();
    // Échap l'atteint toujours : la palette se ferme.
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("bascule de thème", () => {
  it("pose data-theme sur <html>, se mémorise et change de libellé", async () => {
    mockFetch(base);
    const { user } = renderShell("/settings");
    expect(document.documentElement.getAttribute("data-theme")).not.toBe("light");
    await user.click(screen.getByRole("button", { name: "Passer au thème clair" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(window.localStorage.getItem("domainrecon.theme")).toBe("light");
    await user.click(screen.getByRole("button", { name: "Passer au thème sombre" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(window.localStorage.getItem("domainrecon.theme")).toBe("dark");
    expect(screen.getByRole("button", { name: "Passer au thème clair" })).toBeInTheDocument();
  });

  it("thème clair déjà posé au démarrage : le bouton propose le thème sombre", () => {
    document.documentElement.setAttribute("data-theme", "light");
    mockFetch(base);
    renderShell("/settings");
    expect(screen.getByRole("button", { name: "Passer au thème sombre" })).toBeInTheDocument();
  });

  it("sans stockage (navigation privée) : la bascule marche pour la session", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("bloqué");
    });
    mockFetch(base);
    const { user } = renderShell("/settings");
    await user.click(screen.getByRole("button", { name: "Passer au thème clair" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(screen.getByRole("button", { name: "Passer au thème sombre" })).toBeInTheDocument();
  });
});

describe("palette de commandes", () => {
  const openByKeyboard = async (user: ReturnType<typeof userEvent.setup>) => {
    await user.keyboard("{Control>}k{/Control}");
    return screen.findByRole("combobox");
  };

  it("Ctrl+K l'ouvre, le champ prend le focus, Échap la ferme", async () => {
    mockFetch({ ...base, "/api/history": { total: 0, scans: [] } });
    const { user } = renderShell("/settings");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    const input = await openByKeyboard(user);
    expect(screen.getByRole("dialog", { name: "Palette de commandes" })).toBeInTheDocument();
    expect(input).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // Le bouton de l'en-tête l'ouvre aussi, et Ctrl+K la referme.
    await user.click(screen.getByRole("button", { name: "Rechercher ou lancer une commande" }));
    expect(await screen.findByRole("combobox")).toBeInTheDocument();
    await user.keyboard("{Control>}k{/Control}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("chaque ouverture repart d'une saisie vide : la dernière recherche ne masque pas le reste", async () => {
    mockFetch({ ...base, "/api/history": { total: 0, scans: [] } });
    const { user } = renderShell("/settings");
    const input = await openByKeyboard(user);
    await user.type(input, "hist");
    expect(within(screen.getByRole("listbox")).getAllByRole("option")).toHaveLength(1);
    await user.keyboard("{ArrowDown}{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    const reopened = await openByKeyboard(user);
    expect(reopened).toHaveValue("");
    expect(reopened).toHaveFocus();
    const options = within(screen.getByRole("listbox")).getAllByRole("option");
    expect(options).toHaveLength(8);
    // La première option est de nouveau l'active.
    expect(options[0]).toHaveAttribute("aria-selected", "true");
  });

  it("liste les pages, filtre à la frappe et ouvre la page choisie à Entrée", async () => {
    mockFetch({ ...base, "/api/history": { total: 0, scans: [] } });
    const { user } = renderShell("/");
    const input = await openByKeyboard(user);
    const list = screen.getByRole("listbox", { name: "Résultats" });
    expect(within(list).getAllByRole("option")).toHaveLength(8);
    await user.type(input, "hist");
    const options = within(list).getAllByRole("option");
    expect(options).toHaveLength(1);
    expect(options[0]).toHaveTextContent("Historique");
    expect(options[0]).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Enter}");
    expect(screen.getByTestId("path")).toHaveTextContent("/history");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("les flèches changent l'option active, annoncée par aria-activedescendant", async () => {
    mockFetch({ ...base, "/api/history": { total: 0, scans: [] } });
    const { user } = renderShell("/");
    const input = await openByKeyboard(user);
    const options = () => within(screen.getByRole("listbox")).getAllByRole("option");
    expect(options()[0]).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{ArrowDown}{ArrowDown}");
    expect(options()[2]).toHaveAttribute("aria-selected", "true");
    expect(input).toHaveAttribute("aria-activedescendant", options()[2].id);
    // Boucle : la flèche du haut depuis la première option mène à la dernière.
    await user.keyboard("{ArrowUp}{ArrowUp}{ArrowUp}");
    expect(options()[options().length - 1]).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Enter}");
    expect(screen.getByTestId("path")).toHaveTextContent("/settings");
  });

  it("un domaine saisi propose de le scanner : le suivi en direct s'ouvre avec le domaine", async () => {
    const { calls } = mockFetch({
      ...base,
      "/api/history": { total: 0, scans: [] },
      "POST /api/scans": () => jsonResponse({ id: JOB, status: "running" }, 202),
    });
    const { user } = renderShell("/settings");
    const input = await openByKeyboard(user);
    await user.type(input, "example.org");
    const first = within(screen.getByRole("listbox")).getAllByRole("option")[0];
    expect(first).toHaveTextContent("Scanner example.org");
    await user.keyboard("{Enter}");
    expect(await screen.findByText(`/scans/live/${JOB}`)).toBeInTheDocument();
    expect(screen.getByTestId("state")).toHaveTextContent('{"domain":"example.org"}');
    expect(JSON.parse(String(launches(calls)[0]?.init.body))).toEqual({ domain: "example.org" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("une saisie qui n'est pas un domaine ne propose pas de scan", async () => {
    mockFetch({ ...base, "/api/history": { total: 0, scans: [] } });
    const { user } = renderShell("/settings");
    const input = await openByKeyboard(user);
    await user.type(input, "historique inconnu");
    expect(screen.queryByRole("option", { name: /Scanner/ })).not.toBeInTheDocument();
    expect(screen.getByText("Aucun résultat.")).toBeInTheDocument();
  });

  it("propose les scans récents et ouvre le résultat choisi", async () => {
    const recent = (id: number, domain: string) => ({
      id,
      domain,
      ip_address: null,
      subdomains_count: null,
      open_ports_count: null,
      security_score: { score: 80, grade: "B" },
      tags: [],
      scan_timestamp: "2026-01-01T10:00:00Z",
      status: "success",
    });
    mockFetch({ ...base, "/api/history": { total: 2, scans: [recent(7, "alpha.example"), recent(8, "beta.example")] } });
    const { user } = renderShell("/settings");
    const input = await openByKeyboard(user);
    const list = screen.getByRole("listbox");
    await waitFor(() => expect(within(list).getAllByRole("option")).toHaveLength(10));
    expect(within(list).getByText("Scans récents")).toBeInTheDocument();
    await user.type(input, "beta");
    const options = within(list).getAllByRole("option");
    expect(options).toHaveLength(1);
    expect(options[0]).toHaveTextContent("Résultat de beta.example");
    await user.click(options[0]);
    expect(screen.getByTestId("path")).toHaveTextContent("/scans/8");
  });
});

describe("état du serveur", () => {
  it("se lit par une icône colorée (data-state) et par un texte", async () => {
    mockFetch({ ...base, "/api/health": () => jsonResponse({ ...health, api: "degraded", database: "read-only" }, 503) });
    const degraded = renderShell("/settings");
    const text = await screen.findByText("Serveur dégradé");
    const status = text.closest("[data-state]") as HTMLElement;
    expect(status).toHaveAttribute("data-state", "degraded");
    expect(status.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    degraded.unmount();

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    renderShell("/settings");
    const offline = (await screen.findByText("Serveur injoignable")).closest("[data-state]");
    expect(offline).toHaveAttribute("data-state", "offline");
  });

  it("pendant la vérification : état « checking » et texte dédié", () => {
    mockFetch({ ...base, "/api/health": () => new Promise<Response>(() => undefined) });
    renderShell("/settings");
    const text = screen.getByText("Vérification du serveur…");
    expect(text.closest("[data-state]")).toHaveAttribute("data-state", "checking");
  });
});
