import { vi } from "vitest";

export type MockHandler = (request: { url: URL; init: RequestInit }) => Response | Promise<Response>;

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// Valeur JSON renvoyée telle quelle. Pas `unknown` : il absorberait l'union et
// ferait perdre le typage contextuel des gestionnaires (`({ url }) => …`).
type JsonValue = string | number | boolean | null | object;

// Remplace fetch : chaque route est « MÉTHODE /api/chemin » ou « /api/chemin »
// (paramètres de requête ignorés) ; une valeur non fonction est renvoyée en JSON.
export function mockFetch(routes: Record<string, MockHandler | JsonValue>) {
  const calls: Array<{ method: string; url: URL; init: RequestInit }> = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    calls.push({ method, url, init });
    const route = routes[`${method} ${url.pathname}`] ?? routes[url.pathname];
    if (route === undefined) return jsonResponse({ detail: `Route non simulée : ${method} ${url.pathname}` }, 404);
    if (typeof route === "function") return (route as MockHandler)({ url, init });
    return jsonResponse(route);
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}
