import { describe, expect, it, vi } from "vitest";
import i18n from "../i18n";
import { jsonResponse, mockFetch } from "../test/fetchMock";
import {
  ApiError,
  apiFetch,
  apiRequest,
  buildUrl,
  errorDetail,
  getToken,
  isPrintableAscii,
  jsonBody,
  setToken,
  setTokenPrompt,
} from "./client";

// Attend l'ApiError d'un appel censé échouer (le test échoue s'il réussit).
const failure = (call: Promise<unknown>): Promise<ApiError> =>
  call.then(
    () => {
      throw new Error("L'appel aurait dû échouer");
    },
    (error: unknown) => error as ApiError,
  );

describe("client d'API", () => {
  it("construit l'URL sous /api avec la langue", () => {
    expect(buildUrl("/scan/1", "en")).toBe("/api/scan/1?lang=en");
    expect(buildUrl("/api/history?limit=5", "fr")).toBe("/api/history?limit=5&lang=fr");
    expect(buildUrl("/health")).toBe("/api/health");
  });

  it("ajoute la langue et le jeton, décode le JSON", async () => {
    setToken("abc");
    const { calls } = mockFetch({ "GET /api/scan/1": { id: 1 } });
    await expect(apiFetch<{ id: number }>("/scan/1", { lang: "en" })).resolves.toEqual({ id: 1 });
    expect(calls[0].url.searchParams.get("lang")).toBe("en");
    expect(new Headers(calls[0].init.headers).get("X-API-Token")).toBe("abc");
    expect(window.sessionStorage.getItem("domainrecon.token")).toBe("abc");
  });

  it("lève une ApiError avec le code, les paramètres et le détail rendu", async () => {
    mockFetch({
      "POST /api/scans": () =>
        jsonResponse({ detail: "Cible invalide : 'a b'", code: "target.invalid", params: { target: "a b" } }, 400),
    });
    const error = await failure(apiFetch("/scans", { method: "POST", ...jsonBody({ domain: "a b" }) }));
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 400, code: "target.invalid", params: { target: "a b" } });
    expect(error.detail).toBe("Cible invalide : 'a b'");
    expect(errorDetail(error)).toBe("Cible invalide : 'a b'");
  });

  it("donne un message lisible pour une réponse sans détail exploitable", async () => {
    mockFetch({ "/api/history": () => new Response("<html>proxy</html>", { status: 503 }) });
    const error = await failure(apiFetch("/history"));
    expect(error.detail).toBe(i18n.t("errors.http.503"));
    expect(error.code).toBeNull();
  });

  it("met en phrase une erreur de validation 422 au format FastAPI", async () => {
    mockFetch({
      "/api/history": () =>
        jsonResponse({ detail: [{ loc: ["query", "limit"], msg: "Input should be less than or equal to 200" }] }, 422),
    });
    const error = await failure(apiFetch("/history"));
    expect(error.detail).toBe("Données refusées : Input should be less than or equal to 200");
  });

  it("signale un serveur injoignable (statut 0)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    const error = await failure(apiRequest("/health"));
    expect(error).toMatchObject({ status: 0, detail: i18n.t("errors.network") });
  });

  it("sur 401, demande le jeton puis rejoue la requête", async () => {
    const prompt = vi.fn(async () => "s3cret");
    setTokenPrompt(prompt);
    mockFetch({
      "/api/scan/1": ({ init }) =>
        new Headers(init.headers).get("X-API-Token") === "s3cret"
          ? jsonResponse({ ok: true })
          : jsonResponse({ detail: "Authentification requise" }, 401),
    });
    await expect(apiFetch("/scan/1")).resolves.toEqual({ ok: true });
    expect(prompt).toHaveBeenCalledWith("missing");
    expect(getToken()).toBe("s3cret");
    setTokenPrompt(null);
  });

  it("un jeton refusé est oublié et redemandé avec la raison « rejected »", async () => {
    setToken("ancien");
    const prompt = vi.fn(async () => null);
    setTokenPrompt(prompt);
    mockFetch({ "/api/scan/1": () => jsonResponse({ detail: "Authentification requise" }, 401) });
    const error = await failure(apiFetch("/scan/1"));
    expect(error).toMatchObject({ status: 401 });
    expect(prompt).toHaveBeenCalledWith("rejected");
    expect(getToken()).toBe("");
    setTokenPrompt(null);
  });

  it("sans invite enregistrée, un 401 devient une ApiError", async () => {
    mockFetch({ "/api/scan/1": () => jsonResponse({ detail: "Authentification requise" }, 401) });
    await expect(apiFetch("/scan/1")).rejects.toMatchObject({ status: 401, detail: "Authentification requise" });
  });

  it("renvoie undefined pour une réponse 204", async () => {
    mockFetch({ "POST /api/system/open-data-dir": () => new Response(null, { status: 204 }) });
    await expect(apiFetch("/system/open-data-dir", { method: "POST", ...jsonBody({}) })).resolves.toBeUndefined();
  });

  it("un jeton hors ASCII imprimable n'est ni gardé ni envoyé (pas de TypeError d'en-tête)", async () => {
    setToken("clé-secrète");
    expect(getToken()).toBe("");
    expect(window.sessionStorage.getItem("domainrecon.token")).toBeNull();
    expect(isPrintableAscii("abc-123_XYZ")).toBe(true);
    expect(isPrintableAscii("clé")).toBe(false);
    expect(isPrintableAscii("a\tb")).toBe(false);
    // Valeur altérée dans le stockage de l'onglet : la requête part sans jeton.
    window.sessionStorage.setItem("domainrecon.token", "clé");
    const { calls } = mockFetch({ "GET /api/scan/1": { id: 1 } });
    await expect(apiFetch("/scan/1")).resolves.toEqual({ id: 1 });
    expect(new Headers(calls[0].init.headers).has("X-API-Token")).toBe(false);
  });

  it("une annulation pendant la lecture du corps reste une annulation (pas une ApiError)", async () => {
    const aborted = () => Promise.reject(new DOMException("annulé", "AbortError"));
    mockFetch({
      "GET /api/scan/1": () => ({ ok: true, status: 200, json: aborted }) as unknown as Response,
      "GET /api/scan/2": () => ({ ok: false, status: 500, json: aborted }) as unknown as Response,
    });
    await expect(apiFetch("/scan/1")).rejects.toMatchObject({ name: "AbortError" });
    await expect(apiFetch("/scan/2")).rejects.toMatchObject({ name: "AbortError" });
  });

  it("un corps d'erreur illisible reste une ApiError au message générique", async () => {
    mockFetch({ "GET /api/scan/3": () => new Response("pas du json", { status: 500 }) });
    const error = await failure(apiFetch("/scan/3"));
    expect(error).toBeInstanceOf(ApiError);
    expect(error.detail).toBe(i18n.t("errors.http.500"));
  });

  it("sépare les erreurs de validation avec la ponctuation de la langue", async () => {
    mockFetch({
      "/api/history": () => jsonResponse({ detail: [{ msg: "Value error, premier" }, { msg: "deuxième" }] }, 422),
    });
    expect((await failure(apiFetch("/history"))).detail).toBe("Données refusées : premier ; deuxième");
    await i18n.changeLanguage("en");
    expect((await failure(apiFetch("/history"))).detail).toBe("Data rejected: premier; deuxième");
  });
});
