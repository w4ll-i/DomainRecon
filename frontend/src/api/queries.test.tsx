import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { setLang } from "../i18n";
import { jsonResponse, mockFetch } from "../test/fetchMock";
import { makeScan, makeTimeline } from "../test/fixtures";
import { getToken, setToken, setTokenPrompt } from "./client";
import type { ScanResponse } from "./types";
import {
  fetchHealth,
  HEARTBEAT_INTERVAL,
  historyPath,
  sendHeartbeat,
  useCancelJob,
  useDeleteScan,
  useHeartbeat,
  useOpenDataDir,
  useScan,
  useStartScan,
  useSystemInfo,
  useUpdateMeta,
} from "./queries";

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("requêtes", () => {
  it("construit l'URL de l'historique (recherche, filtres, page)", () => {
    expect(historyPath({ q: "", grade: "", status: "", page: 1 })).toBe("/history?limit=25&offset=0");
    expect(historyPath({ q: "shop", grade: "N/A", status: "error", page: 3 })).toBe(
      "/history?limit=25&offset=50&domain=shop&grade=N%2FA&status=error",
    );
  });

  it("relit le scan dans la nouvelle langue quand on change de langue", async () => {
    const { calls } = mockFetch({ "GET /api/scan/42": () => jsonResponse(makeScan()) });
    const { result } = renderHook(() => useScan(42), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(calls[0].url.searchParams.get("lang")).toBe("fr");
    await act(async () => {
      await setLang("en");
    });
    await waitFor(() => expect(calls.some((call) => call.url.searchParams.get("lang") === "en")).toBe(true));
  });

  it("garde le scan affiché pendant la relecture en une autre langue, jamais d'un scan à l'autre", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    mockFetch({
      "GET /api/scan/42": async ({ url }) => {
        if (url.searchParams.get("lang") === "en") await gate;
        return jsonResponse(makeScan());
      },
      "GET /api/scan/7": () => jsonResponse(makeScan({ id: 7 })),
    });
    const { result, rerender } = renderHook(({ id }) => useScan(id), { wrapper: wrapper(), initialProps: { id: 42 } });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    await act(async () => {
      await setLang("en");
    });
    // Relecture en cours : l'ancien texte reste affiché, signalé comme provisoire.
    expect(result.current.data?.id).toBe(42);
    expect(result.current.isPlaceholderData).toBe(true);
    release();
    await waitFor(() => expect(result.current.isPlaceholderData).toBe(false));
    // Autre scan : on n'affiche jamais les données du précédent.
    rerender({ id: 7 });
    expect(result.current.data).toBeUndefined();
    expect(result.current.isPending).toBe(true);
    await waitFor(() => expect(result.current.data?.id).toBe(7));
  });

  it("ne lit rien sans identifiant", () => {
    const { calls } = mockFetch({});
    renderHook(() => useScan(null), { wrapper: wrapper() });
    expect(calls).toHaveLength(0);
  });

  it("lance un scan en JSON et renvoie la tâche", async () => {
    const { calls } = mockFetch({ "POST /api/scans": () => jsonResponse({ id: "abc", status: "running" }, 202) });
    const { result } = renderHook(() => useStartScan(), { wrapper: wrapper() });
    let job: unknown;
    await act(async () => {
      job = await result.current.mutateAsync("example.com");
    });
    expect(job).toEqual({ id: "abc", status: "running" });
    expect(new Headers(calls[0].init.headers).get("Content-Type")).toBe("application/json");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ domain: "example.com" });
  });

  it("lance un scan dans la langue courante (refus rendu dans la bonne langue)", async () => {
    const { calls } = mockFetch({ "POST /api/scans": () => jsonResponse({ id: "abc", status: "running" }, 202) });
    await setLang("en");
    const { result } = renderHook(() => useStartScan(), { wrapper: wrapper() });
    await act(async () => {
      await result.current.mutateAsync("example.com");
    });
    expect(calls[0].url.searchParams.get("lang")).toBe("en");
  });

  it("annule, supprime et ouvre le dossier dans la langue courante", async () => {
    const { calls } = mockFetch({
      "POST /api/scans/abc/cancel": () => jsonResponse({ id: "abc", status: "cancelled" }),
      "DELETE /api/scan/7": () => new Response(null, { status: 204 }),
      "POST /api/system/open-data-dir": () => new Response(null, { status: 204 }),
    });
    await setLang("en");
    const cancel = renderHook(() => useCancelJob(), { wrapper: wrapper() });
    const remove = renderHook(() => useDeleteScan(), { wrapper: wrapper() });
    const open = renderHook(() => useOpenDataDir(), { wrapper: wrapper() });
    await act(async () => {
      await cancel.result.current.mutateAsync("abc");
      await remove.result.current.mutateAsync(7);
      await open.result.current.mutateAsync();
    });
    expect(calls).toHaveLength(3);
    for (const call of calls) expect(call.url.searchParams.get("lang")).toBe("en");
  });

  it("une suppression d'un scan déjà supprimé (404) n'est pas une erreur", async () => {
    mockFetch({ "DELETE /api/scan/7": () => jsonResponse({ detail: "Scan non trouvé" }, 404) });
    const { result } = renderHook(() => useDeleteScan(), { wrapper: wrapper() });
    let outcome: unknown;
    await act(async () => {
      outcome = await result.current.mutateAsync(7);
    });
    expect(outcome).toBe("missing");
  });

  it.each([
    ["supprimé", () => new Response(null, { status: 204 })],
    ["déjà supprimé (404)", () => jsonResponse({ detail: "Scan non trouvé" }, 404)],
  ])("scan %s : il quitte le cache (toutes langues) et les timelines sont à relire", async (_label, respond) => {
    mockFetch({ "DELETE /api/scan/7": respond });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    client.setQueryData(["scan", 7, "fr"], makeScan());
    client.setQueryData(["scan", 7, "en"], makeScan());
    client.setQueryData(["scan", 8, "fr"], makeScan());
    client.setQueryData(["timeline", "example.com", "fr"], makeTimeline());
    client.setQueryData(["history", "list", {}, "fr"], { total: 1, scans: [] });
    const { result } = renderHook(() => useDeleteScan(), {
      wrapper: ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await act(async () => {
      await result.current.mutateAsync(7);
    });
    expect(client.getQueryData(["scan", 7, "fr"])).toBeUndefined();
    expect(client.getQueryData(["scan", 7, "en"])).toBeUndefined();
    expect(client.getQueryData(["scan", 8, "fr"])).toBeDefined();
    expect(client.getQueryState(["timeline", "example.com", "fr"])?.isInvalidated).toBe(true);
    expect(client.getQueryState(["history", "list", {}, "fr"])?.isInvalidated).toBe(true);
  });

  it("qualifie l'état du serveur", async () => {
    mockFetch({ "/api/health": () => jsonResponse({ api: "healthy", database: "connected", version: "1.0.0" }) });
    await expect(fetchHealth()).resolves.toEqual({ state: "online", version: "1.0.0" });
    mockFetch({ "/api/health": () => jsonResponse({ api: "degraded", database: "read-only", version: "1.0.0" }, 503) });
    await expect(fetchHealth()).resolves.toEqual({ state: "degraded", version: "1.0.0" });
  });

  it("enregistrer des notes : la réponse est rangée sous la langue de la requête, même si la langue change entre-temps", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    mockFetch({
      "PATCH /api/scan/42/meta": async () => {
        await gate;
        return jsonResponse(makeScan({ notes: "réponse du PATCH (rendue en français)" }));
      },
      "GET /api/scan/42": ({ url }) =>
        jsonResponse(makeScan({ notes: url.searchParams.get("lang") === "en" ? "lecture en anglais" : "lecture en français" })),
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
    const { result } = renderHook(() => ({ scan: useScan(42), meta: useUpdateMeta(42) }), {
      wrapper: ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await waitFor(() => expect(result.current.scan.isSuccess).toBe(true));
    act(() => result.current.meta.mutate({ notes: "n" }));
    await act(async () => {
      await setLang("en");
    });
    await waitFor(() => expect(client.getQueryData<ScanResponse>(["scan", 42, "en"])?.notes).toBe("lecture en anglais"));
    release();
    await waitFor(() => expect(result.current.meta.isSuccess).toBe(true));
    // Rangée sous « fr » (langue de l'envoi), jamais sous « en » ; la clé « en » est relue.
    expect(client.getQueryData<ScanResponse>(["scan", 42, "fr"])?.notes).toBe("réponse du PATCH (rendue en français)");
    await waitFor(() => expect(client.getQueryData<ScanResponse>(["scan", 42, "en"])?.notes).toBe("lecture en anglais"));
    expect(result.current.scan.data?.notes).toBe("lecture en anglais");
  });

  it("les informations du serveur sont lues dans la langue de l'interface (erreurs comprises)", async () => {
    const { calls } = mockFetch({ "GET /api/system/info": { version: "1.0.0", data_dir: "/d", portable: false, frozen: false } });
    await setLang("en");
    const { result } = renderHook(() => useSystemInfo(), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(calls[0].url.searchParams.get("lang")).toBe("en");
  });
});

// Onglet caché ou visible : visibilityState est en lecture seule dans jsdom.
function setVisibility(state: DocumentVisibilityState) {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  document.dispatchEvent(new Event("visibilitychange"));
}

describe("battement de l'interface", () => {
  afterEach(() => {
    vi.useRealTimers();
    setTokenPrompt(null);
    Reflect.deleteProperty(document, "visibilityState");
  });

  const heartbeats = (calls: Array<{ method: string; url: URL }>) =>
    calls.filter((call) => call.method === "POST" && call.url.pathname === "/api/system/heartbeat");

  it("au montage, puis toutes les 30 s même onglet caché, et au retour sur l'onglet ; plus rien après le démontage", async () => {
    vi.useFakeTimers();
    setToken("abc");
    const { calls } = mockFetch({ "POST /api/system/heartbeat": () => new Response(null, { status: 204 }) });
    const { unmount } = renderHook(() => useHeartbeat());
    expect(heartbeats(calls)).toHaveLength(1);
    // JSON (anti-CSRF du serveur) et jeton, comme les autres requêtes.
    const headers = new Headers(calls[0].init.headers);
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(headers.get("X-API-Token")).toBe("abc");
    await vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL);
    expect(heartbeats(calls)).toHaveLength(2);
    setVisibility("hidden");
    expect(heartbeats(calls)).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(2 * HEARTBEAT_INTERVAL);
    expect(heartbeats(calls)).toHaveLength(4);
    setVisibility("visible");
    expect(heartbeats(calls)).toHaveLength(5);
    unmount();
    await vi.advanceTimersByTimeAsync(2 * HEARTBEAT_INTERVAL);
    setVisibility("visible");
    expect(heartbeats(calls)).toHaveLength(5);
  });

  it("silencieux : ni saisie du jeton ni jeton effacé sur un 401, aucune erreur remontée", async () => {
    const prompt = vi.fn(async () => "nouveau");
    setTokenPrompt(prompt);
    setToken("ancien");
    mockFetch({ "POST /api/system/heartbeat": () => jsonResponse({ detail: "Jeton requis", code: "api.auth_required", params: {} }, 401) });
    await expect(sendHeartbeat()).resolves.toBe("refused");
    expect(prompt).not.toHaveBeenCalled();
    expect(getToken()).toBe("ancien");
    mockFetch({ "POST /api/system/heartbeat": () => jsonResponse({ detail: "Erreur" }, 500) });
    await expect(sendHeartbeat()).resolves.toBe("refused");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    await expect(sendHeartbeat()).resolves.toBe("unreachable");
  });

  const failingFetch = () =>
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );

  it("serveur arrêté après un battement réussi (onglet gelé puis réveillé) : signalé, puis effacé s'il répond de nouveau", async () => {
    vi.useFakeTimers();
    mockFetch({ "POST /api/system/heartbeat": () => new Response(null, { status: 204 }) });
    const { result } = renderHook(() => useHeartbeat());
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(result.current).toBe(false);
    // Arrêt automatique pendant que l'onglet était gelé : au réveil, plus de serveur.
    failingFetch();
    setVisibility("hidden");
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(result.current).toBe(false); // battement d'onglet caché : rien envoyé au changement
    setVisibility("visible");
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(result.current).toBe(true);
    // Relancé (même port) : le message disparaît au battement suivant.
    mockFetch({ "POST /api/system/heartbeat": () => new Response(null, { status: 204 }) });
    await act(() => vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL));
    expect(result.current).toBe(false);
  });

  it("serveur jamais joint, ou refus HTTP : pas de message d'arrêt (l'état du serveur le dit déjà)", async () => {
    vi.useFakeTimers();
    failingFetch();
    const { result } = renderHook(() => useHeartbeat());
    await act(() => vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL));
    expect(result.current).toBe(false);
    mockFetch({ "POST /api/system/heartbeat": () => new Response(null, { status: 204 }) });
    await act(() => vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL));
    mockFetch({ "POST /api/system/heartbeat": () => jsonResponse({ detail: "Erreur" }, 500) });
    await act(() => vi.advanceTimersByTimeAsync(HEARTBEAT_INTERVAL));
    expect(result.current).toBe(false);
  });

  it("tient un Web Lock tant que l'onglet est ouvert (Chromium ne gèle pas une page qui en tient un), rendu au démontage", async () => {
    const released: string[] = [];
    const request = vi.fn((name: string, callback: () => Promise<void>) =>
      callback().then(() => {
        released.push(name);
      }),
    );
    Object.defineProperty(navigator, "locks", { configurable: true, value: { request } });
    try {
      mockFetch({ "POST /api/system/heartbeat": () => new Response(null, { status: 204 }) });
      const { unmount } = renderHook(() => useHeartbeat());
      expect(request).toHaveBeenCalledTimes(1);
      await Promise.resolve();
      expect(released).toEqual([]);
      unmount();
      await waitFor(() => expect(released).toEqual([request.mock.calls[0][0]]));
    } finally {
      Reflect.deleteProperty(navigator, "locks");
    }
  });

  it("sans Web Locks (ancien navigateur, jsdom) : le battement fonctionne quand même", () => {
    const { calls } = mockFetch({ "POST /api/system/heartbeat": () => new Response(null, { status: 204 }) });
    const { unmount } = renderHook(() => useHeartbeat());
    expect(heartbeats(calls)).toHaveLength(1);
    unmount();
  });
});
