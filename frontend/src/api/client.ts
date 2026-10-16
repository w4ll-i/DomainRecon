import i18n, { type Lang } from "../i18n";
import { STORAGE_KEYS, readSession, writeSession } from "../lib/storage";
import type { ErrorBody } from "./types";

// Erreur d'appel à l'API : `detail` est lisible tel quel (texte rendu par le
// serveur, ou message de l'interface) ; `status` vaut 0 pour une erreur réseau.
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly params: Record<string, unknown>;
  readonly detail: string;

  constructor(status: number, detail: string, code: string | null = null, params: Record<string, unknown> = {}) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.params = params;
    this.detail = detail;
  }
}

export type TokenPrompt = (reason: "missing" | "rejected") => Promise<string | null>;

export interface ApiInit extends RequestInit {
  lang?: Lang;
  // false : un 401 n'ouvre pas la saisie du jeton et ne l'efface pas (requête de fond, battement).
  interactive?: boolean;
}

// Jeton d'API : sessionStorage (propre à l'onglet) ; en mémoire seulement si
// le stockage est indisponible.
let memoryToken = "";
const tokenListeners = new Set<() => void>();
let tokenPrompt: TokenPrompt | null = null;
let pendingPrompt: Promise<string | null> | null = null;

// Le navigateur envoie un en-tête en Latin-1 et le serveur le compare au jeton
// encodé en UTF-8 : seul un jeton ASCII imprimable peut passer.
const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

export function isPrintableAscii(token: string): boolean {
  return PRINTABLE_ASCII.test(token);
}

export function getToken(): string {
  return readSession(STORAGE_KEYS.token) ?? memoryToken;
}

// Un jeton qui ne passerait pas en en-tête (hors ASCII imprimable) n'est jamais
// gardé : il vaut « aucun jeton » (la boîte de saisie le refuse déjà).
export function setToken(raw: string): void {
  const token = isPrintableAscii(raw) ? raw : "";
  writeSession(STORAGE_KEYS.token, token || null);
  // Copie en mémoire seulement si le stockage de l'onglet n'a pas pris la
  // valeur : sinon un jeton effacé du stockage ressusciterait depuis la mémoire.
  memoryToken = readSession(STORAGE_KEYS.token) === (token || null) ? "" : token;
  tokenListeners.forEach((listener) => listener());
}

export function subscribeToken(listener: () => void): () => void {
  tokenListeners.add(listener);
  return () => {
    tokenListeners.delete(listener);
  };
}

// Branche la boîte de saisie du jeton (TokenDialog).
export function setTokenPrompt(prompt: TokenPrompt | null): void {
  tokenPrompt = prompt;
}

// Saisie partagée par tous les appels refusés en même temps.
function askToken(reason: "missing" | "rejected"): Promise<string | null> {
  if (!tokenPrompt) return Promise.resolve(null);
  if (!pendingPrompt) {
    pendingPrompt = tokenPrompt(reason).finally(() => {
      pendingPrompt = null;
    });
  }
  return pendingPrompt;
}

// Chemin relatif à /api (« /scan/12 ») ; un chemin commençant par /api est gardé.
export function buildUrl(path: string, lang?: Lang): string {
  const url = new URL(path.startsWith("/api/") ? path : `/api${path}`, "http://domainrecon.local");
  if (lang) url.searchParams.set("lang", lang);
  return url.pathname + url.search;
}

export function describeDetail(detail: unknown, status: number): string {
  if (typeof detail === "string" && detail.trim()) return detail.trim();
  if (Array.isArray(detail)) {
    const parts = detail
      .map((entry) =>
        entry && typeof entry === "object" && "msg" in entry
          ? String((entry as { msg: unknown }).msg).replace(/^Value error, /, "")
          : "",
      )
      .filter(Boolean);
    if (parts.length) return i18n.t("errors.validation", { details: parts.join(i18n.t("common.listSeparator")) });
  }
  const key = `errors.http.${status}`;
  if (i18n.exists(key)) return i18n.t(key);
  return i18n.t(status >= 500 ? "errors.http.5xx" : "errors.http.other", { status });
}

// Annulation volontaire (AbortController) : jamais transformée en erreur d'API.
function isAbort(error: unknown): boolean {
  return (error as { name?: unknown } | null)?.name === "AbortError";
}

// Erreur d'API d'après le corps (déjà lu) d'une réponse non 2xx : texte rendu par le serveur, code, paramètres.
export function apiErrorFromBody(status: number, body: ErrorBody | null): ApiError {
  const code = typeof body?.code === "string" ? body.code : null;
  const params = body?.params && typeof body.params === "object" ? body.params : {};
  return new ApiError(status, describeDetail(body?.detail, status), code, params);
}

export async function toApiError(res: Response): Promise<ApiError> {
  const body = (await res.json().catch((error: unknown) => {
    // Corps illisible : message générique ; annulation pendant la lecture : remontée telle quelle.
    if (isAbort(error)) throw error;
    return null;
  })) as ErrorBody | null;
  return apiErrorFromBody(res.status, body);
}

async function send(path: string, init: ApiInit, token: string): Promise<Response> {
  const { lang, headers, ...rest } = init;
  const merged = new Headers(headers);
  // Jeton hors ASCII imprimable (stockage altéré) : Headers.set lèverait un
  // TypeError ; la requête part sans jeton et le serveur répond 401.
  if (token && isPrintableAscii(token)) merged.set("X-API-Token", token);
  try {
    return await fetch(buildUrl(path, lang), { ...rest, headers: merged });
  } catch (error) {
    if (isAbort(error)) throw error;
    throw new ApiError(0, i18n.t("errors.network"));
  }
}

// Envoi avec jeton, quel que soit le transport (fetch, XMLHttpRequest) : `attempt` envoie la
// requête avec le jeton donné. Un 401 → saisie du jeton (sauf `interactive: false`) puis une
// seule nouvelle tentative.
export async function withToken<R extends { status: number }>(
  attempt: (token: string) => Promise<R>,
  interactive = true,
): Promise<R> {
  const sent = getToken();
  let res = await attempt(sent);
  if (res.status === 401) {
    const current = getToken();
    if (current && current !== sent) {
      // Jeton saisi entre-temps pour un autre appel : relance sans redemander.
      res = await attempt(current);
    } else if (interactive) {
      if (sent) setToken("");
      const token = await askToken(sent ? "rejected" : "missing");
      if (token) {
        setToken(token);
        res = await attempt(token);
        if (res.status === 401 && getToken() === token) setToken("");
      }
    }
  }
  return res;
}

// Point d'entrée unique : jeton, langue, 401 → saisie (sauf `interactive: false`)
// puis une seule nouvelle tentative. Lève une ApiError pour toute réponse non 2xx.
export async function apiRequest(path: string, init: ApiInit = {}): Promise<Response> {
  const { interactive = true, ...request } = init;
  const res = await withToken((token) => send(path, request, token), interactive);
  if (!res.ok) throw await toApiError(res);
  return res;
}

export async function apiFetch<T>(path: string, init: ApiInit = {}): Promise<T> {
  const res = await apiRequest(path, init);
  if (res.status === 204) return undefined as T;
  try {
    return (await res.json()) as T;
  } catch (error) {
    if (isAbort(error)) throw error;
    throw new ApiError(res.status, i18n.t("errors.unreadable", { status: res.status }));
  }
}

export function jsonBody(value: unknown): { body: string; headers: Record<string, string> } {
  return { body: JSON.stringify(value), headers: { "Content-Type": "application/json" } };
}

// Action refusée parce que la requête ne vient pas de la machine locale (403 api.local_only) :
// une règle de l'application (ouvrir le dossier, installer la tâche système), pas une panne.
export function isLocalOnly(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403 && error.code === "api.local_only";
}

export function errorDetail(error: unknown): string {
  if (error instanceof ApiError) return error.detail;
  if (error instanceof Error) return error.message;
  return String(error);
}
