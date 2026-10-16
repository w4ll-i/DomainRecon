import { keepPreviousData, QueryClient, QueryClientContext, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useContext, useEffect, useMemo, useState } from "react";
import { currentLang, type Lang, useLang } from "../i18n";
import { buildCatalog, type Catalog } from "../lib/catalog";
import { ApiError, apiFetch, apiRequest, jsonBody } from "./client";
import type {
  HealthResponse,
  HistoryResponse,
  JobStarted,
  JobStatus,
  ModulesResponse,
  ScanProfile,
  ScanResponse,
  SystemInfo,
  TimelineResponse,
} from "./types";

// Pas de nouvel essai sur une erreur 4xx (cible refusée, scan inexistant…).
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        staleTime: 30_000,
        retry: (failureCount, error) =>
          !(error instanceof ApiError && error.status >= 400 && error.status < 500) && failureCount < 2,
      },
    },
  });
}

// Historique : scans chargés par page (l'API en accepte 200 au plus).
export const HISTORY_PAGE_SIZE = 25;

export interface HistoryParams {
  q: string;
  grade: string;
  status: string;
  page: number;
}

export function historyPath(params: HistoryParams, pageSize = HISTORY_PAGE_SIZE): string {
  const search = new URLSearchParams({
    limit: String(pageSize),
    offset: String((Math.max(1, params.page) - 1) * pageSize),
  });
  if (params.q) search.set("domain", params.q);
  if (params.grade) search.set("grade", params.grade);
  if (params.status) search.set("status", params.status);
  return `/history?${search}`;
}

// La langue fait partie des clés : un changement de langue relance les lectures.
export const queryKeys = {
  scan: (id: number, lang: Lang) => ["scan", id, lang] as const,
  history: (params: HistoryParams, lang: Lang) => ["history", "list", params, lang] as const,
  recent: (limit: number, lang: Lang) => ["history", "recent", limit, lang] as const,
  timeline: (domain: string, lang: Lang) => ["timeline", domain, lang] as const,
  job: (id: string) => ["job", id] as const,
  modules: (lang: Lang) => ["modules", lang] as const,
  health: ["health"] as const,
  systemInfo: ["system-info"] as const,
};

export function useScan(id: number | null) {
  const lang = useLang();
  return useQuery({
    queryKey: queryKeys.scan(id ?? 0, lang),
    queryFn: ({ signal }) => apiFetch<ScanResponse>(`/scan/${id}`, { lang, signal }),
    enabled: id !== null,
    // Changer de langue relit le scan : l'ancien texte reste affiché pendant la
    // relecture (rien ne se démonte, le brouillon de notes survit). Jamais d'un
    // scan à un autre : seul le même identifiant garde ses données.
    placeholderData: (previous, previousQuery) => (previousQuery?.queryKey[1] === id ? previous : undefined),
  });
}

// Catalogue des modules (familles, modules, textes d'aide) : l'interface en tire ses
// listes. Illisible (API plus ancienne, erreur), il laisse le repli statique des 18
// modules historiques : l'écran n'attend jamais le catalogue et n'affiche pas d'erreur.
//
// Hors fournisseur de requêtes (composant rendu seul), aucune requête : repli statique.
const inertClient = new QueryClient();

export function useCatalog(): Catalog {
  const lang = useLang();
  const provided = useContext(QueryClientContext);
  const query = useQuery(
    {
      queryKey: queryKeys.modules(lang),
      queryFn: ({ signal }) => apiFetch<ModulesResponse>("/modules", { lang, signal }),
      enabled: Boolean(provided),
      staleTime: 5 * 60_000,
      retry: false,
    },
    provided ?? inertClient,
  );
  return useMemo(() => buildCatalog(query.data), [query.data]);
}

export function useHistory(params: HistoryParams) {
  const lang = useLang();
  return useQuery({
    queryKey: queryKeys.history(params, lang),
    queryFn: ({ signal }) => apiFetch<HistoryResponse>(historyPath(params), { lang, signal }),
    placeholderData: keepPreviousData,
  });
}

export function useRecentScans(limit = 5) {
  const lang = useLang();
  return useQuery({
    queryKey: queryKeys.recent(limit, lang),
    queryFn: ({ signal }) => apiFetch<HistoryResponse>(`/history?limit=${limit}&offset=0`, { lang, signal }),
  });
}

export function useTimeline(domain: string) {
  const lang = useLang();
  return useQuery({
    queryKey: queryKeys.timeline(domain, lang),
    queryFn: ({ signal }) => apiFetch<TimelineResponse>(`/dns-timeline/${encodeURIComponent(domain)}`, { lang, signal }),
    enabled: domain !== "",
  });
}

export function useJobStatus(jobId: string) {
  return useQuery({
    queryKey: queryKeys.job(jobId),
    queryFn: ({ signal }) => apiFetch<JobStatus>(`/scans/${encodeURIComponent(jobId)}`, { signal }),
  });
}

export function useSystemInfo() {
  return useQuery({
    queryKey: queryKeys.systemInfo,
    // Les données ne dépendent pas de la langue (clé sans langue), seules les erreurs en dépendent.
    queryFn: ({ signal }) => apiFetch<SystemInfo>("/system/info", { lang: currentLang(), signal }),
    staleTime: 300_000,
  });
}

export type HealthState = "online" | "degraded" | "offline";

// /api/health est public : appelé sans jeton ni boîte de saisie.
export async function fetchHealth(signal?: AbortSignal): Promise<{ state: HealthState; version: string | null }> {
  try {
    const res = await fetch("/api/health", { signal });
    let version: string | null = null;
    try {
      version = ((await res.json()) as Partial<HealthResponse>).version ?? null;
    } catch {
      version = null;
    }
    return { state: res.ok ? "online" : res.status === 503 ? "degraded" : "offline", version };
  } catch {
    return { state: "offline", version: null };
  }
}

export function useHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 30_000,
    retry: false,
  });
}

// Les mutations passent aussi la langue : un refus du serveur est rendu dans la langue de l'interface.
// Entrée d'un lancement : le domaine seul (profil « complet » du serveur), ou avec le profil,
// les modules choisis et la déclaration d'autorisation.
export interface StartScanInput {
  domain: string;
  profile?: ScanProfile;
  selected?: string[];
  authorized_target?: boolean;
}

export function useStartScan() {
  const lang = useLang();
  return useMutation({
    mutationFn: (input: string | StartScanInput) =>
      apiFetch<JobStarted>("/scans", {
        method: "POST",
        lang,
        ...jsonBody(typeof input === "string" ? { domain: input } : input),
      }),
  });
}

export function useCancelJob() {
  const lang = useLang();
  return useMutation({
    mutationFn: (jobId: string) =>
      apiFetch<{ id: string; status: string }>(`/scans/${encodeURIComponent(jobId)}/cancel`, {
        method: "POST",
        lang,
        ...jsonBody({}),
      }),
  });
}

// 404 : déjà supprimé ailleurs, la ligne est à retirer quand même. Le scan
// disparu quitte le cache (« Résultat » ne doit pas le ressusciter) et les
// timelines, qui le citaient, sont relues.
export function useDeleteScan() {
  const lang = useLang();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number): Promise<"deleted" | "missing"> => {
      try {
        await apiRequest(`/scan/${id}`, { method: "DELETE", lang });
        return "deleted";
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return "missing";
        throw error;
      }
    },
    onSuccess: (_outcome, id) => {
      queryClient.removeQueries({ queryKey: ["scan", id] });
      void queryClient.invalidateQueries({ queryKey: ["timeline"] });
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["history"] }),
  });
}

// La langue de la requête est figée à l'envoi (`onMutate`) : TanStack Query
// applique les options les plus récentes aux rappels d'une mutation en cours,
// et une réponse rendue dans l'ancienne langue ne doit pas être rangée sous la
// clé de la nouvelle.
export function useUpdateMeta(id: number) {
  const lang = useLang();
  const queryClient = useQueryClient();
  return useMutation({
    onMutate: () => ({ requestLang: lang }),
    mutationFn: (body: { tags?: string[]; notes?: string }) =>
      apiFetch<ScanResponse>(`/scan/${id}/meta`, { method: "PATCH", lang, ...jsonBody(body) }),
    onSuccess: (scan, _body, context) => {
      const requestLang = context?.requestLang ?? lang;
      queryClient.setQueryData(queryKeys.scan(id, requestLang), scan);
      // Les autres langues (dont la langue courante si elle a changé entre-temps) sont relues.
      void queryClient.invalidateQueries({ queryKey: ["scan", id], predicate: (query) => query.queryKey[2] !== requestLang });
      void queryClient.invalidateQueries({ queryKey: ["history"] });
    },
  });
}

// Battement de l'interface : en mode navigateur, le serveur s'arrête seul
// environ 2 minutes après le dernier (fermeture du dernier onglet). Toutes les
// 30 s, même onglet en arrière-plan (les navigateurs y ralentissent les
// minuteries à environ une par minute, toujours sous les 2 minutes), plus un
// battement immédiat au montage et au retour sur l'onglet. Limite : un onglet
// gelé par le navigateur (mise en veille des onglets d'Edge, économie de
// mémoire de Chrome, navigateur mobile) ne bat plus, et le serveur s'arrête.
export const HEARTBEAT_INTERVAL = 30_000;

// ok : serveur joint ; unreachable : aucune réponse (erreur réseau, serveur
// arrêté) ; refused : réponse d'erreur (jeton absent ou refusé, 5xx).
export type HeartbeatResult = "ok" | "unreachable" | "refused";

// Silencieux : ni saisie du jeton ni exception ; le battement suivant réessaie.
export async function sendHeartbeat(): Promise<HeartbeatResult> {
  try {
    await apiRequest("/system/heartbeat", { method: "POST", interactive: false, ...jsonBody({}) });
    return "ok";
  } catch (error) {
    return error instanceof ApiError && error.status === 0 ? "unreachable" : "refused";
  }
}

// Web Lock tenu tant que l'onglet est ouvert : Chromium (Chrome, Edge) ne gèle
// pas une page qui en tient un, ce qui protège le battement de la mise en
// veille des onglets (au mieux : selon le navigateur et ses réglages). Nom
// propre à l'onglet ; renvoie la fonction qui le rend.
function holdTabLock(): () => void {
  const locks = typeof navigator === "undefined" ? undefined : navigator.locks;
  if (!locks || typeof locks.request !== "function") return () => {};
  let release = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const name = `domainrecon-onglet-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  try {
    void Promise.resolve(locks.request(name, () => held)).catch(() => {});
  } catch {
    // Web Locks refusés (contexte non sécurisé, --host) : le battement suffit.
  }
  return release;
}

// Vrai quand le serveur, joint par un battement précédent, ne répond plus :
// arrêté (automatiquement, ou fermé), à relancer. Faux de nouveau dès qu'il
// répond (relancé sur le même port).
export function useHeartbeat(): boolean {
  const [stopped, setStopped] = useState(false);
  useEffect(() => {
    let reached = false;
    let active = true;
    const beat = async () => {
      const result = await sendHeartbeat();
      if (!active) return;
      if (result === "ok") reached = true;
      if (result === "ok" || result === "unreachable") setStopped(result === "unreachable" && reached);
    };
    const releaseLock = holdTabLock();
    void beat();
    const timer = window.setInterval(() => void beat(), HEARTBEAT_INTERVAL);
    const onVisible = () => {
      if (document.visibilityState === "visible") void beat();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      active = false;
      releaseLock();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);
  return stopped;
}

export function useOpenDataDir() {
  const lang = useLang();
  return useMutation({
    mutationFn: async () => {
      await apiRequest("/system/open-data-dir", { method: "POST", lang, ...jsonBody({}) });
    },
  });
}
