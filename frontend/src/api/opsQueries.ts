import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type Lang, useLang } from "../i18n";
import { apiFetch, apiRequest, jsonBody } from "./client";
import type {
  AlertRules,
  BatchView,
  ChannelName,
  ChannelView,
  CompareResponse,
  DashboardResponse,
  NotificationsResponse,
  ServiceTestResult,
  SettingsUpdate,
  SettingsView,
  SystemTask,
  VpnStatus,
  Watch,
  WatchInput,
} from "./ops";
import type { ScanProfile } from "./types";
import { type UploadOptions, uploadImport } from "./upload";

// Lectures et écritures des écrans d'exploitation. La langue fait partie des clés des
// lectures dont le serveur rend les textes.

export function useDashboard() {
  const lang = useLang();
  return useQuery({
    queryKey: ["dashboard", lang],
    queryFn: ({ signal }) => apiFetch<DashboardResponse>("/dashboard", { lang, signal }),
  });
}

export function useCompare(a: number | null, b: number | null) {
  const lang = useLang();
  return useQuery({
    queryKey: ["compare", a, b, lang],
    queryFn: ({ signal }) => apiFetch<CompareResponse>(`/compare?a=${a}&b=${b}`, { lang, signal }),
    enabled: a !== null && b !== null && a !== b,
  });
}

export interface BatchInput {
  domains: string[];
  profile: ScanProfile;
  selected?: string[];
  authorized_target: boolean;
}

export function useStartBatch() {
  const lang = useLang();
  return useMutation({
    mutationFn: (input: BatchInput) => apiFetch<BatchView>("/batches", { method: "POST", lang, ...jsonBody(input) }),
  });
}

// Suivi d'un lot : relu toutes les 2 s tant qu'il n'est pas terminé.
export function useBatch(id: string | null) {
  const lang = useLang();
  return useQuery({
    queryKey: ["batch", id, lang],
    queryFn: ({ signal }) => apiFetch<BatchView>(`/batches/${id}`, { lang, signal }),
    enabled: id !== null,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "queued" || status === undefined ? 2000 : false;
    },
  });
}

export function useCancelBatch() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ id: string; status: string }>(`/batches/${id}/cancel`, { method: "POST", ...jsonBody({}) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["batch"] }),
  });
}

export function useWatches() {
  const lang = useLang();
  return useQuery({
    queryKey: ["watches", lang],
    queryFn: ({ signal }) => apiFetch<{ watches: Watch[] }>("/watches", { lang, signal }),
  });
}

function useRefreshWatches() {
  const queryClient = useQueryClient();
  return () => {
    void queryClient.invalidateQueries({ queryKey: ["watches"] });
    void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  };
}

export function useCreateWatch() {
  const lang = useLang();
  const refresh = useRefreshWatches();
  return useMutation({
    mutationFn: (input: WatchInput) => apiFetch<Watch>("/watches", { method: "POST", lang, ...jsonBody(input) }),
    onSuccess: refresh,
  });
}

export interface WatchPatch {
  frequency?: Watch["frequency"];
  enabled?: boolean;
  rules?: AlertRules;
  channels?: Watch["channels"];
}

export function useUpdateWatch() {
  const lang = useLang();
  const refresh = useRefreshWatches();
  return useMutation({
    mutationFn: ({ id, patch }: { id: number; patch: WatchPatch }) =>
      apiFetch<Watch>(`/watches/${id}`, { method: "PATCH", lang, ...jsonBody(patch) }),
    onSuccess: refresh,
  });
}

export function useDeleteWatch() {
  const refresh = useRefreshWatches();
  return useMutation({
    mutationFn: (id: number) => apiFetch<{ id: number }>(`/watches/${id}`, { method: "DELETE" }),
    onSuccess: refresh,
  });
}

export function useRunWatch() {
  const lang = useLang();
  const refresh = useRefreshWatches();
  return useMutation({
    mutationFn: (id: number) => apiFetch<{ id: number }>(`/watches/${id}/run`, { method: "POST", lang, ...jsonBody({}) }),
    onSuccess: refresh,
  });
}

export function useSystemTask() {
  return useQuery({
    queryKey: ["monitor-task"],
    queryFn: ({ signal }) => apiFetch<SystemTask>("/monitor/task", { signal }),
  });
}

export function useSetSystemTask() {
  const lang = useLang();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (install: boolean) =>
      apiFetch<SystemTask>(`/monitor/task/${install ? "install" : "uninstall"}`, {
        method: "POST",
        lang,
        ...jsonBody({}),
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["monitor-task"] }),
  });
}

export function useNotifications(limit = 50) {
  const lang = useLang();
  return useQuery({
    queryKey: ["notifications", limit, lang],
    queryFn: ({ signal }) => apiFetch<NotificationsResponse>(`/notifications?limit=${limit}`, { lang, signal }),
  });
}

export function useNotificationActions() {
  const queryClient = useQueryClient();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["notifications"] });
  const markRead = useMutation({
    mutationFn: (ids?: number[]) =>
      apiFetch<{ updated: number }>("/notifications/read", { method: "POST", ...jsonBody(ids ? { ids } : {}) }),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: (id: number) => apiFetch<{ id: number }>(`/notifications/${id}`, { method: "DELETE" }),
    onSuccess: refresh,
  });
  const clear = useMutation({
    mutationFn: () => apiFetch<{ deleted: number }>("/notifications?all=true", { method: "DELETE" }),
    onSuccess: refresh,
  });
  return { markRead, remove, clear };
}

export function useChannels() {
  return useQuery({
    queryKey: ["channels"],
    queryFn: ({ signal }) => apiFetch<{ channels: ChannelView[] }>("/notify/channels", { signal }),
  });
}

export function useSaveChannel() {
  const lang = useLang();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ name, enabled, config }: { name: ChannelName; enabled: boolean; config: Record<string, unknown> }) =>
      apiFetch<ChannelView>(`/notify/channels/${name}`, { method: "PUT", lang, ...jsonBody({ enabled, config }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["channels"] }),
  });
}

export function useTestChannel() {
  const lang = useLang();
  return useMutation({
    mutationFn: (name: ChannelName) =>
      apiFetch<{ ok: boolean; error?: string | null }>(`/notify/channels/${name}/test`, {
        method: "POST",
        lang,
        ...jsonBody({}),
      }),
  });
}

export function useSettings() {
  const lang = useLang();
  return useQuery({
    queryKey: ["settings", lang],
    queryFn: ({ signal }) => apiFetch<SettingsView>("/settings", { lang, signal }),
  });
}

export function useSaveSettings() {
  const lang = useLang();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (update: SettingsUpdate) =>
      apiFetch<SettingsView>("/settings", { method: "PUT", lang, ...jsonBody(update) }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["settings"] });
      // Une clé enregistrée change l'état « configurée » du catalogue.
      void queryClient.invalidateQueries({ queryKey: ["modules"] });
    },
  });
}

export function useTestService() {
  const lang = useLang();
  return useMutation({
    mutationFn: (service: string) =>
      apiFetch<ServiceTestResult>(`/settings/test/${encodeURIComponent(service)}`, {
        method: "POST",
        lang,
        ...jsonBody({}),
      }),
  });
}

export function useVpn(enabled = true) {
  const lang = useLang();
  return useQuery({
    queryKey: ["vpn", lang],
    queryFn: ({ signal }) => apiFetch<VpnStatus>("/system/vpn", { lang, signal }),
    enabled,
    retry: false,
    staleTime: 15_000,
  });
}

// Formats d'export serveur (GET /api/scan/{id}/export).
export const EXPORT_FORMATS = ["pdf", "html", "md", "csv", "json", "sarif"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

// Nom de fichier annoncé par Content-Disposition, sinon un nom par défaut.
export function filenameFromDisposition(header: string | null, fallback: string): string {
  const match = header ? /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(header) : null;
  if (!match) return fallback;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

export async function fetchExport(
  scanId: number,
  format: ExportFormat,
  lang: Lang,
): Promise<{ blob: Blob; filename: string }> {
  const res = await apiRequest(`/scan/${scanId}/export?format=${format}`, { lang });
  const blob = await res.blob();
  return { blob, filename: filenameFromDisposition(res.headers.get("Content-Disposition"), `scan-${scanId}.${format}`) };
}

// Import d'une ancienne base (POST /api/import) avec l'avancement de l'envoi. Des scans viennent
// d'être ajoutés : historique, tableau de bord et accueil se relisent.
export function useImportDatabase() {
  const lang = useLang();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { file: File; onProgress?: UploadOptions["onProgress"]; signal?: AbortSignal }) =>
      uploadImport(input.file, { lang, onProgress: input.onProgress, signal: input.signal }),
    onSuccess: (result) => {
      if (result.imported > 0) void queryClient.invalidateQueries();
    },
  });
}
