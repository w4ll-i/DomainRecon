import { useMutation, useQuery } from "@tanstack/react-query";
import { type Lang, useLang } from "../i18n";
import { apiFetch, apiRequest, jsonBody } from "./client";
import { filenameFromDisposition } from "./opsQueries";

// Désinstallation complète (POST /api/system/uninstall) et sauvegarde de la base
// (POST /api/system/backup) : routes réservées à la machine locale, corps JSON.

export type UninstallMode =
  | "windows_installed"
  | "deb"
  | "portable_onefile"
  | "portable_folder"
  | "frozen_other"
  | "source";

export type UninstallItemStatus = "planned" | "deleted" | "missing" | "failed" | "skipped";

export interface UninstallItem {
  kind: string;
  path: string | null;
  status: UninstallItemStatus;
  size: number | null;
}

// Étape restante : code traduit par l'interface (uninstall.remaining.<code>), chemin ou commande.
export interface UninstallStep {
  code: string;
  path?: string;
  command?: string;
}

export interface UninstallReport {
  dry_run: boolean;
  mode: UninstallMode;
  platform: string;
  data_dir: string;
  items: UninstallItem[];
  total_size: number;
  program_removal: { available: boolean; paths: string[] };
  uninstaller: string | null;
  after_exit_scheduled: boolean;
  remaining: UninstallStep[];
  can_exit: boolean;
}

export interface UninstallInput {
  confirm: string;
  remove_program: boolean;
}

// Mot à taper pour confirmer, selon la langue de l'interface (le serveur accepte les deux).
export const CONFIRM_WORD: Record<Lang, string> = { fr: "SUPPRIMER", en: "DELETE" };

// Ce qui serait supprimé (mode « à blanc ») : relu à chaque ouverture de la fenêtre, jamais mis en cache.
export function useUninstallPlan(enabled: boolean) {
  const lang = useLang();
  return useQuery({
    queryKey: ["uninstall-plan", lang],
    queryFn: ({ signal }) =>
      apiFetch<UninstallReport>("/system/uninstall", { method: "POST", lang, signal, ...jsonBody({ dry_run: true }) }),
    enabled,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });
}

export function useUninstall() {
  const lang = useLang();
  return useMutation({
    mutationFn: (input: UninstallInput) =>
      apiFetch<UninstallReport>("/system/uninstall", { method: "POST", lang, ...jsonBody(input) }),
  });
}

export function useFinishUninstall() {
  const lang = useLang();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ exiting: boolean }>("/system/uninstall/finish", { method: "POST", lang, ...jsonBody({}) }),
  });
}

// Copie de la base SQLite, réimportable par « Importer une ancienne base ».
export async function fetchBackup(lang: Lang): Promise<{ blob: Blob; filename: string }> {
  const res = await apiRequest("/system/backup", { method: "POST", lang, ...jsonBody({}) });
  const blob = await res.blob();
  return { blob, filename: filenameFromDisposition(res.headers.get("Content-Disposition"), "domainrecon-sauvegarde.db") };
}
