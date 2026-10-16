import type { FamilyKey, JobEvent, ModuleName, ModuleRunStatus } from "../../api/types";
import { type Catalog, STATIC_CATALOG } from "../../lib/catalog";
import { isFamilyKey, TOTAL_MODULES } from "../../lib/families";

export interface ModuleProgress {
  status: ModuleRunStatus;
  duration: number;
  // Famille annoncée par le serveur avec l'événement (filet pour un module inconnu du catalogue).
  family?: FamilyKey;
}

export type LivePhase = "connecting" | "running" | "done" | "failed" | "cancelled" | "lost";

export interface LiveState {
  phase: LivePhase;
  modules: Partial<Record<ModuleName, ModuleProgress>>;
  done: number;
  total: number;
  scanId: number | null;
  error: { code: string | null; params: Record<string, unknown>; detail: string } | null;
}

export const initialLiveState: LiveState = {
  phase: "connecting",
  modules: {},
  done: 0,
  total: TOTAL_MODULES,
  scanId: null,
  error: null,
};

export type LiveAction = { type: "event"; event: JobEvent } | { type: "lost"; detail: string };

export function isTerminalPhase(phase: LivePhase): boolean {
  return phase === "done" || phase === "failed" || phase === "cancelled" || phase === "lost";
}

// Réducteur idempotent : le serveur rejoue tous les événements à chaque
// connexion, un module déjà connu n'est donc jamais compté deux fois.
export function liveReducer(state: LiveState, action: LiveAction): LiveState {
  if (action.type === "lost") {
    // Une tâche déjà terminée (réussie, échouée, annulée) n'est jamais « perdue » :
    // l'écran ne montrerait pas deux issues à la fois.
    if (state.phase === "done" || state.phase === "failed" || state.phase === "cancelled") return state;
    return { ...state, phase: "lost", error: { code: null, params: {}, detail: action.detail } };
  }
  const { event } = action;
  const nextPhase: LivePhase = isTerminalPhase(state.phase) ? state.phase : "running";
  switch (event.event) {
    case "module": {
      const family = isFamilyKey(event.data.family) ? event.data.family : undefined;
      const modules = {
        ...state.modules,
        [event.data.name]: { status: event.data.status, duration: event.data.duration, ...(family ? { family } : {}) },
      };
      const count = Object.keys(modules).length;
      return { ...state, phase: nextPhase, modules, done: Math.min(state.total, Math.max(state.done, count)) };
    }
    case "progress": {
      const total = event.data.total > 0 ? event.data.total : state.total;
      return { ...state, phase: nextPhase, total, done: Math.min(total, Math.max(state.done, event.data.done)) };
    }
    case "done":
      return { ...state, phase: "done", scanId: event.data.scan_id };
    case "failed":
      return {
        ...state,
        phase: "failed",
        error: { code: event.data.code ?? null, params: event.data.params ?? {}, detail: event.data.detail ?? "" },
      };
    case "cancelled":
      return { ...state, phase: "cancelled" };
    default:
      return state;
  }
}

export type LiveTileState = "pending" | "running" | "done" | "partial" | "skipped";

// État d'une tuile : avancement, pas un verdict (la note vient après le scan).
// Modules d'une famille à l'écran : ceux du catalogue (dans son ordre), puis ceux que le
// serveur a annoncés pour cette famille sans que le catalogue les connaisse. Une fois le
// scan terminé, seuls restent ceux qui ont tourné (un profil rapide ou personnalisé n'en
// lance qu'une partie : les autres ne sont pas « en attente »).
export function familyModules(state: LiveState, family: FamilyKey, catalog: Catalog = STATIC_CATALOG): string[] {
  const announced = Object.entries(state.modules)
    .filter(([name, result]) => (result?.family ?? catalog.familyOf(name)) === family)
    .map(([name]) => name);
  const names = [...new Set([...catalog.modules(family), ...announced])];
  return state.phase === "done" ? names.filter((name) => state.modules[name]) : names;
}

export function familyProgress(
  state: LiveState,
  family: FamilyKey,
  catalog: Catalog = STATIC_CATALOG,
): { done: number; total: number; unmeasured: number; state: LiveTileState } {
  const modules = familyModules(state, family, catalog);
  const results = modules
    .map((name) => state.modules[name])
    .filter((result): result is ModuleProgress => Boolean(result));
  const done = results.length;
  const total = modules.length;
  const unmeasured = results.filter((result) => result.status === "failed" || result.status === "timeout").length;
  const active = state.phase === "running" || (state.phase === "connecting" && done > 0);
  if (done < total) return { done, total, unmeasured, state: active ? "running" : "pending" };
  if (results.every((result) => result.status === "skipped")) return { done, total, unmeasured, state: "skipped" };
  return { done, total, unmeasured, state: unmeasured ? "partial" : "done" };
}
