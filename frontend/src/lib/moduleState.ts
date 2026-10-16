import type { TFunction } from "i18next";
import type { MeasuredResult, ModuleName, ModuleRunStatus, ScanResponse } from "../api/types";
import { isModuleName, MODULE_NAMES } from "./families";

// Un module sans résultat exploitable (échec, délai dépassé, sans objet) n'est
// jamais un « rien trouvé » : sa valeur de repli ({measured: false}, ou {}
// pour un ancien scan) ne doit pas se lire comme une mesure.
//
// « not_launched » : le module n'a pas été lancé (profil du scan, clé absente,
// autorisation refusée). Jamais confondu avec « ok » ni avec un échec.
export type ModuleViewStatus = ModuleRunStatus | "not_launched";

export interface ModuleAvailability {
  status: ModuleViewStatus;
  error: string | null;
}

// Scan antérieur : takeover classé « sans objet » alors qu'il n'a pas été
// vérifié faute d'énumération (texte d'origine, jamais traduit).
const LEGACY_TAKEOVER_SKIP = /^Énumération des sous-domaines en échec/;

// Scan antérieur à module_status : la colonne des takeovers est ajoutée à NULL
// aux anciens scans et lue comme une liste vide, indiscernable d'un « rien
// trouvé ». Seul le score, calculé alors sur les données d'origine, dit si la
// vérification a eu lieu (critère « takeover » mesuré).
function takeoverNeverChecked(scan: Partial<Pick<ScanResponse, "security_score">>): boolean {
  const criterion = scan.security_score?.breakdown?.takeover;
  return !criterion || criterion.measured === false;
}

// Module du registre sans champ propre dans le scan : son résultat est dans `modules`.
function genericState(
  scan: Pick<ScanResponse, "module_status"> & Partial<Pick<ScanResponse, "modules" | "modules_launched">>,
  name: ModuleName,
): ModuleAvailability {
  const result = scan.modules?.[name];
  const entry = scan.module_status?.[name];
  const status = result?.status ?? entry?.status;
  if (status === "ok" || status === "failed" || status === "timeout" || status === "skipped") {
    const error = result?.error ?? entry?.error ?? null;
    if (status === "ok") {
      // Résultat « ok » dont les données disent « non mesuré » (valeur de repli).
      const data = result?.data;
      if (data && typeof data === "object" && !Array.isArray(data) && (data as MeasuredResult).measured === false) {
        const measured = data as MeasuredResult;
        return { status: measured.skipped ? "skipped" : "failed", error: measured.error ?? error };
      }
      return { status: "ok", error: null };
    }
    return { status, error };
  }
  // Aucun résultat : le module n'a pas tourné dans ce scan.
  return { status: "not_launched", error: null };
}

// Scan dont la liste des modules lancés est connue : un module historique qui n'en fait
// pas partie n'a pas été lancé (sa valeur par défaut n'est pas une mesure).
function legacyNotLaunched(scan: Partial<Pick<ScanResponse, "modules_launched">>, name: ModuleName): boolean {
  return Array.isArray(scan.modules_launched) && !scan.modules_launched.includes(name);
}

export function moduleState(
  scan: Pick<ScanResponse, "module_status"> &
    Partial<Pick<ScanResponse, "security_score" | "modules" | "modules_launched">>,
  name: ModuleName,
  value?: unknown,
): ModuleAvailability {
  if (!isModuleName(name)) return genericState(scan, name);
  if (legacyNotLaunched(scan, name) && !scan.module_status?.[name]) return { status: "not_launched", error: null };
  const entry = scan.module_status?.[name];
  const noTakeover = !Array.isArray(value) || value.length === 0;
  if (name === "subdomain_takeover" && !entry && noTakeover && takeoverNeverChecked(scan)) {
    return { status: "failed", error: null };
  }
  if (name === "subdomain_takeover" && entry?.status === "skipped" && LEGACY_TAKEOVER_SKIP.test(entry.error ?? "")) {
    return { status: "failed", error: entry.error ?? null };
  }
  if (entry && (entry.status === "failed" || entry.status === "timeout" || entry.status === "skipped")) {
    return { status: entry.status, error: entry.error ?? null };
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const result = value as MeasuredResult;
    if (result.measured === false) {
      return { status: result.skipped ? "skipped" : "failed", error: result.error ?? null };
    }
    // Scan antérieur : un objet sans aucune clé est la valeur par défaut de la
    // colonne (aucune donnée enregistrée), pas un résultat « rien trouvé » ; le
    // score le lit déjà comme non mesuré (score.py). Les listes vides restent
    // un résultat valide (aucun sous-domaine, aucun port…).
    if (Object.keys(result).length === 0) return { status: "failed", error: null };
  }
  return { status: "ok", error: null };
}

export function moduleValue(scan: ScanResponse, name: ModuleName): unknown {
  if (!isModuleName(name)) return scan.modules?.[name]?.data;
  return name === "screenshot" ? scan.screenshot_path : scan[name];
}

export function scanModuleState(scan: ScanResponse, name: ModuleName): ModuleAvailability {
  return moduleState(scan, name, moduleValue(scan, name));
}

export interface FailedModule {
  name: ModuleName;
  status: "failed" | "timeout";
  error: string | null;
}

// Modules en échec ou hors délai (bandeau du résultat, PDF).
export function failedModules(scan: Pick<ScanResponse, "module_status"> & Partial<Pick<ScanResponse, "modules">>): FailedModule[] {
  // Les 18 historiques d'abord, puis les autres modules du registre dans l'ordre du scan.
  const others = [...Object.keys(scan.module_status ?? {}), ...Object.keys(scan.modules ?? {})].filter((name) => !isModuleName(name));
  return [...new Set<string>([...MODULE_NAMES, ...others])].flatMap((name) => {
    const entry = scan.module_status?.[name] ?? scan.modules?.[name];
    return entry && (entry.status === "failed" || entry.status === "timeout")
      ? [{ name, status: entry.status, error: entry.error ?? null }]
      : [];
  });
}

export function unavailableText(state: ModuleAvailability, t: TFunction): string {
  const status = t(`moduleStatus.${state.status}`);
  return state.error ? t("unavailable.withReason", { status, reason: state.error }) : status;
}
