import { useMemo, useState } from "react";
import type { ScanProfile } from "../../api/types";
import { useCatalog } from "../../api/queries";
import type { Catalog } from "../../lib/catalog";

// Choix de profil d'un scan (nouveau scan, lot, surveillance) : profil, modules du profil
// « personnalisé » et déclaration d'autorisation.
export interface ScanOptions {
  profile: ScanProfile;
  selected: string[];
  authorized: boolean;
}

export const PROFILES: readonly ScanProfile[] = ["rapide", "complet", "personnalise"];

export const DEFAULT_OPTIONS: ScanOptions = { profile: "complet", selected: [], authorized: false };

// Modules passifs : la présélection du profil personnalisé (aucune sonde envoyée à la cible).
export function passiveModules(catalog: Catalog): string[] {
  return catalog.moduleNames.filter((name) => catalog.info(name)?.category === "passif");
}

// Un module actif ou sensible exige l'autorisation de tester la cible.
export function requiresAuthorization(catalog: Catalog, name: string): boolean {
  const info = catalog.info(name);
  return Boolean(info?.requires_authorization) || info?.category === "actif" || info?.category === "sensible";
}

export function needsAuthorization(catalog: Catalog, options: ScanOptions): boolean {
  return options.profile === "personnalise" && options.selected.some((name) => requiresAuthorization(catalog, name));
}

// Faux tant que le choix ne peut pas être envoyé : aucun module, ou autorisation manquante.
export function optionsValid(catalog: Catalog, options: ScanOptions): boolean {
  if (options.profile === "personnalise" && options.selected.length === 0) return false;
  return !needsAuthorization(catalog, options) || options.authorized;
}

// Corps du lancement : le profil « complet » est celui du serveur par défaut, et l'autorisation
// n'est transmise que si elle est utile.
export function optionsPayload(catalog: Catalog, options: ScanOptions) {
  const custom = options.profile === "personnalise";
  const authorized = needsAuthorization(catalog, options) && options.authorized;
  return {
    ...(options.profile === "complet" ? {} : { profile: options.profile }),
    ...(custom ? { selected: options.selected } : {}),
    ...(authorized ? { authorized_target: true } : {}),
  };
}

export function useScanOptions(initial: ScanOptions = DEFAULT_OPTIONS) {
  const catalog = useCatalog();
  const [options, setOptions] = useState<ScanOptions>(initial);
  return useMemo(
    () => ({
      catalog,
      options,
      setOptions,
      needsAuth: needsAuthorization(catalog, options),
      valid: optionsValid(catalog, options),
      payload: () => optionsPayload(catalog, options),
    }),
    [catalog, options],
  );
}
