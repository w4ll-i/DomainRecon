import { useSyncExternalStore } from "react";
import { readLocal, STORAGE_KEYS, writeLocal } from "./storage";

// Thème de l'interface : sombre (défaut de tokens.css) ou clair (data-theme="light"
// sur <html>). Le choix de l'utilisateur est mémorisé (localStorage) ; sans choix,
// la préférence du système (prefers-color-scheme) s'applique au premier lancement.
// Sans stockage (navigation privée), le thème appliqué au document suffit pour la
// session : la bascule fonctionne, elle ne survit simplement pas au rechargement.
export type Theme = "dark" | "light";

const listeners = new Set<() => void>();

// Choix mémorisé ; toute autre valeur (corrompue, ancienne) vaut « aucun choix ».
export function storedTheme(): Theme | null {
  const value = readLocal(STORAGE_KEYS.theme);
  return value === "dark" || value === "light" ? value : null;
}

const LIGHT_QUERY = "(prefers-color-scheme: light)";

// Préférence du système ; sombre sans matchMedia (jsdom, très vieux navigateurs).
export function systemTheme(): Theme {
  try {
    return typeof globalThis.matchMedia === "function" && globalThis.matchMedia(LIGHT_QUERY).matches ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export const resolveTheme = (): Theme => storedTheme() ?? systemTheme();

// Thème actuellement posé sur le document.
export function appliedTheme(): Theme {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

function apply(theme: Theme): void {
  if (appliedTheme() === theme && document.documentElement.hasAttribute("data-theme")) return;
  document.documentElement.setAttribute("data-theme", theme);
  listeners.forEach((listener) => listener());
}

// Choix explicite : posé sur le document et mémorisé.
export function setTheme(theme: Theme): void {
  writeLocal(STORAGE_KEYS.theme, theme);
  apply(theme);
}

export const toggleTheme = (): void => setTheme(appliedTheme() === "light" ? "dark" : "light");

// Au démarrage : applique le thème, puis suit le système tant que l'utilisateur
// n'a rien choisi. Renvoie la fonction qui arrête ce suivi.
export function initTheme(): () => void {
  apply(resolveTheme());
  if (typeof globalThis.matchMedia !== "function") return () => {};
  let query: MediaQueryList;
  try {
    query = globalThis.matchMedia(LIGHT_QUERY);
  } catch {
    return () => {};
  }
  const onChange = () => {
    if (storedTheme() === null) apply(systemTheme());
  };
  query.addEventListener?.("change", onChange);
  return () => query.removeEventListener?.("change", onChange);
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// Thème courant (nouveau rendu à chaque bascule) et la bascule elle-même.
export function useTheme(): { theme: Theme; toggle: () => void } {
  const theme = useSyncExternalStore(subscribe, appliedTheme, () => "dark" as const);
  return { theme, toggle: toggleTheme };
}
