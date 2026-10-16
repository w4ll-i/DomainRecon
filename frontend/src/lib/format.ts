import type { GeoData, Lang } from "../api/types";

const LOCALES: Record<Lang, string> = { fr: "fr-FR", en: "en-GB" };

// Dates de l'API : ISO 8601 UTC (suffixe Z), affichées à l'heure locale.
export function formatDate(iso: string | null | undefined, lang: Lang): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  return new Intl.DateTimeFormat(LOCALES[lang], {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

// Nombre dans la langue de l'interface, avec au plus `decimals` décimales.
export function formatNumber(value: number, lang: Lang, decimals = 0): string {
  return new Intl.NumberFormat(LOCALES[lang], { maximumFractionDigits: decimals }).format(value);
}

export function formatDuration(seconds: number | null | undefined, lang: Lang): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  return `${new Intl.NumberFormat(LOCALES[lang], { maximumFractionDigits: 1 }).format(seconds)} s`;
}

// Longueur en caractères Unicode, comme len() côté API.
export function charCount(value: string): number {
  return [...value].length;
}

// Identifiant de scan lu dans l'URL (bornes de l'API : 1 à 2^31 - 1).
export function parseId(raw: string | undefined): number | null {
  if (!raw || !/^\d+$/.test(raw)) return null;
  const id = Number(raw);
  return id >= 1 && id <= 2147483647 ? id : null;
}

// Code pays ISO à deux lettres (country_code, ou country quand il porte le code).
export function countryCode(geo?: GeoData | null): string {
  const code = [geo?.country_code, geo?.country].find((c) => typeof c === "string" && /^[A-Za-z]{2}$/.test(c));
  return code ? code.toUpperCase() : "";
}

// Nom du pays dans la langue de l'interface (un drapeau emoji s'affiche en
// lettres sous Windows).
export function countryName(geo: GeoData | null | undefined, lang: Lang): string {
  const code = countryCode(geo);
  if (code) {
    try {
      return new Intl.DisplayNames([LOCALES[lang]], { type: "region" }).of(code) ?? code;
    } catch {
      return code;
    }
  }
  return typeof geo?.country === "string" ? geo.country : "";
}

// Taille de fichier dans la langue de l'interface (unités binaires : Kio/Mio/Gio, KiB/MiB/GiB).
export function formatBytes(bytes: number, lang: Lang): string {
  const units = lang === "fr" ? ["o", "Kio", "Mio", "Gio"] : ["B", "KiB", "MiB", "GiB"];
  let value = Math.max(0, bytes);
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${formatNumber(value, lang, index === 0 ? 0 : 1)} ${units[index]}`;
}
