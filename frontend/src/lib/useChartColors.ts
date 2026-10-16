import { useSyncExternalStore } from "react";
import { GRADE_COLORS, type GradeToken, TOKENS } from "./colors";

// Couleurs et police du thème courant pour ce qui se dessine hors CSS (canvas de
// Chart.js). Elles sont lues sur les jetons de tokens.css : le thème clair, posé
// par data-theme sur <html>, redéfinit les siennes, et le graphique suit la bascule.
export interface ChartColors {
  accent: string;
  text: string;
  textSecondary: string;
  border: string;
  borderStrong: string;
  surface: string;
  fontMono: string;
  // Couleur de chaque note (A à F, N/A) dans le thème courant, en #rrggbb.
  grades: Record<GradeToken, string>;
}

// Repli (thème sombre) : tests, ou feuille de style pas encore appliquée.
const FALLBACK: ChartColors = {
  accent: TOKENS.accent,
  text: TOKENS.text,
  textSecondary: TOKENS.textMuted,
  border: TOKENS.border,
  borderStrong: TOKENS.borderStrong,
  surface: TOKENS.surface,
  fontMono: '"JetBrains Mono", monospace',
  grades: { ...GRADE_COLORS },
};

type TokenKey = Exclude<keyof ChartColors, "grades">;

const TOKEN_NAMES: Record<TokenKey, string> = {
  accent: "--accent",
  text: "--text",
  textSecondary: "--text-secondary",
  border: "--border",
  borderStrong: "--border-strong",
  surface: "--surface",
  fontMono: "--font-mono",
};

const GRADE_TOKEN_NAMES: Record<GradeToken, string> = {
  A: "--grade-a",
  B: "--grade-b",
  C: "--grade-c",
  D: "--grade-d",
  F: "--grade-f",
  NA: "--grade-na",
};

// Contexte d'un canvas d'un pixel, créé à la demande : le canvas sait lire toute la
// syntaxe CSS des couleurs, y compris color-mix() dont sont faites les notes B et D.
// Il n'est jamais touché quand les jetons sont déjà en #rrggbb. null : indisponible
// (jsdom sans canvas, navigateur trop ancien).
let probe: CanvasRenderingContext2D | null | undefined;

function probeContext(): CanvasRenderingContext2D | null {
  if (probe === undefined) {
    try {
      probe = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
    } catch {
      probe = null;
    }
  }
  return probe;
}

// Couleur de départ du canvas : une valeur refusée la laisse en place (voir toHex).
const SENTINEL = "#010203";

// Valeur d'un jeton de couleur en #rrggbb ; null si elle ne se lit pas (repli à l'appelant).
function toHex(value: string): string | null {
  const hex = value.match(/^#([0-9a-f]{6})$/i);
  if (hex) return `#${hex[1].toLowerCase()}`;
  if (!value) return null;
  const context = probeContext();
  if (!context) return null;
  context.fillStyle = SENTINEL;
  context.fillStyle = value;
  // Valeur refusée par le navigateur : la couleur de départ est restée.
  if (context.fillStyle === SENTINEL) return null;
  context.clearRect(0, 0, 1, 1);
  context.fillRect(0, 0, 1, 1);
  const [r, g, b] = context.getImageData(0, 0, 1, 1).data;
  return `#${[r, g, b].map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
}

function themeKey(): string {
  return document.documentElement.getAttribute("data-theme") ?? "";
}

// null tant que les jetons ne sont pas appliqués au document.
function readColors(): ChartColors | null {
  const style = getComputedStyle(document.documentElement);
  if (!style.getPropertyValue(TOKEN_NAMES.accent).trim()) return null;
  const colors: ChartColors = { ...FALLBACK, grades: { ...FALLBACK.grades } };
  for (const key of Object.keys(TOKEN_NAMES) as TokenKey[]) {
    colors[key] = style.getPropertyValue(TOKEN_NAMES[key]).trim() || FALLBACK[key];
  }
  for (const grade of Object.keys(GRADE_TOKEN_NAMES) as GradeToken[]) {
    colors.grades[grade] = toHex(style.getPropertyValue(GRADE_TOKEN_NAMES[grade]).trim()) ?? FALLBACK.grades[grade];
  }
  return colors;
}

// Un snapshot stable tant que le thème ne change pas (exigé par useSyncExternalStore).
let cached: { theme: string; colors: ChartColors } | null = null;

function getSnapshot(): ChartColors {
  const theme = themeKey();
  if (cached?.theme === theme) return cached.colors;
  const colors = readColors();
  if (!colors) return FALLBACK;
  cached = { theme, colors };
  return colors;
}

function subscribe(onChange: () => void): () => void {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  return () => observer.disconnect();
}

export function useChartColors(): ChartColors {
  return useSyncExternalStore(subscribe, getSnapshot, () => FALLBACK);
}

// Oublie les couleurs lues (tests : les jetons posés sur <html> changent d'un test à l'autre).
export function resetChartColors(): void {
  cached = null;
  probe = undefined;
}
