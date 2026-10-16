// Miroir du thème sombre « Monochrome pro » de src/styles/tokens.css pour ce qui dessine
// hors CSS (Chart.js, Cytoscape, jsPDF, carte). Vérifié par src/styles/tokens.test.ts.
export const TOKENS = {
  bg: "#0a0a0a",
  surface: "#111111",
  surfaceRaised: "#1a1a1a",
  border: "#262626",
  borderStrong: "#333333",
  text: "#ededed",
  textMuted: "#a1a1a1",
  accent: "#3b82f6",
} as const;

export const GRADE_COLORS = {
  A: "#46a758",
  B: "#8ba446",
  C: "#e0a030",
  D: "#e67f47",
  F: "#ec5d5e",
  NA: "#737373",
} as const;

export type GradeToken = keyof typeof GRADE_COLORS;

const LETTERS: readonly string[] = ["A", "B", "C", "D", "F"];

// Suffixe d'une note pour les styles (jamais la valeur reçue telle quelle).
export function gradeToken(grade: string | null | undefined): GradeToken {
  return grade && LETTERS.includes(grade) ? (grade as GradeToken) : "NA";
}

export function gradeColor(grade: string | null | undefined): string {
  return GRADE_COLORS[gradeToken(grade)];
}

export function hexToRgb(hex: string): [number, number, number] {
  const value = hex.replace("#", "");
  return [0, 2, 4].map((i) => Number.parseInt(value.slice(i, i + 2), 16)) as [number, number, number];
}

// Couleur #rrggbb avec transparence (Chart.js ne lit pas color-mix) ; toute autre valeur est rendue telle quelle.
export function withAlpha(color: string, alpha: number): string {
  const hex = color.trim().match(/^#([0-9a-f]{6})$/i);
  if (!hex) return color;
  const [r, g, b] = hexToRgb(`#${hex[1]}`);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}
