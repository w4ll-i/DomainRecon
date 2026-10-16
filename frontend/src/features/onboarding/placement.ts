// Calculs de position de la visite guidée : découpe autour de l'élément visé et bulle
// d'explication qui ne sort jamais de l'écran. Fonctions pures, testées sans navigateur.

export interface Box {
  top: number;
  left: number;
  width: number;
  height: number;
}

export interface Size {
  width: number;
  height: number;
}

// Côté de l'élément où se place la bulle ; « center » : pas d'élément visé (ou aucune place
// autour), la bulle est centrée et n'a pas de flèche.
export type Side = "bottom" | "top" | "right" | "left" | "center";

export interface Placement {
  side: Side;
  top: number;
  left: number;
  // Position de la flèche le long du bord de la bulle tourné vers l'élément (en px).
  arrow: number;
}

// Marge entre la bulle et le bord de l'écran, écart entre la bulle et l'élément, marge de
// la découpe autour de l'élément, distance minimale entre la flèche et un coin de la bulle.
export const SCREEN_MARGIN = 12;
export const GAP = 14;
export const CUT_PADDING = 6;
const ARROW_INSET = 18;

const clamp = (value: number, min: number, max: number) => Math.min(Math.max(value, min), Math.max(min, max));

// Découpe : l'élément agrandi de CUT_PADDING, ramené dans l'écran (un élément plus grand
// que la fenêtre ne crée pas de découpe hors champ).
export function cutout(target: Box, viewport: Size, padding = CUT_PADDING): Box {
  const left = Math.max(0, target.left - padding);
  const top = Math.max(0, target.top - padding);
  const right = Math.min(viewport.width, target.left + target.width + padding);
  const bottom = Math.min(viewport.height, target.top + target.height + padding);
  return { top, left, width: Math.max(0, right - left), height: Math.max(0, bottom - top) };
}

// Bulle centrée dans l'écran (accueil sans élément, ou repli).
export function centered(bubble: Size, viewport: Size): Placement {
  return {
    side: "center",
    top: clamp((viewport.height - bubble.height) / 2, SCREEN_MARGIN, viewport.height - bubble.height - SCREEN_MARGIN),
    left: clamp((viewport.width - bubble.width) / 2, SCREEN_MARGIN, viewport.width - bubble.width - SCREEN_MARGIN),
    arrow: 0,
  };
}

// Place la bulle à côté de l'élément : dessous, dessus, à droite puis à gauche, le premier
// côté où elle tient entière. Sans place nulle part (petit écran, élément immense), elle se
// cale contre le bord le plus dégagé, ramenée dans l'écran.
export function computePlacement(target: Box | null, bubble: Size, viewport: Size): Placement {
  if (!target) return centered(bubble, viewport);
  const cut = cutout(target, viewport);
  const space = {
    bottom: viewport.height - (cut.top + cut.height) - GAP - SCREEN_MARGIN,
    top: cut.top - GAP - SCREEN_MARGIN,
    right: viewport.width - (cut.left + cut.width) - GAP - SCREEN_MARGIN,
    left: cut.left - GAP - SCREEN_MARGIN,
  };
  const fits = {
    bottom: space.bottom >= bubble.height,
    top: space.top >= bubble.height,
    right: space.right >= bubble.width,
    left: space.left >= bubble.width,
  };
  const order = ["bottom", "top", "right", "left"] as const;
  const side = order.find((candidate) => fits[candidate]);
  if (!side) {
    // Aucun côté ne suffit (élément plus haut que l'écran d'un téléphone) : la bulle se cale contre
    // le bord haut ou bas le plus dégagé, sans flèche ; elle couvre alors une partie de l'élément,
    // jamais l'écran au-delà de ses bords.
    const fallback = centered(bubble, viewport);
    const pinTop = space.top > space.bottom;
    return {
      ...fallback,
      top: pinTop ? SCREEN_MARGIN : Math.max(SCREEN_MARGIN, viewport.height - bubble.height - SCREEN_MARGIN),
    };
  }
  const centerX = cut.left + cut.width / 2;
  const centerY = cut.top + cut.height / 2;
  const maxLeft = viewport.width - bubble.width - SCREEN_MARGIN;
  const maxTop = viewport.height - bubble.height - SCREEN_MARGIN;
  if (side === "bottom" || side === "top") {
    const left = clamp(centerX - bubble.width / 2, SCREEN_MARGIN, maxLeft);
    const top = side === "bottom" ? cut.top + cut.height + GAP : cut.top - GAP - bubble.height;
    return { side, top, left, arrow: clamp(centerX - left, ARROW_INSET, bubble.width - ARROW_INSET) };
  }
  const top = clamp(centerY - bubble.height / 2, SCREEN_MARGIN, maxTop);
  const left = side === "right" ? cut.left + cut.width + GAP : cut.left - GAP - bubble.width;
  return { side, top, left, arrow: clamp(centerY - top, ARROW_INSET, bubble.height - ARROW_INSET) };
}
