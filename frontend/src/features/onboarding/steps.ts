// Étapes de la visite guidée. Chaque étape vise un élément réel de l'interface par son
// attribut data-tour (posé dans AppShell, NewScanPage, ProfilePicker et l'écran Résultat) ;
// une étape sans cible s'affiche au centre. `route` : écran à ouvrir avant de chercher
// l'élément. Les textes sont dans onboarding.steps.<clé> (title, text, point1…pointN).
export interface TourStep {
  key: string;
  target: string | null;
  route?: string;
  points?: number;
}

const tour = (name: string) => `[data-tour="${name}"]`;

const BASE_STEPS: readonly TourStep[] = [
  { key: "palette", target: tour("palette"), route: "/" },
  { key: "domain", target: tour("domain"), route: "/" },
  { key: "profiles", target: tour("profiles"), route: "/", points: 3 },
  { key: "nav", target: tour("nav"), points: 5 },
  { key: "settings", target: tour("nav-settings"), points: 3 },
  { key: "help", target: tour("nav-help") },
];

// Avec un scan enregistré, la visite ouvre son résultat et en montre les parties ; sans scan,
// une étape centrée explique l'écran de résultat sans quitter l'écran courant.
export function buildSteps(scanId: number | null): TourStep[] {
  if (scanId === null) return [...BASE_STEPS, { key: "resultIntro", target: null, points: 4 }];
  const route = `/scans/${scanId}`;
  return [
    ...BASE_STEPS,
    { key: "resultScore", target: tour("result-score"), route },
    { key: "resultFinding", target: tour("result-finding"), route },
    { key: "resultFamily", target: tour("result-family"), route },
    { key: "resultExport", target: tour("result-export"), route },
  ];
}

// Élément visé présent et affiché ; absent ou masqué (attribut hidden, display: none),
// l'étape est sautée.
export function findTarget(selector: string, root: ParentNode = document): HTMLElement | null {
  const element = root.querySelector<HTMLElement>(selector);
  if (!element || !element.isConnected || element.closest("[hidden]")) return null;
  if (typeof element.checkVisibility === "function" && !element.checkVisibility()) return null;
  return element;
}
