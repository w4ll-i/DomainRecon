import { describe, expect, it } from "vitest";
import gradeBadgeCss from "../components/GradeBadge.module.css?raw";
import { GRADE_COLORS, TOKENS, gradeColor, gradeToken, hexToRgb } from "../lib/colors";
import mainSource from "../main.tsx?raw";
import fontsCss from "./fonts.css?raw";
import globalCss from "./global.css?raw";
import tokensCss from "./tokens.css?raw";

// Toutes les feuilles de style de l'application (jetons, globales, modules CSS).
const stylesheets = import.meta.glob("../**/*.css", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

type Rgb = [number, number, number];
type Tokens = Record<string, string>;
type Pair = [string, string];
// Couleur CSS avec transparence : rgb non prémultiplié et alpha de 0 à 1.
interface Rgba {
  rgb: Rgb;
  alpha: number;
}
interface MixPart {
  color: Rgba;
  share?: number;
}

const stripComments = (css: string) => css.replace(/\/\*[\s\S]*?\*\//g, "");

// Déclarations « --nom: valeur; » d'un corps de règle.
function declarations(body: string): Tokens {
  const found: Tokens = {};
  for (const match of body.matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) found[match[1]] = match[2].replace(/\s+/g, " ").trim();
  return found;
}

// Corps de la première règle (sans imbrication) dont le sélecteur est exactement `selector`.
function rule(css: string, selector: string): string {
  for (const match of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (match[1].trim() === selector) return match[2];
  }
  return "";
}

// Règles de tokens.css : sélecteur -> corps.
const blocks = new Map<string, string>();
for (const match of stripComments(tokensCss).matchAll(/([^{}]+)\{([^{}]*)\}/g)) blocks.set(match[1].trim(), match[2]);

const LIGHT_SELECTOR = ':root[data-theme="light"]';
const PREFERS_LIGHT_SELECTOR = ":root:not([data-theme])";
const darkTokens = declarations(blocks.get(":root") ?? "");
const lightOverrides = declarations(blocks.get(LIGHT_SELECTOR) ?? "");
// Le thème clair hérite de :root ce qu'il ne redéfinit pas (même élément, <html>).
const themes = { dark: darkTokens, light: { ...darkTokens, ...lightOverrides } } as const;

function splitTopLevel(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") depth--;
    else if (text[i] === "," && depth === 0) {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(text.slice(start));
  return parts.map((part) => part.trim());
}

// color-mix(in srgb, …) : interpolation prémultipliée (CSS Color 5). Sans part
// donnée, 50 % ; une seule part donnée, l'autre prend le complément ; une somme
// inférieure à 100 % rend le résultat d'autant plus transparent.
function mix(a: MixPart, b: MixPart): Rgba {
  const shareA = a.share ?? (b.share === undefined ? 50 : 100 - b.share);
  const shareB = b.share ?? 100 - shareA;
  const total = shareA + shareB;
  const [weightA, weightB] = [shareA / total, shareB / total];
  const alpha = a.color.alpha * weightA + b.color.alpha * weightB;
  const rgb = [0, 1, 2].map((i) =>
    alpha === 0 ? 0 : (a.color.rgb[i] * a.color.alpha * weightA + b.color.rgb[i] * b.color.alpha * weightB) / alpha,
  ) as Rgb;
  return { rgb, alpha: (alpha * Math.min(total, 100)) / 100 };
}

// Valeur d'un jeton : #rgb, #rrggbb, rgb(a)(), transparent, var(--x), color-mix(in srgb, …).
function evaluate(value: string, tokens: Tokens): Rgba {
  const v = value.trim();
  if (v === "transparent") return { rgb: [0, 0, 0], alpha: 0 };
  const hex = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hex) {
    const digits = hex[1].length === 3 ? [...hex[1]].map((digit) => digit + digit).join("") : hex[1];
    return { rgb: hexToRgb(`#${digits}`), alpha: 1 };
  }
  const reference = v.match(/^var\(\s*--([a-z0-9-]+)\s*\)$/);
  if (reference) {
    const target = tokens[reference[1]];
    if (target === undefined) throw new Error(`jeton inconnu : --${reference[1]}`);
    return evaluate(target, tokens);
  }
  const rgba = v.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)$/);
  if (rgba) {
    return { rgb: [Number(rgba[1]), Number(rgba[2]), Number(rgba[3])], alpha: rgba[4] === undefined ? 1 : Number(rgba[4]) };
  }
  const mixed = v.match(/^color-mix\(\s*in srgb\s*,([\s\S]+)\)$/);
  if (mixed) {
    const [first, second] = splitTopLevel(mixed[1]).map((part): MixPart => {
      const withShare = part.match(/^([\s\S]+?)\s+([\d.]+)%$/);
      return withShare
        ? { color: evaluate(withShare[1], tokens), share: Number(withShare[2]) }
        : { color: evaluate(part, tokens) };
    });
    return mix(first, second);
  }
  throw new Error(`couleur non gérée : ${value}`);
}

// Couleur posée sur un fond opaque.
function flatten({ rgb, alpha }: Rgba, base: Rgb = [0, 0, 0]): Rgb {
  return [0, 1, 2].map((i) => rgb[i] * alpha + base[i] * (1 - alpha)) as Rgb;
}

function toHex(rgb: Rgb): string {
  return `#${rgb.map((channel) => Math.round(channel).toString(16).padStart(2, "0")).join("")}`;
}

function luminance([r, g, b]: Rgb): number {
  const channel = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const STATES = ["success", "warning", "danger", "info"] as const;
const GRADES = ["grade-a", "grade-b", "grade-c", "grade-d", "grade-f"] as const;

describe("jetons de design", () => {
  it("tokens.css ne contient que le thème sombre (:root), le thème clair et le repli pré-JS", () => {
    expect([...blocks.keys()]).toEqual([":root", LIGHT_SELECTOR, PREFERS_LIGHT_SELECTOR]);
    expect(blocks.get(":root")).toMatch(/color-scheme:\s*dark/);
    expect(blocks.get(LIGHT_SELECTOR)).toMatch(/color-scheme:\s*light/);
    expect(blocks.get(PREFERS_LIGHT_SELECTOR)).toMatch(/color-scheme:\s*light/);
  });

  it("le repli pré-JS (prefers-color-scheme) peint clair et reste lisible", () => {
    // Évite le flash sombre avant que le JS ne pose data-theme : les jetons de
    // peinture repris doivent déjà donner un contraste AA en clair.
    const prejs = declarations(blocks.get(PREFERS_LIGHT_SELECTOR) ?? "");
    expect(prejs.bg).toBe("#ffffff");
    // Le repli reprend les mêmes fonds, bordures et textes que le thème clair complet.
    for (const [name, value] of Object.entries(prejs)) expect(lightOverrides[name], name).toBe(value);
    const pageBackgrounds = ["bg", "bg-deep", "surface", "surface-card", "surface-raised"];
    for (const fg of ["text", "text-secondary", "text-tertiary"]) {
      for (const bg of pageBackgrounds.filter((name) => fg !== "text-tertiary" || name !== "surface-raised")) {
        expect(contrast(hexToRgb(prejs[fg]), hexToRgb(prejs[bg])), `${fg} sur ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it("reprend les valeurs de la palette monochrome (thème sombre)", () => {
    expect(darkTokens).toMatchObject({
      bg: "#0a0a0a",
      surface: "#111111",
      "surface-raised": "#1a1a1a",
      border: "#262626",
      "border-strong": "#333333",
      text: "#ededed",
      "text-secondary": "#a1a1a1",
      // #737373 (3:1 seulement) reste le gris des icônes ; le texte tertiaire est plus clair (AA).
      "text-tertiary": "#808080",
      "text-dim": "#737373",
      primary: "#ededed",
      "on-primary": "#0a0a0a",
      accent: "#3b82f6",
      "accent-text": "#3b82f6",
    });
  });

  it("reprend les valeurs de la palette monochrome (thème clair)", () => {
    expect(themes.light).toMatchObject({
      bg: "#ffffff",
      surface: "#fafafa",
      "surface-raised": "#f4f4f5",
      border: "#eaeaea",
      "border-strong": "#d4d4d4",
      text: "#0a0a0a",
      "text-secondary": "#525252",
      "text-tertiary": "#737373",
      primary: "#0a0a0a",
      "on-primary": "#ffffff",
      accent: "#2563eb",
      "accent-text": "#2563eb",
    });
  });

  it("un seul accent bleu : aucun second accent, aucune couleur de famille", () => {
    expect(darkTokens).not.toHaveProperty("accent-2");
    expect(Object.keys(darkTokens).filter((name) => name.startsWith("family-"))).toEqual([]);
    // Les états sobres ne sont pas bleus : le bleu est réservé à l'accent.
    expect(darkTokens.info).toBe("#a1a1a1");
  });

  it("aucune couleur or : ni l'ancien or ni l'ancien ambre dans les jetons ni dans les feuilles de style", () => {
    const gold = /#e3c179|#efce8a|#b07d24|#c28a2b|#7f5a1a/i;
    const offenders = Object.entries(stylesheets)
      .filter(([, source]) => gold.test(stripComments(source)))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });

  it.each(STATES)("%s a un fond teinté de 10 % obtenu par color-mix", (state) => {
    expect(darkTokens[`${state}-bg`]).toBe(`color-mix(in srgb, var(--${state}) 10%, transparent)`);
  });

  it("surfaces plates : aucune ombre colorée ni dégradé, une ombre discrète pour les modales seulement", () => {
    expect(darkTokens["shadow-sm"]).toBe("none");
    expect(darkTokens).not.toHaveProperty("shadow-accent");
    expect(darkTokens).not.toHaveProperty("accent-grad-from");
    // Seul --shadow-md (modales, popovers, notifications) garde une ombre, très discrète.
    expect(darkTokens["shadow-md"]).toMatch(/rgba\(0, 0, 0, 0\.[0-3]\d?\)/);
  });

  it("le thème clair redéfinit chaque couleur littérale du thème sombre", () => {
    // Une couleur oubliée garderait sa valeur sombre en thème clair.
    const literal = Object.entries(darkTokens)
      .filter(([, value]) => /^#[0-9a-f]{3,8}$/i.test(value) || value.includes("rgba("))
      .map(([name]) => name);
    expect(literal.filter((name) => !(name in lightOverrides))).toEqual([]);
  });

  it("le thème clair redéfinit les jetons dont la valeur propre au thème change", () => {
    for (const name of ["accent-text", "on-accent", "primary", "on-primary", "shadow-md"]) {
      expect(lightOverrides, name).toHaveProperty(name);
    }
  });

  it("le thème clair ne définit que des jetons qui existent dans :root", () => {
    expect(Object.keys(lightOverrides).filter((name) => !(name in darkTokens))).toEqual([]);
  });

  it("toute variable utilisée par une feuille de style est définie quelque part", () => {
    const declared = new Set<string>();
    const used = new Set<string>();
    for (const css of Object.values(stylesheets).map(stripComments)) {
      for (const match of css.matchAll(/(--[a-z0-9-]+)\s*:/g)) declared.add(match[1]);
      for (const match of css.matchAll(/var\(\s*(--[a-z0-9-]+)/g)) used.add(match[1]);
    }
    expect(declared.size).toBeGreaterThan(50);
    expect([...used].filter((name) => !declared.has(name))).toEqual([]);
  });

  it("garde les anciens noms de la v1 comme alias des nouveaux", () => {
    const aliases: Pair[] = [
      ["text-muted", "text-secondary"],
      ["ok", "success"],
      ["critical", "danger"],
      ["ok-bg", "success-bg"],
      ["critical-bg", "danger-bg"],
      ["font-sans", "font-body"],
    ];
    for (const [old, current] of aliases) expect(darkTokens[old], old).toBe(`var(--${current})`);
    // Et les noms inchangés existent toujours.
    for (const name of ["warning-bg", "info-bg", "neutral-bg", "grade-na", "focus-ring", "radius", "radius-sm", "space-6"]) {
      expect(darkTokens, name).toHaveProperty(name);
    }
  });

  it("les constantes TypeScript (Chart.js, Cytoscape) suivent le thème sombre de tokens.css", () => {
    const hex = (name: string) => toHex(flatten(evaluate(`var(--${name})`, themes.dark)));
    expect(TOKENS).toEqual({
      bg: hex("bg"),
      surface: hex("surface"),
      surfaceRaised: hex("surface-raised"),
      border: hex("border"),
      borderStrong: hex("border-strong"),
      text: hex("text"),
      textMuted: hex("text-muted"),
      accent: hex("accent"),
    });
    expect(GRADE_COLORS).toEqual({
      A: hex("grade-a"),
      B: hex("grade-b"),
      C: hex("grade-c"),
      D: hex("grade-d"),
      F: hex("grade-f"),
      NA: hex("grade-na"),
    });
  });

  it("ramène toute note inconnue à N/A", () => {
    expect(gradeToken("A")).toBe("A");
    expect(gradeToken("N/A")).toBe("NA");
    expect(gradeToken("Z")).toBe("NA");
    expect(gradeToken(null)).toBe("NA");
    expect(gradeColor("F")).toBe("#ec5d5e");
    expect(hexToRgb("#3b82f6")).toEqual([59, 130, 246]);
  });
});

describe("évaluateur de couleurs des tests", () => {
  // Garde-fou : un évaluateur faux ferait passer tous les contrastes à vide.
  it("calcule contraste, mélange srgb, transparence et alias", () => {
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5);
    expect(contrast([255, 255, 255], [255, 255, 255])).toBeCloseTo(1, 5);
    const quarter = evaluate("color-mix(in srgb, #fff 25%, #000)", {});
    expect(quarter.alpha).toBe(1);
    for (const channel of quarter.rgb) expect(channel).toBeCloseTo(63.75, 5);
    // 10 % de rouge opaque sur du transparent, posé sur du noir puis sur du blanc.
    const tint = evaluate("color-mix(in srgb, #ff0000 10%, transparent)", {});
    expect(tint.alpha).toBeCloseTo(0.1, 5);
    expect(flatten(tint, [0, 0, 0])[0]).toBeCloseTo(25.5, 5);
    expect(flatten(tint, [255, 255, 255])).toEqual([expect.closeTo(255, 5), expect.closeTo(229.5, 5), expect.closeTo(229.5, 5)]);
    expect(evaluate("var(--a)", { a: "var(--b)", b: "#abc" }).rgb).toEqual([170, 187, 204]);
    expect(toHex(flatten(evaluate("var(--grade-b)", themes.dark)))).toBe("#8ba446");
    expect(() => evaluate("var(--absent)", {})).toThrow("jeton inconnu");
    expect(() => evaluate("hsl(0 0% 0%)", {})).toThrow("couleur non gérée");
  });
});

describe("polices", () => {
  const fontFaces = [...stripComments(fontsCss).matchAll(/@font-face\s*\{([^}]*)\}/g)].map((match) => match[1]);
  const families = (css: string) => [...css.matchAll(/font-family:\s*([^;]+);/g)].map((match) => match[1].trim());

  it("les jetons nomment Inter (texte) et JetBrains Mono (données), rien d'autre en tête de pile", () => {
    expect(darkTokens["font-display"]).toMatch(/^"Inter"/);
    expect(darkTokens["font-body"]).toMatch(/^"Inter"/);
    expect(darkTokens["font-display"]).toBe(darkTokens["font-body"]);
    expect(darkTokens["font-mono"]).toMatch(/^"JetBrains Mono"/);
  });

  it("fonts.css ne déclare que Inter et JetBrains Mono, en woff2, latin et latin étendu", () => {
    const declared = new Set(fontFaces.map((face) => /font-family:\s*"([^"]+)"/.exec(face)?.[1]));
    expect([...declared].sort()).toEqual(["Inter", "JetBrains Mono"]);
    for (const face of fontFaces) {
      expect(face).toMatch(/format\("woff2"\)/);
      expect(face).not.toMatch(/\.woff[^2]|\.ttf|\.otf|format\("woff"\)/);
      expect(face).toMatch(/-(latin|latin-ext)-\d{3}-normal\.woff2/);
    }
    // Poids utiles seulement : Inter 400/500/600, JetBrains Mono 400/500, en deux sous-ensembles.
    expect(fontFaces).toHaveLength((3 + 2) * 2);
    const weights = (family: string) => [
      ...new Set(fontFaces.filter((face) => face.includes(`"${family}"`)).map((face) => /font-weight:\s*(\d+)/.exec(face)?.[1])),
    ].sort();
    expect(weights("Inter")).toEqual(["400", "500", "600"]);
    expect(weights("JetBrains Mono")).toEqual(["400", "500"]);
  });

  it("aucune ancienne police ni aucune autre famille nommée dans les feuilles de style", () => {
    const named = new Set<string>();
    for (const css of Object.values(stylesheets).map(stripComments)) {
      for (const list of families(css)) for (const part of list.split(",")) named.add(part.trim().replace(/^["']|["']$/g, ""));
    }
    const allowed = new Set([
      "Inter",
      "JetBrains Mono",
      "system-ui",
      "-apple-system",
      "Segoe UI",
      "sans-serif",
      "ui-monospace",
      "SFMono-Regular",
      "Consolas",
      "monospace",
      "inherit",
    ]);
    expect([...named].filter((name) => !name.startsWith("var(") && !allowed.has(name))).toEqual([]);
    for (const old of ["Hanken Grotesk", "IBM Plex Mono", "Bricolage"]) {
      expect(tokensCss).not.toContain(old);
      expect(fontsCss).not.toContain(old);
    }
  });

  it("main.tsx charge fonts.css avant les jetons et les feuilles de style globales", () => {
    const order = ["./styles/fonts.css", "./styles/tokens.css", "./styles/global.css"].map((path) => mainSource.indexOf(`"${path}"`));
    expect(order.every((index) => index >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(mainSource).not.toMatch(/leaflet/i);
  });

  it("échelle typographique 12 / 13 / 14 / 16 / 20 / 24 / 32 / 48 px, sans autre taille", () => {
    const sizes = new Set<string>();
    for (const css of Object.values(stylesheets).map(stripComments)) {
      for (const match of css.matchAll(/font-size:\s*([^;]+);/g)) sizes.add(match[1].trim());
    }
    const scale = new Set(["12px", "13px", "14px", "16px", "20px", "24px", "32px", "48px", "inherit"]);
    expect([...sizes].filter((size) => !scale.has(size) && !size.startsWith("var(--fs-"))).toEqual([]);
  });
});

describe.each(["dark", "light"] as const)("contrastes AA, thème %s", (theme) => {
  const tokens = themes[theme];
  const rgb = (name: string, base?: Rgb) => flatten(evaluate(`var(--${name})`, tokens), base);
  // Un fond teinté (translucide) se pose sur une surface ou sur le fond de page.
  const tinted = (tint: string, over: string) => rgb(tint, rgb(over));
  // Paires sous le seuil, en clair pour l'échec ; `!(value >= minimum)` retient aussi un NaN.
  const describePairs = (pairs: Pair[], minimum: number, over?: string) =>
    pairs
      .map(([fg, bg]) => ({
        label: over ? `${fg} sur ${bg} (posé sur ${over})` : `${fg} sur ${bg}`,
        value: contrast(rgb(fg), over ? tinted(bg, over) : rgb(bg)),
      }))
      .filter(({ value }) => !(value >= minimum))
      .map(({ label, value }) => `${label} : ${value.toFixed(2)}`);

  const pages = ["bg", "bg-deep", "surface", "surface-card", "surface-raised"];
  const cards = ["bg", "surface", "surface-card"];

  it("texte lisible : au moins 4,5:1 sur les fonds prévus", () => {
    const pairs: Pair[] = [
      ...["text", "text-secondary", "text-muted", "accent-text"].flatMap((fg) => pages.map((bg): Pair => [fg, bg])),
      // Le troisième niveau ne se pose ni sur --surface-raised ni sur un fond teinté.
      ...["bg", "bg-deep", "surface", "surface-card"].map((bg): Pair => ["text-tertiary", bg]),
      ...[...STATES, ...GRADES, "ok", "critical"].flatMap((fg) => cards.map((bg): Pair => [fg, bg])),
      // Texte posé sur un aplat : bouton principal inversé (survol compris), aplat de l'accent,
      // bouton et pastille « danger ».
      ...["primary", "primary-hover"].map((bg): Pair => ["on-primary", bg]),
      ...["accent", "accent-hover"].map((bg): Pair => ["on-accent", bg]),
      ...["danger", "success", "warning"].map((bg): Pair => ["bg", bg]),
    ];
    expect(describePairs(pairs, 4.5)).toEqual([]);
  });

  it("éléments graphiques et grand texte : au moins 3:1", () => {
    // Aplats, bordures, icônes, note N/A : jamais du texte courant.
    const pairs = ["accent", "text-dim", "grade-na"].flatMap((fg): Pair[] => [
      [fg, "bg"],
      [fg, "surface"],
    ]);
    expect(describePairs(pairs, 3)).toEqual([]);
  });

  it("pastille lisible : chaque état sur son fond teinté, posé sur la surface ou le fond de page", () => {
    const pairs: Pair[] = [
      ...[...STATES, "ok", "critical"].map((state): Pair => [state, `${state}-bg`]),
      ["accent-text", "accent-bg"],
      ["text", "neutral-bg"],
    ];
    expect(["surface", "bg"].flatMap((over) => describePairs(pairs, 4.5, over))).toEqual([]);
  });

  it("texte secondaire lisible sur les fonds teintés des états", () => {
    // Avec les jetons de la v1, il fallait l'éviter sur un fond teinté ; ce n'est plus le cas.
    const pairs = STATES.map((state): Pair => ["text-secondary", `${state}-bg`]);
    expect(["surface", "bg"].flatMap((over) => describePairs(pairs, 4.5, over))).toEqual([]);
  });

  // Pastille de note (GradeBadge) : « --grade-bg: color-mix(in srgb, var(--grade-color) N%,
  // var(--jeton)) ». Le fond est opaque (la couleur de la note dans un jeton de surface) : le
  // contraste ne dépend donc pas du fond derrière la pastille (ligne survolée, carte, page).
  it("note lisible sur la teinte de sa pastille (GradeBadge)", () => {
    const tint = /--grade-bg:\s*color-mix\(\s*in srgb\s*,\s*var\(--grade-color\)\s+([\d.]+)%\s*,\s*var\(--([a-z-]+)\)\s*\)/.exec(
      stripComments(gradeBadgeCss),
    );
    expect(tint, "--grade-bg de GradeBadge.module.css").not.toBeNull();
    const [, share, surface] = tint as RegExpExecArray;
    const background = (hue: string) =>
      flatten(evaluate(`color-mix(in srgb, var(--${hue}) ${share}%, var(--${surface}))`, tokens));
    // Les cinq notes (texte de la note) et « N/A » (texte secondaire sur la teinte du gris N/A).
    const pairs: Pair[] = [...GRADES.map((grade): Pair => [grade, grade]), ["text-secondary", "grade-na"]];
    const failures = pairs
      .map(([fg, hue]) => ({ label: `${fg} sur la teinte de ${hue}`, value: contrast(rgb(fg), background(hue)) }))
      .filter(({ value }) => !(value >= 4.5))
      .map(({ label, value }) => `${label} : ${value.toFixed(2)}`);
    expect(failures).toEqual([]);
  });

  // Bandeau du résultat (modules en échec) : fond teinté sur la surface, puis
  // pastille neutre par-dessus (ResultHeader).
  it.each(["warning-bg", "danger-bg"])("pastille neutre (modules en échec) lisible sur le bandeau %s", (banner) => {
    const base = tinted(banner, "surface");
    expect(contrast(rgb("text"), flatten(evaluate("var(--neutral-bg)", tokens), base))).toBeGreaterThanOrEqual(4.5);
  });

  it("les alias de la v1 donnent la même couleur que les noms canoniques", () => {
    const aliases: Pair[] = [
      ["text-muted", "text-secondary"],
      ["ok", "success"],
      ["critical", "danger"],
      ["ok-bg", "success-bg"],
      ["critical-bg", "danger-bg"],
    ];
    for (const [old, current] of aliases) {
      expect(evaluate(`var(--${old})`, tokens), old).toEqual(evaluate(`var(--${current})`, tokens));
    }
  });

  it("les cinq notes ont chacune leur couleur", () => {
    expect(new Set(GRADES.map((name) => toHex(rgb(name)))).size).toBe(GRADES.length);
  });

});

describe("feuilles de style globales", () => {
  const css = stripComments(globalCss);

  it("le fond est uni : aucun halo radial, aucune grille, aucun masque", () => {
    expect(rule(css, "body")).toMatch(/background:\s*var\(--bg\)/);
    expect(css).not.toMatch(/radial-gradient|mask-image|body::before|body::after/);
    expect(stripComments(tokensCss)).not.toMatch(/radial-gradient|mask-image/);
  });

  it("l'en-tête collant est plat : fond plein, filet, aucun flou", () => {
    const header = rule(css, ".app-header");
    expect(header).toMatch(/position:\s*sticky/);
    expect(header).toMatch(/background:\s*var\(--bg\)/);
    expect(header).not.toMatch(/blur|backdrop-filter/);
  });

  it("aucun flou ni verre dans les feuilles de style de l'application", () => {
    const offenders = Object.entries(stylesheets)
      .filter(([, source]) => /backdrop-filter|filter:\s*blur|blur\(/.test(stripComments(source)))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });

  it("aucune étiquette en majuscules espacées : ni text-transform, ni letter-spacing, ni jetons de tracking", () => {
    const offenders = Object.entries(stylesheets)
      .filter(([, source]) => /text-transform:\s*uppercase|letter-spacing/.test(stripComments(source)))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
    expect(Object.keys(darkTokens).filter((name) => name.startsWith("tracking"))).toEqual([]);
  });

  it("le bouton principal est inversé : aplat --primary (blanc sur noir, noir sur blanc), sans dégradé ni ombre", () => {
    const primary = rule(css, '.btn[data-variant="primary"]');
    expect(primary).toMatch(/background:\s*var\(--primary\);/);
    expect(primary).toMatch(/color:\s*var\(--on-primary\)/);
    expect(primary).not.toMatch(/gradient|box-shadow/);
    const hover = rule(css, '.btn[data-variant="primary"]:hover:not(:disabled)');
    expect(hover).toMatch(/background:\s*var\(--primary-hover\)/);
    expect(hover).not.toMatch(/gradient|box-shadow|transform/);
    expect(css).not.toMatch(/linear-gradient|--shadow-accent|--accent-grad/);
    // Inversion réelle : clair sur sombre dans un thème, sombre sur clair dans l'autre.
    expect(luminance(hexToRgb(themes.dark.primary))).toBeGreaterThan(luminance(hexToRgb(themes.dark.bg)));
    expect(luminance(hexToRgb(themes.light.primary))).toBeLessThan(luminance(hexToRgb(themes.light.bg)));
  });

  it("aucune animation d'entrée : ni fondu, ni cascade, ni compteur animé ; seuls le spinner et la progression bougent", () => {
    expect(css).not.toMatch(/fadeIn|enter-hero|enter-fade|enter-card|animation-delay|translateY|\.stagger|\.i-\d+/);
    const animations = Object.values(stylesheets)
      .flatMap((source) => [...stripComments(source).matchAll(/@keyframes\s+([\w-]+)/g)])
      .map((match) => match[1]);
    expect(animations).toEqual(["spin"]);
  });

  it("mouvement de 150 ms au plus (hors spinner)", () => {
    expect(darkTokens["dur-base"]).toBe("150ms");
    expect(darkTokens).not.toHaveProperty("dur-slow");
    const long = Object.entries(stylesheets).flatMap(([file, source]) =>
      [...stripComments(source).matchAll(/transition[^;{}]*?\b(\d+(?:\.\d+)?)(ms|s)\b/g)]
        .map((match) => (match[2] === "s" ? Number(match[1]) * 1000 : Number(match[1])))
        .filter((ms) => ms > 150)
        .map((ms) => `${file} : ${ms} ms`),
    );
    expect(long).toEqual([]);
  });

  it("le mouvement réduit désactive toute animation et toute transition", () => {
    const reduced = css.slice(css.indexOf("@media (prefers-reduced-motion: reduce)"));
    expect(reduced).toMatch(/animation:\s*none\s*!important/);
    expect(reduced).toMatch(/transition:\s*none\s*!important/);
  });

  it("aucune feuille de style de l'application ne charge de ressource externe ni de data: (CSP stricte)", () => {
    const external = /url\(\s*["']?(?:https?:)?\/\/|@import\s+(?:url\()?\s*["']?(?:https?:)?\/\/|url\(\s*["']?data:/i;
    const offenders = Object.entries(stylesheets)
      .filter(([, source]) => external.test(stripComments(source)))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });
});
