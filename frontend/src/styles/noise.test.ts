import { describe, expect, it } from "vitest";
import packageJson from "../../package.json";

// Code de l'application (hors tests) : les composants et les modules.
const sources = import.meta.glob(["../**/*.ts", "../**/*.tsx", "!../**/*.test.ts", "!../**/*.test.tsx"], {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const offenders = (pattern: RegExp) =>
  Object.entries(sources)
    .filter(([, code]) => pattern.test(code))
    .map(([file]) => file);

describe("retrait du bruit visuel", () => {
  it("aucune classe d'animation d'entrée ni de cascade dans le code", () => {
    expect(offenders(/enter-(hero|fade|card)|\bstagger\b|\bi-\d+\b/)).toEqual([]);
  });

  it("ni compteur qui défile, ni radar des familles, ni animation pilotée par script", () => {
    expect(offenders(/CountUp|FamilyRadar|useEntered|canAnimate|requestAnimationFrame/)).toEqual([]);
  });

  it("aucune ressource cartographique externe : plus de Leaflet ni de tuiles CARTO", () => {
    expect(offenders(/leaflet|basemaps\.cartocdn|openstreetmap\.org\/(?!copyright)/i)).toEqual([]);
    const dependencies = Object.keys({ ...packageJson.dependencies, ...packageJson.devDependencies });
    expect(dependencies.filter((name) => /leaflet/i.test(name))).toEqual([]);
    expect(dependencies).toEqual(expect.arrayContaining(["world-atlas", "d3-geo", "topojson-client"]));
  });

  it("seules Inter et JetBrains Mono sont installées comme polices", () => {
    const fonts = Object.keys(packageJson.dependencies).filter((name) => name.startsWith("@fontsource"));
    expect(fonts.sort()).toEqual(["@fontsource/inter", "@fontsource/jetbrains-mono"]);
  });
});
