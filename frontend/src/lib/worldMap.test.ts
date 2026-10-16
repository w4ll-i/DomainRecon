import { describe, expect, it } from "vitest";
import { MAP_HEIGHT, MAP_WIDTH, projectPoint, worldLandPath, worldOutlinePath } from "./worldMap";

describe("carte du monde embarquée", () => {
  it("trace les terres (Natural Earth 1:110m) et le contour, sans rien charger", () => {
    const land = worldLandPath();
    expect(land.startsWith("M")).toBe(true);
    expect(land.length).toBeGreaterThan(5000);
    // Calculé une seule fois.
    expect(worldLandPath()).toBe(land);
    expect(worldOutlinePath().startsWith("M")).toBe(true);
    // Ni lien ni donnée externe dans le tracé.
    expect(land).not.toMatch(/[a-df-z]{3,}|http/i);
  });

  it("projette un point dans le cadre de la carte", () => {
    for (const [lat, lon] of [
      [48.85, 2.35],
      [-33.9, 151.2],
      [64, -150],
      [0, 0],
    ]) {
      const point = projectPoint(lat, lon);
      expect(point).not.toBeNull();
      const [x, y] = point as [number, number];
      expect(x).toBeGreaterThan(0);
      expect(x).toBeLessThan(MAP_WIDTH);
      expect(y).toBeGreaterThan(0);
      expect(y).toBeLessThan(MAP_HEIGHT);
    }
  });

  it("le méridien d'origine et l'équateur tombent au centre de la carte", () => {
    const [x, y] = projectPoint(0, 0) as [number, number];
    expect(x).toBeCloseTo(MAP_WIDTH / 2, 0);
    expect(y).toBeCloseTo(MAP_HEIGHT / 2, 0);
  });

  it("refuse les coordonnées invalides", () => {
    expect(projectPoint(91, 0)).toBeNull();
    expect(projectPoint(0, 181)).toBeNull();
    expect(projectPoint(Number.NaN, 0)).toBeNull();
  });
});
