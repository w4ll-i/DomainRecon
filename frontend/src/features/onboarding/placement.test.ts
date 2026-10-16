import { describe, expect, it } from "vitest";
import { computePlacement, cutout, GAP, SCREEN_MARGIN, type Box, type Size } from "./placement";
import { buildSteps } from "./steps";

const VIEW: Size = { width: 1280, height: 720 };
const BUBBLE: Size = { width: 360, height: 220 };

// La bulle tient entièrement dans l'écran, marges comprises.
function expectInside(placement: { top: number; left: number }, bubble: Size, view: Size) {
  expect(placement.left).toBeGreaterThanOrEqual(SCREEN_MARGIN);
  expect(placement.top).toBeGreaterThanOrEqual(SCREEN_MARGIN);
  expect(placement.left + bubble.width).toBeLessThanOrEqual(view.width - SCREEN_MARGIN);
  expect(placement.top + bubble.height).toBeLessThanOrEqual(view.height - SCREEN_MARGIN);
}

// La bulle ne recouvre pas la découpe de l'élément.
function expectNoOverlap(placement: { top: number; left: number }, bubble: Size, cut: Box) {
  const apart =
    placement.left + bubble.width <= cut.left ||
    placement.left >= cut.left + cut.width ||
    placement.top + bubble.height <= cut.top ||
    placement.top >= cut.top + cut.height;
  expect(apart).toBe(true);
}

describe("placement de la bulle", () => {
  it("sous l'élément quand il y a la place, flèche pointée sur son centre", () => {
    const target = { top: 10, left: 400, width: 300, height: 36 };
    const placement = computePlacement(target, BUBBLE, VIEW);
    expect(placement.side).toBe("bottom");
    expect(placement.top).toBe(cutout(target, VIEW).top + cutout(target, VIEW).height + GAP);
    expect(placement.left + placement.arrow).toBe(550);
    expectInside(placement, BUBBLE, VIEW);
    expectNoOverlap(placement, BUBBLE, cutout(target, VIEW));
  });

  it("au-dessus d'un élément en bas de l'écran", () => {
    const target = { top: 640, left: 500, width: 200, height: 40 };
    const placement = computePlacement(target, BUBBLE, VIEW);
    expect(placement.side).toBe("top");
    expectInside(placement, BUBBLE, VIEW);
    expectNoOverlap(placement, BUBBLE, cutout(target, VIEW));
  });

  it("à droite d'un menu latéral haut comme l'écran", () => {
    const target = { top: 60, left: 8, width: 210, height: 600 };
    const placement = computePlacement(target, BUBBLE, VIEW);
    expect(placement.side).toBe("right");
    expectInside(placement, BUBBLE, VIEW);
    expectNoOverlap(placement, BUBBLE, cutout(target, VIEW));
    expect(placement.arrow).toBeGreaterThanOrEqual(18);
    expect(placement.arrow).toBeLessThanOrEqual(BUBBLE.height - 18);
  });

  it("à gauche d'un élément collé au bord droit", () => {
    const target = { top: 100, left: 1000, width: 260, height: 520 };
    const placement = computePlacement(target, BUBBLE, VIEW);
    expect(placement.side).toBe("left");
    expectInside(placement, BUBBLE, VIEW);
    expectNoOverlap(placement, BUBBLE, cutout(target, VIEW));
  });

  it("ramenée dans l'écran près d'un coin, la flèche reste sur la bulle", () => {
    const target = { top: 8, left: 1220, width: 40, height: 32 };
    const placement = computePlacement(target, BUBBLE, VIEW);
    expect(placement.side).toBe("bottom");
    expectInside(placement, BUBBLE, VIEW);
    expect(placement.arrow).toBeLessThanOrEqual(BUBBLE.width - 18);
  });

  it("centrée sans élément ; calée contre le bord le plus dégagé quand aucun côté n'a la place", () => {
    expect(computePlacement(null, BUBBLE, VIEW)).toEqual({ side: "center", top: 250, left: 460, arrow: 0 });
    const phone = { width: 375, height: 667 };
    const bubble = { width: 351, height: 300 };
    const placement = computePlacement({ top: 150, left: 12, width: 351, height: 400 }, bubble, phone);
    expect(placement.side).toBe("center");
    expect(placement.top).toBe(SCREEN_MARGIN);
    expectInside(placement, bubble, phone);
    const low = computePlacement({ top: 40, left: 12, width: 351, height: 420 }, bubble, phone);
    expect(low.top).toBe(phone.height - bubble.height - SCREEN_MARGIN);
    expectInside(low, bubble, phone);
  });

  it("téléphone : sous le champ domaine, sans sortir de l'écran", () => {
    const phone = { width: 375, height: 667 };
    const bubble = { width: 351, height: 240 };
    const placement = computePlacement({ top: 220, left: 16, width: 343, height: 52 }, bubble, phone);
    expect(placement.side).toBe("bottom");
    expectInside(placement, bubble, phone);
  });

  it("la découpe reste dans l'écran", () => {
    expect(cutout({ top: -50, left: -10, width: 2000, height: 2000 }, VIEW)).toEqual({ top: 0, left: 0, width: 1280, height: 720 });
    expect(cutout({ top: 100, left: 100, width: 50, height: 20 }, VIEW)).toEqual({ top: 94, left: 94, width: 62, height: 32 });
  });
});

describe("étapes", () => {
  it("sans scan : une étape centrée explique le résultat ; avec un scan : quatre étapes sur son écran", () => {
    const without = buildSteps(null);
    expect(without.map((step) => step.key)).toEqual(["palette", "domain", "profiles", "nav", "settings", "help", "resultIntro"]);
    expect(without.at(-1)).toMatchObject({ target: null });
    expect(without.at(-1)?.route).toBeUndefined();
    const withScan = buildSteps(7);
    expect(withScan.slice(6).map((step) => [step.key, step.route])).toEqual([
      ["resultScore", "/scans/7"],
      ["resultFinding", "/scans/7"],
      ["resultFamily", "/scans/7"],
      ["resultExport", "/scans/7"],
    ]);
  });
});
