import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GRADE_COLORS, TOKENS, withAlpha } from "./colors";
import { resetChartColors, useChartColors } from "./useChartColors";

const root = document.documentElement;

function setTokens(values: Record<string, string>) {
  for (const [name, value] of Object.entries(values)) root.style.setProperty(name, value);
}

beforeEach(() => {
  resetChartColors();
});

afterEach(() => {
  root.removeAttribute("style");
  root.removeAttribute("data-theme");
  resetChartColors();
});

describe("couleurs des graphiques", () => {
  it("replie sur le thème sombre quand les jetons ne sont pas appliqués", () => {
    const { result } = renderHook(() => useChartColors());
    expect(result.current).toMatchObject({
      accent: TOKENS.accent,
      text: TOKENS.text,
      textSecondary: TOKENS.textMuted,
      border: TOKENS.border,
      borderStrong: TOKENS.borderStrong,
      surface: TOKENS.surface,
    });
    expect(result.current.fontMono).toContain("JetBrains Mono");
  });

  it("lit les jetons du document et suit la bascule de thème", async () => {
    setTokens({ "--accent": "#e3c179", "--accent-2": "#5fd3e0", "--font-mono": '"JetBrains Mono", monospace' });
    const { result } = renderHook(() => useChartColors());
    expect(result.current.accent).toBe("#e3c179");

    // Le thème clair redéfinit les jetons et pose data-theme sur <html> : le hook se met à jour.
    await act(async () => {
      setTokens({ "--accent": "#b07d24", "--accent-2": "#1e93a4" });
      root.setAttribute("data-theme", "light");
      // Laisse passer le rappel (micro-tâche) du MutationObserver.
      await Promise.resolve();
    });
    expect(result.current.accent).toBe("#b07d24");
    // Un jeton absent garde le repli.
    expect(result.current.surface).toBe(TOKENS.surface);
  });

  it("garde le même objet tant que le thème ne change pas (pas de rendu inutile)", () => {
    setTokens({ "--accent": "#e3c179" });
    const { result, rerender } = renderHook(() => useChartColors());
    const first = result.current;
    rerender();
    expect(result.current).toBe(first);
  });

  it("replie sur les couleurs de notes du thème sombre quand les jetons ne sont pas appliqués", () => {
    const { result } = renderHook(() => useChartColors());
    expect(result.current.grades).toEqual(GRADE_COLORS);
  });

  it("lit les couleurs de notes des jetons, et suit la bascule de thème", async () => {
    setTokens({
      "--accent": "#3b82f6",
      "--grade-a": "#46a758",
      "--grade-b": "#8ba446",
      "--grade-c": "#e0a030",
      "--grade-d": "#e67f47",
      "--grade-f": "#ec5d5e",
      "--grade-na": "#737373",
    });
    const { result } = renderHook(() => useChartColors());
    expect(result.current.grades).toEqual(GRADE_COLORS);

    await act(async () => {
      setTokens({ "--accent": "#b07d24", "--grade-a": "#206d44", "--grade-f": "#B13035" });
      root.setAttribute("data-theme", "light");
      await Promise.resolve();
    });
    // Le thème clair assombrit les notes ; une valeur en majuscules est ramenée en minuscules.
    expect(result.current.grades.A).toBe("#206d44");
    expect(result.current.grades.F).toBe("#b13035");
    expect(result.current.grades.C).toBe("#e0a030");
  });

  // Faux canvas : `pixel` est le pixel que « peint » le navigateur ; null : couleur refusée
  // (la couleur de départ reste en place), sauf la sentinelle hexadécimale posée par le hook.
  function stubCanvas(pixel: [number, number, number] | null) {
    let fill = "";
    const context = {
      get fillStyle() {
        return fill;
      },
      set fillStyle(value: string) {
        if (pixel !== null || /^#[0-9a-f]{6}$/i.test(value)) fill = value;
      },
      clearRect: () => undefined,
      fillRect: () => undefined,
      getImageData: () => ({ data: [...(pixel ?? [0, 0, 0]), 255] }),
    };
    return vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(context as unknown as RenderingContext);
  }

  it("résout par un canvas les notes qui sont un color-mix() (B et D)", () => {
    const getContext = stubCanvas([149, 191, 111]);
    setTokens({
      "--accent": "#e3c179",
      "--grade-a": "#57c98a",
      "--grade-b": "color-mix(in srgb, #57c98a 55%, #e0b34d)",
    });
    const { result } = renderHook(() => useChartColors());
    expect(result.current.grades.B).toBe("#95bf6f");
    // Une note déjà en #rrggbb ne passe pas par le canvas ; une note absente garde le repli.
    expect(result.current.grades.A).toBe("#57c98a");
    expect(result.current.grades.D).toBe(GRADE_COLORS.D);
    expect(getContext).toHaveBeenCalledTimes(1);
  });

  it("replie sur la couleur du thème sombre quand le canvas refuse la valeur ou n'existe pas", () => {
    stubCanvas(null);
    setTokens({ "--accent": "#e3c179", "--grade-b": "color-mix(in srgb, #57c98a 55%, #e0b34d)" });
    const refused = renderHook(() => useChartColors());
    expect(refused.result.current.grades.B).toBe(GRADE_COLORS.B);
    refused.unmount();

    // Pas de contexte 2D (jsdom nu, navigateur ancien) : même repli, sans exception.
    resetChartColors();
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
    const missing = renderHook(() => useChartColors());
    expect(missing.result.current.grades.B).toBe(GRADE_COLORS.B);
  });

  it("applique une transparence à une couleur #rrggbb, et rend le reste tel quel", () => {
    expect(withAlpha("#e3c179", 0.16)).toBe("rgba(227, 193, 121, 0.16)");
    expect(withAlpha(" #B07D24 ", 0.5)).toBe("rgba(176, 125, 36, 0.5)");
    expect(withAlpha("rgb(1, 2, 3)", 0.5)).toBe("rgb(1, 2, 3)");
    expect(withAlpha("color-mix(in srgb, red 10%, transparent)", 0.5)).toBe("color-mix(in srgb, red 10%, transparent)");
  });
});
