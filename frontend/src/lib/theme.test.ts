import { describe, expect, it, vi } from "vitest";
import { appliedTheme, initTheme, resolveTheme, setTheme, storedTheme, systemTheme, toggleTheme } from "./theme";

// Simule matchMedia : `light` dit si le système préfère le clair ; `change` rejoue un changement.
function stubSystemTheme(light: boolean) {
  let current = light;
  const listeners = new Set<() => void>();
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => ({
      get matches() {
        return current;
      },
      addEventListener: (_type: string, listener: () => void) => listeners.add(listener),
      removeEventListener: (_type: string, listener: () => void) => listeners.delete(listener),
    })),
  );
  return {
    change(next: boolean) {
      current = next;
      listeners.forEach((listener) => listener());
    },
    listeners,
  };
}

describe("thème de l'interface", () => {
  it("sombre par défaut : ni choix mémorisé, ni préférence du système, ni matchMedia", () => {
    expect(storedTheme()).toBeNull();
    expect(systemTheme()).toBe("dark");
    expect(resolveTheme()).toBe("dark");
    expect(appliedTheme()).toBe("dark");
  });

  it("suit la préférence du système au premier lancement", () => {
    stubSystemTheme(true);
    expect(systemTheme()).toBe("light");
    expect(resolveTheme()).toBe("light");
  });

  it("le choix mémorisé l'emporte sur la préférence du système", () => {
    stubSystemTheme(true);
    window.localStorage.setItem("domainrecon.theme", "dark");
    expect(resolveTheme()).toBe("dark");
    window.localStorage.setItem("domainrecon.theme", "light");
    stubSystemTheme(false);
    expect(resolveTheme()).toBe("light");
  });

  it("ignore une valeur mémorisée corrompue", () => {
    window.localStorage.setItem("domainrecon.theme", "bleu");
    expect(storedTheme()).toBeNull();
    expect(resolveTheme()).toBe("dark");
  });

  it("setTheme pose data-theme sur <html> et mémorise le choix", () => {
    setTheme("light");
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(window.localStorage.getItem("domainrecon.theme")).toBe("light");
    expect(appliedTheme()).toBe("light");
    setTheme("dark");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(appliedTheme()).toBe("dark");
  });

  it("toggleTheme alterne clair et sombre", () => {
    toggleTheme();
    expect(appliedTheme()).toBe("light");
    toggleTheme();
    expect(appliedTheme()).toBe("dark");
    expect(window.localStorage.getItem("domainrecon.theme")).toBe("dark");
  });

  it("la bascule marche sans stockage : le thème vit alors le temps de la session", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("bloqué");
    });
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("bloqué");
    });
    expect(() => setTheme("light")).not.toThrow();
    expect(appliedTheme()).toBe("light");
    expect(storedTheme()).toBeNull();
  });

  it("initTheme applique le thème résolu au démarrage", () => {
    window.localStorage.setItem("domainrecon.theme", "light");
    const stop = initTheme();
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    stop();
  });

  it("initTheme suit le système tant que l'utilisateur n'a rien choisi, puis cesse", () => {
    const system = stubSystemTheme(false);
    const stop = initTheme();
    expect(appliedTheme()).toBe("dark");
    system.change(true);
    expect(appliedTheme()).toBe("light");
    // Un choix explicite prime sur les changements du système.
    setTheme("dark");
    system.change(true);
    expect(appliedTheme()).toBe("dark");
    stop();
    expect(system.listeners.size).toBe(0);
  });

  it("initTheme sans matchMedia : thème sombre, rien à suivre", () => {
    const stop = initTheme();
    expect(appliedTheme()).toBe("dark");
    expect(() => stop()).not.toThrow();
  });
});
