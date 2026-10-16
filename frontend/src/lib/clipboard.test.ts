import { afterEach, describe, expect, it, vi } from "vitest";
import { copyText } from "./clipboard";

function setClipboard(value: unknown) {
  Object.defineProperty(navigator, "clipboard", { value, configurable: true });
}

function setExecCommand(value: unknown) {
  Object.defineProperty(document, "execCommand", { value, configurable: true, writable: true });
}

afterEach(() => {
  Reflect.deleteProperty(navigator, "clipboard");
  Reflect.deleteProperty(document, "execCommand");
});

describe("copie dans le presse-papiers", () => {
  it("utilise l'API du navigateur quand elle existe", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    setClipboard({ writeText });
    await expect(copyText("add_header X-Frame-Options DENY;")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("add_header X-Frame-Options DENY;");
  });

  it("autorisation refusée : repli sur la copie par sélection, champ temporaire retiré", async () => {
    setClipboard({ writeText: vi.fn().mockRejectedValue(new Error("refusé")) });
    const execCommand = vi.fn(() => {
      // Le texte est dans un champ de saisie sélectionné au moment de la copie.
      const field = document.querySelector("textarea");
      expect(field?.value).toBe("code à copier");
      return true;
    });
    setExecCommand(execCommand);
    await expect(copyText("code à copier")).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(document.querySelector("textarea")).toBeNull();
  });

  it("sans API du navigateur : copie par sélection", async () => {
    setClipboard(undefined);
    setExecCommand(vi.fn(() => true));
    await expect(copyText("x")).resolves.toBe(true);
  });

  it("le focus revient à l'élément qui l'avait", async () => {
    setClipboard(undefined);
    setExecCommand(vi.fn(() => true));
    const button = document.createElement("button");
    document.body.appendChild(button);
    button.focus();
    await copyText("x");
    expect(document.activeElement).toBe(button);
    button.remove();
  });

  it("aucun moyen de copier, ou copie refusée : faux", async () => {
    setClipboard(undefined);
    await expect(copyText("x")).resolves.toBe(false);
    setExecCommand(vi.fn(() => false));
    await expect(copyText("x")).resolves.toBe(false);
    setExecCommand(
      vi.fn(() => {
        throw new Error("interdit");
      }),
    );
    await expect(copyText("x")).resolves.toBe(false);
    expect(document.querySelector("textarea")).toBeNull();
  });
});
