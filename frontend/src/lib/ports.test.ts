import { describe, expect, it } from "vitest";
import { normalizeOpenPorts } from "./ports";

describe("normalizeOpenPorts", () => {
  it("garde les dictionnaires {port, state, service}", () => {
    expect(normalizeOpenPorts([{ port: 443, state: "open", service: "HTTPS" }])).toEqual([
      { port: 443, state: "open", service: "HTTPS" },
    ]);
  });

  it("accepte les entiers nus et les chaînes numériques des anciens scans", () => {
    expect(normalizeOpenPorts([80, "443", { port: "22" }])).toEqual([
      { port: 80 },
      { port: 443 },
      { port: 22, state: undefined, service: undefined },
    ]);
  });

  it("ignore les entrées inutilisables (null, hors bornes, sans port, types inattendus)", () => {
    expect(normalizeOpenPorts([null, undefined, {}, { port: 70000 }, { port: -1 }, 1.5, true, "abc", [80], { port: 22 }])).toEqual([
      { port: 22, state: undefined, service: undefined },
    ]);
  });

  it("une valeur qui n'est pas un tableau (null, objet, chaîne) donne une liste vide", () => {
    for (const value of [null, undefined, 443, "443", { port: 443 }]) expect(normalizeOpenPorts(value)).toEqual([]);
  });

  it("ne garde ni service ni état qui ne sont pas du texte", () => {
    expect(normalizeOpenPorts([{ port: 25, state: 1, service: { x: 1 } }])).toEqual([{ port: 25, state: undefined, service: undefined }]);
  });
});
