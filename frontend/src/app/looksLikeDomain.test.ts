import { describe, expect, it } from "vitest";
import { looksLikeDomain } from "./looksLikeDomain";

describe("saisie qui ressemble à un domaine", () => {
  it.each(["example.com", "sub.example.co.uk", "exemple.fr", "xn--bcher-kva.example"])("accepte %s", (value) => {
    expect(looksLikeDomain(value)).toBe(true);
  });

  it.each(["", "hist", "example", "exemple .fr", "https://example.com", "example.com/chemin", "user@example.com", "a.b", "example."])(
    "refuse %j",
    (value) => {
      expect(looksLikeDomain(value)).toBe(false);
    },
  );
});
