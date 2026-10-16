import { describe, expect, it } from "vitest";
import { charCount, countryCode, countryName, formatDate, formatDuration, formatNumber, parseId } from "./format";

describe("formats", () => {
  it("formate une date ISO UTC dans la langue choisie", () => {
    expect(formatDate("2026-09-28T10:05:00Z", "fr")).toMatch(/^\d{2}\/\d{2}\/2026 \d{2}:\d{2}$/);
    expect(formatDate("2026-09-28T10:05:00Z", "en")).toMatch(/^\d{2}\/\d{2}\/2026,? \d{2}:\d{2}$/);
    expect(formatDate("pas une date", "fr")).toBe("pas une date");
    expect(formatDate(null, "fr")).toBe("—");
  });

  it("formate une durée", () => {
    expect(formatDuration(23.4, "fr")).toBe("23,4 s");
    expect(formatDuration(23.4, "en")).toBe("23.4 s");
    expect(formatDuration(null, "fr")).toBe("—");
  });

  it("formate un nombre dans la langue choisie, avec au plus le nombre de décimales demandé", () => {
    expect(formatNumber(23.47, "fr", 1)).toBe("23,5");
    expect(formatNumber(23.4, "en", 1)).toBe("23.4");
    expect(formatNumber(23, "fr", 1)).toBe("23");
    expect(formatNumber(7.8, "fr")).toBe("8");
  });

  it("compte les caractères Unicode comme l'API (un emoji = 1)", () => {
    expect(charCount("é😀a")).toBe(3);
  });

  it("lit un identifiant d'URL", () => {
    expect(parseId("42")).toBe(42);
    for (const raw of ["abc", "0", "-1", "1.5", "99999999999", undefined]) expect(parseId(raw)).toBeNull();
  });

  it("nomme le pays dans la langue choisie", () => {
    expect(countryCode({ country: "us" })).toBe("US");
    expect(countryCode({ country: "France" })).toBe("");
    expect(countryName({ country_code: "US" }, "fr")).toBe("États-Unis");
    expect(countryName({ country_code: "US" }, "en")).toBe("United States");
    expect(countryName({ country: "Atlantis" }, "fr")).toBe("Atlantis");
  });
});
