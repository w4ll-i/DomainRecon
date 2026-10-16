import { describe, expect, it, vi } from "vitest";
import {
  STORAGE_KEYS,
  getLastScanId,
  readLocal,
  readSession,
  setLastScanId,
  subscribeLastScan,
  writeLocal,
  writeSession,
} from "./storage";

describe("stockage du navigateur", () => {
  it("lit et écrit localStorage et sessionStorage", () => {
    writeLocal("cle", "valeur");
    writeSession("jeton", "abc");
    expect(readLocal("cle")).toBe("valeur");
    expect(readSession("jeton")).toBe("abc");
    writeLocal("cle", null);
    expect(readLocal("cle")).toBeNull();
  });

  it("survit à un stockage bloqué (navigation privée, site bloqué)", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("bloqué");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("bloqué");
    });
    expect(() => writeLocal("cle", "x")).not.toThrow();
    expect(readLocal("cle")).toBeNull();
    expect(readSession(STORAGE_KEYS.token)).toBeNull();
  });

  it("mémorise le dernier scan consulté et prévient les abonnés", () => {
    const listener = vi.fn();
    const unsubscribe = subscribeLastScan(listener);
    setLastScanId(12);
    expect(getLastScanId()).toBe(12);
    expect(window.localStorage.getItem("domainrecon.lastScan")).toBe("12");
    setLastScanId(12);
    expect(listener).toHaveBeenCalledTimes(1);
    setLastScanId(null);
    expect(getLastScanId()).toBeNull();
    unsubscribe();
    setLastScanId(3);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("ignore un identifiant de scan corrompu", () => {
    for (const raw of ["abc", "0", "-4", "1.5", ""]) {
      window.localStorage.setItem("domainrecon.lastScan", raw);
      expect(getLastScanId()).toBeNull();
    }
  });
});
