import { describe, expect, it } from "vitest";
import type { JobEvent, ModuleName, ModuleRunStatus } from "../../api/types";
import { MODULE_FAMILY, MODULE_NAMES } from "../../lib/families";
import { initialLiveState, type LiveState, liveReducer } from "./liveReducer";
import { currentModule, formatClock, formatModuleDuration, isoDuration } from "./liveView";

const moduleEvent = (name: ModuleName, status: ModuleRunStatus = "ok"): JobEvent => ({
  event: "module",
  data: { name, family: MODULE_FAMILY[name], status, duration: 0.1 },
});
const apply = (state: LiveState, event: JobEvent) => liveReducer(state, { type: "event", event });

describe("module en cours", () => {
  it("attend le premier module tant qu'aucun n'est terminé", () => {
    expect(currentModule(initialLiveState)).toEqual({ kind: "waiting" });
  });

  it("montre le premier module restant (ordre canonique) et le nombre de ceux qui le suivent", () => {
    const state = [moduleEvent("dns_records"), moduleEvent("subdomains")].reduce(apply, initialLiveState);
    expect(currentModule(state)).toEqual({ kind: "running", name: "security_headers", more: 15 });
  });

  it("saute les modules déjà terminés, quel que soit leur ordre d'arrivée", () => {
    // Les modules d'une même vague finissent dans le désordre : le premier restant change.
    const state = [moduleEvent("security_headers"), moduleEvent("dns_records")].reduce(apply, initialLiveState);
    expect(currentModule(state)).toEqual({ kind: "running", name: "subdomains", more: 15 });
  });

  it("un seul module restant : aucun « +N »", () => {
    const state = MODULE_NAMES.filter((name) => name !== "screenshot")
      .map((name) => moduleEvent(name))
      .reduce(apply, initialLiveState);
    expect(currentModule(state)).toEqual({ kind: "running", name: "screenshot", more: 0 });
  });

  it("tout est terminé mais l'événement final n'est pas arrivé : finalisation", () => {
    const state = MODULE_NAMES.map((name) => moduleEvent(name)).reduce(apply, initialLiveState);
    expect(state.phase).toBe("running");
    expect(currentModule(state)).toEqual({ kind: "finalizing" });
  });

  it("le total du plan borne le décompte (plan plus court que les 18 modules connus)", () => {
    const planned = apply(initialLiveState, { event: "progress", data: { done: 0, total: 3 } });
    expect(currentModule(planned)).toEqual({ kind: "waiting" });
    const state = [moduleEvent("dns_records"), moduleEvent("subdomains")].reduce(apply, planned);
    expect(currentModule(state)).toEqual({ kind: "running", name: "security_headers", more: 0 });
    expect(currentModule(apply(state, moduleEvent("security_headers")))).toEqual({ kind: "finalizing" });
  });

  it("plus rien n'est en cours une fois la tâche terminée, annulée, échouée ou perdue", () => {
    const running = apply(initialLiveState, moduleEvent("cors"));
    expect(currentModule(apply(running, { event: "done", data: { scan_id: 1 } }))).toEqual({ kind: "none" });
    expect(currentModule(apply(running, { event: "cancelled", data: {} }))).toEqual({ kind: "none" });
    expect(currentModule(apply(running, { event: "failed", data: { code: null, params: {}, detail: "x" } }))).toEqual({ kind: "none" });
    expect(currentModule(liveReducer(running, { type: "lost", detail: "perdu" }))).toEqual({ kind: "none" });
  });
});

describe("chronomètre", () => {
  it.each([
    [0, "0:00"],
    [7, "0:07"],
    [59, "0:59"],
    [60, "1:00"],
    [125, "2:05"],
    [3599, "59:59"],
    [3600, "1:00:00"],
    [3723, "1:02:03"],
    [7.9, "0:07"],
  ])("%s s s'affiche %s", (seconds, text) => {
    expect(formatClock(seconds)).toBe(text);
  });

  it("ramène une valeur négative ou illisible à 0:00", () => {
    expect(formatClock(-5)).toBe("0:00");
    expect(formatClock(Number.NaN)).toBe("0:00");
    expect(formatClock(Number.POSITIVE_INFINITY)).toBe("0:00");
  });

  it.each([
    [0, "PT0S"],
    [7, "PT7S"],
    [60, "PT1M"],
    [65, "PT1M5S"],
    [3600, "PT1H"],
    [3723, "PT1H2M3S"],
    [-3, "PT0S"],
  ])("durée ISO 8601 de %s s : %s", (seconds, iso) => {
    expect(isoDuration(seconds)).toBe(iso);
  });
});

describe("durée d'un module", () => {
  it("deux décimales sous 10 s, une au-delà, dans la langue de l'interface", () => {
    expect(formatModuleDuration(0.123, "fr")).toBe("0,12 s");
    expect(formatModuleDuration(0.1, "fr")).toBe("0,1 s");
    expect(formatModuleDuration(1, "fr")).toBe("1 s");
    expect(formatModuleDuration(9.994, "fr")).toBe("9,99 s");
    expect(formatModuleDuration(12.34, "fr")).toBe("12,3 s");
    expect(formatModuleDuration(12.34, "en")).toBe("12.3 s");
    expect(formatModuleDuration(0, "fr")).toBe("0 s");
  });

  it("n'invente pas de durée : « — » quand la valeur n'est pas un nombre", () => {
    expect(formatModuleDuration(Number.NaN, "fr")).toBe("—");
    expect(formatModuleDuration(Number.POSITIVE_INFINITY, "fr")).toBe("—");
    expect(formatModuleDuration(undefined as unknown as number, "fr")).toBe("—");
    expect(formatModuleDuration("3" as unknown as number, "fr")).toBe("—");
  });
});
