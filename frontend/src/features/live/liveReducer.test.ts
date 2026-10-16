import { describe, expect, it } from "vitest";
import type { JobEvent, ModuleName, ModuleRunStatus } from "../../api/types";
import { MODULE_FAMILY } from "../../lib/families";
import { familyProgress, initialLiveState, type LiveState, liveReducer } from "./liveReducer";

const moduleEvent = (name: ModuleName, status: ModuleRunStatus = "ok"): JobEvent => ({
  event: "module",
  data: { name, family: MODULE_FAMILY[name], status, duration: 0.1 },
});

const apply = (state: LiveState, event: JobEvent) => liveReducer(state, { type: "event", event });

describe("état du suivi en direct", () => {
  it("compte les modules terminés et l'avancement", () => {
    const state = [moduleEvent("dns_records"), moduleEvent("cors")].reduce(apply, initialLiveState);
    expect(state.phase).toBe("running");
    expect(state.done).toBe(2);
    expect(state.total).toBe(18);
    expect(state.modules.cors).toEqual({ status: "ok", duration: 0.1, family: "web" });
  });

  it("reste juste quand le serveur rejoue tout le flux (reconnexion, changement de langue)", () => {
    const events: JobEvent[] = [
      moduleEvent("dns_records"),
      moduleEvent("cors"),
      { event: "progress", data: { done: 2, total: 18 } },
      moduleEvent("waf", "timeout"),
    ];
    const once = events.reduce(apply, initialLiveState);
    const replayed = events.reduce(apply, once);
    expect(replayed.done).toBe(3);
    expect(Object.keys(replayed.modules)).toHaveLength(3);
    expect(replayed.modules.waf?.status).toBe("timeout");
  });

  it("ne dépasse jamais le total", () => {
    const state = apply(initialLiveState, { event: "progress", data: { done: 25, total: 18 } });
    expect(state.done).toBe(18);
  });

  it("s'arrête sur un événement final et n'en sort plus", () => {
    const done = apply(apply(initialLiveState, moduleEvent("cors")), { event: "done", data: { scan_id: 42 } });
    expect(done).toMatchObject({ phase: "done", scanId: 42 });
    expect(apply(done, moduleEvent("waf")).phase).toBe("done");
    const failed = apply(initialLiveState, {
      event: "failed",
      data: { code: "scan.internal_error", params: {}, detail: "Erreur interne" },
    });
    expect(failed).toMatchObject({ phase: "failed", error: { code: "scan.internal_error", detail: "Erreur interne" } });
    expect(apply(initialLiveState, { event: "cancelled", data: {} }).phase).toBe("cancelled");
    expect(liveReducer(initialLiveState, { type: "lost", detail: "Tâche introuvable" })).toMatchObject({
      phase: "lost",
      error: { detail: "Tâche introuvable" },
    });
  });

  it("une tâche déjà terminée n'est jamais « perdue » (une seule issue à l'écran)", () => {
    const lost = { type: "lost", detail: "Tâche introuvable" } as const;
    const failed = apply(initialLiveState, { event: "failed", data: { code: null, params: {}, detail: "Erreur" } });
    expect(liveReducer(failed, lost)).toBe(failed);
    const done = apply(initialLiveState, { event: "done", data: { scan_id: 3 } });
    expect(liveReducer(done, lost)).toBe(done);
    const cancelled = apply(initialLiveState, { event: "cancelled", data: {} });
    expect(liveReducer(cancelled, lost)).toBe(cancelled);
  });

  it("résume une famille : en attente, en cours, terminée, partielle, sans objet", () => {
    expect(familyProgress(initialLiveState, "dns").state).toBe("pending");
    const running = [moduleEvent("dns_records"), moduleEvent("subdomains")].reduce(apply, initialLiveState);
    expect(familyProgress(running, "dns")).toEqual({ done: 2, total: 4, unmeasured: 0, state: "running" });
    expect(familyProgress(running, "tls").state).toBe("running");
    const partial = [
      moduleEvent("open_ports"),
      moduleEvent("geo_data"),
      moduleEvent("network_extended", "timeout"),
    ].reduce(apply, initialLiveState);
    expect(familyProgress(partial, "network")).toEqual({ done: 3, total: 3, unmeasured: 1, state: "partial" });
    const identity = [moduleEvent("whois_data"), moduleEvent("screenshot", "skipped")].reduce(apply, initialLiveState);
    expect(familyProgress(identity, "identity").state).toBe("done");
    const skipped = [moduleEvent("email_security", "skipped")].reduce(apply, initialLiveState);
    expect(familyProgress(skipped, "email").state).toBe("skipped");
    const cancelled = apply(running, { event: "cancelled", data: {} });
    expect(familyProgress(cancelled, "web").state).toBe("pending");
  });
});
