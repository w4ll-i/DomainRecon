import i18n, { type Lang } from "../i18n";
import { ApiError, apiRequest } from "./client";
import type { JobEvent } from "./types";

export interface RawSseEvent {
  event: string;
  data: string;
}

// Analyse incrémentale du format text/event-stream : renvoie les événements
// complets et le reste (événement coupé entre deux paquets). Un « \r » final
// peut être la moitié d'un « \r\n » coupé entre deux paquets : il reste tel
// quel dans le reste (sinon le « \n » suivant ferait une ligne vide de trop et
// couperait l'événement en deux).
export function parseSse(buffer: string): { events: RawSseEvent[]; rest: string } {
  const pendingCr = buffer.endsWith("\r");
  const text = pendingCr ? buffer.slice(0, -1) : buffer;
  const blocks = text.replace(/\r\n?/g, "\n").split("\n\n");
  const rest = (blocks.pop() ?? "") + (pendingCr ? "\r" : "");
  const events: RawSseEvent[] = [];
  for (const block of blocks) {
    let event = "message";
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (!line || line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      let value = colon === -1 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }
    if (data.length) events.push({ event, data: data.join("\n") });
  }
  return { events, rest };
}

const KNOWN_EVENTS = new Set(["module", "progress", "done", "failed", "cancelled"]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): boolean => typeof value === "number" && Number.isFinite(value) && value >= 0;

// Forme minimale de chaque événement : un événement mal formé est écarté
// (comme un JSON invalide) plutôt que de casser le rendu.
function wellFormed(event: string, data: unknown): boolean {
  if (event === "cancelled") return true;
  if (!isRecord(data)) return false;
  if (event === "module") return typeof data.name === "string" && typeof data.status === "string";
  if (event === "progress") return isCount(data.done) && isCount(data.total);
  if (event === "done") return isCount(data.scan_id);
  return true;
}

export function toJobEvent(raw: RawSseEvent): JobEvent | null {
  if (!KNOWN_EVENTS.has(raw.event)) return null;
  let data: unknown;
  try {
    data = JSON.parse(raw.data);
  } catch {
    return null;
  }
  return wellFormed(raw.event, data) ? ({ event: raw.event, data } as JobEvent) : null;
}

export interface StreamOptions {
  lang: Lang;
  signal: AbortSignal;
  onEvent: (event: JobEvent) => void;
  onOpen?: () => void;
}

// Lecture par fetch (et non EventSource) : le jeton d'API part dans l'en-tête
// X-API-Token, et l'annulation passe par AbortController.
export async function streamJobEvents(jobId: string, options: StreamOptions): Promise<"closed"> {
  const res = await apiRequest(`/scans/${encodeURIComponent(jobId)}/events`, {
    lang: options.lang,
    signal: options.signal,
    headers: { Accept: "text/event-stream" },
  });
  if (!res.body) throw new ApiError(res.status, i18n.t("errors.unreadable", { status: res.status }));
  options.onOpen?.();
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const parsed = parseSse(buffer);
    buffer = parsed.rest;
    for (const raw of parsed.events) {
      const event = toJobEvent(raw);
      if (event) options.onEvent(event);
    }
  }
  return "closed";
}
