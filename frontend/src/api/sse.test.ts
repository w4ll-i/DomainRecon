import { describe, expect, it } from "vitest";
import { mockFetch } from "../test/fetchMock";
import { setToken } from "./client";
import { parseSse, streamJobEvents, toJobEvent } from "./sse";
import type { JobEvent } from "./types";

function streamOf(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
}

describe("flux SSE des tâches", () => {
  it("découpe les événements, y compris coupés entre deux paquets", () => {
    const first = parseSse('event: module\ndata: {"name":"dns_records"}\n\nevent: prog');
    expect(first.events).toEqual([{ event: "module", data: '{"name":"dns_records"}' }]);
    const second = parseSse(`${first.rest}ress\ndata: {"done":1,"total":18}\n\n`);
    expect(second.events).toEqual([{ event: "progress", data: '{"done":1,"total":18}' }]);
    expect(second.rest).toBe("");
  });

  it("ignore les commentaires et accepte les fins de ligne CRLF", () => {
    expect(parseSse(': ping\r\n\r\nevent: done\r\ndata: {"scan_id":4}\r\n\r\n').events).toEqual([
      { event: "done", data: '{"scan_id":4}' },
    ]);
  });

  it("type les événements connus et écarte le reste", () => {
    expect(toJobEvent({ event: "done", data: '{"scan_id":4}' })).toEqual({ event: "done", data: { scan_id: 4 } });
    expect(toJobEvent({ event: "cancelled", data: "{}" })).toEqual({ event: "cancelled", data: {} });
    expect(toJobEvent({ event: "bizarre", data: "{}" })).toBeNull();
    expect(toJobEvent({ event: "module", data: "pas du json" })).toBeNull();
  });

  it("lit le flux par fetch, avec la langue et le jeton d'API (pas EventSource)", async () => {
    setToken("abc");
    const { calls } = mockFetch({
      "GET /api/scans/job1/events": () =>
        ({
          ok: true,
          status: 200,
          body: streamOf([
            'event: module\ndata: {"name":"cors","family":"web","status":"ok","duration":0.2}\n\nevent: do',
            'ne\ndata: {"scan_id":9}\n\n',
          ]),
        }) as unknown as Response,
    });
    const events: JobEvent[] = [];
    let opened = false;
    const result = await streamJobEvents("job1", {
      lang: "en",
      signal: new AbortController().signal,
      onOpen: () => {
        opened = true;
      },
      onEvent: (event) => events.push(event),
    });
    expect(result).toBe("closed");
    expect(opened).toBe(true);
    expect(events).toEqual([
      { event: "module", data: { name: "cors", family: "web", status: "ok", duration: 0.2 } },
      { event: "done", data: { scan_id: 9 } },
    ]);
    expect(calls[0].url.searchParams.get("lang")).toBe("en");
    expect(new Headers(calls[0].init.headers).get("X-API-Token")).toBe("abc");
    expect(new Headers(calls[0].init.headers).get("Accept")).toBe("text/event-stream");
  });

  it("un CRLF coupé entre deux paquets ne scinde pas l'événement", () => {
    // Paquet 1 finit par CR, paquet 2 commence par LF : une seule fin de ligne
    // (sinon un événement à deux lignes « data » serait coupé en deux).
    const split = parseSse("event: x\r\ndata: a\r");
    expect(split.events).toEqual([]);
    expect(parseSse(`${split.rest}\ndata: b\r\n\r\n`).events).toEqual([{ event: "x", data: "a\nb" }]);
    const first = parseSse('event: done\r\ndata: {"scan_id":4}\r');
    expect(first.events).toEqual([]);
    const second = parseSse(`${first.rest}\n\r\nevent: cancelled\r\ndata: {}\r\n\r\n`);
    expect(second.events).toEqual([
      { event: "done", data: '{"scan_id":4}' },
      { event: "cancelled", data: "{}" },
    ]);
    expect(second.rest).toBe("");
    // Coupure juste après la ligne vide (CRLF CR puis LF) : pas d'événement fantôme.
    const a = parseSse('data: x\r\n\r');
    const b = parseSse(`${a.rest}\ndata: y\r\n\r\n`);
    expect([...a.events, ...b.events].map((event) => event.data)).toEqual(["x", "y"]);
    // Un CR isolé reste une fin de ligne valide dès que le paquet suivant le confirme.
    const c = parseSse("data: z\r");
    expect(parseSse(`${c.rest}\rdata: w\r\rdata: v`).events.map((event) => event.data)).toEqual(["z", "w"]);
  });

  it("reconstitue les événements d'un flux coupé octet par octet (CRLF compris)", () => {
    const source = 'event: module\r\ndata: {"name":"cors"}\r\n\r\nevent: done\r\ndata: {"scan_id":1}\r\n\r\n';
    let rest = "";
    const events: string[] = [];
    for (const char of source) {
      const parsed = parseSse(rest + char);
      rest = parsed.rest;
      events.push(...parsed.events.map((event) => event.event));
    }
    expect(events).toEqual(["module", "done"]);
  });
});
