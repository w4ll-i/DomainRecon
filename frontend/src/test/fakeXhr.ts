import { vi } from "vitest";

// Faux XMLHttpRequest : l'envoi d'un fichier (api/upload.ts) se joue à la main, sans réseau.
// Chaque requête créée est gardée dans `instances` ; le test la fait progresser, répondre ou échouer.
type Listener = ((event?: unknown) => void) | null;

export class FakeXHR {
  static instances: FakeXHR[] = [];

  method = "";
  url = "";
  headers: Record<string, string> = {};
  body: unknown = null;
  status = 0;
  response: unknown = "";
  responseType = "";
  aborted = false;
  sent = false;
  upload: { onprogress: Listener } = { onprogress: null };
  onload: Listener = null;
  onerror: Listener = null;
  onabort: Listener = null;
  ontimeout: Listener = null;

  constructor() {
    FakeXHR.instances.push(this);
  }

  open(method: string, url: string): void {
    this.method = method;
    this.url = url;
  }

  setRequestHeader(name: string, value: string): void {
    this.headers[name] = value;
  }

  send(body: unknown): void {
    this.body = body;
    this.sent = true;
  }

  abort(): void {
    this.aborted = true;
    this.onabort?.();
  }

  // ---- Côté test ----

  progress(loaded: number, total: number): void {
    this.upload.onprogress?.({ lengthComputable: true, loaded, total });
  }

  respond(status: number, body: unknown): void {
    this.status = status;
    this.response = typeof body === "string" ? body : JSON.stringify(body);
    this.onload?.();
  }

  fail(): void {
    this.onerror?.();
  }

  // Champ « file » du formulaire envoyé.
  get file(): File | null {
    const value = (this.body as FormData | null)?.get("file");
    return value instanceof File ? value : null;
  }
}

// Remplace XMLHttpRequest pour la durée du test (restauré par unstubGlobals).
export function stubXhr(): typeof FakeXHR {
  FakeXHR.instances = [];
  vi.stubGlobal("XMLHttpRequest", FakeXHR);
  return FakeXHR;
}

export function lastXhr(): FakeXHR {
  const request = FakeXHR.instances[FakeXHR.instances.length - 1];
  if (!request) throw new Error("Aucune requête XMLHttpRequest envoyée");
  return request;
}
