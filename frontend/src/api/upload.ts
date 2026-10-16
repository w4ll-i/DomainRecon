import i18n, { type Lang } from "../i18n";
import { ApiError, apiErrorFromBody, buildUrl, isPrintableAscii, withToken } from "./client";
import type { ImportResult } from "./ops";
import type { ErrorBody } from "./types";

// Taille maximale d'une base importée, en Mio (MAX_IMPORT_BYTES côté serveur) : vérifiée avant
// l'envoi pour ne pas téléverser en vain ; le serveur reste juge (413 api.import_too_large).
export const MAX_IMPORT_MIB = 512;

export interface UploadProgress {
  loaded: number;
  total: number;
}

export interface UploadOptions {
  lang?: Lang;
  // Octets envoyés au fil du téléversement (pas le traitement par le serveur).
  onProgress?: (progress: UploadProgress) => void;
  signal?: AbortSignal;
}

interface RawResponse {
  status: number;
  text: string;
}

// fetch ne rapporte pas l'avancement d'un envoi : un formulaire volumineux part par XMLHttpRequest.
// Le navigateur pose lui-même le Content-Type multipart et sa frontière (jamais à la main).
function postForm(path: string, form: FormData, options: UploadOptions, token: string): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const abortError = () => new DOMException("Envoi annulé", "AbortError");
    if (options.signal?.aborted) {
      reject(abortError());
      return;
    }
    const request = new XMLHttpRequest();
    request.open("POST", buildUrl(path, options.lang));
    if (token && isPrintableAscii(token)) request.setRequestHeader("X-API-Token", token);
    request.responseType = "text";
    const onAbort = () => request.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const done = () => options.signal?.removeEventListener("abort", onAbort);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) options.onProgress?.({ loaded: event.loaded, total: event.total });
    };
    request.onload = () => {
      done();
      resolve({ status: request.status, text: typeof request.response === "string" ? request.response : "" });
    };
    request.onerror = () => {
      done();
      reject(new ApiError(0, i18n.t("errors.network")));
    };
    request.ontimeout = request.onerror;
    request.onabort = () => {
      done();
      reject(abortError());
    };
    request.send(form);
  });
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

const isCount = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0;

// Réponse 200 de l'import : six champs, sinon la réponse est jugée illisible.
export function parseImportResult(body: unknown): ImportResult | null {
  if (!body || typeof body !== "object") return null;
  const data = body as Record<string, unknown>;
  const { read, imported, ignored, duplicates, unusable, unknown_columns: columns } = data;
  if (![read, imported, ignored, duplicates, unusable].every(isCount)) return null;
  const unknown = Array.isArray(columns) ? columns.filter((name): name is string => typeof name === "string") : [];
  return {
    read: read as number,
    imported: imported as number,
    ignored: ignored as number,
    duplicates: duplicates as number,
    unusable: unusable as number,
    unknown_columns: unknown,
  };
}

// Envoie l'ancienne base (champ « file » d'un formulaire multipart) à POST /api/import, avec le
// jeton d'API comme toutes les requêtes (saisie du jeton sur un 401, une seule reprise). Lève une
// ApiError au texte déjà traduit par le serveur ; une annulation lève une AbortError.
export async function uploadImport(file: File, options: UploadOptions = {}): Promise<ImportResult> {
  const form = new FormData();
  form.append("file", file);
  const response = await withToken((token) => postForm("/import", form, options, token));
  const body = parseJson(response.text);
  if (response.status < 200 || response.status >= 300) {
    throw apiErrorFromBody(response.status, body && typeof body === "object" ? (body as ErrorBody) : null);
  }
  const result = parseImportResult(body);
  if (!result) throw new ApiError(response.status, i18n.t("errors.unreadable", { status: response.status }));
  return result;
}
