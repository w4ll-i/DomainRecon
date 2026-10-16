import type { OpenPort } from "../api/types";

// Numéro de port valide (entier ou chaîne numérique), sinon null.
function toPort(value: unknown): number | null {
  const port = typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value) : value;
  return typeof port === "number" && Number.isInteger(port) && port >= 0 && port <= 65535 ? port : null;
}

// Liste de ports normalisée. Anciens scans : entiers nus (`[80, 443]`, format
// que score.py et findings.py acceptent aussi), dictionnaires `{port, state,
// service}`, liste absente (null) ou entrées inutilisables (ignorées).
export function normalizeOpenPorts(value: unknown): OpenPort[] {
  if (!Array.isArray(value)) return [];
  const entries: OpenPort[] = [];
  for (const item of value as unknown[]) {
    const bare = toPort(item);
    if (bare !== null) {
      entries.push({ port: bare });
    } else if (item && typeof item === "object") {
      const entry = item as { port?: unknown; state?: unknown; service?: unknown };
      const port = toPort(entry.port);
      if (port !== null) {
        entries.push({
          port,
          state: typeof entry.state === "string" ? entry.state : undefined,
          service: typeof entry.service === "string" ? entry.service : undefined,
        });
      }
    }
  }
  return entries;
}
