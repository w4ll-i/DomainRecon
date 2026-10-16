import type { BatchItem } from "../../api/ops";

// Domaines d'une liste collée ou importée : séparés par espaces, virgules, points-virgules
// ou sauts de ligne ; la première colonne d'un CSV suffit (le serveur normalise et filtre).
export function parseDomainList(text: string): string[] {
  const entries = text
    .split(/[\s,;]+/)
    .map((entry) => entry.trim().replace(/^["']|["']$/g, ""))
    .filter(Boolean);
  return [...new Set(entries)];
}

function csvCell(value: string | number | null): string {
  const text = value === null ? "" : String(value);
  // Neutralise l'interprétation d'une formule par un tableur.
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

// Résultats d'un lot au format CSV : domaine, état, note, score, identifiant du scan, erreur.
export function batchCsv(items: BatchItem[]): string {
  const rows = items.map((item) =>
    [item.domain, item.status, item.grade, item.score, item.scan_id, item.error].map(csvCell).join(","),
  );
  return ["domain,status,grade,score,scan_id,error", ...rows].join("\n") + "\n";
}
