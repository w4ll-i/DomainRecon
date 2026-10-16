// « Comment corriger » d'un module (GET /api/modules : fix, fix_snippet, fix_ref). Lecture des
// trois textes, miroir de domainrecon/i18n/fix.py (convention : contrat des modules §9.1).
// Tout est rendu en TEXTE par l'interface, jamais en HTML.

// En-tête de variante d'un extrait : « # » et une espace, en première colonne.
const SNIPPET_HEADER = "# ";

// Étapes d'un `fix` : une par ligne non vide, espaces de bord retirés. L'interface les numérote.
export function fixSteps(text: string | undefined): string[] {
  if (!text) return [];
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

// Segment d'une étape : texte courant, ou code en ligne (entre accents graves).
export interface InlineSegment {
  text: string;
  code: boolean;
}

// Découpe une étape en texte et code en ligne (`ainsi`). Un accent grave sans fermeture reste du
// texte : un texte mal formé s'affiche tel quel au lieu de disparaître.
export function splitInlineCode(line: string): InlineSegment[] {
  const parts = line.split("`");
  // Nombre pair de parties : un accent grave reste ouvert, la dernière partie n'est pas du code.
  const closed = parts.length % 2 === 1 ? parts.length : parts.length - 1;
  const segments: InlineSegment[] = [];
  let pending = "";
  parts.forEach((part, index) => {
    if (index < closed && index % 2 === 1) {
      // Paire d'accents graves vide : ignorée, le texte de part et d'autre se rejoint.
      if (part) {
        if (pending) segments.push({ text: pending, code: false });
        pending = "";
        segments.push({ text: part, code: true });
      }
    } else {
      // Texte courant, ou accent grave resté ouvert : restitué avec son accent.
      pending += index >= closed && index % 2 === 1 ? `\`${part}` : part;
    }
  });
  if (pending) segments.push({ text: pending, code: false });
  return segments;
}

// Variante d'un extrait : libellé (nom de produit ou de format) et code à copier.
export interface SnippetVariant {
  label: string | null;
  code: string;
}

// Variantes d'un `fix_snippet`. Une ligne qui commence par « # » et une espace ouvre une variante
// (libellé = le reste de la ligne) ; sans aucun en-tête, une seule variante sans libellé. Le code
// est rendu sans lignes vides de bord, lignes intérieures intactes ; l'en-tête n'en fait pas partie.
export function snippetVariants(text: string | undefined): SnippetVariant[] {
  if (!text || !text.trim()) return [];
  const variants: Array<{ label: string | null; lines: string[] }> = [];
  for (const line of text.replace(/\r\n?/g, "\n").split("\n")) {
    if (line.startsWith(SNIPPET_HEADER)) {
      variants.push({ label: line.slice(SNIPPET_HEADER.length).trim(), lines: [] });
      continue;
    }
    if (variants.length === 0) variants.push({ label: null, lines: [] });
    variants[variants.length - 1].lines.push(line);
  }
  return variants
    .map(({ label, lines }) => ({ label: label || null, code: lines.join("\n").replace(/^\n+|\n+$/g, "") }))
    .filter((variant) => variant.code !== "");
}

// Adresse de documentation : https seulement (le serveur écarte déjà les autres ; l'interface
// ne s'y fie pas, un lien venu d'ailleurs ne doit jamais devenir javascript: ni http:).
export function safeHttpsUrl(text: string | undefined): URL | null {
  if (!text) return null;
  try {
    const url = new URL(text.trim());
    return url.protocol === "https:" && url.hostname.includes(".") && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}
