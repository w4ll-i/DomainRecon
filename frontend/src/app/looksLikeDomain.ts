// Une saisie qui ressemble à un domaine (« exemple.fr », sans espace ni chemin) propose
// d'être scannée ; le serveur reste juge de sa validité.
export function looksLikeDomain(value: string): boolean {
  return /^[^\s/@:]+\.[^\s/@:.]{2,}$/.test(value);
}
