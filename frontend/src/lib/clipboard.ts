// Copie un texte dans le presse-papiers. L'API moderne d'abord (contexte sécurisé : 127.0.0.1 et
// localhost le sont) ; à défaut, la copie par un champ de saisie temporaire. Renvoie faux quand
// aucune des deux n'a abouti (autorisation refusée, navigateur ancien).
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Refus d'autorisation : on tente la copie par sélection.
  }
  return copyBySelection(text);
}

function copyBySelection(text: string): boolean {
  if (typeof document === "undefined" || typeof document.execCommand !== "function") return false;
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.className = "visually-hidden";
  const active = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  document.body.appendChild(field);
  try {
    field.select();
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    field.remove();
    active?.focus();
  }
}
