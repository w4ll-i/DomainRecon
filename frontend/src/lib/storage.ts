// Accès au stockage du navigateur. Il peut être indisponible (navigation
// privée, données de site bloquées) : chaque accès est protégé et une
// lecture impossible vaut « absent ».
export const STORAGE_KEYS = {
  token: "domainrecon.token",
  lang: "domainrecon.lang",
  lastScan: "domainrecon.lastScan",
  theme: "domainrecon.theme",
  onboarded: "domainrecon.onboarded",
} as const;

type Kind = "local" | "session";

function read(kind: Kind, key: string): string | null {
  try {
    const storage = kind === "local" ? window.localStorage : window.sessionStorage;
    return storage.getItem(key);
  } catch {
    return null;
  }
}

function write(kind: Kind, key: string, value: string | null): void {
  try {
    const storage = kind === "local" ? window.localStorage : window.sessionStorage;
    if (value === null) storage.removeItem(key);
    else storage.setItem(key, value);
  } catch {
    // Stockage indisponible : la valeur ne vit qu'en mémoire (voir les appelants).
  }
}

export const readLocal = (key: string): string | null => read("local", key);
export const writeLocal = (key: string, value: string | null): void => write("local", key, value);
export const readSession = (key: string): string | null => read("session", key);
export const writeSession = (key: string, value: string | null): void => write("session", key, value);

const lastScanListeners = new Set<() => void>();

// Dernier scan consulté (entrée « Résultat » du menu).
export function getLastScanId(): number | null {
  const raw = readLocal(STORAGE_KEYS.lastScan);
  if (!raw || !/^\d+$/.test(raw)) return null;
  const id = Number(raw);
  return id > 0 ? id : null;
}

export function setLastScanId(id: number | null): void {
  if (getLastScanId() === id) return;
  writeLocal(STORAGE_KEYS.lastScan, id === null ? null : String(id));
  lastScanListeners.forEach((listener) => listener());
}

export function subscribeLastScan(listener: () => void): () => void {
  lastScanListeners.add(listener);
  return () => {
    lastScanListeners.delete(listener);
  };
}
