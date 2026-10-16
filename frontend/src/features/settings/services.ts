import type { CatalogKey } from "../../api/types";

// Services dont le serveur sait tester la clé (api/service_checks.py) ; les modules peuvent en ajouter.
export const BASE_TESTABLE = [
  "shodan",
  "virustotal",
  "censys",
  "abuseipdb",
  "urlscan",
  "otx",
  "safebrowsing",
  "securitytrails",
  "builtwith",
  "circl",
  "intelx",
  "github",
];

export interface Service {
  id: string;
  label: string;
  keys: CatalogKey[];
}

// Services lus depuis le catalogue (clés déclarées par les modules), triés par nom.
export function servicesOf(modules: Array<{ keys?: CatalogKey[] }>): Service[] {
  const services = new Map<string, Service>();
  for (const module of modules) {
    for (const key of module.keys ?? []) {
      const service = services.get(key.service) ?? { id: key.service, label: key.label || key.service, keys: [] };
      if (!service.keys.some((item) => item.name === key.name)) service.keys.push(key);
      services.set(key.service, service);
    }
  }
  return [...services.values()].sort((a, b) => a.label.localeCompare(b.label));
}
