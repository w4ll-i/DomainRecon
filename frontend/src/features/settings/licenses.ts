// Composants livrés avec DomainRecon et leur licence (liste indicative ; le
// texte complet est dans THIRD_PARTY_NOTICES.md, livré avec l'application).
export interface LicenseEntry {
  name: string;
  license: string;
  scope: "ui" | "backend" | "data";
}

export const LICENSES: readonly LicenseEntry[] = [
  { name: "React, React DOM", license: "MIT", scope: "ui" },
  { name: "React Router", license: "MIT", scope: "ui" },
  { name: "TanStack Query", license: "MIT", scope: "ui" },
  { name: "i18next, react-i18next", license: "MIT", scope: "ui" },
  { name: "Chart.js, react-chartjs-2", license: "MIT", scope: "ui" },
  { name: "Cytoscape.js", license: "MIT", scope: "ui" },
  { name: "d3-geo, topojson-client", license: "ISC", scope: "ui" },
  { name: "jsPDF, jsPDF-AutoTable", license: "MIT", scope: "ui" },
  { name: "Lucide", license: "ISC", scope: "ui" },
  { name: "Inter, JetBrains Mono", license: "OFL-1.1", scope: "ui" },
  { name: "FastAPI, Pydantic, SQLAlchemy", license: "MIT", scope: "backend" },
  { name: "Starlette, Uvicorn, HTTPX", license: "BSD-3-Clause", scope: "backend" },
  { name: "dnspython", license: "ISC", scope: "backend" },
  { name: "python-whois", license: "MIT", scope: "backend" },
  { name: "tldextract, idna, python-dotenv", license: "BSD-3-Clause", scope: "backend" },
  { name: "pywebview", license: "BSD-3-Clause", scope: "backend" },
  { name: "Playwright", license: "Apache-2.0", scope: "backend" },
  { name: "Chromium", license: "BSD-3-Clause", scope: "backend" },
  { name: "Natural Earth 1:110m (carte du monde, via world-atlas)", license: "Public domain", scope: "data" },
];
