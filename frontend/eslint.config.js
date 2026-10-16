import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

// La CSP stricte de l'interface (servie par FastAPI) interdit les styles et
// scripts en ligne : les règles ci-dessous l'imposent dès l'écriture du code.
export default defineConfig([
  globalIgnores(["node_modules", "playwright-report", "test-results"]),
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser, ...globals.node },
    },
    plugins: { "react-hooks": reactHooks, "react-refresh": reactRefresh },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true, allowExportNames: ["useToast", "useConfirm", "useTokenDialog", "FAMILY_VIEWS", "routes"] },
      ],
      // Pas d'évaluation de texte en code (la CSP interdit déjà unsafe-eval).
      "no-eval": "error",
      "no-new-func": "error",
      "no-implied-eval": "error",
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='style']",
          message: "CSP stricte : pas d'attribut style (utiliser une classe CSS Module ou un attribut data-*).",
        },
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Aucune donnée injectée en HTML brut.",
        },
      ],
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Aucune donnée injectée en HTML brut (nœuds DOM ou JSX)." },
        { property: "outerHTML", message: "Aucune donnée injectée en HTML brut (nœuds DOM ou JSX)." },
        { property: "insertAdjacentHTML", message: "Aucune donnée injectée en HTML brut (nœuds DOM ou JSX)." },
      ],
    },
  },
]);
