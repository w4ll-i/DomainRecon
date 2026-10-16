import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useCatalog } from "../../../api/queries";
import type { ScanResponse } from "../../../api/types";
import { KvList, type KvRow } from "../../../components/KvList";
import { ModuleCard } from "../../../components/ModuleCard";
import { Pill } from "../../../components/Pills";
import { humanizeKey } from "../../../lib/catalog";
import { scanModuleState } from "../../../lib/moduleState";
import styles from "./generic.module.css";
import modules from "./modules.module.css";

// Affichage d'un module du registre SANS composant dédié : tout module ajouté côté serveur
// s'affiche ainsi, lisiblement, sans code d'interface. Statut honnête (jamais « rien
// trouvé » pour un module non lancé, en échec ou sans objet), textes d'aide du catalogue,
// puis les données principales en listes et tableaux simples. Données rendues en TEXTE.

// Clés de la sortie qui décrivent la mesure, pas son contenu.
const META_KEYS = new Set(["measured", "skipped", "error"]);
const MAX_ITEMS = 50;
const MAX_COLUMNS = 8;
const MAX_DEPTH = 3;
const MAX_RAW = 1500;

type Json = unknown;

const isScalar = (value: Json): value is string | number | boolean | null | undefined =>
  value === null || value === undefined || ["string", "number", "boolean"].includes(typeof value);
const isRecord = (value: Json): value is Record<string, Json> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const keyLabel = (key: string) => (/^[a-z][a-z0-9_]*$/.test(key) ? humanizeKey(key) : key);

function compact(value: Json): string {
  try {
    const text = JSON.stringify(value) ?? "";
    return text.length > MAX_RAW ? `${text.slice(0, MAX_RAW)}…` : text;
  } catch {
    return "";
  }
}

function Scalar({ value }: { value: Json }) {
  const { t } = useTranslation();
  if (typeof value === "boolean") return <>{t(value ? "common.yes" : "common.no")}</>;
  if (value === null || value === undefined || value === "") return <>{t("common.na")}</>;
  return <>{String(value)}</>;
}

function Table({ rows }: { rows: Array<Record<string, Json>> }) {
  const { t } = useTranslation();
  // Colonnes : les clés rencontrées, les valeurs simples d'abord.
  const columns: string[] = [];
  for (const scalarOnly of [true, false]) {
    for (const row of rows) {
      for (const [key, value] of Object.entries(row)) {
        if (columns.length < MAX_COLUMNS && !columns.includes(key) && (!scalarOnly || isScalar(value))) columns.push(key);
      }
    }
  }
  return (
    <div className={styles.scroll} role="region" tabIndex={0} aria-label={t("generic.tableAria")}>
      {/* Rôles explicites : sur mobile, le tableau passe en blocs (display: block), qui
          effaceraient sa sémantique dans certains navigateurs. */}
      <table className={styles.table} role="table">
        <thead role="rowgroup">
          <tr role="row">
            {columns.map((column) => (
              <th key={column} scope="col" role="columnheader">
                {keyLabel(column)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody role="rowgroup">
          {rows.map((row, index) => (
            <tr key={index} role="row">
              {columns.map((column) => (
                // data-label : l'intitulé de la colonne, repris devant la valeur sur mobile (lignes empilées).
                <td key={column} role="cell" data-label={keyLabel(column)}>
                  {isScalar(row[column]) ? <Scalar value={row[column]} /> : <span className="mono">{compact(row[column])}</span>}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function More({ hidden }: { hidden: number }) {
  const { t } = useTranslation();
  return hidden > 0 ? <p className={modules.muted}>{t("generic.more", { count: hidden })}</p> : null;
}

function ListNode({ items, depth }: { items: Json[]; depth: number }) {
  const { t } = useTranslation();
  if (items.length === 0) return <p className={modules.muted}>{t("generic.none")}</p>;
  const shown = items.slice(0, MAX_ITEMS);
  const hidden = items.length - shown.length;
  if (shown.every(isScalar)) {
    return (
      <>
        <ul className={`${styles.list} mono`}>
          {shown.map((item, index) => (
            <li key={index}>
              <Scalar value={item} />
            </li>
          ))}
        </ul>
        <More hidden={hidden} />
      </>
    );
  }
  if (shown.every(isRecord) && depth < MAX_DEPTH) {
    return (
      <>
        <Table rows={shown as Array<Record<string, Json>>} />
        <More hidden={hidden} />
      </>
    );
  }
  return (
    <>
      <ul className={styles.list}>
        {shown.map((item, index) => (
          <li key={index}>{isScalar(item) ? <Scalar value={item} /> : <span className="mono">{compact(item)}</span>}</li>
        ))}
      </ul>
      <More hidden={hidden} />
    </>
  );
}

function ObjectNode({ data, depth, skip }: { data: Record<string, Json>; depth: number; skip?: ReadonlySet<string> }) {
  const { t } = useTranslation();
  const entries = Object.entries(data).filter(([key]) => !skip?.has(key));
  if (entries.length === 0) return <p className={modules.muted}>{t("generic.none")}</p>;
  if (depth >= MAX_DEPTH) return <pre className={`${styles.raw} mono`}>{compact(data)}</pre>;
  const rows: KvRow[] = entries
    .filter(([, value]) => isScalar(value))
    .map(([key, value]) => ({ label: keyLabel(key), value: value as ReactNode, mono: true }));
  const nested = entries.filter(([, value]) => !isScalar(value));
  return (
    <>
      {rows.length > 0 && <KvList rows={rows} />}
      {nested.map(([key, value]) => (
        <div key={key} className={depth > 0 ? `${styles.block} ${styles.nested}` : styles.block}>
          <h3 className={modules.subTitle}>{keyLabel(key)}</h3>
          {Array.isArray(value) ? (
            <ListNode items={value} depth={depth + 1} />
          ) : isRecord(value) ? (
            <ObjectNode data={value} depth={depth + 1} />
          ) : null}
        </div>
      ))}
    </>
  );
}

// Données principales d'un module : un objet (cas normal du contrat de module), une
// liste, ou une valeur simple.
export function GenericData({ data }: { data: Json }) {
  const { t } = useTranslation();
  if (isRecord(data)) {
    const error = typeof data.error === "string" && data.error ? data.error : null;
    return (
      <>
        {error && <p className={modules.warnText}>{error}</p>}
        <ObjectNode data={data} depth={0} skip={META_KEYS} />
      </>
    );
  }
  if (Array.isArray(data)) return <ListNode items={data} depth={0} />;
  if (isScalar(data) && data !== null && data !== undefined) return <p className="mono">{String(data)}</p>;
  return <p className={modules.muted}>{t("generic.none")}</p>;
}

export function GenericModule({ scan, module = "" }: { scan: ScanResponse; module?: string }) {
  const { t } = useTranslation();
  const catalog = useCatalog();
  const info = catalog.info(module);
  const state = scanModuleState(scan, module);
  const result = scan.modules?.[module];
  const missingKeys = (info?.keys ?? []).filter((key) => key.required && !key.configured);
  const notLaunched = state.status === "not_launched";
  return (
    <ModuleCard scan={scan} module={module} showChildrenWhenUnavailable>
      {info?.help?.checks && (
        <div className={styles.help}>
          <p className={styles.helpChecks}>{info.help.checks}</p>
          {info.help.why && <p className={styles.helpWhy}>{info.help.why}</p>}
        </div>
      )}
      {catalog.live && info && (
        <div className={styles.meta}>
          <Pill tone="neutral">{t(`generic.category.${info.category}`, { defaultValue: info.category })}</Pill>
          {info.requires_authorization && <Pill tone="warning">{t("generic.requiresAuth")}</Pill>}
          {state.status === "ok" && typeof result?.duration === "number" && (
            <span className={`${styles.duration} mono`}>{t("generic.duration", { seconds: result.duration.toFixed(1) })}</span>
          )}
        </div>
      )}
      {notLaunched && missingKeys.length > 0 && (
        <p className={modules.note} data-tone="info">
          {t("generic.missingKeys", { keys: missingKeys.map((key) => key.label).join(t("common.listSeparator")) })}
        </p>
      )}
      {notLaunched && info?.requires_authorization && (
        <p className={modules.note} data-tone="info">
          {t("generic.authHint")}
        </p>
      )}
      {state.status === "ok" && <GenericData data={result?.data} />}
    </ModuleCard>
  );
}
