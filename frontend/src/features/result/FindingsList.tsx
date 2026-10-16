import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { useCatalog } from "../../api/queries";
import type { Finding, FamilyKey, FamilyState, ScanResponse } from "../../api/types";
import { GlossaryText } from "../../components/Term";
import { SeverityBadge } from "../../components/Pills";
import { STATE_ICONS } from "../../lib/icons";
import { moduleLabel } from "../../lib/catalog";
import { findingsEmptyKey } from "../../lib/score";
import { FixAdvice } from "./FixAdvice";
import styles from "./result.module.css";


// Un constat expliqué en trois temps : ce que c'est (ce que le module vérifie), pourquoi c'est
// important, comment corriger. Les trois textes viennent du catalogue des modules ; le conseil
// de l'interface (par module, sinon par famille) ne sert que de repli quand le catalogue n'a pas
// d'étapes pour le module (voir FixAdvice).
function FindingDetail({ finding, id }: { finding: Finding; id: string }) {
  const { t } = useTranslation();
  const catalog = useCatalog();
  const info = catalog.info(finding.module);
  const help = info?.help;
  const what = help?.checks || t("understand.whatDefault", { module: moduleLabel(t, catalog, finding.module) });
  const why = help?.why || t("understand.whyDefault");
  const fallback = t(`fix.modules.${finding.module}`, { defaultValue: t(`fix.families.${finding.family}`) });
  return (
    <dl id={id} className={styles.detail}>
      <div>
        <dt>{t("understand.what")}</dt>
        <dd>
          <GlossaryText text={what} />
        </dd>
      </div>
      <div>
        <dt>{t("understand.why")}</dt>
        <dd>
          <GlossaryText text={why} />
        </dd>
      </div>
      <div>
        <dt>{t("understand.fix")}</dt>
        <dd>
          <FixAdvice info={info} fallback={fallback} id={id} />
        </dd>
      </div>
    </dl>
  );
}

function FindingItem({ finding, scanId, linkFamily, id }: { finding: Finding; scanId: number; linkFamily: boolean; id: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <li className={styles.finding} data-severity={finding.severity} data-tour="result-finding">
      <SeverityBadge severity={finding.severity} />
      <span className={styles.findingMessage}>{finding.message}</span>
      <button
        type="button"
        className={styles.understand}
        aria-expanded={open}
        aria-controls={`${id}-detail`}
        onClick={() => setOpen((value) => !value)}
      >
        {t("understand.toggle")}
        <ChevronDown aria-hidden />
      </button>
      {linkFamily && (
        <Link
          // Droit à l'onglet du module concerné (un module inconnu de la famille ouvre son premier onglet).
          to={`/scans/${scanId}/${finding.family}/${encodeURIComponent(finding.module)}`}
          className={styles.findingFamily}
          aria-label={t("findings.openFamily", { family: t(`families.${finding.family}.name`) })}
        >
          {t(`families.${finding.family}.name`)}
          <ChevronRight aria-hidden />
        </Link>
      )}
      {open && <FindingDetail finding={finding} id={`${id}-detail`} />}
    </li>
  );
}

// Liste de famille vide : « rien à corriger » seulement si l'état de la famille
// est sain ; un état dégradé sans constat renvoie au détail des modules.
function emptyFamilyKey(state: FamilyState): string {
  if (state === "unmeasured") return "family.noFindingsUnmeasured";
  if (state === "skipped") return "family.noFindingsSkipped";
  if (state === "warning" || state === "critical") return "family.noFindingsDegraded";
  return "family.noFindings";
}

// État que dit une liste vide (icône et ton du message) : sain, ou une raison de ne pas conclure.
const EMPTY_STATES: Record<string, FamilyState> = {
  "findings.none": "ok",
  "findings.noneLowCoverage": "warning",
  "findings.noneError": "critical",
  "family.noFindings": "ok",
  "family.noFindingsUnmeasured": "unmeasured",
  "family.noFindingsSkipped": "skipped",
  "family.noFindingsDegraded": "warning",
};

// « À corriger » : constats calculés par l'API, déjà triés par gravité. Une
// liste vide n'est « rien à corriger » que si le scan a pu conclure.
// `limit` : nombre de constats montrés d'emblée (les plus graves d'abord) ; un bouton montre le reste.
export function FindingsList({
  scan,
  family,
  titleId,
  limit,
}: {
  scan: ScanResponse;
  family?: FamilyKey;
  titleId: string;
  limit?: number;
}) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const findings = (scan.findings ?? []).filter((finding) => !family || finding.family === family);
  if (!findings.length) {
    const key = family ? emptyFamilyKey(scan.families?.[family]?.state ?? "unmeasured") : findingsEmptyKey(scan);
    const state = EMPTY_STATES[key] ?? "unmeasured";
    const Icon = STATE_ICONS[state];
    return (
      <p className={styles.empty} data-state={state}>
        <Icon aria-hidden />
        <span>{t(key)}</span>
      </p>
    );
  }
  const shown = limit !== undefined && !expanded ? findings.slice(0, limit) : findings;
  const hidden = findings.length - shown.length;
  return (
    <>
    <ul className={styles.findings} aria-labelledby={titleId}>
      {shown.map((finding, index) => (
        <FindingItem
          key={`${finding.module}-${index}`}
          finding={finding}
          scanId={scan.id}
          linkFamily={!family}
          id={`${titleId}-f${index}`}
        />
      ))}
    </ul>
    {limit !== undefined && findings.length > limit && (
      <button
        type="button"
        className={`btn ${styles.more}`}
        data-variant="ghost"
        aria-expanded={expanded}
        onClick={() => setExpanded((value) => !value)}
      >
        {expanded ? t("findings.showLess") : t("findings.showAll", { count: hidden })}
      </button>
    )}
    </>
  );
}
