import type { ReactNode } from "react";
import type { ModuleName, ScanResponse } from "../api/types";
import { scanModuleState } from "../lib/moduleState";
import { useModuleLabel } from "../lib/useModuleLabel";
import styles from "./ModuleCard.module.css";
import { ModuleStatusPill } from "./Pills";
import { UnavailableNotice } from "./UnavailableNotice";

interface ModuleCardProps {
  scan: ScanResponse;
  module: ModuleName;
  children?: ReactNode;
  // Contenu partiel à garder sous l'avertissement (chaîne de redirections…).
  showChildrenWhenUnavailable?: boolean;
  headerExtra?: ReactNode;
}

export function ModuleCard({ scan, module, children, showChildrenWhenUnavailable = false, headerExtra }: ModuleCardProps) {
  const label = useModuleLabel();
  const state = scanModuleState(scan, module);
  const unavailable = state.status !== "ok";
  const titleId = `module-${module}`;
  return (
    <section className={styles.card} aria-labelledby={titleId} data-module={module} data-status={state.status}>
      <header className={styles.header}>
        <h2 id={titleId} className={styles.title}>
          {label(module)}
        </h2>
        {headerExtra}
        <ModuleStatusPill status={state.status} />
      </header>
      {unavailable && <UnavailableNotice state={state} />}
      {(!unavailable || showChildrenWhenUnavailable) && children}
    </section>
  );
}
