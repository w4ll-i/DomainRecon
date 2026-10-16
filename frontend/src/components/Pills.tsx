import { CircleX, Info, LoaderCircle, type LucideIcon, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { Severity } from "../api/types";
import type { ModuleViewStatus } from "../lib/moduleState";
import type { Tone } from "../lib/tones";
import styles from "./Pills.module.css";

export function Pill({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={styles.pill} data-tone={tone} title={title}>
      {children}
    </span>
  );
}

const SCAN_STATUS_TONES: Record<string, Tone> = { success: "ok", partial: "warning", error: "critical" };

export function ScanStatusPill({ status }: { status: string }) {
  const { t } = useTranslation();
  const known = Object.hasOwn(SCAN_STATUS_TONES, status);
  return <Pill tone={known ? SCAN_STATUS_TONES[status] : "neutral"}>{t(`scanStatus.${known ? status : "unknown"}`)}</Pill>;
}

export type ModulePillStatus = ModuleViewStatus | "pending" | "running";

// OK (vert), non mesuré (gris pointillé), sans objet (gris), en cours (accent animé).
const MODULE_TONES: Record<ModulePillStatus, Tone> = {
  ok: "ok",
  failed: "na",
  timeout: "na",
  skipped: "neutral",
  not_launched: "neutral",
  pending: "na",
  running: "accent",
};

export function ModuleStatusPill({ status }: { status: ModulePillStatus }) {
  const { t } = useTranslation();
  return (
    <Pill tone={MODULE_TONES[status]}>
      {status === "running" && <LoaderCircle aria-hidden className="spin" />}
      {t(`moduleStatus.${status}`)}
    </Pill>
  );
}

// Une icône par gravité : la gravité ne se lit jamais par la seule couleur.
const SEVERITY_ICONS: Record<Severity, LucideIcon> = {
  critical: CircleX,
  high: CircleX,
  medium: TriangleAlert,
  low: Info,
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { t } = useTranslation();
  const Icon = SEVERITY_ICONS[severity] ?? Info;
  return (
    <span className={styles.severity} data-severity={severity}>
      <Icon aria-hidden />
      {t(`severity.${severity}`)}
    </span>
  );
}
