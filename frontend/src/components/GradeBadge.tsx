import { useTranslation } from "react-i18next";
import { gradeToken } from "../lib/colors";
import styles from "./GradeBadge.module.css";

interface GradeBadgeProps {
  grade: string | null | undefined;
  size?: "xl" | "md" | "sm";
  label?: string;
}

export function GradeBadge({ grade, size = "md", label }: GradeBadgeProps) {
  const { t } = useTranslation();
  const token = gradeToken(grade);
  const text = token === "NA" ? "N/A" : token;
  return (
    <span
      className={`${styles.grade} ${styles[size]}`}
      data-grade={token}
      role="img"
      aria-label={label ?? t("grade.aria", { grade: text })}
    >
      {text}
    </span>
  );
}
