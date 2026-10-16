import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import styles from "../styles/ops.module.css";

// Écran vide qui explique quoi faire : une icône, un titre, une phrase et l'action à mener.
export function EmptyHint({
  icon: Icon,
  title,
  text,
  children,
}: {
  icon: LucideIcon;
  title: string;
  text: string;
  children?: ReactNode;
}) {
  return (
    <div className={styles.empty}>
      <Icon aria-hidden />
      <p className={styles.emptyTitle}>{title}</p>
      <p className={styles.muted}>{text}</p>
      {children}
    </div>
  );
}
