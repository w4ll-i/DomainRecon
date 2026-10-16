import type { ReactNode } from "react";
import type { Tone } from "../lib/tones";
import styles from "./StatCard.module.css";

interface StatCardProps {
  // « hero » : grande carte d'un chiffre clé ; « secondary » : petite carte d'appoint.
  variant: "hero" | "secondary";
  // Étiquette courte, mise en majuscules par le CSS (mono).
  label: string;
  value: ReactNode;
  // Icône décorative (par exemple <Globe />) : le ton la colore, le texte dit l'état.
  icon?: ReactNode;
  tone?: Tone;
  // Classe supplémentaire (espacement…).
  className?: string;
}

// Carte à deux niveaux. L'entrée est animée par les classes de global.css : .
// pour une grande carte, . pour une petite (même fondu court).
export function StatCard({ variant, label, value, icon, tone = "neutral", className }: StatCardProps) {
  const enter = variant === "hero" ? "" : "";
  return (
    <div className={[styles.card, enter, className].filter(Boolean).join(" ")} data-variant={variant} data-tone={tone}>
      <span className={styles.head}>
        {icon && (
          <span className={styles.icon} aria-hidden="true">
            {icon}
          </span>
        )}
        <span className={styles.label}>{label}</span>
      </span>
      <span className={styles.value}>{value}</span>
    </div>
  );
}
