import type { Tone } from "../lib/tones";
import styles from "./CountBadge.module.css";

interface CountBadgeProps {
  count: number;
  // « critical » est le rouge (danger) ; « neutral » par défaut.
  tone?: Tone;
  // Au-delà, la pastille affiche « max+ » (99+ par défaut).
  max?: number;
}

// Pastille ronde à petit chiffre : compte de constats, de modules, d'éléments. La
// couleur dit le ton, le chiffre dit la quantité : l'un n'est jamais le seul indice.
export function CountBadge({ count, tone = "neutral", max = 99 }: CountBadgeProps) {
  const value = Number.isFinite(count) ? Math.max(0, Math.trunc(count)) : 0;
  return (
    <span className={styles.badge} data-tone={tone}>
      {value > max ? `${max}+` : value}
    </span>
  );
}
