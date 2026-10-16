import styles from "../styles/ops.module.css";

// Mini courbe de tendance des scores (0 à 100) : un trait, sans axe. Moins de deux points
// mesurés : rien à tracer.
export function Sparkline({ values, label }: { values: Array<number | null>; label: string }) {
  const points = values.filter((value): value is number => value !== null);
  if (points.length < 2) return <span aria-hidden>—</span>;
  const width = 90;
  const height = 24;
  const step = width / (points.length - 1);
  const path = points
    .map((value, index) => {
      const y = height - 2 - (Math.min(100, Math.max(0, value)) / 100) * (height - 4);
      return `${(index * step).toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg className={styles.sparkline} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      <polyline points={path} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}
