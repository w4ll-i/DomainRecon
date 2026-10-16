import {
  CategoryScale,
  type ChartData,
  Chart as ChartJS,
  type ChartOptions,
  Filler,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from "chart.js";
import { Line } from "react-chartjs-2";
import { useTranslation } from "react-i18next";
import type { Lang, TimelineEntry } from "../../api/types";
import { gradeToken, withAlpha } from "../../lib/colors";
import { formatDate } from "../../lib/format";
import { timelineScoreView } from "../../lib/score";
import { useChartColors } from "../../lib/useChartColors";
import styles from "./timeline.module.css";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip);

// Pointillés des segments qui touchent un score indicatif.
const INDICATIVE_DASH = [6, 4];

// Courbe du score (entrées dont la ligne montre un score, indicatif compris).
// Même règle que le tableau (lib/score.ts) : points colorés par note ; un score
// indicatif (couverture insuffisante) se distingue aussi sans la couleur
// (WCAG 1.4.1) : triangle creux, segments en pointillés, « (indicatif) » dans
// l'infobulle et dans la description pour les lecteurs d'écran. Les couleurs (courbe,
// grille, graduations, notes) viennent des jetons du thème courant (useChartColors) :
// le graphique se redessine à la bascule clair / sombre.
export function ScoreChart({ entries, lang }: { entries: TimelineEntry[]; lang: Lang }) {
  const { t } = useTranslation();
  const colors = useChartColors();
  const views = entries.map((entry) => timelineScoreView(entry));
  const indicative = views.map((view) => view.kind === "indicative");
  const values = views.map((view) => view.value ?? 0);
  const gradeColors = entries.map((entry, index) => colors.grades[gradeToken(views[index].kind === "score" ? entry.grade : "N/A")]);
  const indicativeCount = indicative.filter(Boolean).length;
  const suffix = (index: number) => (indicative[index] ? ` ${t("common.indicative")}` : "");
  const data: ChartData<"line"> = {
    labels: entries.map((entry) => formatDate(entry.timestamp, lang)),
    datasets: [
      {
        label: t("timeline.chartTitle"),
        data: values,
        borderColor: colors.accent,
        // Aire sous la courbe : un aplat très léger de l'accent, sans dégradé.
        backgroundColor: withAlpha(colors.accent, 0.08),
        fill: true,
        tension: 0.3,
        borderWidth: 2,
        pointRadius: indicative.map((value) => (value ? 6 : 5)),
        pointHoverRadius: indicative.map((value) => (value ? 8 : 7)),
        pointStyle: indicative.map((value) => (value ? "triangle" : "circle")),
        // Point creux (fond de la carte) pour un score indicatif.
        pointBackgroundColor: gradeColors.map((color, index) => (indicative[index] ? colors.surface : color)),
        pointBorderColor: gradeColors,
        pointBorderWidth: indicative.map((value) => (value ? 2 : 1)),
        segment: {
          borderDash: (ctx) => (indicative[ctx.p0DataIndex] || indicative[ctx.p1DataIndex] ? INDICATIVE_DASH : undefined),
        },
      },
    ],
  };
  const tick = { color: colors.textSecondary, font: { family: colors.fontMono, size: 11 } };
  const options: ChartOptions<"line"> = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    scales: {
      y: { min: 0, max: 100, grid: { color: colors.border }, border: { color: colors.borderStrong }, ticks: tick },
      x: { grid: { display: false }, border: { color: colors.borderStrong }, ticks: tick },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: colors.surface,
        titleColor: colors.text,
        bodyColor: colors.text,
        borderColor: colors.borderStrong,
        borderWidth: 1,
        padding: 10,
        cornerRadius: 6,
        titleFont: { family: colors.fontMono, size: 11 },
        bodyFont: { family: colors.fontMono, size: 12 },
        callbacks: {
          label: (ctx) => `${t("timeline.chartTooltip", { label: ctx.dataset.label, value: ctx.formattedValue })}${suffix(ctx.dataIndex)}`,
        },
      },
    },
  };
  const last = values.length - 1;
  const aria = {
    count: entries.length,
    first: `${values[0]}${suffix(0)}`,
    last: `${values[last]}${suffix(last)}`,
    indicative: indicativeCount,
  };
  return (
    <>
      <div className={styles.chart}>
        <Line
          data={data}
          options={options}
          role="img"
          aria-label={t(indicativeCount ? "timeline.chartAriaIndicative" : "timeline.chartAria", aria)}
        />
      </div>
      {indicativeCount > 0 && <p className={styles.muted}>{t("timeline.chartIndicativeNote")}</p>}
    </>
  );
}
