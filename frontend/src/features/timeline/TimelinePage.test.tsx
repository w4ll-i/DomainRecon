import { act, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SecurityScore } from "../../api/types";
import { formatDate } from "../../lib/format";
import { resetChartColors } from "../../lib/useChartColors";
import { jsonResponse, mockFetch } from "../../test/fetchMock";
import { makeSummary, makeTimeline } from "../../test/fixtures";
import { renderWithProviders } from "../../test/render";
import { HistoryPage } from "../history/HistoryPage";
import { TimelinePage } from "./TimelinePage";

// Chart.js dessine dans un canvas (absent de jsdom) : le graphique est remplacé
// par un témoin qui expose ses données, ses attributs d'accessibilité, le style
// de chaque point, le texte de l'infobulle de chaque point et les couleurs de la
// courbe, de la grille et des graduations (data-line, data-grid, data-tick).
interface ChartDataset {
  label: string;
  data: number[];
  borderColor?: string;
  pointStyle?: string[];
  pointBackgroundColor?: string[];
  pointBorderColor?: string[];
  segment?: { borderDash?: (ctx: { p0DataIndex: number; p1DataIndex: number }) => number[] | undefined };
}
interface ChartProps {
  data: { datasets: ChartDataset[] };
  options?: {
    scales?: { y?: { grid?: { color?: string }; ticks?: { color?: string } } };
    plugins?: {
      tooltip?: { callbacks?: { label?: (ctx: { dataIndex: number; formattedValue: string; dataset: ChartDataset }) => string } };
    };
  };
  "aria-label"?: string;
  role?: string;
}
vi.mock("react-chartjs-2", () => ({
  Line: (props: ChartProps) => {
    const dataset = props.data.datasets[0];
    const label = props.options?.plugins?.tooltip?.callbacks?.label;
    return (
      <div
        data-testid="chart"
        role={props.role}
        aria-label={props["aria-label"]}
        data-line={dataset.borderColor}
        data-grid={props.options?.scales?.y?.grid?.color}
        data-tick={props.options?.scales?.y?.ticks?.color}
      >
        {dataset.data.join(",")}
        <ol data-testid="chart-points">
          {dataset.data.map((value, index) => (
            <li
              key={index}
              data-style={dataset.pointStyle?.[index]}
              data-fill={dataset.pointBackgroundColor?.[index]}
              data-border={dataset.pointBorderColor?.[index]}
              data-dash={
                index > 0 ? String(Boolean(dataset.segment?.borderDash?.({ p0DataIndex: index - 1, p1DataIndex: index }))) : undefined
              }
            >
              {label ? label({ dataIndex: index, formattedValue: String(value), dataset }) : ""}
            </li>
          ))}
        </ol>
      </div>
    );
  },
}));

const chartValues = () => screen.getByTestId("chart").firstChild?.textContent;

function renderTimeline(domain = "example.com") {
  return renderWithProviders(<TimelinePage />, { route: `/history/${domain}`, path: "/history/:domain" });
}

// Les couleurs du graphique sont lues sur les jetons du document et mémorisées par thème :
// un test qui pose des jetons ne doit rien laisser derrière lui.
const root = document.documentElement;
beforeEach(() => {
  resetChartColors();
});
afterEach(() => {
  root.removeAttribute("style");
  root.removeAttribute("data-theme");
  resetChartColors();
});

describe("écran Timeline", () => {
  it("trace l'évolution du score et liste les scans", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    // Le titre est affiché dès le chargement : c'est le total qui signale l'arrivée des données.
    expect(await screen.findByText("3 scan(s) pour example.com")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Timeline de example.com" })).toBeInTheDocument();
    // Le scan noté N/A (sans score) n'est pas tracé.
    expect(screen.getByRole("img", { name: "Évolution du score sur 2 scans, de 62 à 78" })).toBeInTheDocument();
    expect(chartValues()).toBe("62,78");
    const rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(rows).toHaveLength(4);
    expect(within(rows[1]).getByRole("link")).toHaveAttribute("href", "/scans/40");
  });

  it("dit la vérité : premier relevé, N/A non mesuré, score absent sans mesure, changements DNS", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    expect(rows[1]).toHaveTextContent("Premier relevé");
    const unmeasured = within(rows[2]).getByTitle("Non mesuré (échec, délai dépassé ou sans objet)");
    expect(unmeasured).toHaveTextContent("N/A");
    // Explication visible (légende liée à la cellule), pas seulement en infobulle.
    const note = screen.getByText("N/A : valeur non mesurée (échec, délai dépassé ou sans objet).");
    expect(unmeasured.closest("td")).toHaveAttribute("aria-describedby", note.id);
    expect(screen.queryByText(/Seuls les/)).not.toBeInTheDocument();
    // Rien de mesuré : le serveur ne transmet pas le score, jamais présenté comme un 0/100.
    expect(rows[2]).not.toHaveTextContent("/100");
    expect(within(rows[2]).getByRole("img", { name: "Note N/A" })).toBeInTheDocument();
    expect(rows[2]).toHaveTextContent("+ 93.184.216.34");
    expect(rows[2]).toHaveTextContent("− 93.184.216.30");
    expect(rows[3]).toHaveTextContent("Aucun changement");
  });

  it("ancien scan noté sous 50 % de couverture : score indicatif, note N/A", async () => {
    const timeline = makeTimeline();
    timeline.timeline[1] = { ...timeline.timeline[1], security_score: 71, grade: "C", coverage: 45, measured_max: 40 };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    expect(rows[2]).toHaveTextContent("71/100 (indicatif)");
    expect(within(rows[2]).getByRole("img", { name: "Note N/A" })).toBeInTheDocument();
  });

  it("scan actuel sous 50 % : score indicatif, tracé, comme dans l'Historique", async () => {
    const timeline = makeTimeline();
    timeline.timeline[1] = { ...timeline.timeline[1], security_score: 60, grade: "N/A", coverage: 40, measured_max: 40 };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    expect(rows[2]).toHaveTextContent("60/100 (indicatif)");
    expect(within(rows[2]).getByRole("img", { name: "Note N/A" })).toBeInTheDocument();
    expect(chartValues()).toBe("62,60,78");
  });

  it("courbe : un score indicatif se distingue autrement que par la couleur (forme, pointillés, infobulle, lecteur d'écran)", async () => {
    const timeline = makeTimeline();
    timeline.timeline[0] = { ...timeline.timeline[0], security_score: 60, grade: "N/A", coverage: 40, measured_max: 40 };
    timeline.timeline[1] = { ...timeline.timeline[1], security_score: 62, grade: "C", coverage: 80, measured_max: 80 };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    const chart = await screen.findByRole("img", {
      name: "Évolution du score sur 3 scans, de 60 (indicatif) à 78, dont 1 score(s) indicatif(s)",
    });
    expect(chartValues()).toBe("60,62,78");
    const points = within(chart).getAllByRole("listitem");
    // Point indicatif : triangle creux ; vraies notes : rond plein.
    expect(points.map((point) => point.dataset.style)).toEqual(["triangle", "circle", "circle"]);
    expect(points[0].dataset.fill).not.toBe(points[0].dataset.border);
    expect(points[1].dataset.fill).toBe(points[1].dataset.border);
    // Segment qui touche le point indicatif : en pointillés ; les autres, pleins.
    expect(points.slice(1).map((point) => point.dataset.dash)).toEqual(["true", "false"]);
    // Infobulle.
    expect(points[0]).toHaveTextContent("Évolution du score : 60 (indicatif)");
    expect(points[1]).toHaveTextContent("Évolution du score : 62");
    expect(points[1]).not.toHaveTextContent("indicatif");
    expect(screen.getByText("Triangle creux et trait en pointillés : score indicatif (couverture insuffisante), pas une note.")).toBeInTheDocument();
  });

  it("courbe sans score indicatif : pas de légende des scores indicatifs", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    await screen.findByRole("img", { name: "Évolution du score sur 2 scans, de 62 à 78" });
    expect(screen.queryByText(/Triangle creux/)).not.toBeInTheDocument();
  });

  it("ancien scan sans measured_max noté sous 50 % : N/A comme dans l'Historique, non tracé", async () => {
    const timeline = makeTimeline();
    timeline.timeline[1] = { ...timeline.timeline[1], security_score: 71, grade: "C", coverage: 45, measured_max: null };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    expect(rows[2]).not.toHaveTextContent("/100");
    expect(within(rows[2]).getByRole("img", { name: "Note N/A" })).toBeInTheDocument();
    expect(chartValues()).toBe("62,78");
  });

  it.each<[string, SecurityScore, string]>([
    ["note normale", { score: 78, grade: "B", coverage: 90, measured_max: 90 }, "78/100"],
    ["N/A sous 50 % avec critères comptés", { score: 60, grade: "N/A", coverage: 40, measured_max: 40 }, "60/100 (indicatif)"],
    ["aucune mesure", { score: 0, grade: "N/A", coverage: 0, measured_max: 0 }, "N/A"],
    ["ancien scan noté sous 50 % sans measured_max", { score: 71, grade: "C", coverage: 45 }, "N/A"],
    ["scan en erreur, sans note", {}, "N/A"],
    ["score en chaîne", { score: "78", grade: "B", coverage: 90 } as unknown as SecurityScore, "N/A"],
    ["score illisible", { score: "abc", grade: "B" } as unknown as SecurityScore, "N/A"],
    ["measured_max en chaîne", { score: 60, grade: "N/A", coverage: 40, measured_max: "40" } as unknown as SecurityScore, "N/A"],
    ["measured_max booléen", { score: 60, grade: "N/A", coverage: 40, measured_max: true } as unknown as SecurityScore, "N/A"],
  ])("même affichage du score que l'Historique : %s", async (_label, ss, expected) => {
    // Relevé tel que le serveur l'envoie (history._timeline_entry, _number).
    const num = (value: unknown) => (typeof value === "number" && Number.isFinite(value) ? value : null);
    const coverage = num(ss.coverage);
    const measuredMax = num(ss.measured_max);
    const low = coverage !== null && coverage < 50;
    const kept = coverage !== 0 && ((ss.grade !== "N/A" && !low) || (measuredMax !== null && measuredMax > 0));
    const timeline = makeTimeline();
    timeline.timeline[1] = {
      ...timeline.timeline[1],
      security_score: kept ? num(ss.score) : null,
      grade: typeof ss.grade === "string" ? ss.grade : null,
      coverage,
      measured_max: measuredMax,
    };
    mockFetch({
      "GET /api/history": { total: 1, scans: [makeSummary({ security_score: ss })] },
      "GET /api/dns-timeline/example.com": timeline,
    });
    const scoreText = (cell: HTMLElement) => (cell.textContent ?? "").replace(/\s+/g, " ").trim();
    const history = renderWithProviders(<HistoryPage />, { route: "/history", path: "/history" });
    const historyRow = within(await screen.findByRole("table")).getAllByRole("row")[1];
    const historyCell = within(historyRow).getAllByRole("cell")[1];
    const historyScore = scoreText(historyCell);
    const historyBadge = within(historyRow).getByRole("img", { name: /^Note / }).getAttribute("aria-label");
    history.unmount();
    renderTimeline();
    const timelineRow = within(await screen.findByRole("table")).getAllByRole("row")[2];
    const timelineScore = within(timelineRow).getAllByRole("cell")[4];
    expect(historyScore).toBe(expected);
    // Texte exact du score (la cellule ajoute ensuite la note et la couverture).
    expect(scoreText(timelineScore.querySelector(".mono") as HTMLElement)).toBe(expected);
    if (!expected.includes("indicatif")) expect(within(timelineScore).queryByText(/indicatif/)).not.toBeInTheDocument();
    if (expected === "N/A") expect(timelineScore).not.toHaveTextContent("/100");
    // Même badge de note des deux côtés (N/A compris, même sans note enregistrée).
    expect(within(timelineScore).getByRole("img", { name: /^Note / })).toHaveAttribute("aria-label", historyBadge);
  });

  it("relevé non comparable quand l'historique affiché est incomplet", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline({ total_scans: 12 }) });
    renderTimeline();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    expect(rows[1]).toHaveTextContent("Non comparable");
  });

  it("signale la troncature : seuls les relevés les plus récents sont affichés", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline({ total_scans: 150 }) });
    renderTimeline();
    expect(await screen.findByText("Seuls les 3 relevés les plus récents sont affichés, sur 150.")).toBeInTheDocument();
    expect(screen.getByText("150 scan(s) pour example.com")).toBeInTheDocument();
  });

  it("limite les changements affichés par type", async () => {
    const timeline = makeTimeline();
    const added = Array.from({ length: 8 }, (_, i) => `10.0.0.${i}`);
    timeline.timeline[2] = { ...timeline.timeline[2], dns_changes: { A: { added, removed: [] } } };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    const rows = within(await screen.findByRole("table")).getAllByRole("row");
    expect(rows[3]).toHaveTextContent("… et 3 autre(s)");
  });

  it("propose les domaines liés du même site", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const related = await screen.findByRole("link", { name: "shop.example.com (1 scan(s))" });
    expect(related).toHaveAttribute("href", "/history/shop.example.com");
  });

  it("pas assez de données : explication et domaines liés", async () => {
    const base = makeTimeline();
    mockFetch({ "GET /api/dns-timeline/shop.example.com": { ...base, domain: "shop.example.com", total_scans: 1, timeline: [base.timeline[0]] } });
    renderTimeline("shop.example.com");
    expect(await screen.findByText("Pas assez de données")).toBeInTheDocument();
    expect(screen.getByText(/Actuellement : 1 scan\(s\) pour shop\.example\.com\./)).toBeInTheDocument();
    expect(screen.queryByTestId("chart")).not.toBeInTheDocument();
  });

  it("nom de domaine invalide dans l'adresse : message clair, sans « Réessayer »", async () => {
    mockFetch({
      "GET /api/dns-timeline/bad_domain": () => jsonResponse({ detail: "Nom de domaine invalide", code: null, params: {} }, 400),
    });
    renderTimeline("bad_domain");
    expect(await screen.findByText("Nom de domaine invalide")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("« bad_domain » n'est pas un nom de domaine valide : vérifiez l'adresse.");
    expect(screen.queryByRole("button", { name: "Réessayer" })).not.toBeInTheDocument();
    expect(within(screen.getByRole("alert")).getByRole("link", { name: "Retour à l'historique" })).toHaveAttribute("href", "/history");
  });

  it("domaine jamais scanné : message, pas d'erreur", async () => {
    mockFetch({
      "GET /api/dns-timeline/inconnu.example": () => jsonResponse({ detail: "Aucun scan trouvé pour ce domaine", code: null, params: {} }, 404),
    });
    renderTimeline("inconnu.example");
    expect(await screen.findByText("Aucun historique pour ce domaine.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    // Pas de données : pas d'indicateurs.
    expect(screen.queryByRole("group", { name: "Indicateurs de la timeline" })).not.toBeInTheDocument();
  });
});

describe("écran Timeline : indicateurs", () => {
  const kpiCard = (kpis: HTMLElement, label: string) => within(kpis).getByText(label).closest("[data-variant]") as HTMLElement;

  it("résume le domaine en trois cartes : nombre de scans, meilleure note, dernier scan", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const kpis = await screen.findByRole("group", { name: "Indicateurs de la timeline" });
    expect(within(kpis).getAllByText(/^(Scans|Meilleure note|Dernier scan)$/)).toHaveLength(3);
    expect(kpiCard(kpis, "Scans")).toHaveTextContent("3");
    // Meilleure note : le B de 78 points (le C de 62 est moins bon ; le relevé sans note n'entre pas en compte).
    const best = kpiCard(kpis, "Meilleure note");
    expect(within(best).getByRole("img", { name: "Note B" })).toBeInTheDocument();
    expect(best).toHaveTextContent("78/100");
    // Dernier scan : la date du dernier relevé, mise en forme comme dans le tableau.
    expect(kpiCard(kpis, "Dernier scan")).toHaveTextContent(formatDate("2026-09-28T10:05:00Z", "fr"));
    // Aucun attribut style (CSP stricte), aucune cascade d'entrée.
    expect(kpis.className).not.toMatch(/stagger/);
    expect(kpis.querySelector("[style]")).toBeNull();
  });

  it("le nombre de scans est le total du serveur, même quand seuls les relevés récents sont listés", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline({ total_scans: 150 }) });
    renderTimeline();
    const kpis = await screen.findByRole("group", { name: "Indicateurs de la timeline" });
    expect(kpiCard(kpis, "Scans")).toHaveTextContent("150");
  });

  it("à note égale, la meilleure note garde le score le plus haut ; une note A l'emporte sur toutes", async () => {
    const timeline = makeTimeline();
    timeline.timeline[0] = { ...timeline.timeline[0], security_score: 70, grade: "B", coverage: 90, measured_max: 90 };
    timeline.timeline[2] = { ...timeline.timeline[2], security_score: 74, grade: "B", coverage: 90, measured_max: 90 };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    const first = renderTimeline();
    let best = kpiCard(await screen.findByRole("group", { name: "Indicateurs de la timeline" }), "Meilleure note");
    expect(best).toHaveTextContent("74/100");
    first.unmount();

    timeline.timeline[0] = { ...timeline.timeline[0], security_score: 95, grade: "A" };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    best = kpiCard(await screen.findByRole("group", { name: "Indicateurs de la timeline" }), "Meilleure note");
    expect(within(best).getByRole("img", { name: "Note A" })).toBeInTheDocument();
    expect(best).toHaveTextContent("95/100");
  });

  it("sans vraie note (score indicatif, N/A) : « N/A », jamais une note inventée", async () => {
    const timeline = makeTimeline();
    // Couverture sous 50 % : score indicatif, pas de note ; l'autre relevé n'a rien mesuré.
    timeline.timeline[0] = { ...timeline.timeline[0], security_score: 60, grade: "N/A", coverage: 40, measured_max: 40 };
    timeline.timeline[2] = { ...timeline.timeline[2], security_score: null, grade: "N/A", coverage: 0, measured_max: 0 };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    const kpis = await screen.findByRole("group", { name: "Indicateurs de la timeline" });
    const best = kpiCard(kpis, "Meilleure note");
    expect(best).toHaveTextContent("N/A");
    expect(within(best).queryByRole("img")).not.toBeInTheDocument();
    expect(best).not.toHaveTextContent("/100");
    expect(best).toHaveAttribute("data-tone", "na");
  });

  it("le ton de la carte suit la meilleure note (la lettre dit la même chose)", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const kpis = await screen.findByRole("group", { name: "Indicateurs de la timeline" });
    expect(kpiCard(kpis, "Meilleure note")).toHaveAttribute("data-tone", "ok");
    expect(kpiCard(kpis, "Scans")).toHaveAttribute("data-tone", "accent");
  });

  it("pas assez de données : les indicateurs du relevé unique restent affichés", async () => {
    const base = makeTimeline();
    mockFetch({
      "GET /api/dns-timeline/shop.example.com": { ...base, domain: "shop.example.com", total_scans: 1, timeline: [base.timeline[0]] },
    });
    renderTimeline("shop.example.com");
    const kpis = await screen.findByRole("group", { name: "Indicateurs de la timeline" });
    expect(kpiCard(kpis, "Scans")).toHaveTextContent("1");
    expect(kpiCard(kpis, "Meilleure note")).toHaveTextContent("62/100");
    expect(screen.getByText("Pas assez de données")).toBeInTheDocument();
  });

  it("aucun indicateur pendant le chargement ni sans relevé", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": () => new Promise<Response>(() => undefined) });
    const loading = renderTimeline();
    expect(screen.getByRole("status")).toHaveTextContent("Chargement…");
    expect(screen.queryByRole("group", { name: "Indicateurs de la timeline" })).not.toBeInTheDocument();
    loading.unmount();

    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline({ total_scans: 0, timeline: [] }) });
    renderTimeline();
    expect(await screen.findByText("Pas assez de données")).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Indicateurs de la timeline" })).not.toBeInTheDocument();
  });
});

describe("écran Timeline : mise en page et mouvement", () => {
  it("titre de niveau 1 avec étiquette et domaine, sections nommées", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    const { container } = renderTimeline();
    await screen.findByRole("group", { name: "Indicateurs de la timeline" });
    const title = screen.getByRole("heading", { level: 1, name: "Timeline de example.com" });
    expect(screen.getByText("Évolution")).toBeInTheDocument();
    // Le domaine est mis en valeur dans le titre sans changer le nom accessible.
    expect(title.querySelector("span")).toHaveTextContent("example.com");
    // Chaque bloc est une région nommée par son titre de niveau 2.
    const chart = screen.getByRole("region", { name: "Évolution du score" });
    const records = screen.getByRole("region", { name: "Scans et changements DNS" });
    const related = screen.getByRole("region", { name: "Autres cibles du même site (example.com)" });
    expect(within(chart).getByTestId("chart")).toBeInTheDocument();
    expect(within(records).getByRole("table")).toBeInTheDocument();
    expect(within(related).getByRole("link", { name: "shop.example.com (1 scan(s))" })).toBeInTheDocument();
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("le tableau, qui défile à l'horizontale sur un écran étroit, est une région nommée atteignable au clavier", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const region = await screen.findByRole("region", { name: "Relevés de la timeline (défilable horizontalement)" });
    expect(region).toHaveAttribute("tabindex", "0");
    expect(within(region).getByRole("table")).toBeInTheDocument();
  });

  it("chaque cellule de donnée porte son libellé (data-label) pour la mise en cartes sur téléphone", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const row = within(await screen.findByRole("table")).getAllByRole("row")[3];
    // La date sert de titre à la carte : elle n'a pas de libellé.
    expect(within(row).getAllByRole("cell").map((cell) => cell.getAttribute("data-label"))).toEqual([
      null,
      "IP",
      "Sous-dom.",
      "Ports",
      "Score",
      "Changements DNS",
    ]);
  });

  it("pas de courbe ni de carte « courbe » avec moins de deux scores, mais le tableau et les indicateurs restent", async () => {
    const timeline = makeTimeline();
    timeline.timeline[0] = { ...timeline.timeline[0], security_score: null, grade: "N/A", coverage: 0, measured_max: 0 };
    mockFetch({ "GET /api/dns-timeline/example.com": timeline });
    renderTimeline();
    await screen.findByRole("group", { name: "Indicateurs de la timeline" });
    expect(screen.queryByTestId("chart")).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Évolution du score" })).not.toBeInTheDocument();
    expect(screen.getByRole("table")).toBeInTheDocument();
  });
});

describe("écran Timeline : couleurs du graphique", () => {
  const setTokens = (values: Record<string, string>) => {
    for (const [name, value] of Object.entries(values)) root.style.setProperty(name, value);
  };

  it("replie sur le thème sombre quand les jetons ne sont pas appliqués", async () => {
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const chart = await screen.findByTestId("chart");
    expect(chart).toHaveAttribute("data-line", "#3b82f6");
    expect(chart).toHaveAttribute("data-grid", "#262626");
    expect(chart).toHaveAttribute("data-tick", "#a1a1a1");
    // Notes C puis B : couleurs du thème sombre.
    expect(within(chart).getAllByRole("listitem").map((point) => point.dataset.border)).toEqual(["#e0a030", "#8ba446"]);
  });

  it("prend les couleurs des jetons du thème et se redessine à la bascule clair / sombre", async () => {
    setTokens({
      "--accent": "#e3c179",
      "--border": "#243149",
      "--text-secondary": "#8a97b3",
      "--grade-b": "#95bf6f",
      "--grade-c": "#e0b34d",
    });
    mockFetch({ "GET /api/dns-timeline/example.com": makeTimeline() });
    renderTimeline();
    const chart = await screen.findByTestId("chart");
    expect(chart).toHaveAttribute("data-line", "#e3c179");
    expect(within(chart).getAllByRole("listitem").map((point) => point.dataset.border)).toEqual(["#e0b34d", "#95bf6f"]);

    // Le thème clair redéfinit les jetons (accent ambre, notes assombries) et pose data-theme sur <html>.
    await act(async () => {
      setTokens({
        "--accent": "#b07d24",
        "--border": "#d3dae8",
        "--text-secondary": "#46536e",
        "--grade-b": "#3f7a3a",
        "--grade-c": "#7e5a14",
      });
      root.setAttribute("data-theme", "light");
      // Laisse passer le rappel (micro-tâche) du MutationObserver.
      await Promise.resolve();
    });
    expect(chart).toHaveAttribute("data-line", "#b07d24");
    expect(chart).toHaveAttribute("data-grid", "#d3dae8");
    expect(chart).toHaveAttribute("data-tick", "#46536e");
    expect(within(chart).getAllByRole("listitem").map((point) => point.dataset.border)).toEqual(["#7e5a14", "#3f7a3a"]);
  });
});
