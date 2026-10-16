import cytoscape, { type Core, type NodeSingular, type StylesheetJson } from "cytoscape";
import { Maximize, ZoomIn, ZoomOut } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { ScanResponse } from "../../../api/types";
import { type ChartColors, useChartColors } from "../../../lib/useChartColors";
import { buildGraphElements } from "./graphElements";
import styles from "./modules.module.css";

const STYLESHEET_ID = "__________cytoscape_stylesheet";

// Cytoscape insère sinon une balise <style> (refusée par la CSP stricte) : un
// élément portant son identifiant l'en dissuade. La règle équivalente
// (.__________cytoscape_container { position: relative }) est dans global.css.
function preventStyleInjection(): void {
  if (document.getElementById(STYLESHEET_ID)) return;
  const marker = document.createElement("meta");
  marker.id = STYLESHEET_ID;
  document.head.appendChild(marker);
}

// Style du graphe dans les couleurs du thème courant (jetons de tokens.css, lus par
// useChartColors) : Cytoscape dessine dans un canvas que le CSS n'atteint pas, et
// des teintes codées en dur du thème sombre y seraient illisibles en thème clair.
function graphStyle(colors: ChartColors): StylesheetJson {
  const { grades } = colors;
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        "font-size": 9,
        "font-family": "Inter, sans-serif",
        color: colors.textSecondary,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-max-width": "90px",
        "text-wrap": "ellipsis",
        "background-opacity": 0.25,
        "border-width": 1.5,
        "border-opacity": 0.8,
        width: 20,
        height: 20,
      },
    },
    {
      selector: 'node[nodeType = "domain"]',
      style: { "background-color": colors.accent, "border-color": colors.accent, width: 40, height: 40, "font-size": 11, color: colors.text },
    },
    {
      selector: 'node[nodeType = "ip"]',
      style: { "background-color": grades.B, "border-color": grades.B, width: 28, height: 28, "font-size": 10, color: grades.B },
    },
    { selector: 'node[nodeType = "sub-resolved"]', style: { "background-color": grades.A, "border-color": grades.A } },
    { selector: 'node[nodeType = "sub-unresolved"]', style: { "background-color": colors.border, "border-color": grades.NA } },
    {
      selector: 'node[nodeType = "sub-untested"]',
      style: { "background-color": colors.surface, "border-color": grades.NA, "border-style": "dashed" },
    },
    {
      selector: 'node[nodeType = "more"]',
      style: { "background-color": colors.surface, "border-color": colors.textSecondary, "border-style": "dashed", color: colors.text },
    },
    {
      selector: 'node[nodeType = "port"]',
      style: { "background-color": grades.C, "border-color": grades.C, width: 14, height: 14, "font-size": 8, color: grades.C },
    },
    { selector: "edge", style: { width: 1, "line-color": colors.border, "curve-style": "bezier" } },
    { selector: "node:selected", style: { "border-width": 3, "border-opacity": 1 } },
  ];
}

export function NetworkGraph({ scan }: { scan: ScanResponse }) {
  const { t } = useTranslation();
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  // Suit la bascule clair/sombre : le graphe est redessiné avec les jetons du nouveau thème.
  const colors = useChartColors();
  const elements = useMemo(() => buildGraphElements(scan, t), [scan, t]);
  const subdomains = elements.filter((element) => String(element.data.nodeType ?? "").startsWith("sub-")).length;
  const ports = elements.filter((element) => element.data.nodeType === "port").length;
  // Sous-domaines résumés par le nœud « +N autres » : le libellé ARIA les compte aussi.
  const more = Number(elements.find((element) => element.data.nodeType === "more")?.data.hidden) || 0;

  useEffect(() => {
    if (!container.current) return undefined;
    setHovered(null);
    preventStyleInjection();
    const instance = cytoscape({
      container: container.current,
      elements,
      style: graphStyle(colors),
      minZoom: 0.1,
      maxZoom: 3,
      boxSelectionEnabled: false,
      layout: {
        name: "concentric",
        concentric: (node: NodeSingular) => {
          const type = node.data("nodeType");
          return type === "domain" ? 3 : type === "ip" ? 2 : type === "port" ? 0 : 1;
        },
        levelWidth: () => 1,
        minNodeSpacing: 30,
        fit: true,
        padding: 30,
        animate: false,
      },
    });
    instance.on("mouseover tap", "node", (event) => {
      setHovered(String(event.target.data("detail") || event.target.data("label") || ""));
    });
    instance.on("mouseout", "node", () => setHovered(null));
    // Au toucher, aucun mouseout n'efface le détail : un toucher sur le fond le fait.
    instance.on("tap", (event) => {
      if (event.target === instance) setHovered(null);
    });
    cy.current = instance;
    return () => {
      instance.destroy();
      cy.current = null;
    };
  }, [elements, colors]);

  const zoom = (factor: number) => {
    const instance = cy.current;
    if (!instance) return;
    instance.zoom({ level: instance.zoom() * factor, renderedPosition: { x: instance.width() / 2, y: instance.height() / 2 } });
  };

  return (
    <section className={styles.card} aria-labelledby="graph-title">
      <h2 id="graph-title" className={styles.cardTitle}>
        {t("dns.graph.title")}
      </h2>
      <div
        ref={container}
        className={styles.graph}
        role="img"
        aria-label={t(more > 0 ? "dns.graph.ariaMore" : "dns.graph.aria", { domain: scan.domain, subdomains, ports, more })}
      />
      <div className={styles.graphControls}>
        <button type="button" className="btn" onClick={() => cy.current?.fit(undefined, 30)}>
          <Maximize aria-hidden />
          {t("dns.graph.fit")}
        </button>
        <button type="button" className="btn" onClick={() => zoom(1.25)} aria-label={t("dns.graph.zoomIn")} title={t("dns.graph.zoomIn")}>
          <ZoomIn aria-hidden />
        </button>
        <button type="button" className="btn" onClick={() => zoom(0.8)} aria-label={t("dns.graph.zoomOut")} title={t("dns.graph.zoomOut")}>
          <ZoomOut aria-hidden />
        </button>
        <p className={styles.muted} role="status">
          {hovered ? t("dns.graph.hover", { label: hovered }) : t("dns.graph.hint")}
        </p>
      </div>
    </section>
  );
}
