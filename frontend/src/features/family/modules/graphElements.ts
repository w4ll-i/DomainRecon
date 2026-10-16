import type { ElementDefinition } from "cytoscape";
import type { TFunction } from "i18next";
import type { ScanResponse } from "../../../api/types";
import { moduleState } from "../../../lib/moduleState";
import { normalizeOpenPorts } from "../../../lib/ports";
import { subdomainCount } from "../../../lib/verdicts";

// Au-delà, le graphe ne tient plus lisiblement dans son cadre : les autres
// sous-domaines sont résumés par un nœud « +N autres ».
export const GRAPH_MAX_SUBDOMAINS = 30;
export const GRAPH_MAX_PORTS = 20;

export type GraphNodeType = "domain" | "ip" | "sub-resolved" | "sub-unresolved" | "sub-untested" | "more" | "port";

// Éléments de la carte réseau. Les libellés sont dessinés dans un canvas
// (texte brut) : aucune donnée n'y est interprétée comme du HTML.
export function buildGraphElements(scan: ScanResponse, t: TFunction): ElementDefinition[] {
  const elements: ElementDefinition[] = [{ data: { id: "domain", label: scan.domain, nodeType: "domain", detail: scan.domain } }];
  if (scan.ip_address) {
    elements.push({ data: { id: "ip", label: scan.ip_address, nodeType: "ip", detail: scan.ip_address } });
    elements.push({ data: { id: "edge-ip", source: "domain", target: "ip" } });
  }
  const all = (Array.isArray(scan.subdomains) ? scan.subdomains : []).filter((sub) => sub && typeof sub === "object");
  const shown = all.slice(0, GRAPH_MAX_SUBDOMAINS);
  shown.forEach((sub, index) => {
    const nodeType: GraphNodeType = sub.ip ? "sub-resolved" : sub.resolution === "not_tested" ? "sub-untested" : "sub-unresolved";
    // Une résolution par joker DNS ne prouve pas que le nom existe : le détail le dit.
    const extra = sub.ip
      ? sub.wildcard === true
        ? t("dns.graph.wildcardIp", { ip: sub.ip })
        : sub.ip
      : t(nodeType === "sub-untested" ? "dns.graph.untested" : "dns.graph.unresolved");
    elements.push({ data: { id: `sub-${index}`, label: sub.subdomain, nodeType, detail: `${sub.subdomain} (${extra})` } });
    elements.push({ data: { id: `edge-sub-${index}`, source: "domain", target: `sub-${index}` } });
  });
  const total = moduleState(scan, "subdomains").status === "ok" ? subdomainCount(scan).total : all.length;
  const hidden = total - shown.length;
  if (hidden > 0) {
    elements.push({
      data: { id: "sub-more", label: t("dns.graph.more", { count: hidden }), nodeType: "more", detail: t("dns.graph.moreDetail"), hidden },
    });
    elements.push({ data: { id: "edge-more", source: "domain", target: "sub-more" } });
  }
  if (scan.ip_address) {
    normalizeOpenPorts(scan.open_ports).slice(0, GRAPH_MAX_PORTS).forEach((port, index) => {
      const label = `${port.port}/${port.service ?? "?"}`;
      elements.push({ data: { id: `port-${index}`, label, nodeType: "port", detail: label } });
      elements.push({ data: { id: `edge-port-${index}`, source: "ip", target: `port-${index}` } });
    });
  }
  return elements;
}
