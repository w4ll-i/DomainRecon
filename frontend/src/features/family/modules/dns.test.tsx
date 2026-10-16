import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import cytoscape from "cytoscape";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import i18n from "../../../i18n";
import { resetChartColors } from "../../../lib/useChartColors";
import { makeScan } from "../../../test/fixtures";
import { DnsFamily, DnsRecordsModule, ReverseDnsModule, SubdomainsModule, TakeoverModule } from "./dns";
import { buildGraphElements } from "./graphElements";
import { NetworkGraph } from "./NetworkGraph";

const cy = vi.hoisted(() => ({
  on: vi.fn(),
  destroy: vi.fn(),
  zoom: vi.fn(() => 1),
  width: vi.fn(() => 400),
  height: vi.fn(() => 300),
  fit: vi.fn(),
}));
vi.mock("cytoscape", () => ({ default: vi.fn(() => cy) }));

const card = (name: string) => screen.getByRole("region", { name });

describe("carte réseau", () => {
  it("construit domaine, IP, sous-domaines (plafonnés) et ports", () => {
    const base = makeScan();
    const subdomains = Array.from({ length: 35 }, (_, i) => ({ subdomain: `s${i}.example.com`, ip: i === 0 ? "1.2.3.4" : null }));
    const elements = buildGraphElements(
      { ...base, subdomains, module_status: { ...base.module_status, subdomains: { status: "ok", error: null, total_found: 120 } } },
      i18n.t,
    );
    const nodes = elements.filter((element) => !("source" in element.data));
    expect(nodes.find((node) => node.data.id === "domain")?.data.label).toBe("example.com");
    expect(nodes.find((node) => node.data.id === "ip")?.data.label).toBe("93.184.216.34");
    expect(nodes.filter((node) => String(node.data.nodeType).startsWith("sub-"))).toHaveLength(30);
    expect(nodes.find((node) => node.data.id === "sub-more")?.data.label).toBe("+90 autres");
    expect(nodes.find((node) => node.data.id === "sub-more")?.data.hidden).toBe(90);
    expect(nodes.filter((node) => node.data.nodeType === "port")).toHaveLength(3);
    expect(nodes.find((node) => node.data.id === "sub-0")?.data.nodeType).toBe("sub-resolved");
    expect(elements.every((element) => typeof element.data.id === "string")).toBe(true);
  });

  it("plafonne les ports à 20 et les rattache à l'IP", () => {
    const open_ports = Array.from({ length: 25 }, (_, i) => ({ port: 1000 + i, state: "open", service: "X" }));
    const elements = buildGraphElements(makeScan({ open_ports }), i18n.t);
    expect(elements.filter((element) => element.data.nodeType === "port")).toHaveLength(20);
    const edges = elements.filter((element) => String(element.data.id).startsWith("edge-port-"));
    expect(edges).toHaveLength(20);
    expect(edges.every((edge) => edge.data.source === "ip")).toBe(true);
  });

  it("sous-domaine résolu par joker : le détail du nœud le dit", () => {
    const subdomains = [
      { subdomain: "any.example.com", ip: "9.9.9.9", wildcard: true },
      { subdomain: "www.example.com", ip: "1.1.1.1" },
    ];
    const elements = buildGraphElements(makeScan({ subdomains }), i18n.t);
    expect(elements.find((element) => element.data.id === "sub-0")?.data.detail).toBe("any.example.com (9.9.9.9, résolution par joker)");
    expect(elements.find((element) => element.data.id === "sub-1")?.data.detail).toBe("www.example.com (1.1.1.1)");
  });

  it("pose le meta marqueur qui empêche Cytoscape d'injecter <style>, et se pilote au clavier", async () => {
    const { unmount } = render(<NetworkGraph scan={makeScan()} />);
    expect(cytoscape).toHaveBeenCalledWith(expect.objectContaining({ container: expect.any(HTMLElement) }));
    expect(document.getElementById("__________cytoscape_stylesheet")?.tagName).toBe("META");
    expect(screen.getByRole("img", { name: "Carte réseau de example.com : 3 sous-domaine(s), 3 port(s)" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Zoom avant" }));
    expect(cy.zoom).toHaveBeenCalledWith({ level: 1.25, renderedPosition: { x: 200, y: 150 } });
    await userEvent.click(screen.getByRole("button", { name: "Recentrer" }));
    expect(cy.fit).toHaveBeenCalledWith(undefined, 30);
    const hover = cy.on.mock.calls.find((call) => call[0] === "mouseover tap")?.[2] as (event: unknown) => void;
    act(() => hover({ target: { data: (key: string) => (key === "detail" ? "www.example.com (93.184.216.34)" : "") } }));
    expect(screen.getByRole("status")).toHaveTextContent("Nœud : www.example.com (93.184.216.34)");
    // Au toucher, aucun mouseout n'efface le détail : un toucher sur le fond le fait.
    const tapBackground = cy.on.mock.calls.find((call) => call[0] === "tap")?.[1] as (event: unknown) => void;
    act(() => tapBackground({ target: { data: () => "" } }));
    expect(screen.getByRole("status")).toHaveTextContent("Nœud : www.example.com (93.184.216.34)");
    act(() => tapBackground({ target: cy }));
    expect(screen.getByRole("status")).not.toHaveTextContent("Nœud :");
    unmount();
    expect(cy.destroy).toHaveBeenCalled();
  });

  it("le libellé ARIA compte aussi les sous-domaines résumés par « +N autres »", () => {
    const base = makeScan();
    const subdomains = Array.from({ length: 35 }, (_, i) => ({ subdomain: `s${i}.example.com`, ip: null }));
    const status = { status: "ok" as const, error: null, total_found: 120 };
    const scan = { ...base, subdomains, module_status: { ...base.module_status, subdomains: status } };
    const { unmount } = render(<NetworkGraph scan={scan} />);
    expect(
      screen.getByRole("img", {
        name: "Carte réseau de example.com : 30 sous-domaine(s) représenté(s), plus 90 autres résumés par un nœud, 3 port(s)",
      }),
    ).toBeInTheDocument();
    unmount();
  });
});

// Cytoscape dessine dans un canvas : sa feuille de style reçoit des couleurs, jamais des
// variables CSS. Elles doivent venir des jetons du thème courant, pas du thème sombre figé.
describe("carte réseau et thème clair/sombre", () => {
  type Rule = { selector: string; style: Record<string, unknown> };
  const root = document.documentElement;
  const styleOf = (call: number) => (vi.mocked(cytoscape).mock.calls[call][0] as unknown as { style: Rule[] }).style;
  const ruleOf = (call: number, selector: string) => styleOf(call).find((rule) => rule.selector === selector)?.style;

  const DARK = {
    "--accent": "#e3c179",
    "--text": "#c8d2e6",
    "--text-secondary": "#8a97b3",
    "--border": "#243149",
    "--surface": "#131d31",
    "--grade-a": "#57c98a",
    "--grade-b": "#95bf6f",
    "--grade-c": "#e0b34d",
    "--grade-na": "#5d6c8a",
  };
  const LIGHT = {
    "--accent": "#b07d24",
    "--text": "#18223a",
    "--text-secondary": "#46536e",
    "--border": "#d3dae8",
    "--surface": "#ffffff",
    "--grade-a": "#206d44",
    "--grade-b": "#44663a",
    "--grade-c": "#7e5a14",
    "--grade-na": "#7a8499",
  };
  const setTokens = (tokens: Record<string, string>) => {
    for (const [name, value] of Object.entries(tokens)) root.style.setProperty(name, value);
  };

  beforeEach(() => {
    resetChartColors();
    vi.mocked(cytoscape).mockClear();
    cy.destroy.mockClear();
  });

  afterEach(() => {
    root.removeAttribute("style");
    root.removeAttribute("data-theme");
    resetChartColors();
  });

  it("dessine avec les jetons du thème courant, puis se redessine à la bascule clair/sombre", async () => {
    setTokens(DARK);
    render(<NetworkGraph scan={makeScan()} />);
    expect(cytoscape).toHaveBeenCalledTimes(1);
    expect(ruleOf(0, "node")).toMatchObject({ color: DARK["--text-secondary"] });
    expect(ruleOf(0, 'node[nodeType = "domain"]')).toMatchObject({ "background-color": DARK["--accent"], color: DARK["--text"] });
    expect(ruleOf(0, 'node[nodeType = "ip"]')).toMatchObject({ "background-color": DARK["--grade-b"] });
    expect(ruleOf(0, "edge")).toMatchObject({ "line-color": DARK["--border"] });

    await act(async () => {
      setTokens(LIGHT);
      root.setAttribute("data-theme", "light");
      // Laisse passer le rappel (micro-tâche) du MutationObserver de useChartColors.
      await Promise.resolve();
    });
    // L'ancien graphe est détruit, le nouveau est dessiné avec les jetons du thème clair.
    expect(cy.destroy).toHaveBeenCalledTimes(1);
    expect(cytoscape).toHaveBeenCalledTimes(2);
    expect(ruleOf(1, "node")).toMatchObject({ color: LIGHT["--text-secondary"] });
    expect(ruleOf(1, 'node[nodeType = "domain"]')).toMatchObject({ "background-color": LIGHT["--accent"], color: LIGHT["--text"] });
    expect(ruleOf(1, 'node[nodeType = "ip"]')).toMatchObject({ "background-color": LIGHT["--grade-b"], color: LIGHT["--grade-b"] });
    expect(ruleOf(1, 'node[nodeType = "sub-resolved"]')).toMatchObject({ "background-color": LIGHT["--grade-a"] });
    expect(ruleOf(1, 'node[nodeType = "sub-unresolved"]')).toMatchObject({ "background-color": LIGHT["--border"], "border-color": LIGHT["--grade-na"] });
    expect(ruleOf(1, 'node[nodeType = "sub-untested"]')).toMatchObject({ "background-color": LIGHT["--surface"] });
    expect(ruleOf(1, 'node[nodeType = "port"]')).toMatchObject({ "background-color": LIGHT["--grade-c"] });
    expect(ruleOf(1, "edge")).toMatchObject({ "line-color": LIGHT["--border"] });

    // Aucune teinte du thème sombre ne subsiste dans le style du graphe clair.
    const style = JSON.stringify(styleOf(1)).toLowerCase();
    for (const value of Object.values(DARK)) expect(style).not.toContain(value);
  });

  it("ne redessine pas le graphe tant que le thème ne change pas", () => {
    setTokens(DARK);
    const scan = makeScan();
    const { rerender } = render(<NetworkGraph scan={scan} />);
    rerender(<NetworkGraph scan={scan} />);
    // Même scan (donc mêmes éléments) et mêmes couleurs : un seul dessin.
    expect(cytoscape).toHaveBeenCalledTimes(1);
  });
});

describe("famille DNS & sous-domaines", () => {
  it("enregistrements par type, MX, SOA, DMARC et types vides", () => {
    render(<DnsRecordsModule scan={makeScan()} />);
    const records = card("Enregistrements DNS");
    expect(records).toHaveTextContent("[10] mail.example.com");
    expect(records).toHaveTextContent("NS : ns.icann.org · Mail : noc.dns.icann.org · Série : 2024");
    expect(records).toHaveTextContent("Source : _dmarc.example.com");
    expect(records).toHaveTextContent("Aucun enregistrement : AAAA, CNAME");
  });

  it("domaine inexistant (NXDOMAIN) et requête en échec : jamais « aucun enregistrement »", () => {
    render(
      <DnsRecordsModule
        scan={makeScan({
          dns_records: { measured: true, nxdomain: true, errors: { TXT: "Délai dépassé (5 s)" }, notes: ["Domaine inexistant (NXDOMAIN)"] },
        })}
      />,
    );
    const records = card("Enregistrements DNS");
    expect(records).toHaveTextContent("Domaine inexistant (NXDOMAIN)");
    expect(records).toHaveTextContent("Le DNS répond que example.com n'existe pas");
    expect(records).toHaveTextContent("Requête échouée : non mesuré");
    expect(records).toHaveTextContent("Délai dépassé (5 s)");
    expect(records).not.toHaveTextContent("Aucun enregistrement DNS trouvé");
  });

  it("NXDOMAIN : la note du serveur n'est pas répétée, quelle que soit sa langue", () => {
    const { unmount } = render(
      <DnsRecordsModule
        scan={makeScan({ dns_records: { measured: true, nxdomain: true, notes: ["Non-existent domain (NXDOMAIN): example.com"] } })}
      />,
    );
    const records = card("Enregistrements DNS");
    expect(records).toHaveTextContent("Domaine inexistant (NXDOMAIN)");
    expect(records).not.toHaveTextContent("Non-existent domain");
    expect(within(records).queryByText("Informations")).toBeNull();
    unmount();

    // Ancien scan sans dns_records.nxdomain : seul le module e-mail le disait.
    render(<DnsRecordsModule scan={makeScan({ dns_records: { A: [] }, email_security: { error: "Non-existent domain (NXDOMAIN)" } })} />);
    expect(card("Enregistrements DNS")).toHaveTextContent("Le DNS répond que example.com n'existe pas");
  });

  it("ancien scan : listes null (notes, alias, sous-domaines, ports, takeover) sans plantage", async () => {
    const scan = makeScan({
      dns_records: { A: ["203.0.113.7"], notes: null as never },
      reverse_dns: { ptr: "ptr.example.net", aliases: null as never },
      subdomains: null as never,
      open_ports: null as never,
      subdomain_takeover: null as never,
    });
    render(<DnsFamily scan={scan} family="dns" />);
    expect(card("Enregistrements DNS")).toHaveTextContent("203.0.113.7");
    expect(card("DNS inverse (PTR)")).toHaveTextContent("ptr.example.net");
    expect(card("Takeover de sous-domaines")).toHaveTextContent("Aucun takeover détecté");
    expect(await screen.findByRole("img", { name: "Carte réseau de example.com : 0 sous-domaine(s), 0 port(s)" })).toBeInTheDocument();
  });

  it("sous-domaines : décompte honnête, non testés, joker, source de secours", () => {
    const base = makeScan();
    render(
      <SubdomainsModule
        scan={{
          ...base,
          subdomains: [...base.subdomains, { subdomain: "any.example.com", ip: "9.9.9.9", wildcard: true }],
          module_status: {
            ...base.module_status,
            subdomains: { status: "ok", error: null, total_found: 250, source: "certspotter", partial: true },
          },
        }}
      />,
    );
    const subs = card("Sous-domaines");
    expect(subs).toHaveTextContent("4 affiché(s) sur 250 trouvé(s) · 2 résolu(s) dont 1 par joker DNS · 1 non testé(s)");
    expect(subs).toHaveTextContent("Source de secours : Cert Spotter");
    expect(within(subs).getByText("Non testé")).toBeInTheDocument();
    expect(within(subs).getByText("9.9.9.9 (résolution par joker)")).toBeInTheDocument();
  });

  it("takeover : aucun (avec le nombre testé), trouvé, ou non vérifié", () => {
    const { unmount } = render(<TakeoverModule scan={makeScan()} />);
    expect(card("Takeover de sous-domaines")).toHaveTextContent("Aucun takeover détecté");
    expect(card("Takeover de sous-domaines")).toHaveTextContent("3 sous-domaine(s) testé(s)");
    unmount();

    const found = render(
      <TakeoverModule
        scan={makeScan({
          subdomain_takeover: [
            { subdomain: "shop.example.com", cname: "x.myshopify.com", provider: "Shopify", risk: "high", confirmed: true, fingerprint_matched: true },
          ],
        })}
      />,
    );
    const takeover = card("Takeover de sous-domaines");
    expect(takeover).toHaveTextContent("1 takeover(s) confirmé(s)");
    expect(takeover).toHaveTextContent("x.myshopify.com");
    expect(takeover).toHaveTextContent("Empreinte du fournisseur");
    found.unmount();

    const base = makeScan();
    render(
      <TakeoverModule
        scan={makeScan({
          module_status: { ...base.module_status, subdomain_takeover: { status: "failed", error: "Non vérifié : énumération en échec" } },
        })}
      />,
    );
    expect(card("Takeover de sous-domaines")).not.toHaveTextContent("Aucun takeover détecté");
    expect(card("Takeover de sous-domaines")).toHaveTextContent("Non vérifié : énumération en échec");
  });

  it("DNS inverse : PTR, ou absence signalée", () => {
    const { unmount } = render(<ReverseDnsModule scan={makeScan()} />);
    expect(card("DNS inverse (PTR)")).toHaveTextContent("93-184-216-34.example.net");
    unmount();
    render(<ReverseDnsModule scan={makeScan({ reverse_dns: { ptr: null, aliases: [], measured: true, error: null } })} />);
    expect(card("DNS inverse (PTR)")).toHaveTextContent("Aucun enregistrement PTR");
  });
});
