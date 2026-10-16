import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { OpenPort } from "../../../api/types";
import i18n from "../../../i18n";
import { makeScan } from "../../../test/fixtures";
import { DnsFamily } from "./dns";
import { buildGraphElements } from "./graphElements";
import { PortsModule } from "./network";

vi.mock("cytoscape", () => ({
  default: vi.fn(() => ({ on: vi.fn(), destroy: vi.fn(), zoom: vi.fn(() => 1), width: vi.fn(() => 400), height: vi.fn(() => 300), fit: vi.fn() })),
}));

// Anciens scans : entiers nus, entrées null, liste absente.
const legacy = (value: unknown) => makeScan({ open_ports: value as OpenPort[] });

describe("ports d'anciens scans (entiers nus, null)", () => {
  it("la carte réseau dessine un nœud par port, sans « undefined »", () => {
    const elements = buildGraphElements(legacy([80, null, { port: 22 }, "443"]), i18n.t);
    const ports = elements.filter((element) => element.data.nodeType === "port");
    expect(ports.map((node) => node.data.label)).toEqual(["80/?", "22/?", "443/?"]);
    expect(JSON.stringify(elements)).not.toContain("undefined");
  });

  it("la carte réseau accepte une liste de ports absente ou non tabulaire", () => {
    for (const value of [null, undefined, 443, { port: 443 }]) {
      const elements = buildGraphElements(legacy(value), i18n.t);
      expect(elements.filter((element) => element.data.nodeType === "port")).toHaveLength(0);
    }
  });

  it("la page DNS ne plante pas avec des ports [null, 80, {port}]", async () => {
    render(<DnsFamily scan={legacy([null, 80, { port: 22, service: "SSH" }])} family="dns" />);
    expect(await screen.findByRole("img", { name: /2 port\(s\)/ })).toBeInTheDocument();
  });

  it("la page Réseau liste les mêmes ports", () => {
    render(<PortsModule scan={legacy([80, null, { port: 22, service: "SSH" }])} />);
    const card = screen.getByRole("region", { name: "Ports ouverts" });
    expect(within(card).getAllByRole("listitem")).toHaveLength(2);
  });
});
