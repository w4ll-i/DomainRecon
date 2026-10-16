import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { OpenPort } from "../../../api/types";
import { HOSTILE, makeScan } from "../../../test/fixtures";
import { GeoMap } from "./GeoMap";
import { GeoModule, NetworkExtModule, PortsModule } from "./network";

const card = (name: string) => screen.getByRole("region", { name });

describe("carte de localisation (SVG vectoriel embarqué)", () => {
  it("dessine les terres et un point, sans tuile ni ressource externe", () => {
    const { container } = render(<GeoMap lat={48.85} lon={2.35} title="example.com" subtitle="Paris, France · 93.184.216.34" />);
    const map = screen.getByRole("img", { name: "Carte de localisation de example.com" });
    expect(map.tagName.toLowerCase()).toBe("svg");
    // Terres (Natural Earth) : un tracé non vide ; le point est un cercle plein au centre de la carte pour Paris.
    const land = container.querySelector("path[class*=mapLand]");
    expect(land?.getAttribute("d")?.length ?? 0).toBeGreaterThan(1000);
    expect(container.querySelectorAll("circle")).toHaveLength(2);
    // Hors ligne par construction : ni image, ni lien, ni attribut style (CSP stricte).
    expect(container.querySelector("img, a, image, [style]")).toBeNull();
    // Le lieu est écrit sous la carte.
    expect(screen.getByText("Paris, France · 93.184.216.34")).toBeInTheDocument();
  });

  it("place le point selon les coordonnées : l'ouest est à gauche, le nord en haut", () => {
    const position = (lat: number, lon: number) => {
      const { container, unmount } = render(<GeoMap lat={lat} lon={lon} title="x" subtitle="" />);
      const circle = container.querySelector("circle") as SVGCircleElement;
      const point = { x: Number(circle.getAttribute("cx")), y: Number(circle.getAttribute("cy")) };
      unmount();
      return point;
    };
    const paris = position(48.85, 2.35);
    const newYork = position(40.7, -74);
    const sydney = position(-33.9, 151.2);
    expect(newYork.x).toBeLessThan(paris.x);
    expect(sydney.x).toBeGreaterThan(paris.x);
    expect(sydney.y).toBeGreaterThan(paris.y);
  });

  it("la bulle n'interprète jamais une donnée comme du HTML", () => {
    const { container } = render(<GeoMap lat={1} lon={2} title={HOSTILE} subtitle="ligne" />);
    expect(container.textContent).toContain(HOSTILE);
    expect(container.querySelector("img")).toBeNull();
  });

  it("coordonnées hors plage : message à la place de la carte", () => {
    render(<GeoMap lat={91} lon={2} title="example.com" subtitle="" />);
    expect(screen.getByRole("status")).toHaveTextContent("La carte n'a pas pu être affichée");
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
});

describe("famille Réseau", () => {
  it("géolocalisation : pays traduit, coordonnées, FAI, carte et avertissement CDN", async () => {
    render(<GeoModule scan={makeScan()} />);
    const geo = card("Géolocalisation");
    expect(within(geo).getByText("Pays").nextElementSibling).toHaveTextContent("États-Unis (US)");
    expect(within(geo).getByText("Coordonnées").nextElementSibling).toHaveTextContent("42.15, -70.82");
    expect(within(geo).getByText("ASN").nextElementSibling).toHaveTextContent("AS15133 Edgecast Inc.");
    expect(geo).toHaveTextContent("IP mutualisée d'un CDN : voisins et géolocalisation non significatifs");
    // Carte chargée à la demande (lazyParts).
    expect(await within(geo).findByRole("img", { name: "Carte de localisation de example.com" })).toBeInTheDocument();
  });

  it("coordonnées hors plage : aucune carte n'est construite", () => {
    const base = makeScan();
    render(<GeoModule scan={{ ...base, geo_data: { ...base.geo_data, lat: 91, lon: 2 } }} />);
    const geo = card("Géolocalisation");
    expect(within(geo).queryByRole("img", { name: /Carte de localisation/ })).not.toBeInTheDocument();
    expect(within(geo).getByText("Coordonnées").nextElementSibling).toHaveTextContent("N/A");
  });

  it("sans coordonnées : pas de carte, message", () => {
    render(<GeoModule scan={makeScan({ geo_data: { measured: true, country: "", lat: null, lon: null } })} />);
    expect(card("Géolocalisation")).toHaveTextContent("Données de géolocalisation non disponibles");
  });

  it("ports : liste, port sensible signalé, aucun port, module en échec", () => {
    const { unmount } = render(<PortsModule scan={makeScan()} />);
    const ports = card("Ports ouverts");
    expect(within(ports).getAllByRole("listitem")).toHaveLength(3);
    expect(within(ports).getByText("3306").closest("li")).toHaveTextContent("Sensible");
    expect(within(ports).getByText("443").closest("li")).not.toHaveTextContent("Sensible");
    unmount();
    const none = render(<PortsModule scan={makeScan({ open_ports: [] })} />);
    expect(card("Ports ouverts")).toHaveTextContent("Aucun port ouvert parmi les ports courants testés");
    none.unmount();
    const base = makeScan();
    render(
      <PortsModule
        scan={makeScan({ open_ports: [], module_status: { ...base.module_status, open_ports: { status: "timeout", error: "Délai dépassé (60 s)" } } })}
      />,
    );
    expect(card("Ports ouverts")).not.toHaveTextContent("Aucun port ouvert");
    expect(card("Ports ouverts")).toHaveTextContent("Délai dépassé (60 s)");
  });

  it("ports : entiers nus d'un ancien scan, jamais « Aucun port ouvert »", () => {
    // Format accepté par score.py et findings.py.
    render(<PortsModule scan={makeScan({ open_ports: [80, 443, 3306] as unknown as OpenPort[] })} />);
    const ports = card("Ports ouverts");
    expect(within(ports).getAllByRole("listitem")).toHaveLength(3);
    expect(within(ports).getByText("3306").closest("li")).toHaveTextContent("Sensible");
    expect(ports).not.toHaveTextContent("Aucun port ouvert");
  });

  it("réseau étendu : anycast non renseigné affiché N/A, pas « Non »", () => {
    const base = makeScan();
    const { unmount } = render(
      <NetworkExtModule scan={{ ...base, network_extended: { ...base.network_extended, asn_info: { asn: "AS15133" } } }} />,
    );
    expect(within(card("Réseau étendu")).getByText("Anycast").nextElementSibling).toHaveTextContent("N/A");
    unmount();
    render(<NetworkExtModule scan={makeScan()} />);
    expect(within(card("Réseau étendu")).getByText("Anycast").nextElementSibling).toHaveTextContent("Non");
  });

  it("réseau étendu : ASN, voisins, liste plafonnée, sources en échec", () => {
    const { unmount } = render(<NetworkExtModule scan={makeScan()} />);
    const net = card("Réseau étendu");
    expect(within(net).getByText("Organisation").nextElementSibling).toHaveTextContent("Edgecast Inc.");
    expect(net).toHaveTextContent("2 domaine(s)");
    expect(net).toHaveTextContent("example.net");
    unmount();
    const base = makeScan();
    render(
      <NetworkExtModule
        scan={{
          ...base,
          network_extended: { ...base.network_extended, neighbors_total: 40, asn_error: "ipinfo.io injoignable" },
        }}
      />,
    );
    const capped = card("Réseau étendu");
    expect(capped).toHaveTextContent("2 affiché(s) sur 40 domaine(s)");
    expect(capped).toHaveTextContent("Non mesuré : ipinfo.io injoignable");
  });
});
