import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeScan } from "../../../test/fixtures";
import { EmailModule } from "./email";
import { TlsModule } from "./tls";

const tlsCard = () => screen.getByRole("region", { name: "Certificat TLS" });
const emailCard = () => screen.getByRole("region", { name: "Sécurité e-mail" });

describe("famille TLS", () => {
  it("certificat valide : verdict, sujet, validité, connexion, SAN", () => {
    render(<TlsModule scan={makeScan()} />);
    const card = tlsCard();
    expect(card).toHaveTextContent("Certificat valide (chaîne, nom d'hôte et dates vérifiés)");
    expect(within(card).getByText("Sujet (CN)").nextElementSibling).toHaveTextContent("www.example.org");
    expect(within(card).getByText("Jours restants").nextElementSibling).toHaveTextContent("154");
    expect(within(card).getByText("Protocole").nextElementSibling).toHaveTextContent("TLSv1.3");
    expect(card).toHaveTextContent("SAN (2)");
  });

  it("certificat invalide : constat en tête avec le code OpenSSL", () => {
    const scan = makeScan();
    render(
      <TlsModule
        scan={{ ...scan, tls_certificate: { ...scan.tls_certificate, valid: false, verify_error: "certificat expiré", verify_code: 10 } }}
      />,
    );
    const card = tlsCard();
    expect(card).toHaveTextContent("Certificat invalide");
    expect(card).toHaveTextContent("certificat expiré");
    expect(card).toHaveTextContent("code OpenSSL 10");
    expect(card).toHaveTextContent("Les navigateurs refusent ce certificat");
  });

  it("pas de HTTPS : constat, pas « non mesuré »", () => {
    render(<TlsModule scan={makeScan({ tls_certificate: { measured: true, https: false, valid: false, verify_error: "port 443 fermé" } })} />);
    const card = tlsCard();
    expect(card).toHaveTextContent("Pas de HTTPS utilisable");
    expect(card).toHaveTextContent("port 443 fermé");
    expect(card).not.toHaveTextContent("Non mesuré");
  });

  it("signale la rétrogradation HTTPS → HTTP", () => {
    const scan = makeScan();
    render(<TlsModule scan={{ ...scan, redirect_chain: { ...scan.redirect_chain, https_downgrade: true } }} />);
    expect(tlsCard()).toHaveTextContent("HTTPS redirige vers HTTP : la connexion chiffrée est abandonnée");
  });

  it("rétrogradation sans détail de certificat : pas de « Aucune information TLS » en dessous", () => {
    const base = makeScan();
    render(
      <TlsModule
        scan={makeScan({
          tls_certificate: { measured: true, https: true, days_remaining: 20 },
          redirect_chain: { ...base.redirect_chain, https_downgrade: true },
        })}
      />,
    );
    const card = tlsCard();
    expect(card).toHaveTextContent("HTTPS redirige vers HTTP");
    expect(card).not.toHaveTextContent("Aucune information TLS");
  });

  it("liste SAN null (ancien scan) : pas de plantage", () => {
    const scan = makeScan();
    render(<TlsModule scan={{ ...scan, tls_certificate: { ...scan.tls_certificate, san: null as unknown as string[] } }} />);
    expect(tlsCard()).toHaveTextContent("SAN (0)");
  });

  it("ancien scan « certificate verify failed » : invalide, pas non mesuré", () => {
    render(<TlsModule scan={makeScan({ tls_certificate: { error: "certificate verify failed: self signed certificate" } })} />);
    const card = tlsCard();
    expect(card).toHaveTextContent("Certificat invalide");
    expect(card).toHaveTextContent("certificate verify failed: self signed certificate");
    expect(card).not.toHaveTextContent("Aucune information TLS");
  });

  it("module en échec : uniquement l'avertissement", () => {
    const base = makeScan();
    render(
      <TlsModule
        scan={makeScan({
          tls_certificate: { measured: false, error: "Analyse TLS impossible : délai" },
          module_status: { ...base.module_status, tls_certificate: { status: "failed", error: "Analyse TLS impossible : délai" } },
        })}
      />,
    );
    const card = tlsCard();
    expect(within(card).getAllByText("Non mesuré (échec du module)")).toHaveLength(2);
    expect(card).not.toHaveTextContent("Sujet (CN)");
  });
});

describe("famille E-mail", () => {
  it("décrit la note à partir de ce qui a été trouvé et détaille SPF, DKIM, DMARC", () => {
    render(<EmailModule scan={makeScan()} />);
    const card = emailCard();
    expect(card).toHaveTextContent("Bon — SPF -all · DMARC reject · DKIM non détecté sur les sélecteurs courants");
    expect(card).toHaveTextContent("v=spf1 -all");
    expect(card).toHaveTextContent("Non détecté (sélecteurs courants testés)");
    expect(within(card).getByText("reject", { selector: "span" })).toBeInTheDocument();
    expect(within(card).getByText("MTA-STS").nextElementSibling).toHaveTextContent("Absent");
    expect(within(card).getByText("TLS-RPT").nextElementSibling).toHaveTextContent("Non mesuré");
    // La raison est un texte visible, pas seulement une infobulle.
    expect(within(card).getByText("Requête _smtp._tls échouée")).toBeVisible();
    expect(card).toHaveTextContent("Publier une clé DKIM");
  });

  it("SPF publié mais non évalué : avertissement avec la raison, jamais « Publié » en vert", () => {
    const scan = makeScan();
    const es = scan.email_security;
    render(
      <EmailModule
        scan={{
          ...scan,
          email_security: {
            ...es,
            spf: {
              ...es.spf,
              record: "v=spf1 redirect=_spf.autre.example",
              all: null,
              grade: null,
              error: "Requête SPF échouée : _spf.autre.example injoignable",
            },
          },
        }}
      />,
    );
    const spf = within(emailCard()).getByText("SPF", { selector: "span" }).closest("[data-tone]");
    expect(spf).toHaveAttribute("data-tone", "warning");
    expect(spf).toHaveTextContent("Publié, évaluation incomplète");
    expect(spf).toHaveTextContent("Requête SPF échouée : _spf.autre.example injoignable");
    expect(spf).toHaveTextContent("v=spf1 redirect=_spf.autre.example");
    expect(within(spf as HTMLElement).queryByText("Publié")).toBeNull();
  });

  it("ancien scan : listes null (notes, recommandations, problèmes, sélecteurs) sans plantage", () => {
    const scan = makeScan();
    const es = scan.email_security;
    const legacy = {
      ...es,
      notes: null,
      recommendations: null,
      spf: { ...es.spf, issues: null },
      dkim: { ...es.dkim, found: true, issues: null, selectors_found: null },
      dmarc: { ...es.dmarc, issues: null },
    } as unknown as typeof es;
    render(<EmailModule scan={{ ...scan, email_security: legacy }} />);
    expect(emailCard()).toHaveTextContent("v=spf1 -all");
    expect(emailCard()).toHaveTextContent("DKIM détecté");
  });

  it("domaine sans messagerie : DKIM sans objet et MX nul", () => {
    const scan = makeScan();
    const es = scan.email_security;
    render(
      <EmailModule
        scan={{
          ...scan,
          email_security: { ...es, null_mx: true, overall_grade: "A", dkim: { ...es.dkim, found: false } },
        }}
      />,
    );
    const card = emailCard();
    expect(card).toHaveTextContent("Sans objet : domaine sans messagerie, aucune signature attendue");
    expect(card).toHaveTextContent("MX nul (RFC 7505) : le domaine n'accepte aucun courrier");
  });

  it("note partielle et requête en échec : « non mesuré » avec la raison", () => {
    const scan = makeScan();
    const es = scan.email_security;
    render(
      <EmailModule
        scan={{
          ...scan,
          email_security: { ...es, partial: true, spf: { found: null, error: "Requête TXT échouée : délai" } },
        }}
      />,
    );
    const card = emailCard();
    expect(card).toHaveTextContent("Note partielle : SPF ou DMARC non mesuré (requête DNS en échec)");
    expect(card).toHaveTextContent("Non mesuré : Requête TXT échouée : délai");
  });

  it("module sans objet (plateforme mutualisée) : avertissement seul", () => {
    const base = makeScan();
    render(
      <EmailModule
        scan={makeScan({
          module_status: {
            ...base.module_status,
            email_security: { status: "skipped", error: "Hôte d'une plateforme mutualisée" },
          },
          email_security: { measured: false, skipped: true, overall_grade: "N/A" },
        })}
      />,
    );
    const card = emailCard();
    expect(card).toHaveTextContent("Hôte d'une plateforme mutualisée");
    expect(card).not.toHaveTextContent("Note globale de la sécurité e-mail");
  });
});
