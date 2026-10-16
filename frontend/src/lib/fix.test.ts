import { describe, expect, it } from "vitest";
import { fixSteps, safeHttpsUrl, snippetVariants, splitInlineCode } from "./fix";

describe("étapes du conseil", () => {
  it("une étape par ligne, espaces de bord retirés, lignes vides écartées", () => {
    expect(fixSteps("Ouvrez la console.\n  Ajoutez l'enregistrement.  \n\nVérifiez.")).toEqual([
      "Ouvrez la console.",
      "Ajoutez l'enregistrement.",
      "Vérifiez.",
    ]);
  });

  it("texte absent ou vide : aucune étape", () => {
    expect(fixSteps(undefined)).toEqual([]);
    expect(fixSteps("")).toEqual([]);
    expect(fixSteps(" \n \n")).toEqual([]);
  });
});

describe("code en ligne", () => {
  it("découpe le texte et le code entre accents graves", () => {
    expect(splitInlineCode("Ajoutez `Strict-Transport-Security` puis relancez")).toEqual([
      { text: "Ajoutez ", code: false },
      { text: "Strict-Transport-Security", code: true },
      { text: " puis relancez", code: false },
    ]);
  });

  it("plusieurs segments de code", () => {
    expect(splitInlineCode("`a` et `b`")).toEqual([
      { text: "a", code: true },
      { text: " et ", code: false },
      { text: "b", code: true },
    ]);
  });

  it("sans accent grave : un seul segment de texte", () => {
    expect(splitInlineCode("Rien de spécial")).toEqual([{ text: "Rien de spécial", code: false }]);
  });

  it("accent grave resté ouvert : le texte s'affiche tel quel, rien ne disparaît", () => {
    expect(splitInlineCode("Ajoutez `max-age")).toEqual([{ text: "Ajoutez `max-age", code: false }]);
    expect(splitInlineCode("`a` puis `b")).toEqual([
      { text: "a", code: true },
      { text: " puis `b", code: false },
    ]);
  });

  it("paire d'accents graves vide : ignorée", () => {
    expect(splitInlineCode("avant `` après")).toEqual([{ text: "avant  après", code: false }]);
  });

  it("une balise HTML reste du texte", () => {
    expect(splitInlineCode("<b>gras</b> `<script>`")).toEqual([
      { text: "<b>gras</b> ", code: false },
      { text: "<script>", code: true },
    ]);
  });
});

describe("variantes d'un extrait", () => {
  it("sans en-tête : une variante sans libellé, code sans lignes vides de bord", () => {
    expect(snippetVariants("\n\nexample.com. IN CAA 0 issue \"letsencrypt.org\"\n")).toEqual([
      { label: null, code: 'example.com. IN CAA 0 issue "letsencrypt.org"' },
    ]);
  });

  it("une ligne « # libellé » ouvre une variante ; l'en-tête n'est pas dans le code à copier", () => {
    const text = [
      "# nginx",
      'add_header Strict-Transport-Security "max-age=63072000" always;',
      "",
      "# Apache",
      'Header always set Strict-Transport-Security "max-age=63072000"',
    ].join("\n");
    expect(snippetVariants(text)).toEqual([
      { label: "nginx", code: 'add_header Strict-Transport-Security "max-age=63072000" always;' },
      { label: "Apache", code: 'Header always set Strict-Transport-Security "max-age=63072000"' },
    ]);
  });

  it("lignes intérieures intactes : accolades, indentation et lignes vides du milieu", () => {
    const text = "# nginx\nserver {\n  listen 443 ssl;\n\n  add_header X-Frame-Options DENY;\n}";
    expect(snippetVariants(text)).toEqual([
      { label: "nginx", code: "server {\n  listen 443 ssl;\n\n  add_header X-Frame-Options DENY;\n}" },
    ]);
  });

  it("« #!/bin/sh » et « #note » (sans espace) ne sont pas des en-têtes", () => {
    expect(snippetVariants("#!/bin/sh\n#note\necho ok")).toEqual([{ label: null, code: "#!/bin/sh\n#note\necho ok" }]);
  });

  it("une ligne indentée « # » n'est pas un en-tête (première colonne seulement)", () => {
    expect(snippetVariants("# nginx\nserver {\n  # commentaire\n}")).toEqual([
      { label: "nginx", code: "server {\n  # commentaire\n}" },
    ]);
  });

  it("fins de ligne Windows normalisées", () => {
    expect(snippetVariants("# DNS\r\nexample.com. IN TXT \"v=spf1 -all\"\r\n")).toEqual([
      { label: "DNS", code: 'example.com. IN TXT "v=spf1 -all"' },
    ]);
  });

  it("variante sans code : écartée (rien à copier)", () => {
    expect(snippetVariants("# nginx\n\n# Apache\nHeader set X 1")).toEqual([{ label: "Apache", code: "Header set X 1" }]);
  });

  it("texte absent, vide ou blanc : aucune variante", () => {
    expect(snippetVariants(undefined)).toEqual([]);
    expect(snippetVariants("")).toEqual([]);
    expect(snippetVariants("  \n ")).toEqual([]);
  });
});

describe("adresse de documentation", () => {
  it("accepte une adresse https", () => {
    expect(safeHttpsUrl("https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Strict-Transport-Security")?.hostname).toBe(
      "developer.mozilla.org",
    );
  });

  it.each([
    "http://example.com/doc",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "//example.com/doc",
    "/doc/relative",
    "https://localhost/doc",
    "https://user:secret@example.com/doc",
    "https://user@example.com/doc",
    "ftp://example.com/doc",
    "n'importe quoi",
    "",
  ])("refuse %j", (value) => {
    expect(safeHttpsUrl(value)).toBeNull();
  });

  it("absente : null", () => {
    expect(safeHttpsUrl(undefined)).toBeNull();
  });
});
