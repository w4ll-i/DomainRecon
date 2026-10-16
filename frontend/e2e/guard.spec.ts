import { expect, test } from "./fixtures";

// Canaris : prouvent que la garde de fixtures.ts se déclenche. Un test marqué
// `test.fail()` réussit seulement si la garde le fait échouer ; si elle cessait
// de voir l'erreur, le test deviendrait « inattendument passé » et échouerait.

test("la réponse de l'interface porte la CSP stricte", async ({ request }) => {
  const response = await request.get("/");
  expect(response.ok()).toBeTruthy();
  const csp = response.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("style-src 'self'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).not.toContain("unsafe-inline");
  expect(csp).not.toContain("unsafe-eval");
});

test("garde : un script en ligne (violation CSP) fait échouer le test", async ({ page }) => {
  test.fail();
  await page.goto("/");
  await page.evaluate(() => {
    const script = document.createElement("script");
    script.textContent = "window.__canari = 1;";
    document.head.appendChild(script);
  });
  await page.waitForTimeout(100);
});

test("garde : une erreur JavaScript non attrapée fait échouer le test", async ({ page }) => {
  test.fail();
  await page.goto("/");
  await page.evaluate(() => {
    setTimeout(() => {
      throw new Error("canari");
    }, 0);
  });
  await page.waitForTimeout(100);
});

test("garde : un console.error applicatif fait échouer le test", async ({ page }) => {
  test.fail();
  await page.goto("/");
  await page.evaluate(() => console.error("canari"));
  await page.waitForTimeout(100);
});

test("garde : une requête vers un hôte externe fait échouer le test", async ({ page }) => {
  test.fail();
  await page.goto("/");
  await page.evaluate(() => {
    void fetch("https://exemple-externe.invalid/tuile.png").catch(() => undefined);
  });
  await page.waitForTimeout(200);
});
