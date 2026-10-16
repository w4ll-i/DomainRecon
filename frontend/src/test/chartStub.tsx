// Remplaçant de react-chartjs-2 pour les tests qui affichent un écran portant un graphique :
// Chart.js dessine dans un canvas, absent de jsdom. Le témoin garde son rôle et son nom
// accessible, et expose les données et les couleurs reçues (data-testid, attributs data-*).
//
// Usage (dans le fichier de test, avant les imports du composant testé) :
//   vi.mock("react-chartjs-2", async () => (await import("../../test/chartStub")).chartStub);
interface StubProps {
  role?: string;
  "aria-label"?: string;
  data?: { datasets?: Array<{ data?: Array<number | null> }> };
}

function stub(testId: string) {
  return function ChartStub(props: StubProps) {
    const values = props.data?.datasets?.[0]?.data ?? [];
    return <div data-testid={testId} role={props.role} aria-label={props["aria-label"]} data-values={values.join(",")} />;
  };
}

export const chartStub = { Radar: stub("radar"), Line: stub("chart") };
