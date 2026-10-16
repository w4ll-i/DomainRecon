import { type ComponentProps, lazy, Suspense } from "react";
import { Loading } from "../../../components/PageState";

// La carte réseau (Cytoscape) et la carte du monde (d3-geo, Natural Earth) sont les deux blocs
// les plus lourds de l'écran d'une famille : chargés à leur première apparition seulement.
const NetworkGraphChunk = lazy(async () => ({ default: (await import("./NetworkGraph")).NetworkGraph }));
const GeoMapChunk = lazy(async () => ({ default: (await import("./GeoMap")).GeoMap }));

export function LazyNetworkGraph(props: ComponentProps<typeof NetworkGraphChunk>) {
  return (
    <Suspense fallback={<Loading />}>
      <NetworkGraphChunk {...props} />
    </Suspense>
  );
}

export function LazyGeoMap(props: ComponentProps<typeof GeoMapChunk>) {
  return (
    <Suspense fallback={<Loading />}>
      <GeoMapChunk {...props} />
    </Suspense>
  );
}
