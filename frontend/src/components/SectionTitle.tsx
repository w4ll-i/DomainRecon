import type { ReactNode } from "react";
import styles from "./SectionTitle.module.css";

interface SectionTitleProps {
  // Étiquette au-dessus du titre, mise en majuscules par le CSS (mono).
  label: string;
  // Titre. Absent : l'étiquette est seule (menu, bandeau), sans titre de section.
  title?: string;
  // Identifiant du titre (ou de l'étiquette quand il n'y a pas de titre), pour
  // aria-labelledby sur la section ou la liste qu'il nomme.
  id?: string;
  // Niveau du titre : h2 par défaut, h1 pour le titre d'un écran, h3 pour une sous-section.
  level?: 1 | 2 | 3;
  // Taille du titre : « hero » (~34 px, écran d'accueil), « page » (28 px, titre d'écran),
  // « section » (22 px, défaut). Le niveau 3 reste à 17 px.
  size?: "hero" | "page" | "section";
  // Mot ou fin de titre mis en valeur par la couleur d'accent (doit figurer dans le titre).
  accent?: string;
  align?: "start" | "center";
  // Élément posé juste après le titre, sur sa ligne (une pastille de compte, par exemple) :
  // il ne fait pas partie du titre, dont le nom accessible reste le texte du titre.
  after?: ReactNode;
}

// Étiquette mono discrète, puis titre : l'en-tête d'une section de page.
export function SectionTitle({ label, title, id, level = 2, size = "section", accent, align = "start", after }: SectionTitleProps) {
  if (title === undefined) {
    return (
      <div className={styles.section} data-align={align}>
        <span id={id} className={`${styles.label} ${styles.alone}`}>
          {label}
        </span>
      </div>
    );
  }
  const Heading = `h${level}` as const;
  // Le mot en valeur : la dernière occurrence, pour « Analyse de domaine » → « domaine ».
  const cut = accent ? title.lastIndexOf(accent) : -1;
  const heading = (
    <Heading id={id} className={styles.title} data-level={level} data-size={size}>
      {accent && cut >= 0 ? (
        <>
          {title.slice(0, cut)}
          <span className={styles.accent}>{accent}</span>
          {title.slice(cut + accent.length)}
        </>
      ) : (
        title
      )}
    </Heading>
  );
  return (
    <div className={styles.section} data-align={align}>
      <span className={styles.label}>{label}</span>
      {after ? (
        <div className={styles.titleRow}>
          {heading}
          {after}
        </div>
      ) : (
        heading
      )}
    </div>
  );
}
