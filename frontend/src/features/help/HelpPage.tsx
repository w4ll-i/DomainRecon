import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { CategoryBadge } from "../../components/CategoryBadge";
import { SectionTitle } from "../../components/SectionTitle";
import { GLOSSARY_KEYS } from "../../lib/glossary";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import styles from "../../styles/ops.module.css";
import { startGuidedTour } from "../onboarding/onboardingEvents";
import help from "./HelpPage.module.css";

const SECTIONS = ["guide", "profiles", "legal", "faq", "glossary"] as const;
const GUIDE_STEPS = [1, 2, 3, 4, 5] as const;
const FAQ_ITEMS = [1, 2, 3, 4, 5, 6, 7, 8] as const;
const CATEGORIES = ["passif", "actif", "cle_api", "sensible"] as const;
const PROFILES = ["rapide", "complet", "personnalise"] as const;

// Aide : guide pas à pas, profils de scan, cadre légal des modules actifs et sensibles,
// questions fréquentes et glossaire (une soixantaine de termes, avec filtre).
export function HelpPage() {
  const { t } = useTranslation();
  const [filter, setFilter] = useState("");
  useDocumentTitle(t("help.title"));

  const query = filter.trim().toLowerCase();
  const terms = GLOSSARY_KEYS.filter((key) => {
    if (!query) return true;
    return `${t(`glossary.${key}.name`)} ${t(`glossary.${key}.def`)}`.toLowerCase().includes(query);
  });

  return (
    <div className={`${styles.page} ${styles.narrow}`}>
      <SectionTitle level={1} size="page" label={t("help.kicker")} title={t("help.title")} />
      <p className={styles.lead}>{t("help.lead")}</p>

      <nav aria-label={t("help.nav")} className={help.nav}>
        {SECTIONS.map((section) => (
          <a key={section} href={`#help-${section}`}>
            {t(`help.sections.${section}`)}
          </a>
        ))}
      </nav>

      <section id="help-guide" className={styles.card} aria-labelledby="help-guide-title">
        <h2 id="help-guide-title" className={styles.emptyTitle}>
          {t("help.sections.guide")}
        </h2>
        <ol className={help.steps}>
          {GUIDE_STEPS.map((step) => (
            <li key={step}>
              <strong>{t(`help.guide.${step}.title`)}</strong>
              <span className={styles.muted}>{t(`help.guide.${step}.text`)}</span>
            </li>
          ))}
        </ol>
        <div>
          <button type="button" className="btn" onClick={startGuidedTour}>
            {t("help.replayOnboarding")}
          </button>
        </div>
      </section>

      <section id="help-profiles" className={styles.card} aria-labelledby="help-profiles-title">
        <h2 id="help-profiles-title" className={styles.emptyTitle}>
          {t("help.sections.profiles")}
        </h2>
        <dl className={help.defs}>
          {PROFILES.map((profile) => (
            <div key={profile}>
              <dt>{t(`scanProfile.${profile}.name`)}</dt>
              <dd>{t(`help.profileDesc.${profile}`)}</dd>
            </div>
          ))}
        </dl>
        <h3 className={styles.label}>{t("help.categories")}</h3>
        <dl className={help.defs}>
          {CATEGORIES.map((category) => (
            <div key={category}>
              <dt>
                <CategoryBadge category={category} />
              </dt>
              <dd>{t(`category.desc.${category}`)}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section id="help-legal" className={styles.card} aria-labelledby="help-legal-title">
        <h2 id="help-legal-title" className={styles.emptyTitle}>
          {t("help.sections.legal")}
        </h2>
        <p>{t("help.legal.intro")}</p>
        <ul className={help.list}>
          <li>{t("help.legal.own")}</li>
          <li>{t("help.legal.active")}</li>
          <li>{t("help.legal.sensitive")}</li>
          <li>{t("help.legal.responsibility")}</li>
        </ul>
        <p className={styles.muted}>{t("help.legal.note")}</p>
      </section>

      <section id="help-faq" className={styles.card} aria-labelledby="help-faq-title">
        <h2 id="help-faq-title" className={styles.emptyTitle}>
          {t("help.sections.faq")}
        </h2>
        {FAQ_ITEMS.map((item) => (
          <details key={item} className={help.faq}>
            <summary>{t(`help.faq.${item}.q`)}</summary>
            <p className={styles.muted}>{t(`help.faq.${item}.a`)}</p>
          </details>
        ))}
        <p className={styles.muted}>
          <Link to="/settings">{t("help.toSettings")}</Link>
        </p>
      </section>

      <section id="help-glossary" className={styles.card} aria-labelledby="help-glossary-title">
        <h2 id="help-glossary-title" className={styles.emptyTitle}>
          {t("help.sections.glossary")}
        </h2>
        <div className={styles.field}>
          <label htmlFor="glossary-filter">{t("help.glossaryFilter")}</label>
          <input
            id="glossary-filter"
            type="search"
            className={styles.input}
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            autoComplete="off"
          />
        </div>
        <p className={styles.muted} role="status">
          {t("help.glossaryCount", { count: terms.length })}
        </p>
        <dl className={help.defs}>
          {terms.map((key) => (
            <div key={key}>
              <dt>{t(`glossary.${key}.name`)}</dt>
              <dd>{t(`glossary.${key}.def`)}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}
