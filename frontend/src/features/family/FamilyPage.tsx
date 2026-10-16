import { ArrowLeft } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";
import { useCatalog, useScan } from "../../api/queries";
import { GradeBadge } from "../../components/GradeBadge";
import { ErrorState, Loading } from "../../components/PageState";
import { Pill } from "../../components/Pills";
import { SectionTitle } from "../../components/SectionTitle";
import { type TabItem, Tabs } from "../../components/Tabs";
import { isFamilyKey } from "../../lib/families";
import { humanizeKey } from "../../lib/catalog";
import { parseId } from "../../lib/format";
import { FAMILY_ICONS, STATE_ICONS } from "../../lib/icons";
import { tabId, tabPanelId } from "../../lib/tabs";
import { familyStateTone } from "../../lib/tones";
import { useDocumentTitle } from "../../lib/useDocumentTitle";
import { useRememberLastScan } from "../../lib/useLastScan";
import { FindingsList } from "../result/FindingsList";
import { ScanError } from "../result/ScanError";
import styles from "./family.module.css";
import { FamilyNav } from "./FamilyNav";
import { GenericFamilyView } from "./registry";
import { activeFamilyTab, FAMILY_TABS, tabFindings, withCatalogTabs } from "./tabs";

// Écran d'une famille : en-tête (note, état, résumé), constats à corriger, puis un
// onglet par module. L'onglet affiché vient de l'adresse (/scans/:id/:family/:module,
// lien profond) ; sans module dans l'adresse, c'est le premier.
export function FamilyPage() {
  const { t } = useTranslation();
  const params = useParams();
  const navigate = useNavigate();
  // Préfixe des identifiants onglet / panneau (aria-controls, aria-labelledby).
  const tabsPrefix = useId();
  const id = parseId(params.id);
  const family = isFamilyKey(params.family) ? params.family : null;
  const query = useScan(family ? id : null);
  const catalog = useCatalog();
  const scan = query.data;
  useDocumentTitle(scan && family ? `${t(`families.${family}.name`)} · ${scan.domain}` : t("nav.result"));

  // Scan supprimé (404) : l'entrée « Résultat » du menu ne doit plus y mener.
  useRememberLastScan(scan, query.error, id);

  if (id === null) return <ErrorState headingLevel={1} title={t("result.notFound")} detail={t("result.invalidId")} />;
  if (!family) {
    return (
      <ErrorState headingLevel={1} title={t("family.unknown")} detail={t("family.unknownText")}>
        <Link to={`/scans/${id}`} className="btn">
          {t("family.backToResult")}
        </Link>
      </ErrorState>
    );
  }
  if (query.isPending) return <Loading />;
  if (query.isError) return <ScanError error={query.error} onRetry={() => void query.refetch()} />;

  const data = query.data;
  const summary = data.families?.[family];
  const state = summary?.state ?? "unmeasured";
  const StateIcon = STATE_ICONS[state];
  const FamilyIcon = FAMILY_ICONS[family];
  const name = t(`families.${family}.name`);

  const tabs = withCatalogTabs(FAMILY_TABS[family], family, catalog);
  const active = activeFamilyTab(family, params.module, tabs);
  const View = active?.component;
  // Un seul module (TLS, e-mail) : rien à choisir, pas de barre d'onglets.
  const showTabs = tabs.length > 1;
  // Filet de sécurité : des modules sans onglet (oubli du registre) gardent une carte honnête chacun.
  const untabbed = tabs.length === 0 && catalog.modules(family).length > 0;
  const items: TabItem[] = tabs.map((tab) => {
    const found = tabFindings(data.findings, tab);
    return { key: tab.key, label: t(tab.labelKey, { defaultValue: tab.title || humanizeKey(tab.key) }), count: found?.count, tone: found?.tone };
  });
  // Un onglet remplace l'entrée courante de l'historique : « Précédent » quitte l'écran.
  const select = (key: string) => navigate(`/scans/${data.id}/${family}/${key}`, { replace: true });

  return (
    <div className={styles.page}>
      <Link to={`/scans/${data.id}`} className={styles.back}>
        <ArrowLeft aria-hidden />
        {t("family.back", { domain: data.domain })}
      </Link>
      <FamilyNav scanId={data.id} families={data.families} />
      <header className={styles.header} data-family={family}>
        <span className={styles.familyIcon} aria-hidden="true">
          <FamilyIcon />
        </span>
        <div className={styles.headerBody}>
          <div className={styles.titleRow}>
            <SectionTitle label={t("family.kicker")} title={name} level={1} size="page" />
            <div className={styles.badges}>
              {summary?.grade && <GradeBadge grade={summary.grade} size="md" />}
              <Pill tone={familyStateTone(summary?.state)}>
                <StateIcon aria-hidden />
                {t(`familyState.${state}`)}
              </Pill>
            </div>
          </div>
          {summary?.summary && <p className={styles.summary}>{summary.summary}</p>}
          <p className={styles.description}>{t(`families.${family}.description`)}</p>
        </div>
      </header>
      <section className={styles.findings} aria-labelledby="family-findings">
        <SectionTitle label={t("family.findingsKicker")} title={t("family.findings")} id="family-findings" />
        <FindingsList scan={data} family={family} titleId="family-findings" />
      </section>
      {untabbed && (
        <div className={styles.panel}>
          <GenericFamilyView scan={data} family={family} />
        </div>
      )}
      {View && active && (
        <div className={styles.modules}>
          {showTabs && (
            <Tabs
              tabs={items}
              activeKey={active.key}
              onChange={select}
              label={t("family.tabs.label", { family: name })}
              idPrefix={tabsPrefix}
            />
          )}
          {/* Le panneau change de clé avec l'onglet et le scan : le module repart d'un état neuf
              (notes en cours de saisie, carte, capture). */}
          <div
            key={`${data.id}:${active.key}`}
            className={styles.panel}
            {...(showTabs ? { role: "tabpanel", id: tabPanelId(tabsPrefix), "aria-labelledby": tabId(tabsPrefix, active.key) } : {})}
          >
            <View scan={data} module={active.module} />
          </div>
        </div>
      )}
    </div>
  );
}
