// Identifiants des onglets (composant Tabs) et de leur panneau. Le panneau affiché
// porte role="tabpanel", id={tabPanelId(préfixe)} et aria-labelledby={tabId(préfixe,
// clé de l'onglet actif)} ; le préfixe est la prop idPrefix de Tabs.
export const tabId = (prefix: string, key: string): string => `${prefix}-tab-${key}`;

export const tabPanelId = (prefix: string): string => `${prefix}-panel`;
