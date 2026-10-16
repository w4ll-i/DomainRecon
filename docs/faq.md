# FAQ et dépannage

## Questions fréquentes

**Puis-je analyser n'importe quel domaine ?**
Non. N'analysez que des domaines que vous administrez ou que vous êtes explicitement autorisé à tester. Un scan
contacte la cible et des services tiers ; les modules actifs envoient des requêtes qui dépassent un usage
normal. Scanner sans autorisation peut être illégal. Voir la [licence](../LICENSE), article 3.

**Faut-il des clés d'API ?**
Non. Les 56 modules passifs fonctionnent sans clé. Les clés ajoutent des modules ou enrichissent ceux qui
tournent déjà : voir [Clés d'API](cles-api.md).

**Pourquoi la note vaut-elle `N/A` ?**
Moins de 50 % du barème applicable a pu être mesuré : site injoignable, modules en échec, profil trop réduit.
DomainRecon préfère ne pas noter plutôt que donner une note trompeuse. Voir [Score de sécurité](score.md).

**Pourquoi un module est-il « sans objet » ou « non lancé » ?**
« Sans objet » : le module ne s'applique pas à la cible (par exemple les contrôles e-mail sur une adresse IP,
ou Nuclei quand son binaire n'est pas installé). « Non lancé » : le profil choisi ne le contient pas, ou sa clé
d'API ou l'autorisation manque.

**Pourquoi le scan de ports n'apparaît-il pas ?**
C'est un module actif : il n'est lancé que dans le profil **Personnalisé**, avec l'autorisation de tester la
cible cochée.

**Mes données partent-elles sur Internet ?**
Seulement ce qu'un scan doit envoyer pour mesurer. Tout le reste reste en local : voir
[Confidentialité](confidentialite.md).

**Puis-je utiliser DomainRecon dans une intégration continue ?**
Oui : `domainrecon scan example.com --fail-under B --format junit -o rapport.xml`. Voir
[Ligne de commande](ligne-de-commande.md).

## Dépannage

| Symptôme | Cause et solution |
|---|---|
| « Windows a protégé votre ordinateur » | Les exécutables ne sont pas signés. Vérifiez l'empreinte, puis **Informations complémentaires > Exécuter quand même**. Voir [Installation](installation.md#avertissement-smartscreen). |
| L'application s'ouvre dans le navigateur au lieu d'une fenêtre | WebView2 (Windows) ou WebKitGTK (Linux, `libwebkit2gtk-4.1-0` et `gir1.2-webkit2-4.1`) manque. Installez-le, ou continuez dans le navigateur. |
| Le portable `.exe` met du temps à démarrer | Normal : à chaque lancement, il décompresse Python, l'interface et Chromium dans un dossier temporaire. |
| « PDF indisponible » | Chromium est absent (installation depuis les sources). Lancez `python -m playwright install --only-shell chromium`, ou choisissez un autre format. |
| L'interface indique que le serveur s'est arrêté | En mode navigateur, le serveur s'arrête environ 2 minutes après la fermeture du dernier onglet. Un onglet mis en veille par le navigateur compte comme fermé. Relancez DomainRecon, puis rechargez la page. |
| `400` avec le code `api.invalid_host` | Le nom utilisé pour joindre DomainRecon n'est pas dans `ALLOWED_HOSTS`. Voir [Configuration](configuration.md#exposer-domainrecon-sur-le-réseau). |
| `400` sur une adresse locale | Les cibles non publiques sont refusées par défaut. `ALLOW_PRIVATE_TARGETS=1` les autorise, sur une instance non exposée seulement. |
| `429` trop de scans | Le nombre de scans simultanés (`MAX_CONCURRENT_SCANS`, 2 par défaut) est atteint. Attendez la fin d'un scan. |
| Le démarrage s'arrête sur une erreur de `.env` | Le fichier n'est ni en UTF-8, ni en UTF-16 avec BOM. Réenregistrez-le en UTF-8. |
| Les clés d'API ont disparu après une restauration | Le fichier `.secret_key` n'a pas été restauré avec la base. Ressaisissez les clés. |

## Journaux

En mode fenêtre, sans console, les journaux sont écrits dans `logs/domainrecon.log`, dans le dossier des
données. En mode console (`--browser`, `--server`, `DomainRecon-console.exe`), ils s'affichent dans la console.
Joignez l'extrait utile à un [ticket](https://github.com/w4ll-i/DomainRecon/issues) après en avoir retiré toute information sensible.
