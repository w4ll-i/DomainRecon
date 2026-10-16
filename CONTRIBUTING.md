# Contribuer à DomainRecon

Merci de votre intérêt. Les signalements de problèmes, les idées et les demandes de fusion sont bienvenus.

## Avant de commencer

DomainRecon est publié sous une [licence « code source disponible »](LICENSE), pas sous une licence libre.
Elle vous permet de lire le code et de proposer des modifications, mais :

- vous ne pouvez modifier le code que pour préparer une contribution à ce dépôt ;
- en envoyant une contribution (code, texte, traduction, données), vous confirmez en avoir le droit et vous
  accordez au titulaire des droits une licence pour l'utiliser, la modifier et la distribuer (article 4 de la
  licence) ;
- le titulaire est libre d'accepter, de modifier ou de refuser une contribution.

Une copie de travail (fork) sert uniquement à préparer une demande de fusion : ne la publiez pas comme une
version distincte.

## Signaler un problème

Ouvrez un [ticket](https://github.com/w4ll-i/DomainRecon/issues/new/choose) avec le modèle **Bogue** ou
**Idée**. Pour un bogue, indiquez la version, le livrable, le système, les étapes pour reproduire et l'extrait
utile du journal. N'y mettez ni clé d'API, ni nom de domaine que vous ne voulez pas rendre public.

Une faille de sécurité ne se signale pas dans un ticket public : suivez [SECURITY.md](SECURITY.md).

## Proposer une modification

1. Pour un changement important, ouvrez d'abord un ticket pour en discuter.
2. Créez une branche à partir de `main`.
3. Faites un changement ciblé, avec ses tests.
4. Lancez les vérifications ci-dessous.
5. Ouvrez une demande de fusion et remplissez le modèle.

L'environnement de développement est décrit dans [docs/developpement.md](docs/developpement.md).

## Vérifications

```bash
python -m pytest -q
ruff check . && ruff format --check .
cd frontend
npm run typecheck && npm run lint && npm run test
npm run build && npm run e2e
```

La CI lance les mêmes vérifications sur chaque demande de fusion.

## Conventions

- **Langue** : code commenté, messages et documentation en français. Tout texte visible dans l'interface ou
  dans un rapport existe en français et en anglais (`domainrecon/i18n/`, `frontend/src/i18n/`).
- **Fichiers** : UTF-8 sans BOM, fins de ligne LF (sauf les `.bat`, en CRLF, voir `.gitattributes`).
- **Python** : 3.10 minimum, formaté et vérifié par `ruff` (configuration dans `pyproject.toml`).
- **Interface** : React et TypeScript strict, vérifiés par `tsc` et ESLint.
- **Tests** : tout changement de comportement s'accompagne d'un test. Les tests Python n'accèdent pas au
  réseau.
- **Modules de scan** : suivez le [contrat des modules](docs/contrat-modules.md) ; le test de contrat vérifie
  chaque module, y compris son « Comment corriger » dans les deux langues.
- **Commits** : messages courts et descriptifs, à l'impératif (« Corrige le calcul de la couverture »).
- **Documentation** : mettez à jour `docs/` et le [CHANGELOG](CHANGELOG.md) (section « Non publié ») quand le
  comportement change.

## Usage responsable

Testez uniquement sur des domaines que vous administrez, sur `example.com` ou avec les faux scanners des tests.
