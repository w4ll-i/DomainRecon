# Lot et comparaison

## Analyser plusieurs domaines (Lot)

L'écran **Lot** lance le même profil sur une liste de domaines.

1. Collez la liste (un domaine par ligne) ou chargez un fichier `.txt` ou `.csv`.
2. Choisissez le profil et, pour un profil personnalisé avec des modules actifs ou sensibles, cochez
   l'autorisation de tester les cibles. Elle vaut pour tous les domaines du lot.
3. Lancez : les scans s'exécutent un par un, avec un suivi en direct. Le lot s'annule à tout moment ; les
   scans déjà terminés restent enregistrés.
4. Les résultats (note et statut de chaque domaine) s'exportent en CSV. Chaque scan est aussi dans
   l'historique, comme un scan lancé seul.

En ligne de commande :

```bash
domainrecon batch domaines.txt
domainrecon batch domaines.txt --profile rapide --format pdf --output-dir rapports
```

`batch` affiche un résumé des notes. Avec `--format` et `--output-dir`, il écrit aussi un rapport par
domaine. `--fail-under B` rend un code de sortie 1 si une note est inférieure à B.

## Comparer deux scans

L'écran **Comparer** met côte à côte deux scans d'un même domaine et liste les différences en clair :

- note et score ;
- constats nouveaux et constats résolus ;
- ports ouverts ou fermés ;
- sous-domaines apparus ou disparus ;
- enregistrements DNS, certificat, technologies.

Un constat n'est compté comme résolu que si son module a tourné dans le second scan : un module non lancé
ne fait jamais disparaître un problème.

Pour suivre un domaine dans la durée, la **Timeline** (bouton de l'écran de résultat ou de l'historique)
trace l'évolution du score et des changements DNS.
