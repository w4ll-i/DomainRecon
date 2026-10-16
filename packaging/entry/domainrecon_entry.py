"""Point d'entrée des exécutables PyInstaller : DomainRecon.exe, DomainRecon-console.exe, domainrecon."""

import multiprocessing
import sys

from domainrecon.__main__ import main

if __name__ == "__main__":
    # Sans effet hors exécutable Windows ; indispensable si une dépendance
    # lance un sous-processus Python (multiprocessing) depuis l'exécutable.
    multiprocessing.freeze_support()
    sys.exit(main())
