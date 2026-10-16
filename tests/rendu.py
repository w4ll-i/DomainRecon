"""Aides de test : rendu des messages traduisibles (voir domainrecon.i18n)."""

from domainrecon.i18n import render


def fr(value):
    """Valeur rendue en français (les textes bruts restent inchangés)."""
    return render(value, "fr")


def en(value):
    """Valeur rendue en anglais."""
    return render(value, "en")
