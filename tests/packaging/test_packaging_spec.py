"""Spec PyInstaller, point d'entrée et structure du dossier packaging/."""

from pathlib import Path

from pkgload import load

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "packaging" / "domainrecon.spec"


def test_spec_syntaxe_python_valide():
    compile(SPEC.read_text(encoding="utf-8"), str(SPEC), "exec")


def test_spec_noms_coherents_avec_les_aides():
    helpers = load("pyi_helpers", "pyi_helpers.py")
    text = SPEC.read_text(encoding="utf-8")
    assert helpers.WINDOWS_EXECUTABLES == ("DomainRecon.exe", "DomainRecon-console.exe")
    assert '_exe("DomainRecon", console=False)' in text
    assert '_exe("DomainRecon-console", console=True)' in text
    assert "_exe(pyi_helpers.LINUX_EXECUTABLE, console=True)" in text
    assert "name=pyi_helpers.APP_NAME" in text
    for fragment in (
        "pyi_rth_domainrecon.py",
        "domainrecon_entry.py",
        "pyi_helpers.package_datas(ROOT)",
        "pyi_helpers.browser_datas(pyi_helpers.build_browsers_dir(ROOT))",
        "pyi_helpers.drop_dest_prefix(a.datas, pyi_helpers.PLAYWRIGHT_LOCAL_BROWSERS)",
        "pyi_helpers.drop_dest_prefix(a.binaries, pyi_helpers.PLAYWRIGHT_LOCAL_BROWSERS)",
        "pyi_helpers.filter_system_libs(a.binaries)",
        'collect_data_files("tldextract")',
        'collect_data_files("whois")',
        'collect_submodules("domainrecon")',
        "upx=False",
    ):
        assert fragment in text, fragment


def test_entree_appelle_main_sans_s_executer_a_l_import():
    module = load("entry", "entry/domainrecon_entry.py")
    from domainrecon.__main__ import main

    assert module.main is main


def test_packaging_n_est_pas_un_paquet_python():
    """Un packaging/__init__.py masquerait la bibliothèque PyPI « packaging » (pytest, PyInstaller)."""
    assert not (ROOT / "packaging" / "__init__.py").exists()


ONEFILE_SPEC = ROOT / "packaging" / "domainrecon-onefile.spec"


def test_spec_onefile_syntaxe_et_contenu():
    text = ONEFILE_SPEC.read_text(encoding="utf-8")
    compile(text, str(ONEFILE_SPEC), "exec")
    for fragment in (
        "pyi_rth_domainrecon.py",
        "domainrecon_entry.py",
        "pyi_helpers.browser_datas(pyi_helpers.build_browsers_dir(ROOT))",
        'datas.append((str(PORTABLE_MARKER), "."))',
        '"portable.flag"',
        'f"DomainRecon-{VERSION}-portable"',
        "console=False",
        "icon=str(ICON)",
        "pyi_helpers.windows_version_info(VERSION",
        "a.binaries,\n    a.datas,",
        "upx=False",
    ):
        assert fragment in text, fragment
    # Onefile : ni COLLECT, ni exclude_binaries, ni dossier _internal.
    assert "COLLECT(" not in text and "exclude_binaries" not in text


def test_spec_onedir_sans_marqueur_portable():
    assert "portable.flag" not in SPEC.read_text(encoding="utf-8")
