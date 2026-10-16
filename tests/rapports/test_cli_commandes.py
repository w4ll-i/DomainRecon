# =============================================================================
# DomainRecon - Tests de la ligne de commande (domainrecon/cli)
# =============================================================================
# scan, batch, history, export, modules, import, découverte des sous-commandes
# et aiguillage depuis `domainrecon`. Le scanner est simulé (aucun réseau) ;
# les scans sont enregistrés dans la base de la session de tests.
# =============================================================================

import json
import sqlite3
import sys
import xml.etree.ElementTree as ET

import pytest

import domainrecon.scanner as scanner
from domainrecon import __main__ as commande
from domainrecon import cli, reports
from domainrecon.cli import importer
from domainrecon.cli._common import below_threshold, table
from domainrecon.core.database import SessionLocal
from domainrecon.core.models import Scan

from .rapports_aides import build_result, unique_domain


@pytest.fixture
def faux_scan(monkeypatch, stockage):
    """perform_full_scan simulé : résultat fixe (note B) ; `appels` garde les arguments reçus."""
    appels = []

    async def scan(domain, on_module=None, profile="complet", authorized_target=False, **kwargs):
        appels.append({"domain": domain, "profile": profile, "authorized": authorized_target, **kwargs})
        if domain.startswith("refuse"):
            raise ValueError("Cible refusée")
        if domain.startswith("plante"):
            raise RuntimeError("clé=SECRET123 dans l'URL")
        if on_module:
            on_module("dns_records", "ok", 0.4)
            on_module("waf", "failed", 1.2)
        return build_result(domain)

    monkeypatch.setattr(scanner, "perform_full_scan", scan)
    return appels


def lancer(capsys, *argv):
    code = cli.run(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


# --- Découverte et aiguillage ----------------------------------------------------


def test_commandes_decouvertes():
    assert {"scan", "batch", "history", "export", "modules", "import"} <= set(cli.command_names())


def test_decouverte_par_module(tmp_path, monkeypatch, capsys):
    """Un fichier ajouté au dossier cli (monitor.py) apporte sa commande ; un fichier cassé est ignoré."""
    (tmp_path / "monitor_demo.py").write_text(
        "def register(subparsers):\n"
        "    p = subparsers.add_parser('monitor-demo', help='demo')\n"
        "    p.add_argument('--n', type=int, default=3)\n"
        "    p.set_defaults(handler=lambda args: args.n)\n",
        encoding="utf-8",
    )
    (tmp_path / "casse_demo.py").write_text("raise RuntimeError('boum')\n", encoding="utf-8")
    (tmp_path / "_prive_demo.py").write_text("def register(s): raise SystemExit(9)\n", encoding="utf-8")
    monkeypatch.setattr(cli, "__path__", [*cli.__path__, str(tmp_path)])
    try:
        assert "monitor-demo" in cli.command_names()
        assert cli.run(["monitor-demo", "--n", "7"]) == 7
        assert "casse_demo" in capsys.readouterr().err
    finally:
        for name in ("monitor_demo", "casse_demo", "_prive_demo"):
            sys.modules.pop(f"domainrecon.cli.{name}", None)


def test_aucune_commande_affiche_l_aide(capsys):
    assert cli.run([]) == 2
    assert "commandes" in capsys.readouterr().err


def test_main_aiguille_vers_les_sous_commandes(capsys):
    assert commande.main(["modules", "--family", "tls"]) == 0
    assert "tls_certificate" in capsys.readouterr().out


def test_main_garde_le_lancement_par_defaut(monkeypatch):
    from domainrecon.desktop import launcher

    appels = []
    monkeypatch.setattr(launcher, "run", lambda mode, **kw: appels.append(mode) or 0)
    assert commande.main(["--browser", "--no-open"]) == 0
    assert appels == ["browser"]


def test_main_sans_argument_utilise_sys_argv(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["domainrecon", "modules", "--format", "json"])
    assert commande.main() == 0
    assert json.loads(capsys.readouterr().out)["modules"]


# --- scan ---------------------------------------------------------------------------


def test_scan_texte_par_defaut(faux_scan, capsys):
    domaine = unique_domain("scan")
    code, out, err = lancer(capsys, "scan", domaine, "--profile", "rapide")
    assert code == 0
    assert f"Rapport DomainRecon - {domaine}" in out and "Note globale" in out
    assert "[1/" in err and "enregistré : note B" in err
    assert faux_scan[0]["domain"] == domaine and faux_scan[0]["profile"] == "rapide"


@pytest.mark.parametrize(
    ("fmt", "verifie"),
    [
        ("json", lambda s: json.loads(s)["scan"]["status"] == "partial"),
        ("md", lambda s: s.startswith("# Rapport DomainRecon")),
        ("html", lambda s: s.startswith("<!doctype html>")),
        ("csv", lambda s: s.startswith("type,domain,severity")),
        ("sarif", lambda s: json.loads(s)["version"] == "2.1.0"),
        ("junit", lambda s: ET.fromstring(s).tag == "testsuites"),
    ],
)
def test_scan_formats_sur_la_sortie_standard(faux_scan, capsys, fmt, verifie):
    code, out, err = lancer(capsys, "scan", unique_domain("fmt"), "--format", fmt)
    assert code == 0 and verifie(out)
    # Avancement et message de fin sur la sortie d'erreur : la sortie standard reste propre.
    assert "Scan de " in err


def test_scan_vers_un_fichier(faux_scan, capsys, tmp_path):
    cible = tmp_path / "sous" / "rapport.html"
    code, out, err = lancer(capsys, "scan", unique_domain("o"), "--format", "html", "-o", str(cible), "-q")
    assert code == 0 and out == ""
    assert cible.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "Rapport écrit" in err and "[1/" not in err


def test_scan_pdf_exige_un_fichier(faux_scan, capsys):
    code, _, err = lancer(capsys, "scan", unique_domain("pdf"), "--format", "pdf")
    assert code == 2 and "-o" in err


def test_scan_pdf_vers_un_fichier(faux_scan, capsys, tmp_path, monkeypatch):
    async def faux_pdf(html):
        return b"%PDF-1.7 test"

    monkeypatch.setattr(reports, "html_to_pdf", faux_pdf)
    cible = tmp_path / "r.pdf"
    code, _, _ = lancer(capsys, "scan", unique_domain("pdf"), "--format", "pdf", "-o", str(cible), "-q")
    assert code == 0 and cible.read_bytes().startswith(b"%PDF-")


def test_scan_pdf_sans_chromium_garde_le_scan(faux_scan, capsys, tmp_path, monkeypatch):
    async def absent(html):
        raise reports.PdfUnavailableError("Chromium n'est pas installé")

    monkeypatch.setattr(reports, "html_to_pdf", absent)
    code, _, err = lancer(
        capsys, "scan", unique_domain("pdf"), "--format", "pdf", "-o", str(tmp_path / "r.pdf"), "-q"
    )
    assert code == 2 and "PDF indisponible" in err and "domainrecon export" in err


def test_scan_fail_under(faux_scan, capsys):
    # La note simulée est B.
    assert lancer(capsys, "scan", unique_domain("f"), "--fail-under", "A", "-q")[0] == 1
    assert lancer(capsys, "scan", unique_domain("f"), "--fail-under", "b", "-q")[0] == 0
    code, _, err = lancer(capsys, "scan", unique_domain("f"), "--fail-under", "C", "-q")
    assert code == 0 and "sous le seuil" not in err
    code, _, err = lancer(capsys, "scan", unique_domain("f"), "--fail-under", "A", "-q")
    assert code == 1 and "sous le seuil" in err


def test_seuil_et_note_absente():
    assert below_threshold("B", "A") and not below_threshold("A", "B") and not below_threshold("B", "B")
    assert below_threshold("N/A", "F") and below_threshold(None, "D")
    assert not below_threshold("F", None)


def test_scan_personnalise_exige_des_modules(faux_scan, capsys):
    code, _, err = lancer(capsys, "scan", unique_domain("p"), "--profile", "personnalise")
    assert code == 2 and "--modules" in err
    assert faux_scan == []


def test_scan_modules_choisis(faux_scan, capsys):
    code, *_ = lancer(
        capsys,
        "scan",
        unique_domain("m"),
        "--profile",
        "personnalise",
        "--modules",
        "dns_records, tls_certificate",
        "-q",
    )
    assert code == 0
    assert set(faux_scan[0]["selected"]) == {"dns_records", "tls_certificate"}


def test_scan_enregistre_le_profil_et_les_modules_lances(monkeypatch, stockage, capsys):
    """Comme le vrai scanner, le résultat ne porte pas le profil : la CLI l'ajoute, comme l'API."""

    async def scan(domain, on_module=None, **kwargs):
        result = build_result(domain)
        result.pop("profile", None)
        result.pop("modules_launched", None)
        return result

    monkeypatch.setattr(scanner, "perform_full_scan", scan)
    domain = unique_domain("profil")
    code, *_ = lancer(capsys, "scan", domain, "--profile", "rapide", "-q", "--format", "json")
    assert code == 0
    with SessionLocal() as db:
        saved = db.query(Scan).filter(Scan.domain == domain).one()
        assert saved.profile == "rapide"
        assert saved.modules_launched and "dns_records" in saved.modules_launched


def test_scan_module_actif_exige_l_autorisation(faux_scan, capsys):
    argv = ("scan", unique_domain("a"), "--profile", "personnalise", "--modules", "tls_deep", "-q")
    code, _, err = lancer(capsys, *argv)
    assert code == 2 and "tls_deep" in err and faux_scan == []
    code, *_ = lancer(capsys, *argv, "--authorized")
    assert code == 0 and faux_scan[0]["authorized"] is True


def test_scan_cible_refusee_et_erreur_inattendue(faux_scan, capsys):
    code, _, err = lancer(capsys, "scan", "refuse.example.com", "-q")
    assert code == 2 and "Cible refusée" in err
    code, _, err = lancer(capsys, "scan", "plante.example.com", "-q")
    assert code == 2 and "RuntimeError" in err
    assert "SECRET123" not in err, "le texte d'une exception inattendue n'est jamais affiché"


def test_scan_profil_inconnu(capsys):
    with pytest.raises(SystemExit) as sortie:
        cli.run(["scan", "example.com", "--profile", "enorme"])
    assert sortie.value.code == 2


# --- batch ----------------------------------------------------------------------------


def test_batch_txt(faux_scan, capsys, tmp_path):
    a, b = unique_domain("b"), unique_domain("b")
    fichier = tmp_path / "domaines.txt"
    fichier.write_text(f"# mes domaines\n{a}\n\n{b}  # principal\n{a}\n", encoding="utf-8")
    code, out, err = lancer(capsys, "batch", str(fichier), "-q")
    assert code == 0
    assert [c["domain"] for c in faux_scan] == [a, b], "doublons et commentaires ignorés"
    assert a in out and b in out and "2 domaine(s) : 2 scanné(s), 0 en erreur" in out


def test_batch_csv_avec_entete(faux_scan, capsys, tmp_path):
    a, b = unique_domain("c"), unique_domain("c")
    fichier = tmp_path / "domaines.csv"
    fichier.write_text(f"id,Domain,owner\n1,{a},moi\n2,{b},moi\n", encoding="utf-8")
    code, *_ = lancer(capsys, "batch", str(fichier), "-q")
    assert code == 0 and [c["domain"] for c in faux_scan] == [a, b]


def test_batch_csv_sans_entete(faux_scan, capsys, tmp_path):
    a = unique_domain("c")
    fichier = tmp_path / "d.csv"
    fichier.write_text(f"{a};x\n", encoding="utf-8")
    fichier.write_text(f"{a},x\n", encoding="utf-8")
    lancer(capsys, "batch", str(fichier), "-q")
    assert faux_scan[0]["domain"] == a


def test_batch_rapports_par_domaine(faux_scan, capsys, tmp_path):
    a = unique_domain("r")
    fichier = tmp_path / "d.txt"
    fichier.write_text(a + "\n", encoding="utf-8")
    sortie = tmp_path / "rapports"
    code, *_ = lancer(capsys, "batch", str(fichier), "--format", "md", "--output-dir", str(sortie), "-q")
    assert code == 0
    fichiers = list(sortie.glob(f"domainrecon-{a}-*.md"))
    assert len(fichiers) == 1 and fichiers[0].read_text(encoding="utf-8").startswith("# Rapport")


def test_batch_format_sans_dossier(faux_scan, capsys, tmp_path):
    fichier = tmp_path / "d.txt"
    fichier.write_text("example.com\n", encoding="utf-8")
    code, _, err = lancer(capsys, "batch", str(fichier), "--format", "json")
    assert code == 2 and "--output-dir" in err


def test_batch_erreurs_et_seuil(faux_scan, capsys, tmp_path):
    fichier = tmp_path / "d.txt"
    fichier.write_text(f"refuse.example.com\n{unique_domain('s')}\n", encoding="utf-8")
    code, out, err = lancer(capsys, "batch", str(fichier), "-q")
    assert code == 2, "un échec ne bloque pas le suivant mais donne le code 2"
    assert len(faux_scan) == 2 and "erreur" in out and "1 en erreur" in out
    fichier.write_text(f"{unique_domain('s')}\n", encoding="utf-8")
    assert lancer(capsys, "batch", str(fichier), "-q", "--fail-under", "A")[0] == 1
    assert lancer(capsys, "batch", str(fichier), "-q", "--fail-under", "C")[0] == 0


def test_batch_fichier_invalide(capsys, tmp_path):
    assert lancer(capsys, "batch", str(tmp_path / "absent.txt"))[0] == 2
    vide = tmp_path / "vide.txt"
    vide.write_text("# rien\n\n", encoding="utf-8")
    code, _, err = lancer(capsys, "batch", str(vide))
    assert code == 2 and "Aucun domaine" in err
    binaire = tmp_path / "b.txt"
    binaire.write_bytes(b"\xff\xfe\x00\x80")
    assert lancer(capsys, "batch", str(binaire))[0] == 2


# --- history -----------------------------------------------------------------------------


def test_history_texte_et_filtres(faux_scan, capsys):
    domaine = unique_domain("h")
    lancer(capsys, "scan", domaine, "-q", "--format", "json")
    code, out, _ = lancer(capsys, "history", "--domain", domaine)
    assert code == 0
    assert out.splitlines()[0].split() == [
        "ID",
        "DATE",
        "(UTC)",
        "DOMAINE",
        "NOTE",
        "SCORE",
        "STATUT",
        "PROFIL",
    ]
    assert domaine in out and " B " in out and "partial" in out
    assert (
        lancer(capsys, "history", "--domain", domaine, "--grade", "A")[1].strip() == "Aucun scan enregistré."
    )
    assert domaine in lancer(capsys, "history", "--domain", domaine, "--grade", "B")[1]
    assert domaine in lancer(capsys, "history", "--domain", domaine, "--status", "partial")[1]
    assert "Aucun scan" in lancer(capsys, "history", "--domain", domaine, "--status", "error")[1]


def test_history_json_et_limite(faux_scan, capsys):
    prefixe = unique_domain("lim")
    for _ in range(3):
        lancer(capsys, "scan", prefixe, "-q", "--format", "json")
    code, out, _ = lancer(capsys, "history", "--domain", prefixe, "-n", "2", "--format", "json")
    data = json.loads(out)
    assert code == 0 and data["total"] == 3 and len(data["scans"]) == 2
    assert data["scans"][0]["id"] > data["scans"][1]["id"], "du plus récent au plus ancien"
    assert data["scans"][0]["grade"] == "B" and data["scans"][0]["score"] == 82
    _, texte, _ = lancer(capsys, "history", "--domain", prefixe, "-n", "2")
    assert "2 scan(s) affiché(s) sur 3" in texte


# --- export ---------------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["text", "json", "csv", "md", "html", "sarif", "junit"])
def test_export_formats(scan_id, capsys, tmp_path, fmt):
    cible = tmp_path / f"r.{fmt}"
    code, _, err = lancer(capsys, "export", str(scan_id), "--format", fmt, "-o", str(cible))
    assert code == 0 and cible.stat().st_size > 0 and "Rapport écrit" in err


def test_export_sortie_standard_et_langue(scan_id, capsys):
    code, out, _ = lancer(capsys, "export", str(scan_id), "--format", "md", "--lang", "en")
    assert code == 0 and "## Summary" in out
    assert lancer(capsys, "export", str(scan_id))[1].startswith("<!doctype html>"), "html par défaut"


def test_export_pdf(scan_id, capsys, tmp_path, monkeypatch):
    async def faux_pdf(html):
        return b"%PDF-1.7 test"

    monkeypatch.setattr(reports, "html_to_pdf", faux_pdf)
    assert lancer(capsys, "export", str(scan_id), "--format", "pdf")[0] == 2
    cible = tmp_path / "r.pdf"
    assert lancer(capsys, "export", str(scan_id), "--format", "pdf", "-o", str(cible))[0] == 0
    assert cible.read_bytes().startswith(b"%PDF-")


def test_export_pdf_sans_chromium(scan_id, capsys, tmp_path, monkeypatch):
    async def absent(html):
        raise reports.PdfUnavailableError("Chromium n'est pas installé")

    monkeypatch.setattr(reports, "html_to_pdf", absent)
    code, _, err = lancer(capsys, "export", str(scan_id), "--format", "pdf", "-o", str(tmp_path / "r.pdf"))
    assert code == 2 and "Chromium" in err


def test_export_scan_inconnu(stockage, capsys):
    code, _, err = lancer(capsys, "export", "99999999")
    assert code == 2 and "introuvable" in err


def test_export_fichier_non_inscriptible(scan_id, capsys, tmp_path):
    bloc = tmp_path / "fichier"
    bloc.write_text("x", encoding="utf-8")
    code, _, err = lancer(capsys, "export", str(scan_id), "-o", str(bloc / "sous" / "r.html"))
    assert code == 2 and "Écriture impossible" in err


# --- modules ---------------------------------------------------------------------------------


def test_modules_catalogue(capsys):
    code, out, _ = lancer(capsys, "modules")
    assert code == 0
    assert out.splitlines()[0].split()[:3] == ["MODULE", "FAMILLE", "CATÉGORIE"]
    assert "tls_certificate" in out and "module(s)." in out


def test_modules_json_et_famille(capsys):
    code, out, _ = lancer(capsys, "modules", "--format", "json", "--family", "tls", "--lang", "en")
    data = json.loads(out)["modules"]
    assert code == 0 and data and {m["family"] for m in data} == {"tls"}
    assert next(m for m in data if m["name"] == "tls_deep")["requires_authorization"] is True
    tous = json.loads(lancer(capsys, "modules", "--format", "json")[1])["modules"]
    assert len(tous) > len(data)


def test_table_alignee():
    texte = table(("A", "BB"), [("xxx", "1"), ("y", "22")])
    assert texte.splitlines() == ["A    BB", "---  --", "xxx  1", "y    22"]


# --- import -----------------------------------------------------------------------------------


def _ancienne_base(chemin, lignes, schema=None):
    schema = schema or (
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, domain VARCHAR(255) NOT NULL, ip_address VARCHAR(45), "
        "dns_records JSON, subdomains JSON, tls_certificate JSON, reverse_dns_data JSON, security_score JSON, "
        "tags JSON, notes TEXT, scan_timestamp DATETIME, status VARCHAR(50), error_message TEXT, "
        "screenshot_path VARCHAR(500), colonne_disparue TEXT)"
    )
    conn = sqlite3.connect(chemin)
    conn.execute(schema)
    for ligne in lignes:
        colonnes = ", ".join(ligne)
        conn.execute(
            f"INSERT INTO scans ({colonnes}) VALUES ({', '.join('?' * len(ligne))})", list(ligne.values())
        )
    conn.commit()
    conn.close()


def _scans_de(domaine):
    with SessionLocal() as db:
        return db.query(Scan).filter(Scan.domain == domaine).order_by(Scan.scan_timestamp).all()


def test_import_ancienne_base(stockage, capsys, tmp_path):
    domaine = unique_domain("imp")
    base = tmp_path / "ancienne.db"
    _ancienne_base(
        base,
        [
            {
                "id": 41,
                "domain": domaine.upper(),
                "ip_address": "192.0.2.1",
                "dns_records": json.dumps({"A": ["192.0.2.1"]}),
                "subdomains": json.dumps(["www." + domaine]),
                "tls_certificate": "pas du json",
                "reverse_dns_data": json.dumps({"ptr": "x"}),
                "security_score": json.dumps({"score": 70, "grade": "C"}),
                "tags": json.dumps(["prod"]),
                "notes": "ancien",
                "scan_timestamp": "2025-03-04 10:11:12.123456",
                "status": "success",
                "screenshot_path": "ancienne_capture.png",
                "colonne_disparue": "x",
            },
            {
                "id": 42,
                "domain": domaine,
                "scan_timestamp": "2025-03-05 08:00:00",
                "security_score": json.dumps(55),
            },
            {"id": 43, "domain": "", "scan_timestamp": "2025-03-05 08:00:00"},
            {"id": 44, "domain": domaine, "scan_timestamp": "n'importe quoi"},
        ],
    )
    code, out, _ = lancer(capsys, "import", str(base))
    assert code == 0
    assert "4 scan(s) lu(s) : 2 importé(s), 0 doublon(s) ignoré(s), 2 inexploitable(s)" in out
    assert "colonne_disparue" in out
    premier, second = _scans_de(domaine)
    assert premier.domain == domaine and premier.id != 41
    assert premier.dns_records == {"A": ["192.0.2.1"]} and premier.subdomains == ["www." + domaine]
    assert premier.tls_certificate is None, "JSON illisible laissé vide"
    assert premier.reverse_dns == {"ptr": "x"}, "reverse_dns_data -> reverse_dns"
    assert premier.tags == ["prod"] and premier.notes == "ancien"
    assert premier.screenshot_path is None
    assert premier.scan_timestamp.isoformat() == "2025-03-04T10:11:12.123456"
    assert second.security_score == {"score": 55}
    assert second.status == "success"
    # Les scans importés sont lisibles par le reste de l'application (rapport compris).
    payload = reports.load_payload(premier.id)
    assert reports.generate(payload, "md").content


def test_import_ignore_les_doublons(stockage, capsys, tmp_path):
    domaine = unique_domain("dup")
    base = tmp_path / "a.db"
    _ancienne_base(base, [{"id": 1, "domain": domaine, "scan_timestamp": "2025-01-01 00:00:00"}])
    assert "1 importé(s)" in lancer(capsys, "import", str(base))[1]
    code, out, _ = lancer(capsys, "import", str(base))
    assert code == 0 and "0 importé(s), 1 doublon(s) ignoré(s)" in out
    assert len(_scans_de(domaine)) == 1


def test_import_a_sec(stockage, capsys, tmp_path):
    domaine = unique_domain("sec")
    base = tmp_path / "a.db"
    _ancienne_base(base, [{"id": 1, "domain": domaine, "scan_timestamp": "2025-01-01 00:00:00"}])
    out = lancer(capsys, "import", str(base), "--dry-run")[1]
    assert "1 à importer" in out and _scans_de(domaine) == []


def test_import_anciens_noms_de_colonnes(stockage, capsys, tmp_path):
    domaine = unique_domain("old")
    base = tmp_path / "v1.db"
    _ancienne_base(
        base,
        [
            {
                "id": 1,
                "target": domaine,
                "ip": "192.0.2.9",
                "timestamp": "2024-05-06T07:08:09Z",
                "score": 80,
                "ssl": json.dumps({"valid": True}),
            }
        ],
        schema="CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, ip TEXT, timestamp TEXT, score INTEGER, ssl TEXT)",
    )
    code, out, _ = lancer(capsys, "import", str(base))
    assert code == 0 and "target->domain" in "".join(importer.import_scans(base, True).mapped)
    (scan,) = _scans_de(domaine)
    assert scan.ip_address == "192.0.2.9" and scan.security_score == {"score": 80}
    assert scan.tls_certificate == {"valid": True}
    assert scan.scan_timestamp.isoformat() == "2024-05-06T07:08:09"


def test_import_entrees_invalides(stockage, capsys, tmp_path):
    assert lancer(capsys, "import", str(tmp_path / "absent.db"))[0] == 2
    texte = tmp_path / "pas_une_base.db"
    texte.write_text("ceci n'est pas SQLite" * 50, encoding="utf-8")
    code, _, err = lancer(capsys, "import", str(texte))
    assert code == 2 and "SQLite" in err
    autre = tmp_path / "autre.db"
    conn = sqlite3.connect(autre)
    conn.execute("CREATE TABLE autre (x INTEGER)")
    conn.commit()
    conn.close()
    code, _, err = lancer(capsys, "import", str(autre))
    assert code == 2 and "scans" in err


def test_import_refuse_la_base_courante(stockage, capsys):
    from domainrecon.core.database import engine

    code, _, err = lancer(capsys, "import", engine.url.database)
    assert code == 2 and "base courante" in err


def test_import_lecture_seule(stockage, tmp_path):
    base = tmp_path / "a.db"
    _ancienne_base(base, [{"id": 1, "domain": unique_domain("ro"), "scan_timestamp": "2025-01-01 00:00:00"}])
    avant = base.read_bytes()
    importer.import_scans(base)
    assert base.read_bytes() == avant, "la base source n'est jamais modifiée"
