# Installation

DomainRecon est livré prêt à l'emploi : chaque livrable embarque Python, l'interface, les polices, la carte
du monde et le navigateur Chromium utilisé pour les captures d'écran et les rapports PDF. Rien d'autre à
installer.

## Choisir un livrable

Les fichiers sont publiés sur la page [Releases](https://github.com/w4ll-i/DomainRecon/releases) du dépôt,
avec le fichier `SHA256SUMS` et une attestation de provenance pour chacun.

| Système | Fichier | Usage |
|---|---|---|
| Windows 10 / 11 (64 bits) | `DomainRecon-1.0.0-setup.exe` | Installeur, sans droits d'administrateur. Pour un poste de travail durable. |
| Windows 10 / 11 (64 bits) | `DomainRecon-1.0.0-portable.exe` | Un seul fichier, rien à installer. S'ouvre d'un double-clic. |
| Windows 10 / 11 (64 bits) | `DomainRecon-1.0.0-portable-win64.zip` | Dossier à extraire (clé USB comprise), ouverture dans le navigateur. |
| Ubuntu 22.04+ / Debian 12+ (amd64) | `domainrecon_1.0.0_amd64.deb` | Paquet installé par `apt`. |

Tailles indicatives : installeur environ 126 Mo, zip portable environ 189 Mo, dossier installé environ 431 Mo.

## Vérifier le fichier téléchargé

Comparez l'empreinte du fichier à la ligne correspondante de `SHA256SUMS`.

Windows (PowerShell) :

```powershell
Get-FileHash .\DomainRecon-1.0.0-setup.exe -Algorithm SHA256
```

Linux, dans le dossier qui contient les fichiers téléchargés et `SHA256SUMS` :

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

Avec la [CLI GitHub](https://cli.github.com/), l'attestation de provenance prouve que le fichier a été construit
par le workflow de publication du dépôt :

```bash
gh attestation verify DomainRecon-1.0.0-setup.exe --repo w4ll-i/DomainRecon
```

## Avertissement SmartScreen

Les exécutables Windows ne sont pas signés : un certificat de signature de code est payant. Au premier
lancement, Windows affiche « Windows a protégé votre ordinateur ». Après avoir vérifié l'empreinte du
fichier, cliquez sur **Informations complémentaires**, puis sur **Exécuter quand même**. L'avertissement
est le même pour l'installeur et pour les deux versions portables.

## Windows : installeur

1. Lancez `DomainRecon-1.0.0-setup.exe`. L'installation se fait pour votre compte, sans droits
   d'administrateur, dans `%LOCALAPPDATA%\Programs\DomainRecon`.
2. Ouvrez **DomainRecon** depuis le menu Démarrer (raccourci sur le Bureau en option). L'application
   s'ouvre dans sa propre fenêtre, avec le moteur WebView2 présent sur Windows 10 et 11. Si WebView2
   manque, elle s'ouvre dans le navigateur. Le raccourci **DomainRecon (dans le navigateur)** l'ouvre
   directement dans le navigateur.
3. Vos données (base des scans, captures, réglages, journaux) sont dans `%LOCALAPPDATA%\DomainRecon`.

## Windows : portable en un seul fichier

1. Placez `DomainRecon-1.0.0-portable.exe` où vous voulez, clé USB comprise.
2. Double-cliquez dessus : rien n'est installé. L'application s'ouvre dans sa propre fenêtre (repli dans le
   navigateur si WebView2 manque).
3. Les données sont écrites dans un dossier `DomainRecon-data` créé à côté du `.exe`, et nulle part
   ailleurs. Pour tout effacer, supprimez le `.exe` et ce dossier.

Le démarrage est plus lent que celui des autres versions : à chaque lancement, le fichier décompresse
Python, l'interface et Chromium dans un dossier temporaire avant de s'ouvrir.

## Windows : portable (zip)

1. Extrayez `DomainRecon-1.0.0-portable-win64.zip` où vous voulez.
2. Double-cliquez sur `Lancer DomainRecon.bat` : une console affiche l'adresse locale, puis l'interface
   s'ouvre dans votre navigateur. Fermez la console pour arrêter DomainRecon.
3. Les données sont écrites dans le dossier `data\` à côté de l'exécutable : le fichier `portable.flag`
   active ce mode. `DomainRecon.exe`, dans le même dossier, ouvre l'application dans une fenêtre.

## Linux : paquet .deb

```bash
sudo apt install ./domainrecon_1.0.0_amd64.deb
```

- `apt` installe aussi les bibliothèques dont Chromium a besoin. Le paquet est construit sur Ubuntu 22.04 :
  il fonctionne sur Ubuntu 22.04 ou plus récent et sur Debian 12 ou plus récent.
- Lancez **DomainRecon** depuis le menu des applications, ou `domainrecon` dans un terminal.
- La fenêtre native utilise WebKitGTK (`libwebkit2gtk-4.1-0` et `gir1.2-webkit2-4.1`, installés comme
  paquets recommandés). Sans eux (installation avec `--no-install-recommends`, serveur sans bureau),
  DomainRecon s'ouvre dans le navigateur ; Ctrl+C dans le terminal l'arrête.
- Application : `/opt/domainrecon`. Données : `~/.local/share/domainrecon` (ou `$XDG_DATA_HOME/domainrecon`).

## Où sont mes données ?

| Mode | Dossier des données |
|---|---|
| Installeur Windows | `%LOCALAPPDATA%\DomainRecon` |
| Portable un seul fichier | `DomainRecon-data\` à côté du `.exe` |
| Portable zip | `data\` à côté de l'exécutable |
| Paquet .deb | `~/.local/share/domainrecon` |
| Depuis les sources | `private/data/` à la racine du dépôt |

Le dossier se trouve aussi dans **Réglages**, avec un bouton pour l'ouvrir. Pour désinstaller, voir
[Désinstallation](desinstallation.md).

## Depuis les sources

Voir [Développement](developpement.md).
