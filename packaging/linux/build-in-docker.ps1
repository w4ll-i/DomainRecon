# =============================================================================
# DomainRecon - Paquet .deb construit et teste dans Docker (depuis Windows)
# =============================================================================
# Usage (PowerShell, Docker Desktop demarre, interface deja construite dans
# domainrecon\web et frontend\node_modules installe : npm ci) :
#   powershell -ExecutionPolicy Bypass -File packaging\linux\build-in-docker.ps1 [-Work <dossier>] [-SkipSmoke]
# Etapes :
#   1. copie dans <Work>\src des seuls fichiers utiles a la construction (liste
#      blanche : code de l'application, packaging, licence, pyproject.toml,
#      paquets npm pour les textes de licence) ;
#   2. conteneur ubuntu:22.04 : docker-build.sh (Python 3.13, dependances
#      figees, packaging/build.py --target linux --skip-frontend) ;
#   3. copie du paquet dans release\<version>\ du depot, puis SHA256SUMS de ce
#      dossier recalcule et NOTES.md copie depuis docs\releases\<version>.md ;
#   4. sauf -SkipSmoke : conteneur ubuntu:22.04 vierge, installation du paquet
#      et test de fumee (docker-smoke.sh).
# <Work> vaut par defaut private\build\docker (ignore par git). Dossier de
# travail, cache de pip et sorties restent sur l'hote : seuls les paquets apt
# vivent dans les conteneurs, supprimes a la fin (--rm).
# =============================================================================
[CmdletBinding()]
param(
    [string]$Work = '',
    [string]$Image = 'ubuntu:22.04',
    [switch]$SkipSmoke
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Work) { $Work = Join-Path $Root 'private\build\docker' }

# Liste blanche : dossiers copies en miroir et fichiers de la racine du depot.
$CopiedDirs = @('domainrecon', 'packaging')
$CopiedFrontend = @('package.json', 'package-lock.json')
$CopiedFiles = @('pyproject.toml', 'LICENSE')

function Invoke-Checked {
    param([string]$Label, [scriptblock]$Command)
    Write-Host "`n>>> $Label"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "Echec (code $LASTEXITCODE) : $Label" }
}

# Chemin Windows -> chemin de montage Docker (barres obliques). Replace() : texte
# litteral (-replace attend une expression reguliere, ou '\' seul est invalide).
function ConvertTo-DockerPath([string]$Path) {
    return (Resolve-Path $Path).Path.Replace('\', '/')
}

# robocopy : codes de retour inferieurs a 8 = succes.
function Copy-Tree([string]$From, [string]$To) {
    robocopy $From $To /MIR /NFL /NDL /NJH /NJS /NP /XD __pycache__ | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copie impossible (robocopy, code $LASTEXITCODE) : $From" }
}

function Copy-Files([string]$From, [string]$To, [string[]]$Names) {
    New-Item -ItemType Directory -Force $To | Out-Null
    foreach ($name in $Names) {
        Copy-Item (Join-Path $From $name) (Join-Path $To $name) -Force
    }
}

# SHA256SUMS : "empreinte  nom" (format de sha256sum), livrables connus presents, ordre ordinal.
function Write-Checksums([string]$Dir, [string]$Version) {
    [string[]]$names = @(
        "DomainRecon-$Version-setup.exe",
        "DomainRecon-$Version-portable.exe",
        "DomainRecon-$Version-portable-win64.zip",
        "domainrecon_${Version}_amd64.deb"
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $Dir $_) -PathType Leaf }
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $lines = foreach ($name in $names) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Dir $name)).Hash.ToLowerInvariant()
        "$hash  $name`n"
    }
    [IO.File]::WriteAllText((Join-Path $Dir 'SHA256SUMS'), (-join $lines), (New-Object Text.UTF8Encoding $false))
}

docker info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) { throw 'Docker ne repond pas : demarrez Docker Desktop.' }
if (-not (Test-Path (Join-Path $Root 'domainrecon\web\index.html'))) {
    throw 'Interface absente (domainrecon\web) : lancez npm ci puis npm run build dans frontend\.'
}
if (-not (Test-Path (Join-Path $Root 'frontend\node_modules'))) {
    throw 'frontend\node_modules absent (textes de licence) : lancez npm ci dans frontend\.'
}

$src = Join-Path $Work 'src'
New-Item -ItemType Directory -Force $src, (Join-Path $Work 'pip-cache') | Out-Null
foreach ($dir in $CopiedDirs) { Copy-Tree (Join-Path $Root $dir) (Join-Path $src $dir) }
Copy-Tree (Join-Path $Root 'frontend\node_modules') (Join-Path $src 'frontend\node_modules')
Copy-Files (Join-Path $Root 'frontend') (Join-Path $src 'frontend') $CopiedFrontend
Copy-Files $Root $src $CopiedFiles

$init = [IO.File]::ReadAllText((Join-Path $Root 'domainrecon\__init__.py'), [Text.Encoding]::UTF8)
$version = [regex]::Match($init, '__version__ = "([^"]+)"').Groups[1].Value
if (-not $version) { throw 'Version introuvable dans domainrecon\__init__.py' }
$deb = "domainrecon_${version}_amd64.deb"
$workMount = ConvertTo-DockerPath $Work

Invoke-Checked "Construction du paquet $deb ($Image)" {
    docker run --rm --shm-size=1g -v "${workMount}:/work" $Image sh /work/src/packaging/linux/docker-build.sh
}
$built = Join-Path $src "release\$version\$deb"
if (-not (Test-Path $built)) { throw "Paquet attendu introuvable : $built" }
$releaseDir = Join-Path $Root "release\$version"
New-Item -ItemType Directory -Force $releaseDir | Out-Null
Copy-Item $built $releaseDir -Force
Write-Checksums $releaseDir $version
$notes = Join-Path $Root "docs\releases\$version.md"
if (Test-Path $notes) { Copy-Item $notes (Join-Path $releaseDir 'NOTES.md') -Force }
Write-Host "Paquet : $(Join-Path $releaseDir $deb)"

if (-not $SkipSmoke) {
    $releaseMount = ConvertTo-DockerPath $releaseDir
    $packagingMount = ConvertTo-DockerPath (Join-Path $Root 'packaging')
    Invoke-Checked "Test de fumee du paquet ($Image vierge)" {
        docker run --rm --shm-size=1g -v "${releaseMount}:/release:ro" -v "${packagingMount}:/packaging:ro" $Image `
            sh /packaging/linux/docker-smoke.sh "/release/$deb" $version
    }
}
