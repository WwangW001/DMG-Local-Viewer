param(
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ProjectRoot = $PSScriptRoot
$BuildRoot = Join-Path $ProjectRoot '.build'
$DownloadRoot = Join-Path $BuildRoot 'downloads'
$SevenZipRoot = Join-Path $BuildRoot '7zip'
$VenvRoot = Join-Path $ProjectRoot '.venv'
$VenvPython = Join-Path $VenvRoot 'Scripts\python.exe'
$DistRoot = Join-Path $ProjectRoot 'dist'

$SevenZipVersion = '26.02'
$SevenZipMsiUrl = 'https://www.7-zip.org/a/7z2602-x64.msi'
$SevenZipMsiSha256 = 'DB407A4F6D4999E5C7BC00CE8A882BE94717B56E7FA68140FE3F12605D91643E'
$SevenZipSourceUrl = 'https://github.com/ip7z/7zip/releases/download/26.02/7z2602-src.7z'
$SevenZipSourceSha256 = 'C7502DD4557481F52CCF1B3E680329F1FDD207E79A25544AFEB3106325474944'

function Get-VerifiedDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Sha256
    )

    if (-not (Test-Path -LiteralPath $Destination)) {
        Invoke-WebRequest -Uri $Url -OutFile $Destination
    }
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash
    if ($Actual -ne $Sha256) {
        throw "Checksum mismatch for $Destination. Expected $Sha256, got $Actual."
    }
}

New-Item -ItemType Directory -Path $BuildRoot, $DownloadRoot, $DistRoot -Force | Out-Null

if (-not (Test-Path -LiteralPath $VenvPython)) {
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        & py.exe -3 -m venv $VenvRoot
    } elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
        & python.exe -m venv $VenvRoot
    } else {
        throw 'Python 3.10 or newer was not found. Install 64-bit Python from python.org.'
    }
}

& $VenvPython -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) and sys.maxsize > 2**32 else '64-bit Python 3.10+ is required')"
& $VenvPython -m pip install --disable-pip-version-check -r (Join-Path $ProjectRoot 'requirements-build.txt')

$MsiPath = Join-Path $DownloadRoot '7z2602-x64.msi'
$SourcePath = Join-Path $DownloadRoot '7z2602-src.7z'
Get-VerifiedDownload -Url $SevenZipMsiUrl -Destination $MsiPath -Sha256 $SevenZipMsiSha256
Get-VerifiedDownload -Url $SevenZipSourceUrl -Destination $SourcePath -Sha256 $SevenZipSourceSha256

$SevenZipExe = Join-Path $SevenZipRoot 'Files\7-Zip\7z.exe'
$SevenZipDll = Join-Path $SevenZipRoot 'Files\7-Zip\7z.dll'
$SevenZipLicense = Join-Path $SevenZipRoot 'Files\7-Zip\License.txt'
if (-not (Test-Path -LiteralPath $SevenZipExe)) {
    New-Item -ItemType Directory -Path $SevenZipRoot -Force | Out-Null
    $Arguments = @('/a', ('"' + $MsiPath + '"'), '/qn', ('TARGETDIR="' + $SevenZipRoot + '"'))
    $Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $Arguments -Wait -PassThru
    if ($Process.ExitCode -ne 0) {
        throw "7-Zip administrative extraction failed with exit code $($Process.ExitCode)."
    }
}

if (-not $SkipTests) {
    & $VenvPython -m unittest -v (Join-Path $ProjectRoot 'test_dmg_crypto.py')
}

& $VenvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name 'DMG-Local-Viewer' `
    --distpath $DistRoot `
    --workpath (Join-Path $BuildRoot 'pyinstaller') `
    --specpath $BuildRoot `
    --add-binary "$SevenZipExe;." `
    --add-binary "$SevenZipDll;." `
    --add-data "$SevenZipLicense;." `
    (Join-Path $ProjectRoot 'app.py')

$LicenseRoot = Join-Path $DistRoot 'licenses'
New-Item -ItemType Directory -Path $LicenseRoot -Force | Out-Null
Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'licenses') -File | Copy-Item -Destination $LicenseRoot -Force
Copy-Item -LiteralPath $SourcePath -Destination (Join-Path $LicenseRoot '7z2602-src.7z') -Force

Copy-Item -LiteralPath (Join-Path $ProjectRoot 'README.md') -Destination $DistRoot -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'RELEASE_NOTES.md') -Destination $DistRoot -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'LICENSE') -Destination $DistRoot -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'THIRD_PARTY_NOTICES.md') -Destination $DistRoot -Force

$Executable = Join-Path $DistRoot 'DMG-Local-Viewer.exe'
$Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Executable).Hash
$HashLine = "$Hash *DMG-Local-Viewer.exe"
Set-Content -LiteralPath (Join-Path $DistRoot 'SHA256SUMS.txt') -Value $HashLine -Encoding Ascii
Write-Host "Build complete: $Executable"
Write-Host "SHA-256: $Hash"
