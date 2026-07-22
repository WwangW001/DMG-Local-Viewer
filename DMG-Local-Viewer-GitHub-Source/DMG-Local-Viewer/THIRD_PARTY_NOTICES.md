# Third-party notices

The portable executable contains the following third-party software:

## 7-Zip 26.02

- Components: `7z.exe`, `7z.dll`
- Project: https://www.7-zip.org/
- Source: https://github.com/ip7z/7zip/releases/tag/26.02
- Licenses: GNU LGPL 2.1 or later for most code, plus the BSD and unRAR notices described in `licenses/7-Zip-License.txt`.
- The bundled binaries are unmodified. The corresponding `7z2602-src.7z` source archive is included with the portable release.

## Python

- Project: https://www.python.org/
- License: Python Software Foundation License Version 2 and incorporated third-party notices. See `licenses/Python-License.txt`.

## cryptography 49.0.0

- Project: https://github.com/pyca/cryptography
- License: dual licensed under Apache License 2.0 or BSD. See the cryptography license files under `licenses/`.

## PyInstaller 6.21.0

- Project: https://pyinstaller.org/
- License: GPL 2.0 with a bootloader exception that permits distribution of generated executables under the application license, subject to dependency licenses.

## Format implementation references

The encrypted-DMG implementation was written in Python using public format information and behavior cross-checked against `vfdecrypt` from dmg2img and the encrypted-DMG implementation in `blacktop/go-apfs`. No dmg2img, vfdecrypt, or go-apfs executable code is bundled in the release.
