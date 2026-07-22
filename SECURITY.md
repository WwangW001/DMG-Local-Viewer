# Security

## Supported use

DMG Local Viewer is intended for local, read-only inspection of trusted encrypted and unencrypted DMG files. It does not include networking, telemetry, update checking, or cloud upload code.

## Sensitive temporary data

The decrypted DMG is written to a randomly named directory under the operating system temporary directory. The application removes that directory on a normal exit. A crash, forced termination, or power loss can leave it behind. Close the application before manually removing stale `dmg_local_viewer_*` directories from `%TEMP%`.

## Reporting a vulnerability

Do not post passwords, decrypted images, or private sample files in a public issue. Report the smallest reproducible description possible and use a private GitHub security advisory when confidential details are required.
