# Release notes

## Current release

- Automatically detects whether a DMG uses the supported `encrcdsa` encryption format.
- Prompts for a password only when the selected DMG is encrypted.
- Opens unencrypted DMG files directly without creating a decrypted copy.
- Keeps the original DMG read-only and extracts into a newly named directory to avoid overwriting existing files.
- Includes the Python runtime, cryptography dependency, and 7-Zip in the Windows executable.
- Contains no networking, telemetry, cloud upload, or update-checking code.

