# Maintenance

Keep every app independently buildable (`cargo build -p aN`). Never reuse an assigned app ID for a changed format, primitive, round count, key size, nonce size or body encoding. Add new IDs for incompatible changes.

Preserve executable-relative paths, private no-clobber publication, the input file, and key files. Never generate or commit real key files. Keep the toy/obsolete/reduced-round classifications visible. Do not describe tests as a formal security audit.

Changes to shared code affect all apps. Run workspace tests, clippy with warnings denied, formatting checks, and the applicable independent verifier after meaningful changes. Shared include files under `support/backends` and `support/tests` also require rustfmt explicitly. Keep app READMEs and apps.json synchronized. Do not alter antivirus settings.
