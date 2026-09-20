# enc-workspace2

100 independently buildable Rust file-encryption apps, **a1–a100**, in one Cargo workspace. Each has the same three-argument command:

```text
a1.exe E input.bin encrypted.bin
a1.exe D encrypted.bin restored.bin
```

`key.key`, the input, and the new output all belong **beside that executable**, regardless of the terminal's working directory. Use plain filenames; quote names with spaces. E and D are uppercase. Original files are retained. Existing outputs are never overwritten. Files are processed in memory, with a **64 MiB plaintext limit**.

## Ready to use on Windows

The delivered Desktop folder includes compiled apps in `dist\a1` through `dist\a100`, plus `dist\keygen.exe`. They are separate executables, not one program that switches algorithms at runtime.

1. Run `make-key.cmd a1` once. It creates 32 random bytes in `dist\a1\key.key` and refuses to replace any existing key.
2. Copy your input into `dist\a1`.
3. In a terminal, run `dist\a1\a1.exe E input.bin encrypted.bin`.
4. Decrypt with `dist\a1\a1.exe D encrypted.bin restored.bin`.

Use the **same app and exact key file** for decryption. Back up the key separately and privately. Losing it loses access to the encrypted files. Do not send the key with the ciphertext. The workspace contains no pre-generated secret keys. You can move an executable into another directory and place its key and files there.

Existing nonempty key files up to 1 MiB are supported as **raw bytes**, including all whitespace. Every app derives its required key size from those bytes. This is not password stretching: short phrases, public files, and predictable keys are weak. Prefer the key generator. A 32-byte random file gives at most 256 bits of key entropy even for Threefish-1024.

## Build or test one app

Install Rust through [rustup](https://rustup.rs/). The pinned toolchain is 1.98.1.

```text
build.cmd a1
test.cmd a1
menu.cmd
```

`build.cmd a1` builds only a1 and copies it to `dist\a1`; it does not replace `key.key`. The menu lists all names and their categories. The equivalent Cargo commands, run in the workspace root, are:

```text
cargo build --release --locked -p a1
cargo test --locked -p a1
cargo test --workspace --locked
cargo build --release --locked --workspace --bins
cargo clean
```

All apps share the root `target` cache. **One `cargo clean` cleans the entire workspace.** It does not remove `dist` or keys. `target`, `dist`, and every `key.key` are ignored by Git. Keep plaintext files in the ignored `dist` directories, not in source directories. Copying a key under a different filename will not automatically be ignored.

On Linux/macOS use Cargo directly; place files beside `target/release/a1`, or copy that binary elsewhere. Run `cargo run --release --locked -p keygen -- /absolute/app/directory` to create a key. Windows binaries do not run on those systems.

## Choosing an app

For ordinary experiments start with **a1 (ChaCha20-Poly1305), a2 (XChaCha20-Poly1305), a5 (AES-256-GCM), or a7 (AES-256-GCM-SIV)**. All files use a custom versioned envelope and an outer HMAC-SHA256; native AEAD apps also retain their own authentication tag. This workspace has automated tests and implementation checks, **not an external security audit or certification**.

Reduced-round ciphers and unusual cipher/mode combinations are experimental. **a90–a91 use obsolete RC4; a92–a100 are deliberately insecure toys.** Authentication does not repair their weak confidentiality. Do not put sensitive data through those apps.

Files expose the app ID and plaintext length. They do not store the original filename. The format is not compatible with enc-workspace, enc-workspace1, OpenSSL command-line files, or other tools unless those tools implement [FORMAT.md](FORMAT.md).

## Structure

- `apps/aN`: each app's manifest, thin backend binding, tests, and README.
- `support/keyfile-core`: common framing, key derivation, authentication, file validation, private output publication.
- `support/backends`: small wrappers around RustCrypto crates; explicitly labelled toy implementations.
- `support/tests`: shared per-app adversarial and real command-line tests.
- `tools/keygen`: random key-file generator.
- `verification`: published vectors, independent checks, dependency scan and results.
- `dist/aN`: local compiled executables and your working files (ignored by Git).

See [SECURITY.md](SECURITY.md), [FORMAT.md](FORMAT.md), and [verification/README.md](verification/README.md).

## App catalog

| App | Algorithm / mode | Classification |
|---|---|---|
| [a1](apps/a1/README.md) | ChaCha20Poly1305 | established primitive |
| [a2](apps/a2/README.md) | XChaCha20Poly1305 | established primitive |
| [a3](apps/a3/README.md) | AES-128-GCM | established primitive |
| [a4](apps/a4/README.md) | AES-192-GCM | established primitive |
| [a5](apps/a5/README.md) | AES-256-GCM | established primitive |
| [a6](apps/a6/README.md) | AES-128-GCM-SIV | established primitive |
| [a7](apps/a7/README.md) | AES-256-GCM-SIV | established primitive |
| [a8](apps/a8/README.md) | AES-128-SIV | established primitive |
| [a9](apps/a9/README.md) | AES-256-SIV | established primitive |
| [a10](apps/a10/README.md) | Ascon-AEAD128 | established primitive |
| [a11](apps/a11/README.md) | ChaCha8Poly1305 | reduced-round / experimental |
| [a12](apps/a12/README.md) | ChaCha12Poly1305 | reduced-round / experimental |
| [a13](apps/a13/README.md) | XChaCha8Poly1305 | reduced-round / experimental |
| [a14](apps/a14/README.md) | XChaCha12Poly1305 | reduced-round / experimental |
| [a15](apps/a15/README.md) | AES-128-EAX | established primitive |
| [a16](apps/a16/README.md) | AES-192-EAX | established primitive |
| [a17](apps/a17/README.md) | AES-256-EAX | established primitive |
| [a18](apps/a18/README.md) | CAMELLIA-128-EAX | established primitive |
| [a19](apps/a19/README.md) | CAMELLIA-192-EAX | established primitive |
| [a20](apps/a20/README.md) | CAMELLIA-256-EAX | established primitive |
| [a21](apps/a21/README.md) | ARIA-128-EAX | established primitive |
| [a22](apps/a22/README.md) | ARIA-192-EAX | established primitive |
| [a23](apps/a23/README.md) | ARIA-256-EAX | established primitive |
| [a24](apps/a24/README.md) | Serpent-256-EAX | composed / experimental |
| [a25](apps/a25/README.md) | Twofish-256-EAX | composed / experimental |
| [a26](apps/a26/README.md) | SM4-128-EAX | composed / experimental |
| [a27](apps/a27/README.md) | Kuznyechik-256-EAX | composed / experimental |
| [a28](apps/a28/README.md) | CAST6-256-EAX | composed / experimental |
| [a29](apps/a29/README.md) | RC6-256-EAX | composed / experimental |
| [a30](apps/a30/README.md) | AES-128-CCM | established primitive |
| [a31](apps/a31/README.md) | AES-192-CCM | established primitive |
| [a32](apps/a32/README.md) | AES-256-CCM | established primitive |
| [a33](apps/a33/README.md) | CAMELLIA-128-CCM | established primitive |
| [a34](apps/a34/README.md) | CAMELLIA-192-CCM | established primitive |
| [a35](apps/a35/README.md) | CAMELLIA-256-CCM | established primitive |
| [a36](apps/a36/README.md) | ARIA-128-CCM | established primitive |
| [a37](apps/a37/README.md) | ARIA-192-CCM | established primitive |
| [a38](apps/a38/README.md) | ARIA-256-CCM | established primitive |
| [a39](apps/a39/README.md) | Serpent-256-CCM | composed / experimental |
| [a40](apps/a40/README.md) | Twofish-256-CCM | composed / experimental |
| [a41](apps/a41/README.md) | SM4-128-CCM | composed / experimental |
| [a42](apps/a42/README.md) | Kuznyechik-256-CCM | composed / experimental |
| [a43](apps/a43/README.md) | CAST6-256-CCM | composed / experimental |
| [a44](apps/a44/README.md) | RC6-256-CCM | composed / experimental |
| [a45](apps/a45/README.md) | AES-128-CTR | established primitive |
| [a46](apps/a46/README.md) | AES-192-CTR | established primitive |
| [a47](apps/a47/README.md) | AES-256-CTR | established primitive |
| [a48](apps/a48/README.md) | CAMELLIA-128-CTR | established primitive |
| [a49](apps/a49/README.md) | CAMELLIA-192-CTR | established primitive |
| [a50](apps/a50/README.md) | CAMELLIA-256-CTR | established primitive |
| [a51](apps/a51/README.md) | ARIA-128-CTR | established primitive |
| [a52](apps/a52/README.md) | ARIA-192-CTR | established primitive |
| [a53](apps/a53/README.md) | ARIA-256-CTR | established primitive |
| [a54](apps/a54/README.md) | Serpent-256-CTR | composed / experimental |
| [a55](apps/a55/README.md) | Twofish-256-CTR | composed / experimental |
| [a56](apps/a56/README.md) | SM4-128-CTR | composed / experimental |
| [a57](apps/a57/README.md) | Kuznyechik-256-CTR | composed / experimental |
| [a58](apps/a58/README.md) | CAST6-256-CTR | composed / experimental |
| [a59](apps/a59/README.md) | RC6-256-CTR | composed / experimental |
| [a60](apps/a60/README.md) | AES-128-CBC | established primitive |
| [a61](apps/a61/README.md) | AES-192-CBC | established primitive |
| [a62](apps/a62/README.md) | AES-256-CBC | established primitive |
| [a63](apps/a63/README.md) | CAMELLIA-128-CBC | established primitive |
| [a64](apps/a64/README.md) | CAMELLIA-192-CBC | established primitive |
| [a65](apps/a65/README.md) | CAMELLIA-256-CBC | established primitive |
| [a66](apps/a66/README.md) | ARIA-128-CBC | established primitive |
| [a67](apps/a67/README.md) | ARIA-192-CBC | established primitive |
| [a68](apps/a68/README.md) | ARIA-256-CBC | established primitive |
| [a69](apps/a69/README.md) | Serpent-256-CBC | composed / experimental |
| [a70](apps/a70/README.md) | Twofish-256-CBC | composed / experimental |
| [a71](apps/a71/README.md) | SM4-128-CBC | composed / experimental |
| [a72](apps/a72/README.md) | Kuznyechik-256-CBC | composed / experimental |
| [a73](apps/a73/README.md) | CAST6-256-CBC | composed / experimental |
| [a74](apps/a74/README.md) | RC6-256-CBC | composed / experimental |
| [a75](apps/a75/README.md) | ChaCha8-HMAC | reduced-round / experimental |
| [a76](apps/a76/README.md) | ChaCha12-HMAC | reduced-round / experimental |
| [a77](apps/a77/README.md) | ChaCha20-HMAC | established primitive |
| [a78](apps/a78/README.md) | XChaCha8-HMAC | reduced-round / experimental |
| [a79](apps/a79/README.md) | XChaCha12-HMAC | reduced-round / experimental |
| [a80](apps/a80/README.md) | XChaCha20-HMAC | established primitive |
| [a81](apps/a81/README.md) | Salsa8-HMAC | reduced-round / experimental |
| [a82](apps/a82/README.md) | Salsa12-HMAC | reduced-round / experimental |
| [a83](apps/a83/README.md) | Salsa20-HMAC | established primitive |
| [a84](apps/a84/README.md) | XSalsa8-HMAC | reduced-round / experimental |
| [a85](apps/a85/README.md) | XSalsa12-HMAC | reduced-round / experimental |
| [a86](apps/a86/README.md) | XSalsa20-HMAC | established primitive |
| [a87](apps/a87/README.md) | Threefish-256-CTR | composed / experimental |
| [a88](apps/a88/README.md) | Threefish-512-CTR | composed / experimental |
| [a89](apps/a89/README.md) | Threefish-1024-CTR | composed / experimental |
| [a90](apps/a90/README.md) | RC4-128-HMAC | obsolete / insecure |
| [a91](apps/a91/README.md) | RC4-256-HMAC | obsolete / insecure |
| [a92](apps/a92/README.md) | Toy repeating-xor | TOY / insecure |
| [a93](apps/a93/README.md) | Toy repeating-add | TOY / insecure |
| [a94](apps/a94/README.md) | Toy beaufort-byte | TOY / insecure |
| [a95](apps/a95/README.md) | Toy affine-byte | TOY / insecure |
| [a96](apps/a96/README.md) | Toy rotate-byte | TOY / insecure |
| [a97](apps/a97/README.md) | Toy xor-rotate | TOY / insecure |
| [a98](apps/a98/README.md) | Toy substitution | TOY / insecure |
| [a99](apps/a99/README.md) | Toy xorshift64 | TOY / insecure |
| [a100](apps/a100/README.md) | Toy lcg64 | TOY / insecure |
