# ENCWS2 version 1 file format

All integers in the header use little endian. Each app has a permanently assigned ID in `apps.json`. Changing an existing algorithm, parameter, or construction requires a new format version or app ID.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 8 | ASCII `ENCWS2` followed by CR LF |
| 8 | 1 | version = 1 |
| 9 | 2 | application ID, u16 LE |
| 11 | 1 | flags = 0 |
| 12 | 8 | exact plaintext length, u64 LE |
| 20 | 32 | fresh OS-random salt |
| 52 | 12 | reserved, all zero |
| 64 | variable | cipher body |
| end − 32 | 32 | HMAC-SHA256(header || cipher body) |

The reader checks magic, version, app ID, zero fields, bounded length, exact expected body length and total file length. It rejects all trailing bytes. The outer HMAC is verified in constant time before decrypting any body or checking CBC padding. No plaintext file is created until authentication and decryption complete successfully.

## Derivation

1. Read 1–1,048,576 raw bytes from `key.key` (no text or hex decoding).
2. `IKM = SHA256(key_file_bytes)`.
3. HKDF-SHA256 extract using the header salt, then expand with the info bytes `enc-workspace2/v1/keys/` followed by the two-byte LE app ID.
4. Request `key_len + nonce_len + 32` bytes. Split into cipher key, cipher nonce/IV, and independent HMAC key in that order. Lengths are fixed per app in `apps.json`.

The 256-bit salt makes repeated encryption probabilistic and separates derived encryption keys between files; app IDs separate apps. This is a raw key-file construction, **not a password KDF**. SHA256/HKDF cannot add entropy to a predictable file.

## Body encodings

- Native AEAD, EAX, and CCM: full 16-byte native tag. SIV (a8/a9) places the tag **before** ciphertext; all other native AEADs append it. Associated data is the entire 64-byte header.
- CCM: 11-byte nonce, 16-byte tag, four-byte message-length field.
- CTR: RustCrypto `Ctr64BE`, including wide-block Threefish. Keep the prefix of the derived IV unchanged and increment its final eight bytes as a big-endian counter modulo 2^64, starting with the derived IV. The small file limit prevents counter repetition. Threefish uses a zero tweak.
- CBC: standard PKCS#7 padding, always adding 1–16 bytes. Padding is checked only after the outer HMAC succeeds.
- ChaCha/XChaCha and Salsa/XSalsa streams: crate-defined standard nonce layout, counter starts at zero; full or reduced rounds as named.
- RC4: derived key, no nonce argument, no initial keystream drop. RC4 is obsolete and insecure.
- Toys: length-preserving byte transforms defined in `support/backends/toy.rs` and independently reproduced in `verification/reference.py`. These are not secure ciphers or standards.

The overhead is 96 bytes plus the native AEAD tag (16), or CBC padding (1–16), or zero for length-preserving bodies. Ciphertext carries no password, key file, original filename, or algorithm negotiation. Decrypt with the same app.
