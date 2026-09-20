# a49: CAMELLIA-192-CTR

**Classification: established primitive.** 

This app reads raw `key.key` bytes beside its executable and encrypts/decrypts one file in memory. Input and output must be plain filenames in that same directory. Use the same app and key for decryption; other numbered apps deliberately use different key domains and IDs.

```text
build.cmd a49
make-key.cmd a49
dist\a49\a49.exe E input.bin encrypted.bin
dist\a49\a49.exe D encrypted.bin restored.bin
test.cmd a49
```

Run the helpers from the workspace root. Copy `input.bin` into `dist\a49` first. Key generation is needed only once; it refuses to replace a key. If you supply your own key file, use 32 or more random bytes. Nonempty raw files up to 1 MiB are accepted, but weak files are still weak. No password stretching is performed.

The derived cipher key is **24 bytes**, and its derived nonce/IV is **16 bytes**. A fresh 32-byte salt and HKDF-SHA256 separate every file's cipher and HMAC keys. The full header and cipher body receive an independent HMAC-SHA256 tag. Native AEADs additionally retain their own 16-byte authentication tag. Plaintext is limited to 64 MiB. All authentication finishes before any output is published. Existing output, original input, key file and executable are never overwritten.

Implementation: [backend source](src/lib.rs), [primitive documentation](https://docs.rs/camellia), and [shared file format](../../FORMAT.md). Tests are in `tests/app.rs`, which includes the workspace's common adversarial and real CLI cases. Published primitive-vector and native-tag tests are present where applicable. Run `cargo test --locked -p a49` from the workspace root.

See [root README](../../README.md) and [security limits](../../SECURITY.md). This project is tested, not externally audited. Toy and obsolete variants are not suitable for confidential data.
