# Verification

Run these from the workspace root:

```text
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo build --release --workspace --bins --locked
```

The shared test source is included separately in all 100 apps. It exercises binary/empty roundtrips at block boundaries, randomization, wrong keys, all header bytes, body/MAC corruption, truncation, trailing bytes, wrong IDs and hostile lengths. Real CLI tests copy each binary to an isolated directory and check executable-relative paths, Unicode filenames, missing/empty keys, no-overwrite behavior, invalid arguments, protected files and no output after authentication failure.

Primitive KATs check published AES, Camellia, ARIA, Serpent, Twofish, SM4, Kuznyechik, CAST6, RC6 and Threefish vectors in the selected bindings. The vector values and provenance are in `primitive-vectors.json`. Standardized Ascon-AEAD128 has three additional KATs from the upstream corpus. Every native AEAD wrapper also tests its native tag and associated-data rejection independently of the outer HMAC. Keygen and private-file helpers have their own tests.

## Independent implementation checks

Install the optional verifier requirements in a Python virtual environment, then run:

```text
python -m pip install -r verification/requirements.txt
python verification/reference.py
```

The verifier uses Python hashlib/hmac, [PyCryptodome](https://www.pycryptodome.org/src/cipher/modern), and cryptography/OpenSSL to independently derive keys and encrypt/decrypt compatible envelopes in both directions. It tests 0, 1, 15, 16, 17, 257 and 4097-byte payloads. It covers AES modes, full-round ChaCha20/XChaCha20, Salsa20, Camellia CTR/CBC, SM4 CTR/CBC, RC4, and separately transcribed toys. It does not implement all 100 primitives. `independent-results.json` lists exact coverage, and `results.json` records the delivered checks.

Toys passing tests means their defined transforms invert correctly, not that they offer confidentiality. Published primitive vectors do not constitute independent validation of every composed mode. The included Python verifier is a test tool, not a supported alternative encryption application.
