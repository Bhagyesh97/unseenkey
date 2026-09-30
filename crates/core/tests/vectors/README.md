# Known-answer test vectors

Each JSON file holds published vectors for one primitive. `tests/vectors.rs`
loads them and checks our wrappers against them on every target, including
`wasm32`, so platform differences are caught by CI.

| File | Source |
|---|---|
| `argon2id.json` | phc-winner-argon2 reference `test.c` (Argon2id, v1.3) |
| `xchacha20poly1305.json` | draft-irtf-cfrg-xchacha, Appendix A.3.1 |
| `hkdf_sha256.json` | RFC 5869, Appendix A, test case 1 |
| `blake3.json` | BLAKE3 official test vectors (empty input) |
| `ed25519.json` | RFC 8032, Section 7.1, test 1 |

Never edit an expected value to make a test pass. If a vector fails, the
implementation is wrong.
