# obsigil-test-vectors

Cross-language test vectors for the
[obsigil](https://gitlab.com/uvar/oboron/obsigil/spec) mandate-token
format — a JWT-like token split into a public **manifest** and an
encrypted **mandate**, each an authenticated, deterministically-sealed
ciphertext (AES-SIV / AES-GCM-SIV) rendered as `b64` or `hex` text.

These vectors are consumed directly by any implementation. They are
plain JSONL files with a stable schema; no tooling is required to read
them. Because obsigil seals bytes deterministically (no nonce), a token
is an exact function of its inputs, so every vector is an exact-match
known-answer test.

## Files

- `test-vectors.jsonl` — positive vectors: per-half octets ⇄ token.
- `negative-test-vectors.jsonl` — inputs that MUST be rejected.

## Keys

Two published keys, **insecure by design** (they are published here),
for conformance testing only. Vectors reference them by role.

### Manifest key (`manifest`)

The public 64-byte manifest key pinned by the spec (§4.2). The manifest
half is sealed *keyless* under it — anyone can open and forge a
manifest. Hex (128 chars):

```
381284633d02ea5f35df8596b5cc4218310060468e8b465455a415174ea6e966a9f48eec4ba446ddfc8b78587895356f45a75a1ab7419454dd9f7aa8a95dbdd5
```

### Mandate key (`mandate`)

A 64-byte secret mandate key, distinct from the manifest key (§4.1),
defined for these vectors as `SHA-512("obsigil test mandate key v1")`.
Hex (128 chars):

```
a341adc813cfa493412cda5900fa4ec83f20a6cdea4fe5c759f7ccdb7ffbec51e01d2ce90c592909adb2ac1cad771790353f439ac86e9b113a17f7c57f0684b0
```

Code `0` (AES-SIV) uses the full 64-byte key directly. Code `1`
(AES-GCM-SIV) derives a 32-byte key with `HKDF-Expand` (info `gcmsiv`,
no Extract; spec §5.1).

## Positive vectors

Each line pins the per-half **octets** (`tag || serialized-fields`, the
normative input) to one exact **token**. The mapping is bidirectional —
a sealer and an opener both reproduce it without a serializer:

```json
{"encoding": "b64",
 "manifest": {"alg": "0", "octets": "6a7b...", "fields": {"iss": "auth.example"}},
 "mandate":  {"alg": "0", "octets": "6a7b...", "fields": {"exp": 4000000000, "tid": "019e..."}},
 "token": "<manifest>0.0<mandate>"}
```

- `encoding` — `b64` (separator `.`) or `hex` (separator `~`).
- `manifest` / `mandate` — each optional; an absent half is omitted
  (manifest-only and mandate-only tokens are valid). `alg` is the
  one-character algorithm code (`0` AES-SIV, `1` AES-GCM-SIV). `octets`
  is the hex of the half's plaintext `tag || serialized-fields` (tag:
  `6a` JSON, `74` TOML, `63` CBOR). `fields` is a **non-normative**
  decode for the reader.
- `token` — the exact token string.

A conforming implementation checks whichever direction it performs:

- **seal:** for each present half,
  `encode(seal(octets, key[role], alg), encoding)`; assemble the halves
  with the separator and codes — the result MUST equal `token`.
- **open:** `parse(token)`, then for each present half
  `open(decode(half_text, encoding), key[role], alg)` MUST equal
  `octets`.

The manifest half uses the `manifest` key; the mandate half uses the
`mandate` key.

## Negative vectors

Each line is an input a conforming implementation MUST reject:

```json
{"op": "verify", "token": "...", "key": "mandate", "now": 4000000001, "reason": "expired exp"}
{"op": "open-manifest", "token": "...", "reason": "manifest missing iss"}
{"op": "parse", "token": "a.b.c", "reason": "more than one separator"}
```

- `op` — the operation that must fail: `verify` (the mandate path, under
  `key` and the given policy), `open-manifest` (yields no claims), or
  `parse` (structural).
- `token` — the input.
- `key` — for `verify`, the mandate key (role keyword or hex);
  defaults to `mandate`.
- `now` / `audience` — optional `verify` policy (NumericDate;
  verifier identifier).
- `reason` — informative; the rule being exercised.

Rejection is **uniform** (spec §9.5): an implementation MUST NOT signal
*why* to the bearer. Through the obsigil CLI a rejection is exit code 1.
Categories: malformed structure (separator count, degenerate half),
unrecognized/unsupported algorithm code, non-canonical encoding
(padding, impossible length, non-zero trailing bits, uppercase/odd
hex), a half below the 17-byte floor, authentication failure (wrong
key), missing or non-UUIDv7 `tid`, missing `exp`, expired `exp`,
`aud` mismatch or empty `aud`, an empty mandate, and a manifest
missing its required `iss`.

## Generation

The vectors are generated from the obsigil reference CLI by
[`tools/generate.py`](tools/generate.py), which seals the chosen octets
and assembles the tokens (and self-checks every line against the CLI).
Regenerate with the `obsigil` binary on `PATH`:

```sh
OBSIGIL_BIN=/path/to/obsigil python3 tools/generate.py
```

The vectors are the canonical reference, not any single implementation
(spec §10).

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.
