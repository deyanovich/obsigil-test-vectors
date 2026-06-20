#!/usr/bin/env python3
"""Generate obsigil test vectors for the canonical-CBOR model.

Both halves of a token are a single canonical CBOR map (RFC 8949 §4.2):
reserved fields at negative integer keys (tid -1, exp -2, aud -3, sub -4,
iss -5), application data at non-negative integer / text-string keys, keys
sorted by their encoded bytes, integers and lengths shortest-form, definite
lengths. We build the per-half octets with a tiny canonical encoder, `seal`
them with the obsigil CLI, and assemble the token; every line is self-checked
against the CLI before it is written (positives reproduce and verify / open;
negatives exit non-zero). Because the verifier now rejects non-canonical
CBOR, a positive whose octets are not canonical fails its own self-check.

Usage:  OBSIGIL_BIN=/path/to/obsigil python3 tools/generate.py
"""

import json
import os
import struct
import subprocess
import uuid

BIN = os.environ.get("OBSIGIL_BIN", "obsigil")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TID = "019ed29a-378d-72f0-b462-4929cd2bfcad"  # a fixed UUIDv7
NIL = "00000000-0000-0000-0000-000000000000"  # version 0 — not a v7
# Version field 7 but variant nibble 0 (NCS, 0b00) — not a well-formed UUIDv7
# (spec §11.3 requires version 7 AND the RFC 4122 variant 0b10).
TID_BADVAR = "019ed29a-378d-72f0-0462-4929cd2bfcad"
V4 = "00000000-0000-4000-8000-000000000000"  # version 4 (the common UUID)
V8 = "00000000-0000-8000-8000-000000000000"  # version 8
# Version 7 but the Microsoft variant (top bits 0b110), not RFC 4122 (0b10).
V7_MSVAR = "019ed29a-378d-72f0-c462-4929cd2bfcad"

# Reserved field -> negative integer key (spec §11, §7).
RKEY = {"tid": -1, "exp": -2, "aud": -3, "sub": -4, "iss": -5}
RESERVED = set(RKEY)


# ------------------------------------------------------------- canonical CBOR
def _head(major, n):
    """A CBOR head: major type (0-7) << 5 | shortest-form argument `n`."""
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x1_0000_0000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor(v):
    """Canonical CBOR (RFC 8949 §4.2) for the value types obsigil uses."""
    if isinstance(v, bool):  # bool is a subclass of int — test it first
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, float):
        # Shortest-form float (RFC 8949 §4.2): the smallest of f16/f32/f64
        # that round-trips the value exactly (matches ciborium / fxamacker).
        for head, fmt in ((0xF9, ">e"), (0xFA, ">f")):
            try:
                packed = struct.pack(fmt, v)
            except (OverflowError, struct.error):
                continue
            if struct.unpack(fmt, packed)[0] == v:
                return bytes([head]) + packed
        return bytes([0xFB]) + struct.pack(">d", v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor(k), cbor(val)) for k, val in v.items())
        return _head(5, len(items)) + b"".join(k + val for k, val in items)
    raise TypeError(f"unsupported CBOR value: {v!r}")


def reserved_map(fields):
    """A CBOR map dict from a logical fields dict: reserved fields at their
    negative integer keys (tid as 16-byte binary), app fields at text keys."""
    m = {}
    if "tid" in fields:
        m[RKEY["tid"]] = uuid.UUID(fields["tid"]).bytes
    for name in ("exp", "aud", "sub", "iss"):
        if name in fields:
            m[RKEY[name]] = fields[name]
    for k, val in fields.items():
        if k not in RESERVED:
            m[k] = val
    return m


def octets(fields):
    return cbor(reserved_map(fields)).hex()


# ------------------------------------------------------------------- CLI glue
def run(args, check=True, stdin=None):
    r = subprocess.run([BIN, *args], capture_output=True, text=True, input=stdin)
    if check and r.returncode != 0:
        raise SystemExit(f"CLI failed ({r.returncode}): obsigil {' '.join(args)}\n{r.stderr}")
    return r


def seal(octets_hex, key, alg, enc):
    return run(["seal", "--octets", octets_hex, "-k", key, "--alg", alg, "-e", enc]).stdout.strip()


def open_half(text, key, alg, enc):
    # `--half=...` (equals form) so a ciphertext text starting with `-`/`_`
    # (the b64url alphabet) is taken as a value, not parsed as a flag.
    r = run(["open", f"--half={text}", "-k", key, "--alg", alg, "-e", enc], check=False)
    return r.stdout.strip() if r.returncode == 0 else None


# Token-positional ops read the token from stdin (`-`), so a token starting
# with `-` (the b64url alphabet) is never mistaken for a flag.
def verify_ok(token, audience=None):
    args = ["verify", "-", "-k", "mandate", "--now", "1000000000"]
    if audience:
        args += ["-a", audience]
    return run(args, check=False, stdin=token).returncode == 0


def open_manifest_ok(token):
    return run(["open-manifest", "-"], check=False, stdin=token).returncode == 0


def sep(enc):
    return "." if enc == "b64" else "~"


def mandate_token(octets_hex, alg="0", enc="b64", key="mandate"):
    return sep(enc) + alg + seal(octets_hex, key, alg, enc)


def manifest_token(octets_hex, alg="0", enc="b64", key="manifest"):
    return seal(octets_hex, key, alg, enc) + alg + sep(enc)


def map_token(map_dict, alg="0", enc="b64", key="mandate"):
    """A mandate-only token whose plaintext is the canonical CBOR of an
    explicit int/text-keyed map — for wrong-type and unknown-key cases."""
    return mandate_token(cbor(map_dict).hex(), alg, enc, key)


# Deliberately NON-canonical CBOR plaintexts (raw bytes, bypassing `cbor`'s
# canonical map encoding), each a mandate-only token the verifier must reject.
def _entry(k, v):
    return cbor(k) + cbor(v)


def _tid():
    return uuid.UUID(TID).bytes


def raw_token(raw_bytes, alg="0", enc="b64", key="mandate"):
    return mandate_token(raw_bytes.hex(), alg, enc, key)


def dup_key():
    # 3-pair map (0xa3) with a duplicate -2 (exp) key.
    return bytes([0xA3]) + _entry(-1, _tid()) + _entry(-2, 4000000000) + _entry(-2, 1)


def unsorted_keys():
    # -2 (0x21) before -1 (0x20): canonical requires -1 first.
    return bytes([0xA2]) + _entry(-2, 4000000000) + _entry(-1, _tid())


def nonshortest_int():
    # exp 4000000000 in an 8-byte int head (0x1b) rather than the 4-byte (0x1a).
    exp_long = bytes([0x1B]) + (4000000000).to_bytes(8, "big")
    return bytes([0xA2]) + _entry(-1, _tid()) + cbor(-2) + exp_long


def indefinite_map():
    # 0xbf ... 0xff: indefinite length; canonical requires definite.
    return bytes([0xBF]) + _entry(-1, _tid()) + _entry(-2, 4000000000) + bytes([0xFF])


def trailing_bytes():
    return cbor(reserved_map(MAND)) + bytes([0x00])


def nonshortest_len():
    # tid (16 bytes) with a non-shortest length head (0x58 0x10, a 1-byte
    # length) instead of the direct 0x50 — non-canonical (spec §7).
    return bytes([0xA2]) + cbor(-1) + bytes([0x58, 0x10]) + _tid() + _entry(-2, 4000000000)


def nonshortest_float():
    # An application float 1.5 encoded as an 8-byte float64; the canonical
    # form is float16 (0xf9 0x3e00), so a non-shortest float is non-canonical.
    f64 = bytes([0xFB]) + struct.pack(">d", 1.5)
    return bytes([0xA3]) + _entry(-1, _tid()) + _entry(-2, 4000000000) + cbor("score") + f64


def manifest_dup():
    # A manifest map (0xa2) with a duplicate -5 (iss) key.
    return bytes([0xA2]) + _entry(-5, "auth.example") + _entry(-5, "other")


_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def set_b64_trailing(token):
    """Set an unused trailing bit of the final b64 symbol of a `.0<half>`
    token while preserving its significant bits, so a lenient decoder would
    decode the identical ciphertext (and wrongly accept); a strict decoder
    rejects the non-zero trailing bits (spec §3)."""
    half = token[2:]
    unused = {2: 4, 3: 2}[len(half) % 4]  # symbols mod 4 -> unused low bits
    idx = _B64.index(token[-1])
    return token[:-1] + _B64[(idx & ~((1 << unused) - 1)) | 1]


# ----------------------------------------------------------- positive builder
def positive(enc, manifest=None, mandate=None):
    """A positive vector. Octets are canonical CBOR; the assembled token is
    self-checked — a present mandate must verify and a present manifest must
    open, both of which the verifier/opener reject if non-canonical."""
    vec = {"encoding": enc}
    left = right = ""
    if manifest:
        oct_ = octets(manifest["fields"])
        text = seal(oct_, "manifest", manifest["alg"], enc)
        assert open_half(text, "manifest", manifest["alg"], enc) == oct_
        vec["manifest"] = {"alg": manifest["alg"], "octets": oct_, "fields": manifest["fields"]}
        left = text + manifest["alg"]
    if mandate:
        oct_ = octets(mandate["fields"])
        text = seal(oct_, "mandate", mandate["alg"], enc)
        assert open_half(text, "mandate", mandate["alg"], enc) == oct_
        vec["mandate"] = {"alg": mandate["alg"], "octets": oct_, "fields": mandate["fields"]}
        right = mandate["alg"] + text
    vec["token"] = left + sep(enc) + right
    if mandate and {"exp", "tid"} <= mandate["fields"].keys():
        aud = mandate["fields"].get("aud")
        assert verify_ok(vec["token"], aud[0] if aud else None), f"should verify: {vec['token']}"
    if manifest:
        assert open_manifest_ok(vec["token"]), f"manifest should open: {vec['token']}"
    return vec


# ----------------------------------------------------------------- positives
M_ISS = {"iss": "auth.example"}
MAND = {"exp": 4000000000, "tid": TID}

positives = [
    # Minimal full token, b64 and hex, both halves AES-SIV.
    positive("b64", manifest={"alg": "0", "fields": M_ISS}, mandate={"alg": "0", "fields": MAND}),
    positive("hex", manifest={"alg": "0", "fields": M_ISS}, mandate={"alg": "0", "fields": MAND}),
    # Mixed algorithms: AES-SIV manifest, AES-GCM-SIV mandate.
    positive("b64", manifest={"alg": "0", "fields": M_ISS}, mandate={"alg": "1", "fields": MAND}),
    # Both halves AES-GCM-SIV.
    positive("b64", manifest={"alg": "1", "fields": M_ISS}, mandate={"alg": "1", "fields": MAND}),
    # Degenerate shapes: manifest-only and mandate-only.
    positive("b64", manifest={"alg": "0", "fields": M_ISS}),
    positive("b64", mandate={"alg": "0", "fields": MAND}),
    positive("hex", mandate={"alg": "1", "fields": MAND}),
    # Rich mandate: aud (multi), sub, and application data; manifest app data.
    positive(
        "b64",
        manifest={"alg": "0", "fields": {"iss": "auth.example", "theme": "dark"}},
        mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID,
                                        "aud": ["api", "billing"], "sub": "u42",
                                        "role": "admin"}},
    ),
    # Manifest advisory exp (§11.1) + mandate iss clause (§11.2).
    positive(
        "b64",
        manifest={"alg": "0", "fields": {"iss": "auth.example", "exp": 4100000000}},
        mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID, "iss": "auth.example"}},
    ),
    # Non-ASCII (UTF-8) field values.
    positive(
        "b64",
        manifest={"alg": "0", "fields": {"iss": "issüer.example"}},
        mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID, "sub": "ñoño"}},
    ),
    # Maximal diversity: hex, AES-SIV manifest + AES-GCM-SIV mandate with app.
    positive(
        "hex",
        manifest={"alg": "0", "fields": M_ISS},
        mandate={"alg": "1", "fields": {"exp": 4000000000, "tid": TID, "sub": "u42",
                                        "role": "admin"}},
    ),
    # Application float value, shortest-form float16 (RFC 8949 §4.2).
    positive("b64", mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID, "score": 1.5}}),
]

# ----------------------------------------------------------------- negatives
negatives = []


def neg(op, token, reason, **policy):
    negatives.append({"op": op, "token": token, **policy, "reason": reason})


valid = mandate_token(octets(MAND))

# structural (parse)
neg("parse", "a.b.c", "more than one separator")
neg("parse", "abcdefgh", "no separator")
neg("parse", ".", "both halves absent (bare separator)")
neg("parse", ".0", "degenerate half: lone algorithm code, empty ciphertext")
neg("parse", "0.", "degenerate half: manifest-side lone algorithm code, empty ciphertext")
neg("parse", "abc0,0def", "single delimiter outside {., ~}: no valid separator")
# algorithm / length / text-encoding (verify) — unchanged by the CBOR model
neg("verify", valid[:1] + "2" + valid[2:], "unrecognized algorithm code", key="mandate", now=1000000000)
neg("verify", ".0AAAA", "half below the 17-byte floor", key="mandate", now=1000000000)
neg("verify", valid + "=", "non-canonical b64: padding", key="mandate", now=1000000000)
neg("verify", valid[:-1] + "*", "non-canonical b64: out-of-alphabet character", key="mandate", now=1000000000)
_hex = mandate_token(octets(MAND), enc="hex")
neg("verify", _hex[:2] + _hex[2:].upper(), "non-canonical hex: uppercase", key="mandate", now=1000000000)
neg("verify", _hex[:-1], "non-canonical hex: odd length", key="mandate", now=1000000000)
neg("verify", _hex[:-1] + "g", "non-canonical hex: out-of-alphabet letter (g)", key="mandate", now=1000000000)
neg("verify", ".0" + "A" * 17, "non-canonical b64: half length is 1 modulo 4", key="mandate", now=1000000000)
neg("verify", set_b64_trailing(valid), "non-canonical b64: non-zero unused trailing bits", key="mandate", now=1000000000)
# authentication / key (verify)
neg("verify", valid, "wrong key (authentication fails)", key="07" * 64, now=1000000000)
# reserved-clause policy (verify)
neg("verify", mandate_token(octets({"exp": 1000000000, "tid": TID})), "expired exp", key="mandate", now=2000000000)
neg("verify", mandate_token(octets({"exp": 4000000000, "tid": TID, "aud": ["api"]})),
    "audience mismatch", key="mandate", now=1000000000, audience="other")
neg("verify", mandate_token(octets({"exp": 4000000000, "tid": TID, "aud": []})),
    "empty aud array", key="mandate", now=1000000000)
neg("verify", mandate_token(octets({"exp": 4000000000})), "missing tid", key="mandate", now=1000000000)
neg("verify", mandate_token(octets({"exp": 4000000000, "tid": NIL})),
    "tid is not a UUIDv7 (version 0)", key="mandate", now=1000000000)
neg("verify", mandate_token(octets({"exp": 4000000000, "tid": TID_BADVAR})),
    "tid is version 7 but not the RFC 4122 variant (§11.3)", key="mandate", now=1000000000)
neg("verify", mandate_token(octets({"exp": 4000000000, "tid": V4})),
    "tid is a UUIDv4 (version 4), not a UUIDv7", key="mandate", now=1000000000)
neg("verify", mandate_token(octets({"exp": 4000000000, "tid": V8})),
    "tid is a UUIDv8 (version 8), not a UUIDv7", key="mandate", now=1000000000)
neg("verify", mandate_token(octets({"exp": 4000000000, "tid": V7_MSVAR})),
    "tid is version 7 but the Microsoft variant (0b110), not RFC 4122", key="mandate", now=1000000000)
neg("verify", mandate_token(octets({"tid": TID})), "missing exp", key="mandate", now=1000000000)
neg("verify", manifest_token(octets(M_ISS)), "empty mandate", key="mandate", now=1000000000)
# reserved-clause type strictness (verify): wrong CBOR types (spec §9.9)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: _tid(), RKEY["aud"]: "api"}),
    "aud is a text string, not an array (§11.4)", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: "not-bytes"}),
    "tid is a text string, not a 16-byte byte string", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: _tid()[:8]}),
    "tid is a byte string shorter than 16 bytes (8)", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: b"\x00" * 32}),
    "tid is a byte string longer than 16 bytes (32)", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: b""}),
    "tid is an empty byte string", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: "4000000000", RKEY["tid"]: _tid()}),
    "exp is a text string, not an integer", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000.0, RKEY["tid"]: _tid()}),
    "exp is a CBOR float, not a NumericDate integer", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: _tid(), RKEY["iss"]: 123}),
    "iss is an integer, not a text string", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: _tid(), RKEY["sub"]: 123}),
    "sub is an integer, not a text string", key="mandate", now=1000000000)
neg("verify", map_token({RKEY["exp"]: 4000000000, RKEY["tid"]: _tid(), RKEY["aud"]: [1]}),
    "aud is an array containing a non-text element", key="mandate", now=1000000000)
# sign-split namespace (spec §7): an unrecognized negative key fails closed
neg("verify", map_token({-9: 1, RKEY["exp"]: 4000000000, RKEY["tid"]: _tid()}),
    "unrecognized negative key fails closed", key="mandate", now=1000000000)
# non-canonical CBOR (spec §7, §9.9)
neg("verify", raw_token(dup_key()), "duplicate CBOR map key", key="mandate", now=1000000000)
neg("verify", raw_token(unsorted_keys()), "CBOR map keys out of canonical order", key="mandate", now=1000000000)
neg("verify", raw_token(nonshortest_int()), "non-shortest CBOR integer", key="mandate", now=1000000000)
neg("verify", raw_token(indefinite_map()), "indefinite-length CBOR map", key="mandate", now=1000000000)
neg("verify", raw_token(trailing_bytes()), "trailing bytes after the CBOR map", key="mandate", now=1000000000)
neg("verify", raw_token(nonshortest_len()), "non-shortest CBOR length header", key="mandate", now=1000000000)
neg("verify", raw_token(nonshortest_float()), "non-shortest CBOR float (f64 for an f16-representable value)", key="mandate", now=1000000000)
# manifest (open-manifest)
neg("open-manifest", manifest_token(octets({"role": "x"})), "manifest missing required iss")
neg("open-manifest", manifest_token(octets(M_ISS), key="mandate"),
    "manifest sealed under the wrong key (authentication fails)")
_mani = manifest_token(octets(M_ISS))  # "<text>0."
neg("open-manifest", _mani[:-2] + "=0.", "non-canonical b64: padding (manifest)")
neg("open-manifest", manifest_token(manifest_dup().hex()), "non-canonical CBOR in manifest (duplicate map key)")
# excessive clock-skew leeway must not extend exp (§9.9)
neg("verify", mandate_token(octets({"exp": 1000, "tid": TID})),
    "excessive leeway must not extend exp (§9.9)",
    key="mandate", now=2000000000, leeway=9999999999)


# --------------------------------------------------------------- self-check
def op_rejects(row):
    op, token = row["op"], row["token"]
    args = [op, "-"]
    if op == "verify":
        args += ["-k", row.get("key", "mandate")]
        if "now" in row:
            args += ["--now", str(row["now"])]
        if "audience" in row:
            args += ["-a", row["audience"]]
        if "leeway" in row:
            args += ["--leeway", str(row["leeway"])]
    return run(args, check=False, stdin=token).returncode == 1


for row in negatives:
    assert op_rejects(row), f"negative should be rejected: {row}"


def write_jsonl(name, rows):
    path = os.path.join(ROOT, name)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path


p1 = write_jsonl("test-vectors.jsonl", positives)
p2 = write_jsonl("negative-test-vectors.jsonl", negatives)
print(f"wrote {len(positives)} positive vectors -> {os.path.basename(p1)}")
print(f"wrote {len(negatives)} negative vectors -> {os.path.basename(p2)}")
print("all self-checks passed (positives reproduce + verify/open; negatives reject)")
