#!/usr/bin/env python3
"""Generate obsigil test vectors from the reference CLI.

For each positive vector we choose the per-half octets, `seal` them with
the obsigil CLI, and assemble the token; for each negative we craft an
input that must be rejected. Every line is self-checked against the CLI
before it is written (positives reproduce bidirectionally and verify;
negatives exit non-zero).

Usage:  OBSIGIL_BIN=/path/to/obsigil python3 tools/generate.py
"""

import json
import os
import subprocess

BIN = os.environ.get("OBSIGIL_BIN", "obsigil")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TAG = {"json": "6a", "toml": "74", "cbor": "63"}
TID = "019ed29a-378d-72f0-b462-4929cd2bfcad"  # a fixed UUIDv7
NIL = "00000000-0000-0000-0000-000000000000"  # version 0 — not a v7


def run(args, check=True):
    r = subprocess.run([BIN, *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"CLI failed ({r.returncode}): obsigil {' '.join(args)}\n{r.stderr}")
    return r


def jhex(fields, fmt="json"):
    """tag || compact-JSON (serde_json layout), as hex."""
    s = json.dumps(fields, separators=(",", ":"), ensure_ascii=False)
    return TAG[fmt] + s.encode("utf-8").hex()


def seal(octets_hex, key, alg, enc):
    return run(["seal", "--octets", octets_hex, "-k", key, "--alg", alg, "-e", enc]).stdout.strip()


def open_half(text, key, alg, enc):
    r = run(["open", "--half", text, "-k", key, "--alg", alg, "-e", enc], check=False)
    return r.stdout.strip() if r.returncode == 0 else None


def verify_ok(token, audience=None):
    args = ["verify", token, "-k", "mandate", "--now", "1000000000"]
    if audience:
        args += ["-a", audience]
    return run(args, check=False).returncode == 0


def sep(enc):
    return "." if enc == "b64" else "~"


def positive(enc, manifest=None, mandate=None):
    vec = {"encoding": enc}
    left = right = ""
    if manifest:
        oct_ = jhex(manifest["fields"])
        text = seal(oct_, "manifest", manifest["alg"], enc)
        assert open_half(text, "manifest", manifest["alg"], enc) == oct_
        vec["manifest"] = {"alg": manifest["alg"], "octets": oct_, "fields": manifest["fields"]}
        left = text + manifest["alg"]
    if mandate:
        oct_ = jhex(mandate["fields"])
        text = seal(oct_, "mandate", mandate["alg"], enc)
        assert open_half(text, "mandate", mandate["alg"], enc) == oct_
        vec["mandate"] = {"alg": mandate["alg"], "octets": oct_, "fields": mandate["fields"]}
        right = mandate["alg"] + text
    vec["token"] = left + sep(enc) + right
    # A positive with a complete mandate must actually verify.
    if mandate and {"exp", "tid"} <= mandate["fields"].keys():
        aud = mandate["fields"].get("aud")
        assert verify_ok(vec["token"], aud[0] if aud else None), f"should verify: {vec['token']}"
    return vec


def parse_token(token):
    return json.loads(run(["parse", token]).stdout)


def positive_via_mint(enc, mandate_fields, mandate_format, mandate_alg="0",
                      manifest_iss=None, manifest_app=None,
                      manifest_format="json", manifest_alg="0"):
    """A positive minted by the CLI — for binary/text serializations whose
    octets are impractical to hand-build — with the octets extracted via
    `open` and both directions re-checked (seal reproduces, token verifies)."""
    reserved = ("exp", "tid", "aud", "sub", "iss")
    app = {k: v for k, v in mandate_fields.items() if k not in reserved}
    args = ["mint", "-k", "mandate", "-e", enc, "--alg", mandate_alg,
            "--format", mandate_format, "--tid", mandate_fields["tid"],
            "--exp", str(mandate_fields["exp"])]
    if "aud" in mandate_fields:
        args += ["--aud", ",".join(mandate_fields["aud"])]
    if "sub" in mandate_fields:
        args += ["--sub", mandate_fields["sub"]]
    if "iss" in mandate_fields:
        args += ["--iss", mandate_fields["iss"]]
    if app:
        args += ["--fields", json.dumps(app, separators=(",", ":"))]
    if manifest_iss:
        args += ["--manifest-iss", manifest_iss,
                 "--manifest-format", manifest_format, "--manifest-alg", manifest_alg]
        if manifest_app:
            args += ["--manifest-fields", json.dumps(manifest_app, separators=(",", ":"))]
    token = run(args).stdout.strip()

    parsed = parse_token(token)
    vec = {"encoding": enc}
    if parsed.get("manifest"):
        h = parsed["manifest"]
        oct_ = open_half(h["text"], "manifest", h["alg"], enc)
        assert oct_ is not None and seal(oct_, "manifest", h["alg"], enc) == h["text"]
        vec["manifest"] = {"alg": h["alg"], "octets": oct_,
                           "fields": {"iss": manifest_iss, **(manifest_app or {})}}
    if parsed.get("mandate"):
        h = parsed["mandate"]
        oct_ = open_half(h["text"], "mandate", h["alg"], enc)
        assert oct_ is not None and seal(oct_, "mandate", h["alg"], enc) == h["text"]
        vec["mandate"] = {"alg": h["alg"], "octets": oct_, "fields": mandate_fields}
    vec["token"] = token
    aud = mandate_fields.get("aud")
    assert verify_ok(token, aud[0] if aud else None), f"should verify: {token}"
    return vec


def mandate_token(octets_hex, alg="0", enc="b64", key="mandate"):
    return sep(enc) + alg + seal(octets_hex, key, alg, enc)


def manifest_token(octets_hex, alg="0", enc="b64", key="manifest"):
    return seal(octets_hex, key, alg, enc) + alg + sep(enc)


# ----------------------------------------------------------------- positives
positives = [
    positive("b64",
             manifest={"alg": "0", "fields": {"iss": "auth.example"}},
             mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID}}),
    positive("hex",
             manifest={"alg": "0", "fields": {"iss": "auth.example"}},
             mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID}}),
    positive("b64",
             manifest={"alg": "0", "fields": {"iss": "auth.example"}},
             mandate={"alg": "1", "fields": {"exp": 4000000000, "tid": TID}}),
    positive("b64",
             manifest={"alg": "1", "fields": {"iss": "auth.example"}},
             mandate={"alg": "1", "fields": {"exp": 4000000000, "tid": TID}}),
    positive("b64", manifest={"alg": "0", "fields": {"iss": "auth.example"}}),
    positive("b64", mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID}}),
    positive("hex", mandate={"alg": "1", "fields": {"exp": 4000000000, "tid": TID}}),
    positive("b64",
             manifest={"alg": "0", "fields": {"iss": "auth.example", "theme": "dark"}},
             mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID,
                                             "aud": ["api", "billing"], "sub": "u42",
                                             "role": "admin"}}),
    # CBOR mandate (tag c; tid as 16-byte binary, §11.3) + JSON manifest.
    positive_via_mint("b64",
                      mandate_fields={"exp": 4000000000, "tid": TID, "sub": "u42", "role": "admin"},
                      mandate_format="cbor",
                      manifest_iss="auth.example", manifest_app={"theme": "dark"}),
    # TOML mandate (tag t), mandate-only.
    positive_via_mint("b64",
                      mandate_fields={"exp": 4000000000, "tid": TID},
                      mandate_format="toml"),
    # CBOR mandate, mandate-only (forward form, binary tid).
    positive_via_mint("b64",
                      mandate_fields={"exp": 4000000000, "tid": TID},
                      mandate_format="cbor"),
    # CBOR manifest + CBOR mandate, full token (both binary).
    positive_via_mint("b64",
                      mandate_fields={"exp": 4000000000, "tid": TID, "sub": "u42"},
                      mandate_format="cbor",
                      manifest_iss="auth.example", manifest_app={"theme": "dark"},
                      manifest_format="cbor"),
    # TOML manifest + JSON mandate, full token.
    positive_via_mint("b64",
                      mandate_fields={"exp": 4000000000, "tid": TID},
                      mandate_format="json",
                      manifest_iss="auth.example", manifest_format="toml"),
    # Maximal diversity: JSON+SIV manifest, CBOR+GCM-SIV mandate, hex.
    positive_via_mint("hex",
                      mandate_fields={"exp": 4000000000, "tid": TID, "sub": "u42"},
                      mandate_format="cbor", mandate_alg="1",
                      manifest_iss="auth.example"),
    # Manifest advisory exp (§11.1) + mandate iss clause (§11.2), JSON.
    positive("b64",
             manifest={"alg": "0", "fields": {"iss": "auth.example", "exp": 4100000000}},
             mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID,
                                             "iss": "auth.example"}}),
    # Non-ASCII (UTF-8) field values, JSON.
    positive("b64",
             manifest={"alg": "0", "fields": {"iss": "issüer.example"}},
             mandate={"alg": "0", "fields": {"exp": 4000000000, "tid": TID, "sub": "ñoño"}}),
]

# ----------------------------------------------------------------- negatives
negatives = []


def neg(op, token, reason, **policy):
    row = {"op": op, "token": token, **policy, "reason": reason}
    negatives.append(row)


valid = mandate_token(jhex({"exp": 4000000000, "tid": TID}))

# structural (parse)
neg("parse", "a.b.c", "more than one separator")
neg("parse", "abcdefgh", "no separator")
neg("parse", ".", "both halves absent (bare separator)")
neg("parse", ".0", "degenerate half: lone algorithm code, empty ciphertext")
# algorithm / length / encoding (verify)
neg("verify", valid[:1] + "2" + valid[2:], "unrecognized algorithm code", key="mandate", now=1000000000)
neg("verify", ".0AAAA", "half below the 17-byte floor", key="mandate", now=1000000000)
neg("verify", valid + "=", "non-canonical b64: padding", key="mandate", now=1000000000)
neg("verify", valid[:-1] + "*", "non-canonical b64: out-of-alphabet character", key="mandate", now=1000000000)
_hex = mandate_token(jhex({"exp": 4000000000, "tid": TID}), enc="hex")
neg("verify", _hex[:2] + _hex[2:].upper(), "non-canonical hex: uppercase", key="mandate", now=1000000000)
# authentication / key (verify)
neg("verify", valid, "wrong key (authentication fails)", key="07" * 64, now=1000000000)
# reserved-clause policy (verify)
neg("verify", mandate_token(jhex({"exp": 1000000000, "tid": TID})), "expired exp", key="mandate", now=2000000000)
neg("verify", mandate_token(jhex({"exp": 4000000000, "tid": TID, "aud": ["api"]})),
    "audience mismatch", key="mandate", now=1000000000, audience="other")
neg("verify", mandate_token(jhex({"exp": 4000000000, "tid": TID, "aud": []})),
    "empty aud array", key="mandate", now=1000000000)
neg("verify", mandate_token(jhex({"exp": 4000000000})), "missing tid", key="mandate", now=1000000000)
neg("verify", mandate_token(jhex({"exp": 4000000000, "tid": NIL})), "tid is not a UUIDv7",
    key="mandate", now=1000000000)
neg("verify", mandate_token(jhex({"tid": TID})), "missing exp", key="mandate", now=1000000000)
neg("verify", manifest_token(jhex({"iss": "auth.example"})), "empty mandate", key="mandate", now=1000000000)
# manifest (open-manifest)
neg("open-manifest", manifest_token(jhex({"role": "x"})), "manifest missing required iss")
neg("open-manifest", manifest_token(jhex({"iss": "auth.example"}), key="mandate"),
    "manifest sealed under the wrong key (authentication fails)")
_mani = manifest_token(jhex({"iss": "auth.example"}))  # "<text>0."
neg("open-manifest", _mani[:-2] + "=0.", "non-canonical b64: padding (manifest)")
# reserved-clause type strictness (verify)
neg("verify", mandate_token(jhex({"exp": 4000000000, "tid": TID, "aud": "api"})),
    "aud is a bare string, not an array (§11.4)", key="mandate", now=1000000000)
neg("verify", mandate_token(jhex({"exp": 4000000000, "tid": "not-a-uuid"})),
    "tid is not a valid UUID", key="mandate", now=1000000000)
neg("verify", mandate_token(jhex({"exp": "4000000000", "tid": TID})),
    "exp is a string, not a number", key="mandate", now=1000000000)
# unrecognized serialization tag (0x79 = 'y')
_ytag = "79" + json.dumps({"exp": 4000000000, "tid": TID}, separators=(",", ":")).encode().hex()
neg("verify", mandate_token(_ytag), "unrecognized serialization tag", key="mandate", now=1000000000)
# non-canonical hex (verify)
_hexv = mandate_token(jhex({"exp": 4000000000, "tid": TID}), enc="hex")
neg("verify", _hexv[:-1], "non-canonical hex: odd length", key="mandate", now=1000000000)


# --------------------------------------------------------------- self-check
def op_rejects(row):
    op, token = row["op"], row["token"]
    args = [op, token]
    if op == "verify":
        args += ["-k", row.get("key", "mandate")]
        if "now" in row:
            args += ["--now", str(row["now"])]
        if "audience" in row:
            args += ["-a", row["audience"]]
    return run(args, check=False).returncode == 1


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
print("all self-checks passed (positives reproduce + verify; negatives reject)")
