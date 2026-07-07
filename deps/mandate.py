"""Scoped machine-mandate credential (SD-JWT VC, simplified) + holder binding.

The issuer signs a VC (ES256) carrying the agent subject, the accountable principal,
the scope, the bound action_hash, a validity window, a single-use jti, and the holder
key (`cnf`). The agent presents it with a KB-JWT (holder-signed, nonce + aud + sd_hash)
— the replay/audience binding that is the security-critical part. Selective disclosure
(the "SD" in SD-JWT) is simplified for M1; the holder binding is real.
"""
import base64
import hashlib
import json
import secrets
import time

import jwt

from crypto import jwk_to_pub
from jcs import Hs


def issue(issuer_priv, principal, agent, scope, action_hash, holder_jwk,
          ttl=300, jti="m-1"):
    now = int(time.time())
    payload = {"iss": "qtsp://issuer", "sub": agent, "principal": principal,
               "vct": "https://vocab.tyche.institute/vct/machine-mandate", "scope": scope, "action_hash": action_hash,
               "cnf": {"jwk": holder_jwk}, "iat": now, "exp": now + ttl, "jti": jti}
    return jwt.encode(payload, issuer_priv, algorithm="ES256",
                      headers={"typ": "dc+sd-jwt"})


def present(sd_jwt, holder_priv, nonce, aud):
    now = int(time.time())
    kb = {"iat": now, "aud": aud, "nonce": nonce, "sd_hash": Hs(sd_jwt)}
    return jwt.encode(kb, holder_priv, algorithm="ES256", headers={"typ": "kb+jwt"})


def verify_presentation(sd_jwt, kb_jwt, issuer_jwk, nonce, aud, leeway=2):
    """Returns the VC claims, or raises. Verifies issuer signature + window (exp),
    holder binding (KB-JWT signed by the cnf key), nonce, aud, and sd_hash."""
    issuer_pub = jwk_to_pub(issuer_jwk)
    claims = jwt.decode(sd_jwt, issuer_pub, algorithms=["ES256"],
                        options={"verify_aud": False}, leeway=leeway)
    holder_pub = jwk_to_pub(claims["cnf"]["jwk"])
    kb = jwt.decode(kb_jwt, holder_pub, algorithms=["ES256"],
                    options={"verify_aud": False}, leeway=leeway)
    if kb.get("nonce") != nonce:
        raise ValueError("KB-JWT nonce mismatch")
    if kb.get("aud") != aud:
        raise ValueError("KB-JWT aud mismatch")
    if kb.get("sd_hash") != Hs(sd_jwt):
        raise ValueError("KB-JWT sd_hash mismatch")
    return claims


# --- Real SD-JWT selective disclosure ------------------------------------------
# Selected claims are issued as salted disclosures (base64url([salt, name, value]));
# the issuer JWT carries only their hashes in `_sd`. The holder reveals a chosen
# subset; undisclosed claims stay private. Format: <jwt>~<disc>~...~<kb_jwt>.

def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _disc_hash(disc: str) -> str:
    return _b64u(hashlib.sha256(disc.encode()).digest())


def make_disclosure(name, value):
    salt = _b64u(secrets.token_bytes(16))
    disc = _b64u(json.dumps([salt, name, value], separators=(",", ":")).encode())
    return disc, _disc_hash(disc)


def issue_sd(issuer_priv, agent, scope, action_hash, holder_jwk, sd_claims,
             ttl=300, jti="m-1"):
    now = int(time.time())
    discs, sd_hashes = [], []
    for k, v in sd_claims.items():
        d, h = make_disclosure(k, v)
        discs.append(d)
        sd_hashes.append(h)
    payload = {"iss": "qtsp://issuer", "sub": agent, "vct": "https://vocab.tyche.institute/vct/machine-mandate",
               "scope": scope, "action_hash": action_hash, "cnf": {"jwk": holder_jwk},
               "iat": now, "exp": now + ttl, "jti": jti,
               "_sd": sd_hashes, "_sd_alg": "sha-256"}
    j = jwt.encode(payload, issuer_priv, algorithm="ES256", headers={"typ": "dc+sd-jwt"})
    return j + "~" + "~".join(discs) + "~"


def present_sd(sd_jwt_full, holder_priv, nonce, aud, reveal):
    parts = [p for p in sd_jwt_full.split("~") if p]
    j, discs = parts[0], parts[1:]
    chosen = [d for d in discs
              if json.loads(base64.urlsafe_b64decode(d + "==="))[1] in reveal]
    issuer_part = j + "~" + "".join(c + "~" for c in chosen)
    sd_hash = _b64u(hashlib.sha256(issuer_part.encode()).digest())
    now = int(time.time())
    kb = jwt.encode({"iat": now, "aud": aud, "nonce": nonce, "sd_hash": sd_hash},
                    holder_priv, algorithm="ES256", headers={"typ": "kb+jwt"})
    return issuer_part + kb


def verify_presentation_sd(presentation, issuer_jwk, nonce, aud, leeway=2):
    parts = presentation.split("~")
    j, kb_jwt = parts[0], parts[-1]
    discs = [p for p in parts[1:-1] if p]
    claims = jwt.decode(j, jwk_to_pub(issuer_jwk), algorithms=["ES256"],
                        options={"verify_aud": False}, leeway=leeway)
    sd = set(claims.get("_sd", []))
    for d in discs:
        if _disc_hash(d) not in sd:
            raise ValueError("disclosure not present in _sd")
        _, name, value = json.loads(base64.urlsafe_b64decode(d + "==="))
        claims[name] = value
    issuer_part = j + "~" + "".join(c + "~" for c in discs)
    sd_hash = _b64u(hashlib.sha256(issuer_part.encode()).digest())
    holder_pub = jwk_to_pub(claims["cnf"]["jwk"])
    kb = jwt.decode(kb_jwt, holder_pub, algorithms=["ES256"],
                    options={"verify_aud": False}, leeway=leeway)
    if kb.get("nonce") != nonce or kb.get("aud") != aud:
        raise ValueError("KB-JWT nonce/aud mismatch")
    if kb.get("sd_hash") != sd_hash:
        raise ValueError("KB-JWT sd_hash mismatch")
    claims.pop("_sd", None)
    claims.pop("_sd_alg", None)
    return claims
