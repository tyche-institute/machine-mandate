"""EC P-256 helpers: keygen, JWK, RFC 7638 thumbprint, raw ECDSA sign/verify.

Real cryptography (the `cryptography` package). These are genuine signatures — the
software stand-in is only the *trust root* (no TPM, no certified QSCD), not the maths.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def gen_ec():
    return ec.generate_private_key(ec.SECP256R1())


def pub_jwk(priv) -> dict:
    n = priv.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64u(n.x.to_bytes(32, "big")),
            "y": b64u(n.y.to_bytes(32, "big"))}


def jwk_to_pub(jwk):
    x = int.from_bytes(b64u_dec(jwk["x"]), "big")
    y = int.from_bytes(b64u_dec(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def jwk_thumbprint(jwk) -> str:
    """RFC 7638 JWK thumbprint over the required EC members, lexicographic, no ws."""
    t = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                   separators=(",", ":"), sort_keys=True).encode()
    return "jkt:" + b64u(hashlib.sha256(t).digest())


def raw_sign(priv, data: bytes) -> str:
    return b64u(priv.sign(data, ec.ECDSA(hashes.SHA256())))


def raw_verify(jwk, data: bytes, sig_b64u: str) -> bool:
    try:
        jwk_to_pub(jwk).verify(b64u_dec(sig_b64u), data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def jose_sign(priv, signing_input: bytes) -> str:
    """ES256 JWS signature (JOSE R||S form, 64 bytes), for JAdES/JWS objects."""
    der = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def jose_verify(jwk, signing_input: bytes, sig_b64u: str) -> bool:
    try:
        raw = b64u_dec(sig_b64u)
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                   int.from_bytes(raw[32:], "big"))
        jwk_to_pub(jwk).verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
