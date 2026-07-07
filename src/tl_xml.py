"""Real ETSI TS 119 612 Trusted-List parser (offline).

Replaces the AAA demo's in-memory `trusted_list.py` fixture with an actual parse of a
signed national Trusted-List XML — "the data the rqscd census already collects"
(the fixture's own words). No network: one XML file in, a trust oracle out.

For each listed trust service we extract the X509 certificate(s), and compute BOTH:
  * the X.509 SHA-256 fingerprint (the ETSI-native trust anchor identity), and
  * the RFC 7638 JWK thumbprint of the embedded public key (the identity the AAA
    Bound-Action-Seal verifier checks via `TrustedList.issuer_listed(jwk)`).

That dual identity is the bridge: a real deployment trust-lists X509 certs; the
offline AAA verifier keys off JWK thumbprints. Same key, two canonical fingerprints.

Parse target verified against a real Belgian TL (TrustServiceStatusList v5).
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

_NS = {
    "tsl": "http://uri.etsi.org/02231/v2#",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

# Qualified service types (ETSI TS 119 612 §5.5.1.1) we treat as trust anchors.
QUALIFIED_TYPES = {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",          # qualified cert issuer
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",       # qualified timestamp
    "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q",          # qualified e-delivery
    "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q",
    "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q",         # qualified preservation
    "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q",
}
_GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"


def _b64_der_to_cert(b64_text: str) -> x509.Certificate:
    der = base64.b64decode("".join(b64_text.split()))
    return x509.load_der_x509_certificate(der)


def _jwk_thumbprint(cert: x509.Certificate) -> str | None:
    """RFC 7638 thumbprint of the cert's public key (EC or RSA). None if unsupported."""
    pub = cert.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        n = pub.curve.name
        crv = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(n)
        if not crv:
            return None
        nums = pub.public_numbers()
        size = (pub.curve.key_size + 7) // 8
        jwk = {
            "crv": crv,
            "kty": "EC",
            "x": base64.urlsafe_b64encode(nums.x.to_bytes(size, "big")).rstrip(b"=").decode(),
            "y": base64.urlsafe_b64encode(nums.y.to_bytes(size, "big")).rstrip(b"=").decode(),
        }
    elif isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        elen = (nums.e.bit_length() + 7) // 8
        nlen = (nums.n.bit_length() + 7) // 8
        jwk = {
            "e": base64.urlsafe_b64encode(nums.e.to_bytes(elen, "big")).rstrip(b"=").decode(),
            "kty": "RSA",
            "n": base64.urlsafe_b64encode(nums.n.to_bytes(nlen, "big")).rstrip(b"=").decode(),
        }
    else:
        return None
    canon = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    return "jkt:" + base64.urlsafe_b64encode(hashlib.sha256(canon).digest()).rstrip(b"=").decode()


@dataclass
class TrustAnchor:
    service_type: str
    service_name: str
    status: str
    subject: str
    x5t_s256: str            # X.509 SHA-256 fingerprint (hex)
    jwk_thumbprint: str | None
    granted: bool


@dataclass
class TrustedListXML:
    scheme_id: str = ""
    sequence: str = ""
    anchors: list[TrustAnchor] = field(default_factory=list)
    services: list[tuple] = field(default_factory=list)  # (service_type, status, granted)
    _by_x5t: set[str] = field(default_factory=set)
    _by_jkt: set[str] = field(default_factory=set)

    @classmethod
    def from_file(cls, path: str, granted_only: bool = True) -> "TrustedListXML":
        root = ET.parse(path).getroot()
        tl = cls()
        si = root.find("tsl:SchemeInformation", _NS)
        if si is not None:
            tl.scheme_id = root.get("Id", "")
            seq = si.find("tsl:TSLSequenceNumber", _NS)
            tl.sequence = seq.text if seq is not None else ""
        for svc in root.iter("{http://uri.etsi.org/02231/v2#}TSPService"):
            info = svc.find("tsl:ServiceInformation", _NS)
            if info is None:
                continue
            stype = info.findtext("tsl:ServiceTypeIdentifier", default="", namespaces=_NS)
            status = info.findtext("tsl:ServiceStatus", default="", namespaces=_NS)
            name_el = info.find("tsl:ServiceName/tsl:Name", _NS)
            sname = name_el.text if name_el is not None else ""
            granted = status == _GRANTED
            # record the SERVICE itself (independent of whether it carries a cert) — remote-QSCD
            # management services often have no X509Certificate, so a cert-only count misses them
            has_cert = any(e.tag.endswith("X509Certificate") and (e.text or "").strip()
                           for e in info.iter())
            tl.services.append((stype, status, granted, has_cert))
            for cert_el in info.iter():
                if not cert_el.tag.endswith("X509Certificate"):
                    continue
                if not (cert_el.text or "").strip():
                    continue
                try:
                    cert = _b64_der_to_cert(cert_el.text)
                    x5t = hashlib.sha256(
                        cert.public_bytes(serialization.Encoding.DER)
                    ).hexdigest()
                    jkt = _jwk_thumbprint(cert)
                    subject = cert.subject.rfc4514_string()
                except Exception:
                    # malformed cert (e.g. EC with explicit params) — skip this one, not the list
                    continue
                anchor = TrustAnchor(
                    service_type=stype, service_name=sname, status=status,
                    subject=subject,
                    x5t_s256=x5t, jwk_thumbprint=jkt, granted=granted,
                )
                if granted_only and not granted:
                    continue
                tl.anchors.append(anchor)
                tl._by_x5t.add(x5t)
                if jkt:
                    tl._by_jkt.add(jkt)
        return tl

    # --- trust oracle: offline, no network ---
    def cert_listed(self, x5t_s256: str) -> bool:
        return x5t_s256.lower() in self._by_x5t

    def issuer_listed(self, jwk_or_jkt) -> bool:
        """AAA-compatible: accepts a jkt string or a JWK dict, returns membership."""
        jkt = jwk_or_jkt if isinstance(jwk_or_jkt, str) else _jwk_from_dict(jwk_or_jkt)
        return jkt in self._by_jkt

    def by_type(self, service_type: str) -> list[TrustAnchor]:
        return [a for a in self.anchors if a.service_type == service_type]

    def service_type_counts(self, granted_only: bool = True) -> dict:
        """Count trust SERVICE entries by type (not certs) — the right unit for rQSCD, whose
        management services carry no X509Certificate of their own."""
        from collections import Counter
        c = Counter(st.rsplit("Svctype/", 1)[-1]
                    for st, status, granted, has_cert in self.services
                    if (not granted_only or granted))
        return dict(c.most_common())

    def rqscd_identity_split(self) -> tuple[int, int]:
        """(cert_bearing, other/name-only) for granted remote-QSCD management services —
        the ~60/40 harmonization split the TSLs show."""
        rq = {"RemoteQSigCDManagement/Q", "RemoteQSealCDManagement/Q"}
        cert = other = 0
        for st, status, granted, has_cert in self.services:
            if granted and st.rsplit("Svctype/", 1)[-1] in rq:
                cert += 1 if has_cert else 0
                other += 0 if has_cert else 1
        return cert, other

    def summary(self) -> dict:
        from collections import Counter
        c = Counter(a.service_type.rsplit("Svctype/", 1)[-1] for a in self.anchors)
        return {
            "scheme_id": self.scheme_id,
            "sequence": self.sequence,
            "anchors": len(self.anchors),
            "distinct_x5t": len(self._by_x5t),
            "distinct_jwk": len(self._by_jkt),
            "by_service_type": dict(c.most_common()),         # cert-anchors grouped by service type
            "services_by_type": self.service_type_counts(),   # granted SERVICE entries by type
        }


def _jwk_from_dict(jwk: dict) -> str:
    canon = json.dumps(
        {k: jwk[k] for k in sorted(jwk) if k in ("crv", "kty", "x", "y", "e", "n")},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    return "jkt:" + base64.urlsafe_b64encode(hashlib.sha256(canon).digest()).rstrip(b"=").decode()


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "vendor/BE.xml"
    tl = TrustedListXML.from_file(path)
    s = tl.summary()
    print(json.dumps(s, indent=2))
    print("\nsample granted qualified-CA anchors:")
    for a in tl.by_type("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")[:3]:
        print(f"  · {a.subject[:70]}")
        print(f"    x5t#S256={a.x5t_s256[:24]}…  jwk={a.jwk_thumbprint}")
    # trust-oracle checks
    if tl.anchors:
        real = tl.anchors[0].x5t_s256
        print(f"\ncert_listed(real anchor) = {tl.cert_listed(real)}")
    print(f"cert_listed('deadbeef…') = {tl.cert_listed('deadbeef')}")
