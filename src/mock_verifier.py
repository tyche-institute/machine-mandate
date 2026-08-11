#!/usr/bin/env python3
"""A self-contained mock OpenID4VP relying-party verifier that NATIVELY resolves the
AgentRuntimeEndorser trusted-list role — the resolution the EC reference verifier cannot do.

It unifies the two-layer attestation check (aep_weld) with the trusted-list role gate
(endorser_role) inside ONE verifier. Given an OID4VP presentation, the issuer identity, the
attestation evidence (EAR + raw TPM quote), and a trusted list, it ACCEPTs only when
  L1  the SD-JWT VC + KB-JWT verify (issuer signature, disclosures, nonce/aud);
  L2  the attestation is affirming, fresh, and bound to the quote (re-derived from raw bytes);
  L3  the issuer is trust-listed under
      http://uri.etsi.org/TrstSvc/Svctype/AgentRuntimeEndorser/Q.
No standalone trust-validator standing in: this verifier IS the resolver.
"""
from __future__ import annotations
import base64, datetime as dt, hashlib, json, os, shutil, sys, tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "fixtures")
sys.path.insert(0, HERE)
sys.path.insert(0, os.environ.get("AAA_DEMO") or os.path.join(HERE, "..", "deps"))
import crypto as aaa_crypto            # noqa: E402
import mandate                        # noqa: E402
from jcs import H                     # noqa: E402
from tl_xml import TrustedListXML     # noqa: E402

AGENT_ENDORSER = "http://uri.etsi.org/TrstSvc/Svctype/AgentRuntimeEndorser/Q"
CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
GRANTED = "http://uri.etsi.org/TrstSvc/Svcstatus/granted"
AEP = json.load(open(os.path.join(FIX, "demo.aep.json")))


def b64u_dec(s): return base64.urlsafe_b64decode((s or "") + "=" * (-len(s or "") % 4))
def b64u_enc(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

def quote_bound_nonce(path):
    d = open(path, "rb").read(); size = int.from_bytes(d[16:18], "big"); raw = d[18:18 + size]
    qs = int.from_bytes(raw[6:8], "big"); off = 8 + qs; ed = int.from_bytes(raw[off:off + 2], "big")
    return raw[off + 2:off + 2 + ed]

def rebind_evidence(quote_path, ear_path, challenge, out_dir):
    """Build a synthetic fixture for a *verifier-chosen* challenge.

    The fixtures are static captures, so we cannot ask a real TPM to quote a new
    nonce. We splice `challenge` into the quote's extraData field and into the
    EAR's eat_nonce solely to exercise the verifier's gate logic. This does not
    produce a matching TPM signature or a newly appraised EAR and must not be
    treated as generated attestation evidence. Returns paths inside out_dir.

    This exists so the freshness gate receives a challenge the verifier chose,
    never one derived from the evidence it is checking.
    """
    d = bytearray(open(quote_path, "rb").read())
    size = int.from_bytes(d[16:18], "big")
    raw_off = 18
    qs = int.from_bytes(d[raw_off + 6:raw_off + 8], "big")
    off = raw_off + 8 + qs
    ed = int.from_bytes(d[off:off + 2], "big")
    if len(challenge) != ed:
        raise ValueError("challenge must be %d bytes for this quote" % ed)
    d[off + 2:off + 2 + ed] = challenge
    q_out = os.path.join(out_dir, os.path.basename(quote_path))
    open(q_out, "wb").write(bytes(d))

    e = json.load(open(ear_path))
    e["eat_nonce"] = b64u_enc(challenge)
    e_out = os.path.join(out_dir, os.path.basename(ear_path))
    json.dump(e, open(e_out, "w"), indent=2)
    return q_out, e_out


def ear_of(path):
    d = json.load(open(path))
    for _, v in (d.get("submods") or {}).items():
        return v.get("ear.status"), b64u_dec(d.get("eat_nonce"))
    return None, b""

def self_signed(cn):
    k = ec.generate_private_key(ec.SECP256R1()); now = dt.datetime(2026, 1, 1)
    c = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650)).sign(k, hashes.SHA256()))
    return k, c

def x5t(c): return hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()

def make_tl(cert, service_type):
    der = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">'
           '<SchemeInformation><TSLSequenceNumber>1</TSLSequenceNumber></SchemeInformation>'
           '<TrustServiceProviderList><TrustServiceProvider><TSPServices><TSPService><ServiceInformation>'
           f'<ServiceTypeIdentifier>{service_type}</ServiceTypeIdentifier>'
           '<ServiceName><Name>mock endorser</Name></ServiceName>'
           f'<ServiceStatus>{GRANTED}</ServiceStatus>'
           f'<ServiceDigitalIdentity><DigitalId><X509Certificate>{der}</X509Certificate></DigitalId></ServiceDigitalIdentity>'
           '</ServiceInformation></TSPService></TSPServices></TrustServiceProvider></TrustServiceProviderList>'
           '</TrustServiceStatusList>')
    fd, p = tempfile.mkstemp(suffix=".xml"); os.write(fd, xml.encode()); os.close(fd); return p


class MockVerifier:
    """A minimal OpenID4VP relying party that resolves the AgentRuntimeEndorser role natively."""

    def __init__(self, trusted_list_path):
        self.tl = TrustedListXML.from_file(trusted_list_path, granted_only=False)
        self.aud = "https://mock-verifier.example"
        self.nonce = None
        self.challenge = None

    def request(self):
        self.nonce = "rp-" + hashlib.sha256(os.urandom(8)).hexdigest()[:12]
        self.challenge = os.urandom(32)   # verifier-chosen freshness nonce (RFC 9334 Appendix A)
        return {"response_type": "vp_token", "client_id": self.aud, "nonce": self.nonce,
                "dcql_query": {"credentials": [{"id": "c1", "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["https://vocab.tyche.institute/vct/machine-mandate"]},
                    "claims": [{"path": ["ear_status"]}, {"path": ["swname"]}, {"path": ["principal"]}]}]}}

    def verify(self, vp_token, issuer_jwk, issuer_x5t, ear_file, quote_file, session_nonce):
        r = {"L1_crypto": False, "L2_attested": False, "L3_endorser_role": False,
             "verdict": "DENY", "reasons": []}
        try:
            claims = mandate.verify_presentation_sd(vp_token, issuer_jwk, self.nonce, self.aud)
            r["L1_crypto"] = True
        except Exception as e:
            r["reasons"].append("L1 crypto/binding fail: %s" % type(e).__name__); return r

        ear_status_file, ear_nonce = ear_of(ear_file)
        bound = quote_bound_nonce(quote_file)
        binding = (ear_nonce == bound)                                   # EAR appraises THIS quote
        fresh = (session_nonce == bound)                                # not a replay
        affirming = (ear_status_file == "affirming" and claims.get("ear_status") == ear_status_file)
        r["L2_attested"] = binding and fresh and affirming
        if not binding: r["reasons"].append("L2: EAR not bound to this quote")
        if not fresh: r["reasons"].append("L2: replay (session nonce != quote nonce)")
        if not affirming: r["reasons"].append("L2: attestation not affirming")

        role_ok = issuer_x5t.lower() in {a.x5t_s256.lower() for a in self.tl.by_type(AGENT_ENDORSER)}
        r["L3_endorser_role"] = role_ok
        if not role_ok: r["reasons"].append("L3: issuer not trust-listed as AgentRuntimeEndorser")

        if r["L1_crypto"] and r["L2_attested"] and r["L3_endorser_role"]:
            r["verdict"] = "ACCEPT"; r["disclosed"] = {"ear_status": claims.get("ear_status"),
                                                       "swname": claims.get("swname")}
        return r


def wallet_present(issuer_key, issuer_jwk, nonce, aud, ear_status):
    holder = ec.generate_private_key(ec.SECP256R1()); holder_jwk = aaa_crypto.pub_jwk(holder)
    action_hash = H({"action_id": AEP["action_id"], "outcome": AEP["measurements"]["outcome_sha256"]})
    sd_full = mandate.issue_sd(issuer_key, agent=AEP["sub"], scope="compliance-review",
                               action_hash=action_hash, holder_jwk=holder_jwk,
                               sd_claims={"principal": AEP["authorizing_principal"]["token_ref"],
                                          "swname": AEP["swname"], "ear_status": ear_status,
                                          "aep_receipt_hash": AEP["receipt_hash"]})
    return mandate.present_sd(sd_full, holder, nonce=nonce, aud=aud,
                              reveal={"principal", "swname", "ear_status"})


def main():
    issuer_key, issuer_cert = self_signed("Tyche Agent-Runtime Endorser")
    issuer_jwk = aaa_crypto.pub_jwk(issuer_key); ix5t = x5t(issuer_cert)
    other_key, other_cert = self_signed("Some Unrelated QTSP")
    A_ear = os.path.join(FIX, "ear-A_good_fresh.json"); A_q = os.path.join(FIX, "token-A_good_fresh.bin")
    B_ear = os.path.join(FIX, "ear-B_outcome_swapped.json"); B_q = os.path.join(FIX, "token-B_outcome_swapped.bin")
    # every session challenge is verifier-chosen and evidence is rebound to it (the
    # replay row rebinds to a stale challenge from an "earlier" session) — never
    # derived from the quote under test (CORRECTION.md)
    td = tempfile.mkdtemp()
    def sub(name):
        p = os.path.join(td, name); os.makedirs(p, exist_ok=True); return p
    STALE = bytes(range(32))
    CH_A = os.urandom(32); CH_B = os.urandom(32)
    q_fresh, e_fresh = rebind_evidence(A_q, A_ear, CH_A, sub("fresh"))
    q_stale, e_stale = rebind_evidence(A_q, A_ear, STALE, sub("stale"))
    q_contra, e_contra = rebind_evidence(B_q, B_ear, CH_B, sub("contra"))

    print("=== Mock OpenID4VP verifier — native AgentRuntimeEndorser resolution ===")
    cases = [
        # label,          TL(cert,type),                    ear,      quote,    session,        ear_status, expect
        ("good_fresh",    (issuer_cert, AGENT_ENDORSER),    e_fresh,  q_fresh,  CH_A,           "affirming",       "ACCEPT"),
        ("wrong_role",    (issuer_cert, CA_QC),             e_fresh,  q_fresh,  CH_A,           "affirming",       "DENY"),
        ("replay",        (issuer_cert, AGENT_ENDORSER),    e_stale,  q_stale,  os.urandom(32), "affirming",       "DENY"),
        ("contraindicated", (issuer_cert, AGENT_ENDORSER),  e_contra, q_contra, CH_B,           "contraindicated", "DENY"),
        ("unlisted",      (other_cert, AGENT_ENDORSER),     e_fresh,  q_fresh,  CH_A,           "affirming",       "DENY"),
    ]
    out = []
    for label, (cert, stype), ear, q, sess, ear_status, expect in cases:
        tl_path = make_tl(cert, stype)
        rp = MockVerifier(tl_path); rp.request()
        vp = wallet_present(issuer_key, issuer_jwk, rp.nonce, rp.aud, ear_status)
        res = rp.verify(vp, issuer_jwk, ix5t, ear, q, sess)
        res.update({"case": label, "expected": expect, "match": res["verdict"] == expect})
        out.append(res); os.unlink(tl_path)
        print("[%-15s] L1=%s L2=%s L3=%s -> %-6s (want %s) %s" % (
            label, res["L1_crypto"], res["L2_attested"], res["L3_endorser_role"],
            res["verdict"], expect, "ok" if res["match"] else "!!"))
        if res["reasons"]: print("    reasons:", "; ".join(res["reasons"]))
    art = os.path.join(HERE, "..", "artifacts"); os.makedirs(art, exist_ok=True)
    json.dump(out, open(os.path.join(art, "mock-verifier.json"), "w"), indent=2)
    shutil.rmtree(td, ignore_errors=True)
    ok = all(r["match"] for r in out)
    print("\nMOCK VERIFIER:", "PASS — a verifier that resolves the endorser role natively over OID4VP "
          "(L1+L2+L3), accepting only genuine/fresh/affirming/endorser-listed presentations" if ok else "CHECK")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
