# CPB-registry vectors for the `machine-mandate` artifact type (v0.1)

Two-sided vector set backing the MachineMandate entry in the CPB registry
(action-state-group/scitt-payload-binding, PR #4). Generated and verified from
this repository's own canonicalisation (`deps/jcs.py`) — regenerate or check with:

    python3 vectors/cpb-registry/gen_vectors.py            # regenerate
    python3 vectors/cpb-registry/gen_vectors.py --verify   # recompute + compare

Positive side: the two frozen derivations (credential derived identifier over the
exact issuer-signed JWT component bytes, 1190 B; the {action_id, outcome} action
digest, 91 canonical bytes) plus key-order-invariance and UTF-8 probes.

Negative side: the member-removal discriminator (an implementation applying the
registry's `jcs-n` removal pass produces a DIFFERENT digest and must fail),
float rejection, byte-exactness of the preimage (trailing-newline mutation),
representation non-interchangeability (bare vs `sha256:`-prefixed), and
lowercase-hex validation.

The algorithm name is stated as `jcs-s` pending the registry's naming decision;
the semantics travel with the vectors either way. Frozen instance values match
`interop/composition-input-manifest-v0.5.json` and `interop/run-credential-preimage.jwt`.

## Day-2 spec-mutation vectors (2026-08-03)

Three vectors from the spec-mutation pass over draft-mih-sokolov-scitt-payload-binding-00
(surviving mutants M08, M10, M11), byte-identical to the vault artifacts and carrying the
same pins as the corpus-format versions contributed upstream in
action-state-group/scitt-payload-binding PR #6 (that corpus uses the registry's own vector
schema, so those files are equivalent, not byte-identical):

- `kat-utf16-key-order.json` — RFC 8785 §3.2.3 sorts member names on UTF-16 code
  units, not code points; observable only above U+FFFF. Two cases: a minimal
  non-BMP pair and the RFC's own seven-member sorting example. Corrected 2026-08-04
  (version 2): the `source` field claimed the sort key was outside the formalized
  fragment, which stopped being true when the accompanying Lean development redefined
  its key order over UTF-16 code units and proved that key injective. The new
  `formalization_status` field states what is machine-checked and what is not. No
  witness, byte string or digest changed.
- `kat-identifier-trailing-newline.json` / `kat-identifier-surrounding-whitespace.json`
  — §4.1 identifier grammar MUST-FAILs (a 64-char lowercase hex string admits no
  trailing newline and no surrounding whitespace; reject, never trim). Split per
  whitespace class so a partial tolerance stays attributable.

Check with:

    python3 vectors/cpb-registry/verify_day2.py

The verifier is stdlib-only and builds the UTF-16 sort key by explicit
surrogate-pair decomposition, sharing no code with the serializers that
produced the pins.
