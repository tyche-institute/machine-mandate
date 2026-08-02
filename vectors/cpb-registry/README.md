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
