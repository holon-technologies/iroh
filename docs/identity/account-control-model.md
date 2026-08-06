# Account-control formal model

`AccountControl.tla` specifies the bounded account-control projection used by the identity
hardening lane. Its concrete checked instance has exactly three controllers with asymmetric
weights `{2,1,1}` and policy thresholds in `1..=4`. Controller addition, revocation, and policy
change quantify explicit approval sets and authorize their total weight against the
pre-transition active set, revoked set, and threshold. Weight 2 alone and the two weight-1
controllers together authorize threshold 2; either weight-1 controller alone does not. A proposed
lower threshold cannot authorize its own policy-change event.

Recovery replaces authority through separate, abstractly valid recovery evidence. Each recovery
attempt carries both a replacement controller set and the replacement policy's retained threshold;
the relation accepts it only when the replacement weight satisfies that threshold. Recovery is
disabled while more than one head is retained and cannot serve as implicit fork resolution.
Revocation likewise cannot leave available weight below the retained policy. Every accepted
transition records its prior authority facts, exact predecessor count, and recovery replacement;
the six invariants are derived from those records rather than fixed-truth ghost booleans.

The repository-owned authority is the independent Rust breadth-first checker:

```sh
scripts/check-identity-model.sh
```

The command is hermetic and requires Rust 1.91, not a host-installed TLC binary. It structurally
validates the checked-in module's weighted authorization clauses, transition recording, recovery
threshold, and state-derived invariant clauses. A separately encoded portable-spec evaluator is
then compared exhaustively with the Rust relation for every explored state and attempt. The Rust
relation enumerates every approval subset, thresholds `1..=4`, accepted and rejected ordinary
transition, fork/resolution, replacement set, retained recovery threshold, and malformed
predecessor attempt. It fails closed at 4,096 states, 128 attempts per reachable state, or 200,000
attempted transitions.

This is a deliberately finite abstraction, not a proof for arbitrary controller counts. The three
controller instance preserves the policy distinctions relevant to weighted authorization: a
single high-weight controller, a coalition of low-weight controllers with equal total weight, an
insufficient low-weight approval, old-policy authorization of a proposed lower threshold, and
satisfiability after revocation and recovery. Controller and approval identity, active/revoked
disjointness, weighted sums, retained thresholds, one-versus-two heads, and predecessor
cardinality are modeled. Cryptographic validity, recovery-delay evidence construction, event
bytes, storage, networking, and unbounded populations are outside this formal abstraction and are
covered by the production/differential/simulation lanes.

For each property, the JSON report emits four checked counters: total evaluations, reachable
antecedent witnesses, relevant accepted transitions, and relevant rejected adversarial attempts.
All four must be nonzero for all six properties, so a generic per-attempt counter cannot establish
non-vacuity. Six asymmetric/retained-threshold witnesses are checked separately.

Seven negative controls mutate actual Rust transition rules: revoked authorization, policy
self-authorization, fork visibility, threshold satisfiability, recovery replacement, predecessor
cardinality, and recovery across a fork. Two more controls mutate the independently encoded
portable rules to use approval cardinality and to reset a recovery threshold. The command succeeds
only when all nine mutations are detected; this is why `scripts/check-identity-model.sh` can fail
closed on a dead property or parity rule rather than accepting fabricated post-transition records.
The TLA+ module is retained as the portable specification; running TLC remains an external
validation option and is not claimed by the hermetic command.

The command report is accepted only when it records six structurally validated TLA+ actions, six
validated invariant definitions, nonzero semantic-parity and asymmetric-weight evidence, all nine
mutation controls, nonzero states and transitions, and all four nonzero witness counters for each
property. Run the same check through the simulator CLI with
`cargo +1.91.0 run --locked --manifest-path krikos-sim/Cargo.toml --bin cargo-sim -- identity
model-check`.

The executable reference model in `krikos-sim/src/identity/model.rs` does not call production
transition logic. Production comparisons are isolated in `adapter.rs`, and a source-inventory test
enforces that dependency boundary. Differential checkpoints compare the stable account ID,
sequence, operation-specific epoch, normalized canonical heads and their complete predecessor
sets, authority/device/policy/migration state, group-key generation, and recipients. The v1 model
keeps migration begin non-advancing, represents recovery begin/finalize as two account events, and
treats the production application-key wrapping operation as out-of-band so it cannot invent an
extra account-log position.
