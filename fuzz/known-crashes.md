# Known crashes

Crashes reproduced by the bounded fuzz campaign that are accepted as known and
tracked, so the campaign's signal stays meaningful. A campaign that is
permanently red teaches everyone to ignore it, which hides new crashes.

Each entry must have an owner and an exit condition. An entry with neither is
a bug being hidden, not a crash being tracked.

`scripts/run-bounded-fuzz.sh` matches a crash against this file by building a
signature from the panic's crate-relative file:line:col location plus its
message, then checking whether that exact signature string appears below (see
the **Signature** field of each entry). Matching on the message alone would
also swallow unrelated panics that happen to share generic text such as
"attempt to subtract with overflow" at a different call site, so the location
is part of the match, not just the message.

## hickory-proto TSIG panic

- **Target:** `doh_extract`
- **First seen:** 2026-07-27 (four consecutive nightly runs as of 2026-07-30:
  2026-07-27, 2026-07-28, 2026-07-29, 2026-07-30)
- **Panic:** `attempt to subtract with overflow`
- **Location:** `hickory-proto-0.26.1/src/rr/rdata/tsig.rs:387:23`
- **Signature:** `hickory-proto-0.26.1/src/rr/rdata/tsig.rs:387:23: attempt to subtract with overflow`
- **Upstream:** not yet reported — file at
  https://github.com/hickory-dns/hickory-dns/issues. This is an arithmetic
  underflow reachable from parsing attacker-controlled DoH input, so it is
  security-relevant and should be reported upstream promptly, not just
  tracked here.
- **Owner:** <assign>
- **Exit condition:** upstream fix released and the declared `hickory-proto`
  version (resolved from crates.io, pulled in transitively via
  `hickory-server`/`hickory-proto` dependencies) bumped past it, then delete
  this entry.
- **Why not fixed here:** the panic is in `hickory-proto` as resolved from
  crates.io, not in the vendored `vendor/hickory-server-0.26.1` tree. This
  project only patches the server crate; the vendoring/patch mechanism has no
  way to reach a transitive dependency resolved independently from crates.io.
