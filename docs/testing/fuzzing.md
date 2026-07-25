# Bounded Protocol Fuzzing

The fuzz package exercises four peer-controlled parsing and framing boundaries:

| Target | Boundary | Maximum input |
| --- | --- | ---: |
| `doh_extract` | DNS-over-HTTPS request extraction | 65,535 bytes |
| `pkarr_body` | signed pkarr publication body validation | 1,104 bytes |
| `relay_segmentation` | relay payload segmentation and byte conservation | 65,546 bytes |
| `config_deserialize` | DNS server configuration deserialization | 65,535 bytes |

Each adapter rejects oversized input before expensive parsing. The relay target's bound is a
10-byte segmentation-control header plus the production 65,536-byte payload maximum. Relay
segmentation additionally asserts that every payload byte belongs to exactly one emitted segment
for all accepted segment sizes and counts.

Install the pinned local tooling and run every target for 30 seconds:

```bash
cargo install cargo-fuzz --locked
scripts/run-bounded-fuzz.sh --seconds 30
```

Run one target while reproducing a failure:

```bash
scripts/run-bounded-fuzz.sh \
  --seconds 300 \
  --target relay_segmentation \
  --artifacts target/fuzz-artifacts
```

The runner permits only reviewed target names and durations from 1 through 3,600 seconds. It gives
libFuzzer an individual-input timeout of 10 seconds, a 2 GiB RSS limit, and a target-specific input
cap. Each target may retain at most 64 files and 64 MiB of artifacts. It copies the checked-in seed
corpus to a temporary directory so a campaign cannot silently mutate reviewed inputs.

Pull requests build all targets and run a one-second smoke campaign. The scheduled workflow runs a
five-minute campaign per target and retains crash artifacts and summaries for 30 days. A crash,
timeout, out-of-memory result, missing adapter assertion, or artifact-budget violation fails its
job. Promote a minimized reproducer into the target's checked-in corpus only after review and add a
normal regression test whenever the failure has a stable non-fuzzing reproduction.
