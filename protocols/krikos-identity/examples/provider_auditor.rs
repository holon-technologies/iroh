//! Compare two provider heads from bounded canonical files and emit equivocation evidence.

use std::{env, fs, io::Read, path::Path};

use krikos_identity::{
    CanonicalWire, IdentityError, ProviderDescriptor, ProviderHeadAuditor, SignedProviderHead,
    limits::MAX_ENCODED_OBJECT_BYTES, merkle::MerkleConsistencyProof,
};

fn read_wire<T: CanonicalWire>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    let maximum_with_sentinel = u64::try_from(MAX_ENCODED_OBJECT_BYTES)
        .map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider auditor input bound",
        })?
        .checked_add(1)
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "provider auditor input bound",
        })?;
    let mut bytes = Vec::with_capacity(MAX_ENCODED_OBJECT_BYTES.saturating_add(1));
    fs::File::open(path)?
        .take(maximum_with_sentinel)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ENCODED_OBJECT_BYTES {
        return Err(IdentityError::LimitExceeded {
            resource: "provider auditor input bytes",
            actual: bytes.len(),
            maximum: MAX_ENCODED_OBJECT_BYTES,
        }
        .into());
    }
    Ok(T::from_canonical_bytes(&bytes)?)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if !(arguments.len() == 3 || arguments.len() == 4 || arguments.len() == 5) {
        return Err(
            "usage: provider_auditor PROVIDER HEAD_A HEAD_B [CONSISTENCY_PROOF] [EVIDENCE_OUT]"
                .into(),
        );
    }
    let provider = read_wire::<ProviderDescriptor>(Path::new(&arguments[0]))?;
    let first = read_wire::<SignedProviderHead>(Path::new(&arguments[1]))?;
    let second = read_wire::<SignedProviderHead>(Path::new(&arguments[2]))?;
    let proof = arguments
        .get(3)
        .map(|path| read_wire::<MerkleConsistencyProof>(Path::new(path)))
        .transpose()?;
    let mut auditor = ProviderHeadAuditor::new(provider.clone(), first.body().log_id());
    let first_disposition = auditor.observe(first, None)?;
    println!("first={first_disposition:?}");
    match auditor.observe(second, proof.as_ref()) {
        Ok(disposition) => {
            println!("second={disposition:?}");
            Ok(())
        }
        Err(IdentityError::ProviderEquivocation) => {
            let evidence = auditor
                .equivocation_evidence()
                .ok_or(IdentityError::StorageCorruption)?;
            evidence.verify(&provider)?;
            if let Some(output) = arguments.get(4) {
                fs::write(output, evidence.to_canonical_bytes()?)?;
            }
            Err(IdentityError::ProviderEquivocation.into())
        }
        Err(error) => Err(error.into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("provider audit failed: {error}");
        std::process::exit(1);
    }
}
