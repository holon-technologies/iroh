//! Run-owned deterministic TLS provider components for repository simulation only.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use curve25519_dalek::montgomery::MontgomeryPoint;
use rustls::{
    Error, NamedGroup,
    crypto::{
        ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
        SupportedKxGroup,
    },
};
use zeroize::Zeroize;

const ENTROPY_CONTEXT: &str = "iroh deterministic simulation TLS entropy v1";

pub(crate) fn deterministic_test_crypto_provider(
    provider: Arc<CryptoProvider>,
    run_seed: [u8; 32],
    scope: &str,
) -> Arc<CryptoProvider> {
    let random = Arc::new(DeterministicEntropy::new(
        run_seed,
        format!("{scope}/rustls-random"),
    ));
    let key_exchange = Arc::new(DeterministicEntropy::new(
        run_seed,
        format!("{scope}/x25519"),
    ));
    let mut provider = (*provider).clone();
    provider.secure_random = Arc::new(DeterministicRandom(random));
    provider.kx_groups = vec![Arc::new(DeterministicX25519(key_exchange))];
    Arc::new(provider)
}

struct DeterministicEntropy {
    seed: [u8; 32],
    scope: Arc<str>,
    next: AtomicU64,
}

impl DeterministicEntropy {
    fn new(seed: [u8; 32], scope: String) -> Self {
        Self {
            seed,
            scope: scope.into(),
            next: AtomicU64::new(0),
        }
    }

    fn fill(&self, destination: &mut [u8]) -> Result<(), ()> {
        let counter = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| ())?;
        let mut hasher = blake3::Hasher::new_derive_key(ENTROPY_CONTEXT);
        hasher.update(&self.seed);
        hasher.update(&(self.scope.len() as u32).to_le_bytes());
        hasher.update(self.scope.as_bytes());
        hasher.update(&counter.to_le_bytes());
        hasher.finalize_xof().fill(destination);
        Ok(())
    }
}

impl fmt::Debug for DeterministicEntropy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicEntropy")
            .field("scope", &self.scope)
            .field("next", &self.next.load(Ordering::Relaxed))
            .field("seed", &"[redacted]")
            .finish()
    }
}

impl Drop for DeterministicEntropy {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[derive(Debug)]
struct DeterministicRandom(Arc<DeterministicEntropy>);

impl SecureRandom for DeterministicRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.0.fill(destination).map_err(|_| GetRandomFailed)
    }
}

#[derive(Debug)]
struct DeterministicX25519(Arc<DeterministicEntropy>);

impl SupportedKxGroup for DeterministicX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut private = [0; 32];
        self.0
            .fill(&mut private)
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        let public = MontgomeryPoint::mul_base_clamped(private).to_bytes();
        Ok(Box::new(ActiveX25519 { private, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ActiveX25519 {
    private: [u8; 32],
    public: [u8; 32],
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer_public: &[u8]) -> Result<SharedSecret, Error> {
        let peer_public: [u8; 32] = peer_public
            .try_into()
            .map_err(|_| Error::General("invalid deterministic X25519 peer key".to_owned()))?;
        let mut shared = MontgomeryPoint(peer_public)
            .mul_clamped(self.private)
            .to_bytes();
        if shared == [0; 32] {
            shared.zeroize();
            return Err(Error::General(
                "invalid deterministic X25519 shared secret".to_owned(),
            ));
        }
        let secret = SharedSecret::from(shared.as_slice());
        shared.zeroize();
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl Drop for ActiveX25519 {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(provider: &CryptoProvider) -> [u8; 32] {
        let mut bytes = [0; 32];
        provider.secure_random.fill(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn entropy_is_repeatable_and_scope_separated() {
        let base = iroh_relay::tls::default_provider();
        let first = deterministic_test_crypto_provider(base.clone(), [3; 32], "endpoint/a");
        let replay = deterministic_test_crypto_provider(base.clone(), [3; 32], "endpoint/a");
        let other = deterministic_test_crypto_provider(base, [3; 32], "endpoint/b");

        assert_eq!(bytes(&first), bytes(&replay));
        assert_ne!(bytes(&first), bytes(&other));
    }

    #[test]
    fn x25519_is_repeatable_scope_separated_and_agrees() {
        let base = iroh_relay::tls::default_provider();
        let a = deterministic_test_crypto_provider(base.clone(), [8; 32], "endpoint/a");
        let a_replay = deterministic_test_crypto_provider(base.clone(), [8; 32], "endpoint/a");
        let b = deterministic_test_crypto_provider(base, [8; 32], "endpoint/b");

        let a_key = a.kx_groups[0].start().unwrap();
        let a_replay_key = a_replay.kx_groups[0].start().unwrap();
        let b_key = b.kx_groups[0].start().unwrap();
        assert_eq!(a_key.pub_key(), a_replay_key.pub_key());
        assert_ne!(a_key.pub_key(), b_key.pub_key());

        let a_public = a_key.pub_key().to_vec();
        let b_public = b_key.pub_key().to_vec();
        let a_secret = a_key.complete(&b_public).unwrap();
        let b_secret = b_key.complete(&a_public).unwrap();
        assert_eq!(a_secret.secret_bytes(), b_secret.secret_bytes());
    }
}
