use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, BlindingSecret, CanonicalWire, ControllerWeight, Digest, DurationMillis, Epoch,
    Extensions, GuardianApprovalBody, GuardianApprovalDecision, GuardianApprovalSet,
    GuardianAuthorityContext, GuardianGrant, GuardianGrantOpening, GuardianSetRoot,
    GuardianThreshold, HashAlgorithm, IdentityError, ProtocolSignature, ProtocolVersion,
    RecoveryAuthority, RecoveryId, RecoveryPolicy, RecoveryPolicyId, RecoveryPolicyVersion,
    RequiredWeight, SignedGuardianApproval, SigningPublicKey, Timestamp, merkle::MerkleSet,
    verify_guardian_authority,
};

const PROTECTED_ACCOUNT_FILL: u8 = 0x11;
const RECOVERY_FILL: u8 = 0x22;
const POLICY_VERSION: RecoveryPolicyVersion = RecoveryPolicyVersion::new(7);
const ACCOUNT_EPOCH: Epoch = Epoch::new(9);
const APPROVED_AT: Timestamp = Timestamp::from_unix_millis(50_000);
const AUTHORITY_TIME: Timestamp = Timestamp::from_unix_millis(50_100);

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

struct GuardianSpec {
    secret: SecretKey,
    account_id: AccountId,
    weight: ControllerWeight,
    blinding: [u8; 32],
    expires_at: Option<Timestamp>,
}

impl GuardianSpec {
    fn new(seed: u8, weight: u32, expires_at: Option<Timestamp>) -> Self {
        Self {
            secret: SecretKey::from_bytes(&[seed; 32]),
            account_id: typed_id::<AccountId>(seed.checked_add(0x40).unwrap()),
            weight: ControllerWeight::new(weight).unwrap(),
            blinding: [seed.checked_add(0x60).unwrap(); 32],
            expires_at,
        }
    }

    fn grant(&self, recovery_policy_id: RecoveryPolicyId) -> GuardianGrant {
        GuardianGrant::try_new(
            ProtocolVersion::V1,
            typed_id::<AccountId>(PROTECTED_ACCOUNT_FILL),
            recovery_policy_id,
            self.account_id,
            SigningPublicKey::ed25519(*self.secret.public().as_bytes()).unwrap(),
            self.weight,
            Epoch::new(3),
            self.expires_at,
            Extensions::default(),
        )
        .unwrap()
    }

    fn blinding(&self) -> BlindingSecret {
        BlindingSecret::try_new(self.blinding).unwrap()
    }
}

struct GuardianUniverse {
    specs: Vec<GuardianSpec>,
    policy: RecoveryPolicy,
    set: MerkleSet,
    root: GuardianSetRoot,
}

impl GuardianUniverse {
    fn new(required_weight: u32) -> Self {
        let specs = vec![
            GuardianSpec::new(1, 1, Some(Timestamp::from_unix_millis(80_000))),
            GuardianSpec::new(2, 1, Some(Timestamp::from_unix_millis(80_000))),
            GuardianSpec::new(3, 1, Some(Timestamp::from_unix_millis(80_000))),
        ];
        let placeholder_policy = typed_id::<RecoveryPolicyId>(0xee);
        let leaves = specs
            .iter()
            .map(|spec| {
                spec.grant(placeholder_policy)
                    .blinded_merkle_leaf(&spec.blinding())
                    .unwrap()
            })
            .collect();
        let set = MerkleSet::new(leaves).unwrap();
        let root = GuardianSetRoot::new(set.root().unwrap()).unwrap();
        let policy = RecoveryPolicy::new(
            POLICY_VERSION,
            RecoveryAuthority::guardian_threshold(
                GuardianThreshold::new(
                    root,
                    u16::try_from(specs.len()).unwrap(),
                    u64::try_from(specs.len()).unwrap(),
                    RequiredWeight::new(required_weight).unwrap(),
                )
                .unwrap(),
            ),
            DurationMillis::new(1_000),
            DurationMillis::new(30_000),
            Extensions::default(),
        )
        .unwrap();
        Self {
            specs,
            policy,
            set,
            root,
        }
    }

    fn approval(
        &self,
        guardian_index: usize,
        proof_index: usize,
        context: GuardianAuthorityContext,
        approved_at: Timestamp,
    ) -> SignedGuardianApproval {
        let spec = &self.specs[guardian_index];
        let opening = self.opening(guardian_index, proof_index);
        let body = GuardianApprovalBody::try_new(
            ProtocolVersion::V1,
            context.protected_account_id(),
            context.recovery_id(),
            context.decision(),
            opening.guardian_grant_id(),
            context.account_epoch(),
            approved_at,
            Extensions::default(),
        )
        .unwrap();
        let signature = spec.secret.sign(&body.signing_bytes().unwrap());
        SignedGuardianApproval::try_new(
            body,
            opening,
            ProtocolSignature::ed25519(signature.to_bytes()),
        )
        .unwrap()
    }

    fn opening(&self, guardian_index: usize, proof_index: usize) -> GuardianGrantOpening {
        let spec = &self.specs[guardian_index];
        let policy_id = self.policy.id().unwrap();
        let grant = spec.grant(policy_id);
        let proof_leaf = self.specs[proof_index]
            .grant(policy_id)
            .blinded_merkle_leaf(&self.specs[proof_index].blinding())
            .unwrap();
        let proof = self.set.inclusion_proof(proof_leaf.key()).unwrap();
        GuardianGrantOpening::try_new(
            ProtocolVersion::V1,
            grant,
            spec.blinding(),
            self.root,
            u16::try_from(proof.leaf_index()).unwrap(),
            proof.audit_path().to_vec(),
            Extensions::default(),
        )
        .unwrap()
    }

    fn context(&self, decision: GuardianApprovalDecision) -> GuardianAuthorityContext {
        GuardianAuthorityContext::try_new(
            typed_id::<AccountId>(PROTECTED_ACCOUNT_FILL),
            typed_id::<RecoveryId>(RECOVERY_FILL),
            self.policy.id().unwrap(),
            POLICY_VERSION,
            ACCOUNT_EPOCH,
            decision,
            AUTHORITY_TIME,
        )
        .unwrap()
    }

    fn approvals(&self, indexes: &[usize]) -> GuardianApprovalSet {
        let context = self.context(GuardianApprovalDecision::Begin);
        GuardianApprovalSet::try_new(
            indexes
                .iter()
                .map(|index| self.approval(*index, *index, context, APPROVED_AT))
                .collect(),
        )
        .unwrap()
    }
}

#[test]
fn exact_current_guardian_membership_and_threshold_are_required() {
    let universe = GuardianUniverse::new(2);
    let context = universe.context(GuardianApprovalDecision::Begin);
    let exact = universe.approvals(&[0, 1]);
    assert_eq!(
        format!("{:?}", exact.as_slice()[0].opening().grant()),
        "GuardianGrant(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", exact.as_slice()[0].opening()),
        "GuardianGrantOpening(<redacted>)"
    );
    let verified = verify_guardian_authority(&universe.policy, &exact, &context).unwrap();
    assert_eq!(verified.approval_count(), 2);
    assert_eq!(verified.total_weight(), 2);
    assert_eq!(verified.recovery_id(), context.recovery_id());

    let minority = universe.approvals(&[0]);
    assert!(matches!(
        verify_guardian_authority(&universe.policy, &minority, &context),
        Err(IdentityError::UnsatisfiableThreshold | IdentityError::AuthorizationDenied)
    ));
}

#[test]
fn wrong_leaf_opening_and_forged_signature_do_not_count() {
    let universe = GuardianUniverse::new(1);
    let context = universe.context(GuardianApprovalDecision::Begin);
    let wrong_path =
        GuardianApprovalSet::try_new(vec![universe.approval(0, 1, context, APPROVED_AT)]).unwrap();
    assert_eq!(
        verify_guardian_authority(&universe.policy, &wrong_path, &context),
        Err(IdentityError::InvalidProof)
    );

    let valid = universe.approvals(&[0]);
    let approval = &valid.as_slice()[0];
    let forged = approval.with_signature(ProtocolSignature::ed25519([0x99; 64]));
    let forged = GuardianApprovalSet::try_new(vec![forged]).unwrap();
    assert_eq!(
        verify_guardian_authority(&universe.policy, &forged, &context),
        Err(IdentityError::InvalidSignature)
    );
}

#[test]
fn every_signed_recovery_subject_field_is_exact() {
    let universe = GuardianUniverse::new(1);
    let begin = universe.context(GuardianApprovalDecision::Begin);
    let opening = universe.opening(0, 0);
    let wrong_account_body = GuardianApprovalBody::try_new(
        ProtocolVersion::V1,
        typed_id::<AccountId>(0x77),
        begin.recovery_id(),
        begin.decision(),
        opening.guardian_grant_id(),
        begin.account_epoch(),
        APPROVED_AT,
        Extensions::default(),
    )
    .unwrap();
    let wrong_account_signature = universe.specs[0]
        .secret
        .sign(&wrong_account_body.signing_bytes().unwrap());
    assert!(matches!(
        SignedGuardianApproval::try_new(
            wrong_account_body,
            opening,
            ProtocolSignature::ed25519(wrong_account_signature.to_bytes()),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let cases = [
        universe.approval(
            0,
            0,
            universe.context(GuardianApprovalDecision::Cancel),
            APPROVED_AT,
        ),
        universe.approval(
            0,
            0,
            GuardianAuthorityContext::try_new(
                begin.protected_account_id(),
                typed_id::<RecoveryId>(0x78),
                begin.recovery_policy_id(),
                begin.recovery_policy_version(),
                begin.account_epoch(),
                begin.decision(),
                begin.authority_time(),
            )
            .unwrap(),
            APPROVED_AT,
        ),
        universe.approval(
            0,
            0,
            GuardianAuthorityContext::try_new(
                begin.protected_account_id(),
                begin.recovery_id(),
                begin.recovery_policy_id(),
                begin.recovery_policy_version(),
                Epoch::new(begin.account_epoch().get() + 1),
                begin.decision(),
                begin.authority_time(),
            )
            .unwrap(),
            APPROVED_AT,
        ),
        universe.approval(
            0,
            0,
            begin,
            Timestamp::from_unix_millis(AUTHORITY_TIME.as_unix_millis() + 1),
        ),
    ];

    for approval in cases {
        let approvals = GuardianApprovalSet::try_new(vec![approval]).unwrap();
        assert!(verify_guardian_authority(&universe.policy, &approvals, &begin).is_err());
    }
}

#[test]
fn expired_revoked_and_duplicate_guardians_fail_closed() {
    // Rebuild through the normal constructor so the root commits the expiring grant.
    let expired = {
        let mut universe = GuardianUniverse::new(1);
        universe.specs[0].expires_at = Some(AUTHORITY_TIME);
        let placeholder = typed_id::<RecoveryPolicyId>(0xee);
        universe.set = MerkleSet::new(
            universe
                .specs
                .iter()
                .map(|spec| {
                    spec.grant(placeholder)
                        .blinded_merkle_leaf(&spec.blinding())
                        .unwrap()
                })
                .collect(),
        )
        .unwrap();
        universe.root = GuardianSetRoot::new(universe.set.root().unwrap()).unwrap();
        universe.policy = RecoveryPolicy::new(
            POLICY_VERSION,
            RecoveryAuthority::guardian_threshold(
                GuardianThreshold::new(universe.root, 3, 3, RequiredWeight::new(1).unwrap())
                    .unwrap(),
            ),
            DurationMillis::new(1_000),
            DurationMillis::new(30_000),
            Extensions::default(),
        )
        .unwrap();
        universe
    };
    let context = expired.context(GuardianApprovalDecision::Begin);
    assert!(matches!(
        verify_guardian_authority(&expired.policy, &expired.approvals(&[0]), &context),
        Err(IdentityError::StaleEvidence | IdentityError::InvalidRelationship { .. })
    ));

    let universe = GuardianUniverse::new(1);
    let approval = universe.approvals(&[0]).as_slice()[0].clone();
    assert!(matches!(
        GuardianApprovalSet::try_new(vec![approval.clone(), approval]),
        Err(IdentityError::DuplicateElement { .. })
    ));

    let old = universe.approvals(&[0]);
    let rotated_policy = RecoveryPolicy::new(
        RecoveryPolicyVersion::new(POLICY_VERSION.get() + 1),
        RecoveryAuthority::guardian_threshold(
            GuardianThreshold::new(universe.root, 3, 3, RequiredWeight::new(1).unwrap()).unwrap(),
        ),
        DurationMillis::new(1_000),
        DurationMillis::new(30_000),
        Extensions::default(),
    )
    .unwrap();
    let rotated_context = GuardianAuthorityContext::try_new(
        typed_id::<AccountId>(PROTECTED_ACCOUNT_FILL),
        typed_id::<RecoveryId>(RECOVERY_FILL),
        rotated_policy.id().unwrap(),
        rotated_policy.policy_version(),
        ACCOUNT_EPOCH,
        GuardianApprovalDecision::Begin,
        AUTHORITY_TIME,
    )
    .unwrap();
    // A current policy never accepts evidence tied to an unrelated grant set/policy instance.
    assert!(verify_guardian_authority(&rotated_policy, &old, &rotated_context).is_err());
}
