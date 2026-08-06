//! Differential adapter for the production identity projection.
//!
//! This is the only identity-simulation source file allowed to depend on `krikos_identity`.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
};

use krikos_base::SecretKey;
use krikos_identity as implementation;
use krikos_runtime::RootSeed;
use rand_core::{TryCryptoRng, TryRng};
use serde::{Deserialize, Serialize};

use super::{
    AccountControlModel, ControllerId, DeviceId, DeviceLifecycle, EventId, ForkResolution,
    IdentityEvent, IdentityOperation, MigrationState, ModelController, ModelPolicy, RecoveryPlan,
};

/// Required semantic actions exercised by every generated differential history.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialCoverage {
    pub policy_change: bool,
    pub controller_revocation: bool,
    pub device_revocation: bool,
    pub fork_and_resolution: bool,
    pub recovery: bool,
    pub migration: bool,
    pub group_recipient_rotation: bool,
}

/// Common public projection compared without sharing transition implementation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialSnapshot {
    pub account_id: [u8; 32],
    pub sequence: u64,
    pub epoch: u64,
    /// Normalized current head labels mapped to their complete predecessor label sets.
    pub canonical_heads: BTreeMap<u64, Vec<u64>>,
    pub active_controllers: Vec<u16>,
    pub revoked_controllers: Vec<u16>,
    pub active_devices: Vec<u16>,
    pub revoked_devices: Vec<u16>,
    pub required_weight: u16,
    pub forked: bool,
    pub migration: MigrationState,
    pub group_key_generation: u64,
    pub group_key_recipients: Vec<u16>,
}

impl DifferentialSnapshot {
    /// Compare two independently observed projections and retain both exact observations.
    pub fn compare(
        self,
        action: impl Into<String>,
        reference: Self,
    ) -> Result<DifferentialStep, DifferentialError> {
        let action = action.into();
        if self != reference {
            return Err(DifferentialError::Divergence {
                action,
                implementation: Box::new(self),
                reference: Box::new(reference),
            });
        }
        Ok(DifferentialStep {
            action,
            implementation: self,
            reference,
        })
    }
}

/// One implementation/reference equality checkpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialStep {
    pub action: String,
    pub implementation: DifferentialSnapshot,
    pub reference: DifferentialSnapshot,
}

/// Deterministic generated history and all differential checkpoints.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialHistoryReport {
    pub root_seed: [u8; 32],
    pub selected_fork_branch: String,
    pub coverage: DifferentialCoverage,
    pub production_evidence: DifferentialProductionEvidence,
    pub steps: Vec<DifferentialStep>,
}

/// Production artifacts that prevent the comparator from substituting expected migration or
/// recipient state for observations.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialProductionEvidence {
    pub migration_crypto_commitment_changed: bool,
    pub new_suite_authorized: bool,
    pub old_suite_rejected: bool,
    pub revoked_recipient_rejected: bool,
    pub group_rotation_wraps: u64,
}

/// Runs one generated history through independent and production state machines.
pub fn run_differential_history(
    seed: RootSeed,
) -> Result<DifferentialHistoryReport, DifferentialError> {
    let controller_secrets = BTreeMap::from([
        (1_u16, SecretKey::from_bytes(&[1; 32])),
        (2, SecretKey::from_bytes(&[2; 32])),
        (3, SecretKey::from_bytes(&[3; 32])),
        (9, SecretKey::from_bytes(&[9; 32])),
        (10, SecretKey::from_bytes(&[10; 32])),
        (19, SecretKey::from_bytes(&[19; 32])),
    ]);
    let provider_secret = SecretKey::from_bytes(&[99; 32]);
    let initial_policy = control_policy(1, 1)?;
    let recovery_policy = recovery_policy()?;
    let provider_policy = provider_policy(&provider_secret)?;
    let controller_one = production_controller(secret(&controller_secrets, 1)?, 1)?;
    let controller_two = production_controller(secret(&controller_secrets, 2)?, 1)?;
    let genesis = implementation::AccountGenesis::new(
        [0x41; 32],
        implementation::Timestamp::from_unix_millis(1),
        initial_policy,
        vec![controller_one.clone(), controller_two.clone()],
        recovery_policy,
        provider_policy,
        implementation::Extensions::default(),
    )?;
    let mut production = implementation::AccountState::from_genesis(&genesis)?;
    let mut controller_labels =
        BTreeMap::from([(controller_one.id()?, 1_u16), (controller_two.id()?, 2_u16)]);
    let mut device_labels = BTreeMap::new();
    let mut production_group_recipients = BTreeSet::new();
    let mut production_group_key_generation = 0_u64;
    let mut lineage = DifferentialLineage::default();
    let mut reference = ReferenceHarness::new(*production.account_id().as_digest().as_bytes())?;
    let mut steps = Vec::new();

    compare_step(
        "genesis",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let changed_policy = control_policy(1, seed.as_bytes()[1])?;
    let change = authorized_event(
        &production,
        implementation::AccountOperation::ChangeControlPolicy(changed_policy),
        production.epoch().checked_next()?,
        10,
        secret(&controller_secrets, 1)?,
    )?;
    apply_production(&mut production, &change, "policy_change")?;
    let reference_id =
        reference.apply(IdentityOperation::ChangePolicy(ModelPolicy::new(1)?), &[1])?;
    lineage.record(&change, reference_id)?;
    compare_step(
        "policy_change",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    for (device, nonce) in [(7_u16, 11_u8), (8, 12)] {
        let application_secret = SecretKey::from_bytes(&[u8::try_from(device)?; 32]);
        let endpoint_fill = u8::try_from(device.checked_add(32).ok_or(DifferentialError::Bounds)?)?;
        let endpoint_secret = SecretKey::from_bytes(&[endpoint_fill; 32]);
        let descriptor = production_device(&application_secret, device, &endpoint_secret)?;
        let device_id = descriptor.id()?;
        device_labels.insert(device_id, device);
        let operation = implementation::AccountOperation::AuthorizeDevice(
            implementation::DeviceAuthorization::new(
                device_id,
                descriptor,
                implementation::DeviceClass::ApplicationOnly,
                None,
                Vec::new(),
                production.epoch().checked_next()?,
                implementation::Extensions::default(),
            )?,
        );
        let event = authorized_event(
            &production,
            operation,
            production.epoch().checked_next()?,
            nonce,
            secret(&controller_secrets, 1)?,
        )?;
        apply_production(&mut production, &event, "authorize_device")?;
        let reference_id = reference.apply(
            IdentityOperation::AuthorizeDevice(DeviceId::new(device)),
            &[1],
        )?;
        lineage.record(&event, reference_id)?;
        compare_step(
            &format!("authorize_device_{device}"),
            &production,
            &reference.state,
            &controller_labels,
            &device_labels,
            None,
            &production_group_recipients,
            production_group_key_generation,
            &lineage,
            &mut steps,
        )?;
    }

    let revoked_device_id = production_device_id(&device_labels, 7)?;
    let revoke_device = authorized_event(
        &production,
        implementation::AccountOperation::RevokeDevice(implementation::RevokeDevice::new(
            revoked_device_id,
            None,
            implementation::Extensions::default(),
        )?),
        production.epoch().checked_next()?,
        13,
        secret(&controller_secrets, 1)?,
    )?;
    apply_production(&mut production, &revoke_device, "revoke_device")?;
    let reference_id = reference.apply(IdentityOperation::RevokeDevice(DeviceId::new(7)), &[1])?;
    lineage.record(&revoke_device, reference_id)?;
    compare_step(
        "revoke_device",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let common_ancestor = *production
        .heads()
        .first()
        .ok_or(DifferentialError::Bounds)?;
    let production_fork_base = production.clone();
    let reference_fork_base = reference.position()?;
    let branch_controller = production_controller(secret(&controller_secrets, 3)?, 1)?;
    controller_labels.insert(branch_controller.id()?, 3);
    let left = authorized_event(
        &production_fork_base,
        implementation::AccountOperation::AddController(branch_controller),
        production_fork_base.epoch().checked_next()?,
        14,
        secret(&controller_secrets, 1)?,
    )?;
    let right_policy = control_policy(1, seed.as_bytes()[2].wrapping_add(1))?;
    let right = authorized_event(
        &production_fork_base,
        implementation::AccountOperation::ChangeControlPolicy(right_policy),
        production_fork_base.epoch().checked_next()?,
        15,
        secret(&controller_secrets, 1)?,
    )?;
    apply_production(&mut production, &left, "fork_left")?;
    apply_production(&mut production, &right, "fork_right")?;
    let left_reference = reference.fork_event(
        reference_fork_base,
        IdentityOperation::AddController(ModelController::new(ControllerId::new(3), 1)?),
        &[1],
    )?;
    let right_reference = reference.fork_event(
        reference_fork_base,
        IdentityOperation::ChangePolicy(ModelPolicy::new(1)?),
        &[1],
    )?;
    lineage.record(&left, left_reference)?;
    lineage.record(&right, right_reference)?;
    compare_step(
        "fork_detected",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let select_left = seed.as_bytes()[0] & 1 == 0;
    let (selected_production, selected_reference, selected_name) = if select_left {
        (left.event_id()?, left_reference, "left")
    } else {
        (right.event_id()?, right_reference, "right")
    };
    let descriptor = implementation::ForkDescriptor::try_new(
        implementation::ProtocolVersion::V1,
        production.account_id(),
        implementation::ForkCommonAncestor::Event(common_ancestor),
        production.heads().to_vec(),
        implementation::Extensions::default(),
    )?;
    let resolution = implementation::ResolveFork::try_new(
        implementation::ProtocolVersion::V1,
        descriptor,
        selected_production,
        Vec::new(),
        Vec::new(),
        implementation::Extensions::default(),
    )?;
    let resolution_event = authorized_event(
        &production,
        implementation::AccountOperation::ResolveFork(resolution),
        left.body().resulting_epoch().checked_next()?,
        16,
        secret(&controller_secrets, 1)?,
    )?;
    apply_production(&mut production, &resolution_event, "resolve_fork")?;
    let reference_id = reference.resolve_fork(selected_reference, &[1])?;
    lineage.record(&resolution_event, reference_id)?;
    compare_step(
        "fork_resolved",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let replacement_nine = production_controller(secret(&controller_secrets, 9)?, 2)?;
    let replacement_ten = production_controller(secret(&controller_secrets, 10)?, 1)?;
    controller_labels.insert(replacement_nine.id()?, 9);
    controller_labels.insert(replacement_ten.id()?, 10);
    let (begin_recovery, recovery_id) =
        begin_recovery_operation(&production, vec![replacement_nine, replacement_ten])?;
    let begin_recovery = authorized_event(
        &production,
        begin_recovery,
        production.epoch().checked_next()?,
        17,
        secret(&controller_secrets, 1)?,
    )?;
    let begin_proposal_id = begin_recovery.body().proposal_id()?;
    apply_production(&mut production, &begin_recovery, "begin_recovery")?;
    let finalize = finalize_recovery_event(
        &production,
        recovery_id,
        begin_proposal_id,
        18,
        &provider_secret,
    )?;
    apply_production(&mut production, &finalize, "finalize_recovery")?;
    let (begin_reference, finalize_reference) =
        reference.recover(vec![(9, 2), (10, 1)], 1, &[1])?;
    lineage.record(&begin_recovery, begin_reference)?;
    lineage.record(&finalize, finalize_reference)?;
    compare_step(
        "recovery",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let post_recovery_application_secret = SecretKey::from_bytes(&[11; 32]);
    let post_recovery_endpoint_secret = SecretKey::from_bytes(&[43; 32]);
    let post_recovery_descriptor = production_device(
        &post_recovery_application_secret,
        11,
        &post_recovery_endpoint_secret,
    )?;
    let post_recovery_device_id = post_recovery_descriptor.id()?;
    device_labels.insert(post_recovery_device_id, 11);
    let authorize_post_recovery_device = authorized_event(
        &production,
        implementation::AccountOperation::AuthorizeDevice(
            implementation::DeviceAuthorization::new(
                post_recovery_device_id,
                post_recovery_descriptor,
                implementation::DeviceClass::ApplicationOnly,
                None,
                Vec::new(),
                production.epoch().checked_next()?,
                implementation::Extensions::default(),
            )?,
        ),
        production.epoch().checked_next()?,
        119,
        secret(&controller_secrets, 9)?,
    )?;
    apply_production(
        &mut production,
        &authorize_post_recovery_device,
        "authorize_post_recovery_device",
    )?;
    let reference_id =
        reference.apply(IdentityOperation::AuthorizeDevice(DeviceId::new(11)), &[9])?;
    lineage.record(&authorize_post_recovery_device, reference_id)?;
    compare_step(
        "authorize_post_recovery_device",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let controller_ten_id = production_controller_id(&controller_labels, 10)?;
    let remove = authorized_event(
        &production,
        implementation::AccountOperation::RemoveController(controller_ten_id),
        production.epoch().checked_next()?,
        120,
        secret(&controller_secrets, 9)?,
    )?;
    apply_production(&mut production, &remove, "revoke_controller")?;
    let reference_id = reference.apply(
        IdentityOperation::RevokeController(ControllerId::new(10)),
        &[9],
    )?;
    lineage.record(&remove, reference_id)?;
    compare_step(
        "revoke_controller",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let pre_migration_crypto_state = implementation::build_checkpoint_body(
        &production,
        implementation::Timestamp::from_unix_millis(120),
    )?
    .crypto_state_id();
    let from_suite = implementation::CryptoSuiteDescriptor::v1()?;
    let to_suite = in_place_suite(2)?;
    let (begin_migration, migration_id) = begin_migration_event(
        &production,
        &from_suite,
        secret(&controller_secrets, 9)?,
        to_suite.clone(),
        secret(&controller_secrets, 19)?,
        121,
    )?;
    let begin_migration_id = begin_migration.event_id()?;
    apply_production(&mut production, &begin_migration, "begin_migration")?;
    let reference_id = reference.apply(IdentityOperation::BeginMigration, &[9])?;
    lineage.record(&begin_migration, reference_id)?;
    compare_step(
        "migration_begin",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let controller_nine_id = production_controller_id(&controller_labels, 9)?;
    let activate = authorized_event_with_crypto_keys(
        &production,
        implementation::AccountOperation::ActivateCryptoMigration(
            implementation::ActivateCryptoMigration::try_new(
                implementation::ProtocolVersion::V1,
                migration_id,
                begin_migration_id,
                implementation::Extensions::default(),
            )?,
        ),
        production.epoch().checked_next()?,
        122,
        controller_nine_id,
        &[(&from_suite, secret(&controller_secrets, 9)?, false)],
    )?;
    let activation_id = activate.event_id()?;
    apply_production(&mut production, &activate, "activate_migration")?;
    let reference_id = reference.apply(IdentityOperation::ActivateMigration, &[9])?;
    lineage.record(&activate, reference_id)?;
    compare_step(
        "migration_activate",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        None,
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    let retire = authorized_event_with_crypto_keys(
        &production,
        implementation::AccountOperation::RetireCryptoSuite(
            implementation::RetireCryptoSuite::try_new(
                implementation::ProtocolVersion::V1,
                migration_id,
                implementation::RetireCryptoSuiteMode::RetirePrevious,
                activation_id,
                None,
                implementation::Extensions::default(),
            )?,
        ),
        production.epoch().checked_next()?,
        123,
        controller_nine_id,
        &[
            (&from_suite, secret(&controller_secrets, 9)?, false),
            (&to_suite, secret(&controller_secrets, 19)?, true),
        ],
    )?;
    apply_production(&mut production, &retire, "retire_previous_suite")?;
    let reference_id = reference.apply(IdentityOperation::CompleteMigration, &[9])?;
    lineage.record(&retire, reference_id)?;
    let post_migration_crypto_state = implementation::build_checkpoint_body(
        &production,
        implementation::Timestamp::from_unix_millis(123),
    )?
    .crypto_state_id();
    let probe_controller = production_controller(&SecretKey::from_bytes(&[20; 32]), 1)?;
    let new_suite_probe = authorized_event_with_crypto_keys(
        &production,
        implementation::AccountOperation::AddController(probe_controller.clone()),
        production.epoch().checked_next()?,
        124,
        controller_nine_id,
        &[(&to_suite, secret(&controller_secrets, 19)?, true)],
    )?;
    let new_suite_authorized = production
        .clone()
        .validate_and_apply(&new_suite_probe)
        .is_ok();
    let old_suite_probe = authorized_event_with_crypto_keys(
        &production,
        implementation::AccountOperation::AddController(probe_controller),
        production.epoch().checked_next()?,
        125,
        controller_nine_id,
        &[(&from_suite, secret(&controller_secrets, 9)?, false)],
    )?;
    let old_suite_rejected = production
        .clone()
        .validate_and_apply(&old_suite_probe)
        .is_err();
    let migration_evidence = CompletedMigrationEvidence {
        before_crypto_state: pre_migration_crypto_state,
        after_crypto_state: post_migration_crypto_state,
        new_suite_authorized,
        old_suite_rejected,
    };
    compare_step(
        "migration_complete",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        Some(&migration_evidence),
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    reference.state.rotate_group_key()?;
    let expected_recipient_ids = reference
        .state
        .snapshot()
        .group_key_recipients
        .iter()
        .map(|device| production_device_id(&device_labels, device.get()))
        .collect::<Result<Vec<_>, _>>()?;
    let application_id = implementation::ApplicationId::new(implementation::Digest::new(
        implementation::HashAlgorithm::Blake3_256,
        [0xa1; 32],
    ));
    let group_id = implementation::GroupId::new(implementation::Digest::new(
        implementation::HashAlgorithm::Blake3_256,
        [0xb2; 32],
    ));
    let distribution = implementation::GroupKeyDistributionSnapshot::from_post_state(
        &production,
        application_id,
        group_id,
        implementation::GroupKeyEpoch::new(1),
        expected_recipient_ids,
    )?;
    let revoked_recipient_rejected = matches!(
        implementation::GroupKeyDistributionSnapshot::from_post_state(
            &production,
            application_id,
            group_id,
            implementation::GroupKeyEpoch::new(1),
            vec![production_device_id(&device_labels, 7)?],
        ),
        Err(implementation::IdentityError::DeviceRevoked)
    );
    let mut rng = RepeatingRng(seed.as_bytes()[3]);
    let rotation = implementation::rotate_group_key_with_rng(
        &distribution,
        &implementation::GroupKey::new([0x90; 32]),
        &mut rng,
    )?;
    production_group_recipients = rotation
        .expected_recipient_ids()
        .map(|device| {
            device_labels
                .get(&device)
                .copied()
                .ok_or(DifferentialError::UnknownProductionIdentity)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    production_group_key_generation = production_group_key_generation
        .checked_add(1)
        .ok_or(DifferentialError::Bounds)?;
    let group_rotation_wraps = u64::try_from(rotation.recipient_key_wraps().as_slice().len())?;
    compare_step(
        "group_recipient_rotation",
        &production,
        &reference.state,
        &controller_labels,
        &device_labels,
        Some(&migration_evidence),
        &production_group_recipients,
        production_group_key_generation,
        &lineage,
        &mut steps,
    )?;

    Ok(DifferentialHistoryReport {
        root_seed: *seed.as_bytes(),
        selected_fork_branch: selected_name.to_owned(),
        coverage: DifferentialCoverage {
            policy_change: true,
            controller_revocation: true,
            device_revocation: true,
            fork_and_resolution: true,
            recovery: true,
            migration: true,
            group_recipient_rotation: true,
        },
        production_evidence: DifferentialProductionEvidence {
            migration_crypto_commitment_changed: migration_evidence.before_crypto_state
                != migration_evidence.after_crypto_state,
            new_suite_authorized,
            old_suite_rejected,
            revoked_recipient_rejected,
            group_rotation_wraps,
        },
        steps,
    })
}

#[derive(Clone, Copy, Debug)]
struct CompletedMigrationEvidence {
    before_crypto_state: implementation::CryptoStateId,
    after_crypto_state: implementation::CryptoStateId,
    new_suite_authorized: bool,
    old_suite_rejected: bool,
}

#[derive(Debug, Default)]
struct DifferentialLineage {
    events: BTreeMap<implementation::EventId, (u64, Vec<u64>)>,
}

impl DifferentialLineage {
    fn record(
        &mut self,
        production: &implementation::AuthorizedEvent,
        reference: EventId,
    ) -> Result<(), DifferentialError> {
        let production_id = production.event_id()?;
        if self.events.contains_key(&production_id)
            || self
                .events
                .values()
                .any(|(label, _)| *label == reference.get())
        {
            return Err(DifferentialError::UnexpectedProductionState);
        }
        let mut predecessors = match production.body().predecessors().event_heads() {
            Some(heads) => heads
                .iter()
                .map(|head| {
                    self.events
                        .get(head)
                        .map(|(label, _)| *label)
                        .ok_or(DifferentialError::UnexpectedProductionState)
                })
                .collect::<Result<Vec<_>, _>>()?,
            None if production.body().sequence().get() == 1 => vec![0],
            None => return Err(DifferentialError::UnexpectedProductionState),
        };
        predecessors.sort_unstable();
        self.events
            .insert(production_id, (reference.get(), predecessors));
        Ok(())
    }

    fn canonical_heads(
        &self,
        production: &implementation::AccountState,
    ) -> Result<BTreeMap<u64, Vec<u64>>, DifferentialError> {
        production
            .heads()
            .iter()
            .map(|head| {
                self.events
                    .get(head)
                    .cloned()
                    .ok_or(DifferentialError::UnexpectedProductionState)
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_step(
    action: &str,
    production: &implementation::AccountState,
    reference: &AccountControlModel,
    controller_labels: &BTreeMap<implementation::ControllerId, u16>,
    device_labels: &BTreeMap<implementation::DeviceId, u16>,
    completed_migration: Option<&CompletedMigrationEvidence>,
    production_group_recipients: &BTreeSet<u16>,
    production_group_key_generation: u64,
    lineage: &DifferentialLineage,
    steps: &mut Vec<DifferentialStep>,
) -> Result<(), DifferentialError> {
    let implementation = production_snapshot(
        production,
        controller_labels,
        device_labels,
        completed_migration,
        production_group_recipients,
        production_group_key_generation,
        lineage,
    )?;
    let reference = reference_snapshot(reference);
    steps.push(implementation.compare(action, reference)?);
    Ok(())
}

fn production_snapshot(
    state: &implementation::AccountState,
    controller_labels: &BTreeMap<implementation::ControllerId, u16>,
    device_labels: &BTreeMap<implementation::DeviceId, u16>,
    completed_migration: Option<&CompletedMigrationEvidence>,
    group_key_recipients: &BTreeSet<u16>,
    group_key_generation: u64,
    lineage: &DifferentialLineage,
) -> Result<DifferentialSnapshot, DifferentialError> {
    let mut active_controllers = state
        .active_controllers()
        .iter()
        .map(|controller| label_controller(controller_labels, controller.id()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut revoked_controllers = state
        .revoked_controllers()
        .iter()
        .map(|controller| label_controller(controller_labels, controller.id()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut active_devices = Vec::new();
    let mut revoked_devices = Vec::new();
    for device in state.devices() {
        let label = *device_labels
            .get(&device.id())
            .ok_or(DifferentialError::UnknownProductionIdentity)?;
        match device.lifecycle() {
            implementation::ProjectedDeviceLifecycle::Active => active_devices.push(label),
            implementation::ProjectedDeviceLifecycle::Revoked => revoked_devices.push(label),
            implementation::ProjectedDeviceLifecycle::Suspended => {
                return Err(DifferentialError::UnexpectedProductionState);
            }
        }
    }
    active_controllers.sort_unstable();
    revoked_controllers.sort_unstable();
    active_devices.sort_unstable();
    revoked_devices.sort_unstable();
    let required = state
        .control_policy()
        .rule_for(implementation::OperationKind::AddController)
        .ok_or(DifferentialError::UnexpectedProductionState)?
        .required_weight()
        .get();
    let migration = match state.lifecycle() {
        implementation::ProjectionLifecycle::MigrationPending => MigrationState::Pending,
        implementation::ProjectionLifecycle::MigrationDual => MigrationState::Dual,
        implementation::ProjectionLifecycle::Active => match completed_migration {
            Some(evidence)
                if evidence.before_crypto_state != evidence.after_crypto_state
                    && evidence.new_suite_authorized
                    && evidence.old_suite_rejected
                    && implementation::build_checkpoint_body(
                        state,
                        implementation::Timestamp::from_unix_millis(200),
                    )?
                    .crypto_state_id()
                        == evidence.after_crypto_state =>
            {
                MigrationState::Complete
            }
            Some(_) => return Err(DifferentialError::InvalidMigrationEvidence),
            None => MigrationState::Stable,
        },
        implementation::ProjectionLifecycle::Forked => MigrationState::Stable,
        _ => return Err(DifferentialError::UnexpectedProductionState),
    };
    Ok(DifferentialSnapshot {
        account_id: *state.account_id().as_digest().as_bytes(),
        sequence: state.sequence().get(),
        epoch: state.epoch().get(),
        canonical_heads: lineage.canonical_heads(state)?,
        active_controllers,
        revoked_controllers,
        active_devices,
        revoked_devices,
        required_weight: u16::try_from(required)?,
        forked: state.lifecycle() == implementation::ProjectionLifecycle::Forked,
        migration,
        group_key_generation,
        group_key_recipients: group_key_recipients.iter().copied().collect(),
    })
}

fn reference_snapshot(state: &AccountControlModel) -> DifferentialSnapshot {
    let snapshot = state.snapshot();
    let mut active_devices = Vec::new();
    let mut revoked_devices = Vec::new();
    for (device, lifecycle) in snapshot.devices {
        match lifecycle {
            DeviceLifecycle::Active => active_devices.push(device.get()),
            DeviceLifecycle::Revoked => revoked_devices.push(device.get()),
        }
    }
    DifferentialSnapshot {
        account_id: snapshot.account_id,
        sequence: snapshot.sequence,
        epoch: snapshot.epoch,
        canonical_heads: state.canonical_head_predecessors(),
        active_controllers: snapshot
            .active_controllers
            .into_iter()
            .map(|controller| controller.id().get())
            .collect(),
        revoked_controllers: snapshot
            .revoked_controllers
            .into_iter()
            .map(ControllerId::get)
            .collect(),
        active_devices,
        revoked_devices,
        required_weight: snapshot.policy.required_weight(),
        forked: snapshot.forked,
        migration: snapshot.migration,
        group_key_generation: snapshot.group_key_generation,
        group_key_recipients: snapshot
            .group_key_recipients
            .into_iter()
            .map(DeviceId::get)
            .collect(),
    }
}

#[derive(Debug)]
struct ReferenceHarness {
    state: AccountControlModel,
    next_event: u64,
    fork_heads: Vec<EventId>,
    fork_base: Option<(EventId, u64, u64)>,
}

impl ReferenceHarness {
    fn new(account_id: [u8; 32]) -> Result<Self, DifferentialError> {
        Ok(Self {
            state: AccountControlModel::new(
                account_id,
                vec![
                    ModelController::new(ControllerId::new(1), 1)?,
                    ModelController::new(ControllerId::new(2), 1)?,
                ],
                ModelPolicy::new(1)?,
            )?,
            next_event: 1,
            fork_heads: Vec::new(),
            fork_base: None,
        })
    }

    fn position(&self) -> Result<(EventId, u64, u64), DifferentialError> {
        let snapshot = self.state.snapshot();
        let predecessor = match snapshot.heads.as_slice() {
            [] if snapshot.sequence == 0 => EventId::new(0),
            [head] if !snapshot.forked => *head,
            _ => return Err(DifferentialError::UnexpectedReferenceState),
        };
        Ok((predecessor, snapshot.sequence, snapshot.epoch))
    }

    fn next_id(&mut self) -> Result<EventId, DifferentialError> {
        let id = EventId::new(self.next_event);
        self.next_event = self
            .next_event
            .checked_add(1)
            .ok_or(DifferentialError::Bounds)?;
        Ok(id)
    }

    fn apply(
        &mut self,
        operation: IdentityOperation,
        approvals: &[u16],
    ) -> Result<EventId, DifferentialError> {
        let (predecessor, sequence, epoch) = self.position()?;
        let resulting_epoch = operation.resulting_epoch(epoch)?;
        let event = IdentityEvent::new(
            self.next_id()?,
            predecessor,
            sequence.checked_add(1).ok_or(DifferentialError::Bounds)?,
            resulting_epoch,
            approvals.iter().copied().map(ControllerId::new).collect(),
            operation,
        )?;
        let id = event.id();
        self.state.apply(&event)?;
        Ok(id)
    }

    fn fork_event(
        &mut self,
        base: (EventId, u64, u64),
        operation: IdentityOperation,
        approvals: &[u16],
    ) -> Result<EventId, DifferentialError> {
        self.fork_base = Some(base);
        let event = IdentityEvent::new(
            self.next_id()?,
            base.0,
            base.1.checked_add(1).ok_or(DifferentialError::Bounds)?,
            base.2.checked_add(1).ok_or(DifferentialError::Bounds)?,
            approvals.iter().copied().map(ControllerId::new).collect(),
            operation,
        )?;
        let id = event.id();
        self.state.apply(&event)?;
        self.fork_heads.push(id);
        Ok(id)
    }

    fn resolve_fork(
        &mut self,
        selected: EventId,
        approvals: &[u16],
    ) -> Result<EventId, DifferentialError> {
        let base = self
            .fork_base
            .ok_or(DifferentialError::UnexpectedReferenceState)?;
        let resolution = ForkResolution::new(
            self.next_id()?,
            self.fork_heads.clone(),
            selected,
            base.1.checked_add(2).ok_or(DifferentialError::Bounds)?,
            base.2.checked_add(2).ok_or(DifferentialError::Bounds)?,
            approvals.iter().copied().map(ControllerId::new).collect(),
            Vec::new(),
            Vec::new(),
        )?;
        let id = resolution.id();
        self.state.resolve_fork(&resolution)?;
        Ok(id)
    }

    fn recover(
        &mut self,
        controllers: Vec<(u16, u16)>,
        required_weight: u16,
        begin_approvals: &[u16],
    ) -> Result<(EventId, EventId), DifferentialError> {
        let plan = RecoveryPlan::new(
            controllers
                .into_iter()
                .map(|(id, weight)| ModelController::new(ControllerId::new(id), weight))
                .collect::<Result<Vec<_>, _>>()?,
            ModelPolicy::new(required_weight)?,
        )?;
        let begin = self.apply(IdentityOperation::BeginRecovery, begin_approvals)?;
        let (predecessor, sequence, epoch) = self.position()?;
        let event = IdentityEvent::new(
            self.next_id()?,
            predecessor,
            sequence.checked_add(1).ok_or(DifferentialError::Bounds)?,
            epoch.checked_add(1).ok_or(DifferentialError::Bounds)?,
            Vec::new(),
            IdentityOperation::Recover(plan),
        )?;
        let finalize = event.id();
        self.state.apply_recovery(&event)?;
        Ok((begin, finalize))
    }
}

fn control_policy(
    required_weight: u32,
    extension_fill: u8,
) -> Result<implementation::ControlPolicy, DifferentialError> {
    let operations = [
        implementation::OperationKind::AuthorizeDevice,
        implementation::OperationKind::RevokeDevice,
        implementation::OperationKind::AddController,
        implementation::OperationKind::RemoveController,
        implementation::OperationKind::ChangeControlPolicy,
        implementation::OperationKind::BeginRecovery,
        implementation::OperationKind::FinalizeRecovery,
        implementation::OperationKind::ResolveFork,
        implementation::OperationKind::BeginCryptoMigration,
        implementation::OperationKind::ActivateCryptoMigration,
        implementation::OperationKind::RetireCryptoSuite,
    ];
    let rules = operations
        .into_iter()
        .map(|operation| policy_rule(operation, required_weight))
        .collect::<Result<Vec<_>, _>>()?;
    let extensions = implementation::Extensions::new(vec![implementation::Extension::new(
        100,
        false,
        vec![extension_fill],
    )?])?;
    Ok(implementation::ControlPolicy::new(rules, extensions)?)
}

fn policy_rule(
    operation: implementation::OperationKind,
    required_weight: u32,
) -> Result<implementation::PolicyRule, DifferentialError> {
    let freshness = if operation == implementation::OperationKind::FinalizeRecovery {
        implementation::FreshnessRequirement::provider_quorum(
            implementation::ProviderFreshness::new(
                implementation::ProviderQuorum::new(1)?,
                implementation::DurationMillis::new(1_000),
            )?,
        )
    } else {
        implementation::FreshnessRequirement::latest_known()
    };
    Ok(implementation::PolicyRule::new(
        operation,
        implementation::RequiredWeight::new(required_weight)?,
        implementation::ControllerSelector::any_active(),
        freshness,
        None,
        implementation::Extensions::default(),
    )?)
}

fn recovery_policy() -> Result<implementation::RecoveryPolicy, DifferentialError> {
    Ok(implementation::RecoveryPolicy::new(
        implementation::RecoveryPolicyVersion::GENESIS,
        implementation::RecoveryAuthority::controller_threshold(
            implementation::ControllerThreshold::new(
                implementation::ControllerSelector::any_active(),
                implementation::RequiredWeight::new(1)?,
            ),
        ),
        implementation::DurationMillis::new(10),
        implementation::DurationMillis::new(100),
        implementation::Extensions::default(),
    )?)
}

fn provider_policy(
    provider_secret: &SecretKey,
) -> Result<implementation::ProviderPolicy, DifferentialError> {
    let provider = implementation::ProviderDescriptor::new(
        implementation::SigningPublicKey::ed25519(*provider_secret.public().as_bytes())?,
        implementation::Extensions::default(),
    )?;
    Ok(implementation::ProviderPolicy::replicated(
        implementation::ProviderPolicyVersion::GENESIS,
        vec![provider],
        implementation::ProviderQuorum::new(1)?,
        implementation::ProviderQuorum::new(1)?,
        implementation::DurationMillis::new(1_000),
        implementation::Extensions::default(),
    )?)
}

fn production_controller(
    secret: &SecretKey,
    weight: u32,
) -> Result<implementation::ControllerDescriptor, DifferentialError> {
    Ok(implementation::ControllerDescriptor::new(
        implementation::SigningPublicKey::ed25519(*secret.public().as_bytes())?,
        implementation::ControllerClass::PersonalDevice,
        implementation::ControllerWeight::new(weight)?,
        implementation::ControllerScope::all_v1_operations(),
        implementation::Extensions::default(),
    )?)
}

fn production_device(
    application_secret: &SecretKey,
    agreement_label: u16,
    endpoint_secret: &SecretKey,
) -> Result<implementation::DeviceDescriptor, DifferentialError> {
    let mut agreement = [0_u8; 32];
    agreement[0] = u8::try_from(agreement_label)?;
    Ok(implementation::DeviceDescriptor::new(
        implementation::SigningPublicKey::ed25519(*application_secret.public().as_bytes())?,
        implementation::AgreementPublicKey::x25519(agreement)?,
        implementation::EndpointPublicKey::new(implementation::SigningPublicKey::ed25519(
            *endpoint_secret.public().as_bytes(),
        )?),
        implementation::Extensions::default(),
    )?)
}

fn authorized_event(
    state: &implementation::AccountState,
    operation: implementation::AccountOperation,
    resulting_epoch: implementation::Epoch,
    nonce: u8,
    signer: &SecretKey,
) -> Result<implementation::AuthorizedEvent, DifferentialError> {
    let predecessors = if state.sequence() == implementation::Sequence::GENESIS {
        implementation::EventPredecessors::genesis(state.genesis_anchor())
    } else {
        implementation::EventPredecessors::events(state.heads().to_vec())?
    };
    let body = implementation::EventBody::new(
        state.account_id(),
        state.sequence().checked_next()?,
        resulting_epoch,
        predecessors,
        operation,
        implementation::Timestamp::from_unix_millis(u64::from(nonce)),
        [nonce; 16],
        implementation::Extensions::default(),
    )?;
    authorize_body(state, body, signer)
}

fn authorize_body(
    state: &implementation::AccountState,
    body: implementation::EventBody,
    signer: &SecretKey,
) -> Result<implementation::AuthorizedEvent, DifferentialError> {
    let checkpoint_id = typed_id::<implementation::CheckpointId>(0x44)?;
    let delay = if matches!(
        body.operation(),
        implementation::AccountOperation::BeginRecovery(_)
    ) {
        let proposal_id = body.proposal_id()?;
        implementation::DelayEvidence::provider_quorum(
            state.provider_policy_id(),
            implementation::ProviderQuorum::new(1)?,
            controller_intent_approvals(state, &body, signer)?,
            implementation::ProviderReceipts::new(vec![provider_receipt(
                state,
                implementation::ProviderLogSubject::EventIntent(proposal_id),
                100,
                100,
                0x67,
                &SecretKey::from_bytes(&[99; 32]),
            )?])?,
        )?
    } else {
        implementation::DelayEvidence::none()
    };
    let evidence = implementation::AdmissionEvidence::new(
        body.proposal_id()?,
        checkpoint_id,
        state.provider_policy_id(),
        implementation::FreshnessEvidence::local_known(checkpoint_id),
        delay,
        implementation::Extensions::default(),
    )?;
    authorize_body_with_evidence(state, body, evidence, signer)
}

fn authorize_body_with_evidence(
    state: &implementation::AccountState,
    body: implementation::EventBody,
    evidence: implementation::AdmissionEvidence,
    signer: &SecretKey,
) -> Result<implementation::AuthorizedEvent, DifferentialError> {
    use implementation::CanonicalWire;
    let event_id = evidence.event_id_for_body(&body)?;
    let signer_key = implementation::SigningPublicKey::ed25519(*signer.public().as_bytes())?;
    let controller = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signer_key)
        .ok_or(DifferentialError::UnknownProductionIdentity)?;
    let approval_body = implementation::ControllerApprovalBody::event(
        controller.id(),
        event_id,
        evidence.admission_evidence_id()?,
        implementation::Extensions::default(),
    )?;
    let signature = signer.sign(&approval_body.to_canonical_bytes()?);
    let keyed = implementation::KeyedSignature::new(
        implementation::CryptoSuiteDescriptor::v1()?.crypto_suite_id()?,
        implementation::ControllerKeyId::for_signing_key(&signer_key)?,
        implementation::AlgorithmSignature::new(1, signature.to_bytes().to_vec())?,
    );
    let approval = implementation::SignedControllerApproval::new(approval_body, vec![keyed])?;
    Ok(implementation::AuthorizedEvent::new(
        body,
        evidence,
        implementation::ControllerApprovals::new(vec![approval])?,
    )?)
}

fn controller_intent_approvals(
    state: &implementation::AccountState,
    body: &implementation::EventBody,
    signer: &SecretKey,
) -> Result<implementation::EventIntentApprovals, DifferentialError> {
    use implementation::CanonicalWire;
    let signer_key = implementation::SigningPublicKey::ed25519(*signer.public().as_bytes())?;
    let controller = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signer_key)
        .ok_or(DifferentialError::UnknownProductionIdentity)?;
    let approval_body = implementation::EventIntentApprovalBody::new(
        controller.id(),
        body.proposal_id()?,
        implementation::Extensions::default(),
    )?;
    let signature = signer.sign(&approval_body.to_canonical_bytes()?);
    Ok(implementation::EventIntentApprovals::new(vec![
        implementation::SignedEventIntentApproval::new(
            approval_body,
            vec![implementation::KeyedSignature::new(
                implementation::CryptoSuiteDescriptor::v1()?.crypto_suite_id()?,
                implementation::ControllerKeyId::for_signing_key(&signer_key)?,
                implementation::AlgorithmSignature::new(1, signature.to_bytes().to_vec())?,
            )],
        )?,
    ])?)
}

fn begin_recovery_operation(
    state: &implementation::AccountState,
    controllers: Vec<implementation::ControllerDescriptor>,
) -> Result<(implementation::AccountOperation, implementation::RecoveryId), DifferentialError> {
    let plan = implementation::RecoveryAuthorityPlan::try_new(
        implementation::ProtocolVersion::V1,
        state.account_id(),
        typed_id::<implementation::CheckpointId>(0x44)?,
        *state.heads().first().ok_or(DifferentialError::Bounds)?,
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
        [0x51; 32],
        controllers,
        state.control_policy().clone(),
        state.recovery_policy().clone(),
        Vec::new(),
        implementation::Timestamp::from_unix_millis(1_000),
        implementation::Extensions::default(),
    )?;
    let proposal = implementation::RecoveryProposal::try_new(
        implementation::ProtocolVersion::V1,
        plan,
        implementation::Extensions::default(),
    )?;
    let recovery_id = proposal.recovery_id()?;
    let evidence = implementation::RecoveryThresholdEvidence::controller_policy(
        state.recovery_policy_id(),
        state.recovery_policy().policy_version(),
    );
    Ok((
        implementation::AccountOperation::BeginRecovery(implementation::BeginRecovery::try_new(
            implementation::ProtocolVersion::V1,
            proposal,
            evidence,
            implementation::Extensions::default(),
        )?),
        recovery_id,
    ))
}

fn finalize_recovery_event(
    state: &implementation::AccountState,
    recovery_id: implementation::RecoveryId,
    begin_proposal_id: implementation::ProposalId,
    nonce: u8,
    provider_secret: &SecretKey,
) -> Result<implementation::AuthorizedEvent, DifferentialError> {
    let anchor = implementation::RecoveryDelayAnchor::try_new(
        implementation::ProtocolVersion::V1,
        state.account_id(),
        recovery_id,
        begin_proposal_id,
        state.provider_policy_id(),
        implementation::ProviderQuorum::new(1)?,
        implementation::ProviderReceipts::new(vec![provider_receipt(
            state,
            implementation::ProviderLogSubject::EventIntent(begin_proposal_id),
            100,
            110,
            0x67,
            provider_secret,
        )?])?,
        implementation::Extensions::default(),
    )?;
    let operation = implementation::AccountOperation::FinalizeRecovery(
        implementation::FinalizeRecovery::try_new(
            implementation::ProtocolVersion::V1,
            recovery_id,
            anchor,
            implementation::Timestamp::from_unix_millis(110),
            implementation::Extensions::default(),
        )?,
    );
    let body = implementation::EventBody::new(
        state.account_id(),
        state.sequence().checked_next()?,
        state.epoch().checked_next()?,
        implementation::EventPredecessors::events(state.heads().to_vec())?,
        operation,
        implementation::Timestamp::from_unix_millis(110),
        [nonce; 16],
        implementation::Extensions::default(),
    )?;
    let checkpoint_id = typed_id::<implementation::CheckpointId>(0x44)?;
    let completion = implementation::ProviderReceipts::new(vec![provider_receipt(
        state,
        implementation::ProviderLogSubject::Checkpoint(checkpoint_id),
        100,
        110,
        nonce,
        provider_secret,
    )?])?;
    let evidence = implementation::AdmissionEvidence::new(
        body.proposal_id()?,
        checkpoint_id,
        state.provider_policy_id(),
        implementation::FreshnessEvidence::provider_quorum(
            checkpoint_id,
            state.provider_policy_id(),
            completion,
        )?,
        implementation::DelayEvidence::none(),
        implementation::Extensions::default(),
    )?;
    Ok(implementation::AuthorizedEvent::new(
        body,
        evidence,
        implementation::ControllerApprovals::new(Vec::new())?,
    )?)
}

fn provider_receipt(
    state: &implementation::AccountState,
    subject: implementation::ProviderLogSubject,
    entry_observed_at: u64,
    head_observed_at: u64,
    log_fill: u8,
    provider_secret: &SecretKey,
) -> Result<implementation::InclusionReceipt, DifferentialError> {
    let provider = implementation::ProviderDescriptor::new(
        implementation::SigningPublicKey::ed25519(*provider_secret.public().as_bytes())?,
        implementation::Extensions::default(),
    )?;
    let log_id = typed_id::<implementation::ProviderLogId>(log_fill)?;
    let entry = implementation::ProviderLogEntryBody::new(
        provider.id()?,
        log_id,
        state.account_id(),
        subject,
        implementation::Timestamp::from_unix_millis(entry_observed_at),
        implementation::Extensions::default(),
    )?;
    let head = implementation::ProviderHeadBody::new(
        provider.id()?,
        log_id,
        implementation::ProviderKeyVersion::GENESIS,
        1,
        entry.merkle_leaf_hash()?,
        implementation::Timestamp::from_unix_millis(head_observed_at),
        implementation::Extensions::default(),
    )?;
    let signature = provider_secret.sign(&head.signing_bytes()?);
    Ok(implementation::InclusionReceipt::new(
        entry,
        0,
        Vec::new(),
        implementation::SignedProviderHead::new(
            head,
            implementation::ProtocolSignature::ed25519(signature.to_bytes()),
        ),
    )?)
}

fn in_place_suite(code: u16) -> Result<implementation::CryptoSuiteDescriptor, DifferentialError> {
    let v1 = implementation::CryptoSuiteDescriptor::v1()?;
    Ok(implementation::CryptoSuiteDescriptor::try_new(
        implementation::ProtocolVersion::V1,
        code,
        v1.hash_algorithm_code(),
        v1.signature_algorithm_code(),
        v1.agreement_algorithm_code(),
        v1.kdf_algorithm_code(),
        v1.aead_algorithm_code(),
        implementation::Extensions::default(),
    )?)
}

fn begin_migration_event(
    state: &implementation::AccountState,
    from_suite: &implementation::CryptoSuiteDescriptor,
    old_secret: &SecretKey,
    to_suite: implementation::CryptoSuiteDescriptor,
    new_secret: &SecretKey,
    nonce: u8,
) -> Result<
    (
        implementation::AuthorizedEvent,
        implementation::CryptoMigrationId,
    ),
    DifferentialError,
> {
    use implementation::CanonicalWire;
    let controller_id = state
        .active_controllers()
        .first()
        .ok_or(DifferentialError::Bounds)?
        .id();
    let old_signing_key =
        implementation::SigningPublicKey::ed25519(*old_secret.public().as_bytes())?;
    let old_key_id = implementation::ControllerKeyId::for_signing_key(&old_signing_key)?;
    let migration = implementation::CryptoMigrationBody::try_new(
        implementation::ProtocolVersion::V1,
        state.account_id(),
        from_suite.crypto_suite_id()?,
        to_suite.clone(),
        vec![implementation::ControllerKeyBinding::try_new(
            controller_id,
            old_key_id,
            implementation::AlgorithmPublicKey::new(
                to_suite.signature_algorithm_code(),
                new_secret.public().as_bytes().to_vec(),
            )?,
            implementation::Extensions::default(),
        )?],
        None,
        [nonce; 32],
        implementation::Extensions::default(),
    )?;
    let migration_id = migration.crypto_migration_id()?;
    let migration_bytes = migration_id.to_canonical_bytes()?;
    let proof = implementation::ControllerKeyBindingProof::try_new(
        migration_id,
        controller_id,
        implementation::AlgorithmSignature::new(
            1,
            old_secret.sign(&migration_bytes).to_bytes().to_vec(),
        )?,
        implementation::AlgorithmSignature::new(
            1,
            new_secret.sign(&migration_bytes).to_bytes().to_vec(),
        )?,
    )?;
    let operation = implementation::AccountOperation::BeginCryptoMigration(
        implementation::BeginCryptoMigration::try_new(
            implementation::ProtocolVersion::V1,
            migration,
            implementation::ControllerKeyBindingProofSet::try_new(vec![proof])?,
            implementation::Extensions::default(),
        )?,
    );
    Ok((
        authorized_event_with_crypto_keys(
            state,
            operation,
            state.epoch(),
            nonce,
            controller_id,
            &[(from_suite, old_secret, false)],
        )?,
        migration_id,
    ))
}

fn authorized_event_with_crypto_keys(
    state: &implementation::AccountState,
    operation: implementation::AccountOperation,
    resulting_epoch: implementation::Epoch,
    nonce: u8,
    controller_id: implementation::ControllerId,
    signers: &[(&implementation::CryptoSuiteDescriptor, &SecretKey, bool)],
) -> Result<implementation::AuthorizedEvent, DifferentialError> {
    let body = implementation::EventBody::new(
        state.account_id(),
        state.sequence().checked_next()?,
        resulting_epoch,
        implementation::EventPredecessors::events(state.heads().to_vec())?,
        operation,
        implementation::Timestamp::from_unix_millis(u64::from(nonce)),
        [nonce; 16],
        implementation::Extensions::default(),
    )?;
    authorize_body_with_crypto_keys(state, body, controller_id, signers)
}

fn authorize_body_with_crypto_keys(
    state: &implementation::AccountState,
    body: implementation::EventBody,
    controller_id: implementation::ControllerId,
    signers: &[(&implementation::CryptoSuiteDescriptor, &SecretKey, bool)],
) -> Result<implementation::AuthorizedEvent, DifferentialError> {
    use implementation::CanonicalWire;
    let checkpoint_id = typed_id::<implementation::CheckpointId>(0x44)?;
    let evidence = implementation::AdmissionEvidence::new(
        body.proposal_id()?,
        checkpoint_id,
        state.provider_policy_id(),
        implementation::FreshnessEvidence::local_known(checkpoint_id),
        implementation::DelayEvidence::none(),
        implementation::Extensions::default(),
    )?;
    let event_id = evidence.event_id_for_body(&body)?;
    let approval_body = implementation::ControllerApprovalBody::event(
        controller_id,
        event_id,
        evidence.admission_evidence_id()?,
        implementation::Extensions::default(),
    )?;
    let bytes = approval_body.to_canonical_bytes()?;
    let keyed = signers
        .iter()
        .map(|(suite, signer, migrated)| {
            let signing_key =
                implementation::SigningPublicKey::ed25519(*signer.public().as_bytes())?;
            let key_id = if *migrated {
                implementation::ControllerKeyId::for_algorithm_key(
                    &implementation::AlgorithmPublicKey::new(
                        suite.signature_algorithm_code(),
                        signing_key.as_bytes().to_vec(),
                    )?,
                )?
            } else {
                implementation::ControllerKeyId::for_signing_key(&signing_key)?
            };
            Ok(implementation::KeyedSignature::new(
                suite.crypto_suite_id()?,
                key_id,
                implementation::AlgorithmSignature::new(
                    suite.signature_algorithm_code(),
                    signer.sign(&bytes).to_bytes().to_vec(),
                )?,
            ))
        })
        .collect::<Result<Vec<_>, DifferentialError>>()?;
    let approval = implementation::SignedControllerApproval::new(approval_body, keyed)?;
    Ok(implementation::AuthorizedEvent::new(
        body,
        evidence,
        implementation::ControllerApprovals::new(vec![approval])?,
    )?)
}

fn typed_id<T: implementation::CanonicalWire>(fill: u8) -> Result<T, DifferentialError> {
    use implementation::CanonicalWire;
    let digest = implementation::Digest::new(implementation::HashAlgorithm::Blake3_256, [fill; 32]);
    Ok(T::from_canonical_bytes(&digest.to_canonical_bytes()?)?)
}

fn secret(secrets: &BTreeMap<u16, SecretKey>, label: u16) -> Result<&SecretKey, DifferentialError> {
    secrets
        .get(&label)
        .ok_or(DifferentialError::UnknownProductionIdentity)
}

fn label_controller(
    labels: &BTreeMap<implementation::ControllerId, u16>,
    id: implementation::ControllerId,
) -> Result<u16, DifferentialError> {
    labels
        .get(&id)
        .copied()
        .ok_or(DifferentialError::UnknownProductionIdentity)
}

fn production_controller_id(
    labels: &BTreeMap<implementation::ControllerId, u16>,
    label: u16,
) -> Result<implementation::ControllerId, DifferentialError> {
    labels
        .iter()
        .find_map(|(id, candidate)| (*candidate == label).then_some(*id))
        .ok_or(DifferentialError::UnknownProductionIdentity)
}

fn production_device_id(
    labels: &BTreeMap<implementation::DeviceId, u16>,
    label: u16,
) -> Result<implementation::DeviceId, DifferentialError> {
    labels
        .iter()
        .find_map(|(id, candidate)| (*candidate == label).then_some(*id))
        .ok_or(DifferentialError::UnknownProductionIdentity)
}

#[derive(Debug)]
struct RepeatingRng(u8);

impl TryRng for RepeatingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        destination.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

fn apply_production(
    state: &mut implementation::AccountState,
    event: &implementation::AuthorizedEvent,
    action: &'static str,
) -> Result<(), DifferentialError> {
    state
        .validate_and_apply(event)
        .map(|_| ())
        .map_err(|source| DifferentialError::ProductionStep { action, source })
}

/// Production construction, independent-model, or semantic comparison failure.
#[derive(Debug, thiserror::Error)]
pub enum DifferentialError {
    #[error("production identity transition failed: {0}")]
    Production(#[from] implementation::IdentityError),
    #[error("production identity transition {action} failed: {source}")]
    ProductionStep {
        action: &'static str,
        source: implementation::IdentityError,
    },
    #[error("independent reference transition failed: {0}")]
    Reference(#[from] super::ModelError),
    #[error("generated identity history exceeded a numeric or collection bound")]
    Bounds,
    #[error("generated identity label is unknown to the production adapter")]
    UnknownProductionIdentity,
    #[error("production projection entered an unexpected state")]
    UnexpectedProductionState,
    #[error("production migration evidence did not prove the post-retirement suite")]
    InvalidMigrationEvidence,
    #[error("reference projection entered an unexpected state")]
    UnexpectedReferenceState,
    #[error("numeric conversion failed: {0}")]
    Conversion(#[from] std::num::TryFromIntError),
    #[error("implementation/reference divergence at {action}")]
    Divergence {
        action: String,
        implementation: Box<DifferentialSnapshot>,
        reference: Box<DifferentialSnapshot>,
    },
}
