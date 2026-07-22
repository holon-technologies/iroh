//! Stable scenario-domain inventory shared by corpus, campaigns, artifacts, and diagnostics.

use serde::{Deserialize, Serialize};

use crate::{Scenario, ScenarioAction};

/// Counts of behavior-bearing scenario entities. Counts avoid embedding backend-private IDs while
/// making coverage and shrinking visible in durable artifacts.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioInventory {
    pub hosts: u64,
    pub endpoints: u64,
    pub links: u64,
    pub nats: u64,
    pub nat_change_actions: u64,
    pub port_mapping_actions: u64,
    pub firewalls: u64,
    pub firewall_rules: u64,
    pub discovery_providers: u64,
    pub discovery_records: u64,
    pub interfaces: u64,
    pub interface_change_actions: u64,
    pub routes: u64,
    #[serde(default)]
    pub relays: u64,
    #[serde(default)]
    pub relay_lifecycle_actions: u64,
    #[serde(default)]
    pub relay_impairments: u64,
}

impl ScenarioInventory {
    pub fn from_scenario(scenario: &Scenario) -> Self {
        let mut inventory = Self {
            hosts: scenario.topology.hosts.len() as u64,
            endpoints: scenario.endpoints.len() as u64,
            links: scenario.topology.links.len() as u64,
            nats: scenario.topology.nats.len() as u64,
            firewalls: scenario
                .topology
                .nats
                .iter()
                .filter(|nat| nat.firewall.is_some())
                .count() as u64,
            firewall_rules: scenario
                .topology
                .nats
                .iter()
                .filter_map(|nat| nat.firewall.as_ref())
                .map(|firewall| firewall.rules.len() as u64)
                .sum(),
            discovery_providers: scenario.topology.discovery.len() as u64,
            relays: scenario.topology.relays.len() as u64,
            relay_impairments: scenario.topology.relay_impairments.len() as u64,
            interfaces: scenario
                .topology
                .hosts
                .iter()
                .map(|host| host.interfaces.len() as u64)
                .sum(),
            ..Self::default()
        };
        for action in &scenario.actions {
            match action.action {
                ScenarioAction::NatChange { .. } => inventory.nat_change_actions += 1,
                ScenarioAction::PortMap { .. } => inventory.port_mapping_actions += 1,
                ScenarioAction::DiscoveryUpdate { .. } => inventory.discovery_records += 1,
                ScenarioAction::InterfaceChange { .. }
                | ScenarioAction::AddressChange { .. }
                | ScenarioAction::HostSleep { .. } => inventory.interface_change_actions += 1,
                ScenarioAction::RouteChange { .. } => inventory.routes += 1,
                ScenarioAction::RelayLifecycle { .. } => {
                    inventory.relay_lifecycle_actions += 1;
                }
                _ => {}
            }
        }
        inventory
    }
}
