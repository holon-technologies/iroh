//! Canonical scenarios ported from representative Patchbay behavior classes.

use serde::{Deserialize, Serialize};

use crate::{
    ActionSchedule, ActionSpec, FirewallAction, FirewallConnectionState, FirewallDirection,
    FirewallProtocol, FirewallRuleSpec, FirewallSpec, InterfaceSpec, IpFamily,
    NatFilteringBehavior, NatMappingBehavior, NatSpec, Scenario, ScenarioAction, ScenarioBuilder,
    ScenarioModelError, ScenarioOperation, SemanticDimension,
};

/// Representative realistic-backend behavior class with one stable canonical scenario.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalParityCase {
    Public,
    FullCone,
    PortRestricted,
    Symmetric,
    DoubleNat,
    Degradation,
    OutageRecovery,
    SwitchUplink,
}

/// Cross-backend scenario plus its source mapping and intentionally deferred semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalParityScenario {
    pub case: CanonicalParityCase,
    pub patchbay_tests: Vec<&'static str>,
    pub compared_dimensions: Vec<SemanticDimension>,
    pub deferred_dimensions: Vec<SemanticDimension>,
    pub scenario: Scenario,
}

/// Returns the complete Stage 4 parity catalog in stable case order.
pub fn canonical_patchbay_scenarios() -> Result<Vec<CanonicalParityScenario>, ScenarioModelError> {
    use CanonicalParityCase as Case;
    [
        Case::Public,
        Case::FullCone,
        Case::PortRestricted,
        Case::Symmetric,
        Case::DoubleNat,
        Case::Degradation,
        Case::OutageRecovery,
        Case::SwitchUplink,
    ]
    .into_iter()
    .map(build)
    .collect()
}

fn build(case: CanonicalParityCase) -> Result<CanonicalParityScenario, ScenarioModelError> {
    use CanonicalParityCase as Case;
    let id = match case {
        Case::Public => "parity/patchbay-public",
        Case::FullCone => "parity/patchbay-full-cone",
        Case::PortRestricted => "parity/patchbay-port-restricted",
        Case::Symmetric => "parity/patchbay-symmetric",
        Case::DoubleNat => "parity/patchbay-double-nat",
        Case::Degradation => "parity/patchbay-degradation-mild",
        Case::OutageRecovery => "parity/patchbay-outage-recovery",
        Case::SwitchUplink => "parity/patchbay-switch-uplink",
    };
    let mut builder =
        ScenarioBuilder::direct_ip_echo(id, IpFamily::Ipv4, ScenarioOperation::Stream)?;
    let scenario = builder.scenario_mut();
    scenario.metadata.tags.extend([
        "parity".to_owned(),
        "patchbay-port".to_owned(),
        format!("case-{case:?}").to_ascii_lowercase(),
    ]);

    let (patchbay_tests, compared_dimensions, deferred_dimensions) = match case {
        Case::Public => (
            vec!["patchbay::nat::nat_none_x_none"],
            common_connection_dimensions(),
            vec![SemanticDimension::Path],
        ),
        Case::FullCone => {
            add_client_nat(
                scenario,
                NatMappingBehavior::EndpointIndependent,
                NatFilteringBehavior::EndpointIndependent,
                false,
            );
            (
                vec!["patchbay::nat::nat_easiest_x_none"],
                common_connection_dimensions(),
                vec![SemanticDimension::Path],
            )
        }
        Case::PortRestricted => {
            add_client_nat(
                scenario,
                NatMappingBehavior::EndpointIndependent,
                NatFilteringBehavior::AddressAndPortDependent,
                true,
            );
            (
                vec!["patchbay::nat::nat_easy_x_none"],
                common_connection_dimensions(),
                vec![SemanticDimension::Path],
            )
        }
        Case::Symmetric => {
            add_client_nat(
                scenario,
                NatMappingBehavior::AddressAndPortDependent,
                NatFilteringBehavior::AddressAndPortDependent,
                false,
            );
            (
                vec![
                    "patchbay::nat::nat_hard_x_none",
                    "patchbay::nat::nat_hard_x_hard[ignored]",
                ],
                common_connection_dimensions(),
                vec![SemanticDimension::Path],
            )
        }
        Case::DoubleNat => {
            add_client_nat(
                scenario,
                NatMappingBehavior::EndpointIndependent,
                NatFilteringBehavior::AddressAndPortDependent,
                false,
            );
            scenario.topology.nats[0].upstream_nat = Some("carrier".to_owned());
            scenario.topology.nats.push(NatSpec {
                id: "carrier".to_owned(),
                inside_host: "client".to_owned(),
                upstream_nat: None,
                public_ip: "198.18.0.1".to_owned(),
                port_start: 41_000,
                port_end: 41_127,
                mapping_behavior: NatMappingBehavior::EndpointIndependent,
                filtering_behavior: NatFilteringBehavior::EndpointIndependent,
                mapping_ttl_nanos: 30_000_000_000,
                hairpin: false,
                max_mappings: 128,
                firewall: None,
            });
            (
                vec!["no direct Patchbay double-NAT fixture"],
                common_connection_dimensions(),
                vec![SemanticDimension::Nat, SemanticDimension::Path],
            )
        }
        Case::Degradation => {
            scenario.topology.links[0].latency_nanos = 10_000_000;
            scenario.topology.links[0].bits_per_second = 10_000_000;
            (
                vec![
                    "patchbay::degrade::degrade_client_0_mild",
                    "patchbay::degrade::degrade_server_0_mild",
                ],
                common_connection_dimensions(),
                vec![SemanticDimension::Path],
            )
        }
        Case::OutageRecovery => {
            insert_outage_actions(scenario);
            (
                vec![
                    "patchbay::link_outage_recovery_client",
                    "patchbay::link_outage_recovery_server",
                ],
                common_connection_dimensions(),
                vec![SemanticDimension::Path],
            )
        }
        Case::SwitchUplink => {
            insert_switch_uplink_actions(scenario);
            (
                vec!["patchbay::switch_uplink::*_v4_to_v4"],
                vec![
                    SemanticDimension::Terminal,
                    SemanticDimension::Authentication,
                    SemanticDimension::Delivery,
                    SemanticDimension::Mobility,
                ],
                vec![SemanticDimension::Path],
            )
        }
    };

    let scenario = builder.build()?;
    Ok(CanonicalParityScenario {
        case,
        patchbay_tests,
        compared_dimensions,
        deferred_dimensions,
        scenario,
    })
}

fn common_connection_dimensions() -> Vec<SemanticDimension> {
    vec![
        SemanticDimension::Terminal,
        SemanticDimension::Authentication,
        SemanticDimension::Delivery,
    ]
}

fn add_client_nat(
    scenario: &mut Scenario,
    mapping_behavior: NatMappingBehavior,
    filtering_behavior: NatFilteringBehavior,
    firewall: bool,
) {
    scenario.requirements.nat = true;
    let client = scenario
        .topology
        .hosts
        .iter_mut()
        .find(|host| host.id == "client")
        .expect("canonical base client");
    client.interfaces[0].addresses[0] = "10.0.0.2/0".to_owned();
    scenario
        .endpoints
        .iter_mut()
        .find(|endpoint| endpoint.id == "client")
        .expect("canonical base client endpoint")
        .bind = "10.0.0.2:31001".to_owned();
    scenario
        .topology
        .hosts
        .iter_mut()
        .find(|host| host.id == "server")
        .expect("canonical base server")
        .interfaces[0]
        .addresses[0] = "192.0.2.2/0".to_owned();
    scenario.topology.nats.push(NatSpec {
        id: "edge".to_owned(),
        inside_host: "client".to_owned(),
        upstream_nat: None,
        public_ip: "203.0.113.7".to_owned(),
        port_start: 40_000,
        port_end: 40_127,
        mapping_behavior,
        filtering_behavior,
        mapping_ttl_nanos: 30_000_000_000,
        hairpin: false,
        max_mappings: 128,
        firewall: firewall.then(standard_firewall),
    });
}

fn standard_firewall() -> FirewallSpec {
    FirewallSpec {
        id: "edge-policy".to_owned(),
        rules: vec![
            FirewallRuleSpec {
                id: "allow-established".to_owned(),
                protocol: FirewallProtocol::Udp,
                direction: Some(FirewallDirection::Inbound),
                source: None,
                destination: None,
                source_ports: None,
                destination_ports: None,
                connection_state: FirewallConnectionState::Established,
                action: FirewallAction::Allow,
            },
            FirewallRuleSpec {
                id: "allow-outbound".to_owned(),
                protocol: FirewallProtocol::Udp,
                direction: Some(FirewallDirection::Outbound),
                source: None,
                destination: None,
                source_ports: None,
                destination_ports: None,
                connection_state: FirewallConnectionState::Any,
                action: FirewallAction::Allow,
            },
        ],
        default_action: FirewallAction::Drop,
    }
}

fn insert_outage_actions(scenario: &mut Scenario) {
    scenario.actions[3].id = "06-stream-after-heal".to_owned();
    scenario.actions[4].id = "07-close".to_owned();
    scenario.actions[5].id = "08-stop-client".to_owned();
    scenario.actions[6].id = "09-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "04-outage".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "03-connect".to_owned(),
            },
            action: ScenarioAction::Partition {
                link: "lan".to_owned(),
                from: "client".to_owned(),
                to: "server".to_owned(),
            },
        },
        ActionSpec {
            id: "05-heal".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "04-outage".to_owned(),
            },
            action: ScenarioAction::Heal {
                link: "lan".to_owned(),
                from: "client".to_owned(),
                to: "server".to_owned(),
            },
        },
    ]);
}

fn insert_switch_uplink_actions(scenario: &mut Scenario) {
    scenario.requirements.mobility = true;
    let client = scenario
        .topology
        .hosts
        .iter_mut()
        .find(|host| host.id == "client")
        .expect("canonical base client");
    client.interfaces[0].addresses[0] = "192.0.2.1/24".to_owned();
    client.interfaces.push(InterfaceSpec {
        id: "wifi0".to_owned(),
        link: "lan".to_owned(),
        addresses: vec!["192.0.3.1/0".to_owned()],
    });
    scenario
        .topology
        .hosts
        .iter_mut()
        .find(|host| host.id == "server")
        .expect("canonical base server")
        .interfaces[0]
        .addresses[0] = "192.0.2.2/0".to_owned();
    scenario
        .endpoints
        .iter_mut()
        .find(|endpoint| endpoint.id == "client")
        .expect("canonical base client endpoint")
        .bind = "0.0.0.0:31001".to_owned();

    scenario.actions[4].id = "08-close".to_owned();
    scenario.actions[5].id = "09-stop-client".to_owned();
    scenario.actions[6].id = "10-stop-server".to_owned();
    scenario.actions.extend([
        ActionSpec {
            id: "05-old-uplink-down".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "04-stream".to_owned(),
            },
            action: ScenarioAction::InterfaceChange {
                host: "client".to_owned(),
                interface: "eth0".to_owned(),
                up: false,
            },
        },
        ActionSpec {
            id: "06-new-route".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "05-old-uplink-down".to_owned(),
            },
            action: ScenarioAction::RouteChange {
                host: "client".to_owned(),
                route: "wifi-uplink".to_owned(),
                destination: "192.0.2.2/32".to_owned(),
                interface: "wifi0".to_owned(),
                next_hop: Some("server".to_owned()),
                active: true,
            },
        },
        ActionSpec {
            id: "07-stream-after-switch".to_owned(),
            schedule: ActionSchedule::AfterAction {
                action: "06-new-route".to_owned(),
            },
            action: ScenarioAction::StreamRoundTrip {
                connection: "c1".to_owned(),
                payload: crate::PayloadSpec {
                    bytes: 32,
                    fill: 0x5a,
                },
            },
        },
    ]);
}
