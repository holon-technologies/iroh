use krikos_local_first_app_tests::{ScenarioNetwork, run_two_node_scenario};

#[tokio::test(flavor = "multi_thread")]
async fn persisted_nodes_converge_directly() -> testresult::TestResult {
    run_two_node_scenario(ScenarioNetwork::Direct).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn persisted_nodes_converge_relay_only() -> testresult::TestResult {
    let (relay_map, _relay_url, _relay_guard) = krikos::test_utils::run_relay_server().await?;
    run_two_node_scenario(ScenarioNetwork::RelayOnly(relay_map)).await?;
    Ok(())
}
