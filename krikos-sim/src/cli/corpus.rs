use super::*;

pub(super) fn execute_corpus(operation: &str, root: Option<&Path>) -> Result<(), CliError> {
    if operation != "test" {
        return Err(CliError::Usage(format!(
            "unsupported corpus operation {operation:?}; expected `test`"
        )));
    }
    let workspace = workspace_root()?;
    let root = absolutize(
        root.map(Path::to_path_buf)
            .unwrap_or_else(|| workspace.join("krikos-sim/corpus"))
            .as_path(),
    )?;
    let corpus = Corpus::load(&root)?;
    let reports = corpus.test(|entry| {
        let seed = parse_seed(&entry.metadata.seed).map_err(|error| error.to_string())?;
        let trace = TraceBuffer::default();
        let runner = ScenarioRunner::deterministic(
            entry.scenario.clone(),
            seed,
            SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_WALL_EPOCH_SECS),
            Arc::new(trace.clone()),
        )
        .map_err(|error| error.to_string())?;
        match simulation_runtime()
            .map_err(|error| error.to_string())?
            .block_on(runner.run_detailed())
        {
            Ok(_) => Ok(None),
            Err(failure) => {
                let suffix_bound = match &entry.metadata.expectation {
                    CorpusExpectation::ExpectedFailure { signature } => {
                        usize::from(signature.causal_event_count.max(1))
                    }
                    CorpusExpectation::Success => 64,
                };
                FailureSignature::from_runner_error(&failure.error, &trace.events(), suffix_bound)
                    .map(Some)
                    .map_err(|error| error.to_string())
            }
        }
    })?;
    println!(
        "status=corpus_ok entries={} root={}",
        reports.len(),
        root.display()
    );
    Ok(())
}
