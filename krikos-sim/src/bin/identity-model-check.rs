//! Hermetic bounded account-control model checker command.

fn main() {
    match krikos_sim::identity::check_account_control_model()
        .and_then(|report| report.to_canonical_json())
    {
        Ok(bytes) => print!("{}", String::from_utf8_lossy(&bytes)),
        Err(error) => {
            eprintln!("identity model check failed: {error}");
            std::process::exit(1);
        }
    }
}
