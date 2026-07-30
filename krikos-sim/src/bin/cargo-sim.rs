#![forbid(unsafe_code)]

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    match krikos_sim::cli::run(args) {
        Ok(()) => {}
        Err(krikos_sim::cli::CliError::Usage(message)) => {
            eprint!("{message}");
            std::process::exit(64);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(error.exit_code().into());
        }
    }
}
