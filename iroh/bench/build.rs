#![forbid(unsafe_code)]

use std::env;

fn main() {
    let profile = env::var("PROFILE").expect("Cargo always sets PROFILE for build scripts");
    let optimization =
        env::var("OPT_LEVEL").expect("Cargo always sets OPT_LEVEL for build scripts");
    println!("cargo:rustc-env=IROH_BENCH_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=IROH_BENCH_OPT_LEVEL={optimization}");
}
