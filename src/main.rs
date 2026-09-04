//! Entry point for the sxt-enterprise binary.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use clap::Parser;
use sxt_enterprise::cli::{self, Cli};

#[cfg_attr(coverage_nightly, coverage(off))]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match cli::run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
