//! Command-line interface for running tests.
use std::path::PathBuf;

use clap::Parser;
use ef_tests::{
    cases::blockchain_test::{BlockchainTestCase, BlockchainTests},
    Case, Suite,
};

/// Command-line arguments for the test runner.
#[derive(Debug, Parser)]
pub struct TestRunnerCommand {
    /// Path to the test suite directory or a single JSON test file.
    ///
    /// If a directory is provided, it should contain a `blockchain_tests` subdirectory.
    /// If a JSON file is provided, it will be run directly as a single test case.
    path: PathBuf,
}

fn main() {
    let cmd = TestRunnerCommand::parse();

    if cmd.path.is_file() && cmd.path.extension().is_some_and(|ext| ext == "json") {
        // Run a single JSON test file directly
        run_single_file(&cmd.path);
    } else {
        // Run the full test suite
        BlockchainTests::new(cmd.path.join("blockchain_tests")).run();
    }
}

/// Run a single JSON test file.
fn run_single_file(path: &PathBuf) {
    println!("Running single test file: {}", path.display());

    let case = BlockchainTestCase::load(path).expect("test case should load");
    match case.run() {
        Ok(()) => println!("Test passed!"),
        Err(e) => {
            eprintln!("Test failed: {e:?}");
            std::process::exit(1);
        }
    }
}
