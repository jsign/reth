//! execution-spec-test execution witness generator
use std::io::{self, Read};

use ef_tests::{cases::blockchain_test::BlockchainTestCase, models::BlockchainTest};

fn main() {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap();

    let case: BlockchainTest = serde_json::from_str(&buffer).unwrap();
    let witnesses = BlockchainTestCase::run_single_case("", &case)
        .unwrap()
        .into_iter()
        .map(|bw| bw.1)
        .collect::<Vec<_>>();

    println!("{}", serde_json::to_string(&witnesses).unwrap());
}
