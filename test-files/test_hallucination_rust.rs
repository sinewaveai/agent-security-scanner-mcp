// Test file for Rust/crates.io package hallucination detection
// Mix of real and fake packages

// Real crates (should be found in crates.io)
use serde;
use tokio;
use reqwest;
use clap;
use log;

// Fake/hallucinated crates (should be detected)
use super_ai_helper_magic;
use ultra_data_processor_fake;
use awesome_ml_utils_notreal;
use magic_http_client_xyz;
use flutter_rust_bridge_fake;

extern crate rand;  // Real
extern crate fake_rand_ultra;  // Fake
