//! A small database service that answers SQL queries with a proof of their correctness.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

extern crate alloc;

pub mod api;
pub mod cli;
pub mod column;
pub mod db;
pub mod prove;
pub mod setup;
pub mod verify;
