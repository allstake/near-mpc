use clap::Parser;
use mpc_test_node::cli::Cli;

fn main() -> anyhow::Result<()> {
    mpc_test_node::cli::run(Cli::parse())
}
