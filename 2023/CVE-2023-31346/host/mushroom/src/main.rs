use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use snp_types::guest_policy::GuestPolicy;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mushroom = Mushroom::parse();
    match mushroom.subcommand {
        MushroomSubcommand::Run(args) => run(args),
        MushroomSubcommand::RunWithId(args) => run_with_id(args),
    }
}

#[derive(Parser)]
#[command(version)]
struct Mushroom {
    #[command(subcommand)]
    subcommand: MushroomSubcommand,
}

#[derive(Subcommand)]
enum MushroomSubcommand {
    /// Run some code.
    Run(RunCommand),
    /// Run some code and also supply and id during launch.
    RunWithId(RunWithIdCommand),
}

#[derive(Args)]
struct ConfigArgs {
    /// Path to the kernel.
    #[arg(long, value_name = "PATH", env = "KERNEL")]
    kernel: PathBuf,
}

#[derive(Args)]
struct RunCommand {
    #[command(flatten)]
    config: ConfigArgs,
}

fn run(run: RunCommand) -> Result<()> {
    let kernel = std::fs::read(run.config.kernel).context("failed to read kernel file")?;

    mushroom::main(
        &kernel,
        GuestPolicy::new(1, 51)
            .with_allow_smt(true)
            .with_allow_migration_agent_association(true)
            .with_allow_debugging(false)
            .with_single_socket_only(true),
        None,
    )?;

    Ok(())
}

#[derive(Args)]
struct RunWithIdCommand {
    #[command(flatten)]
    config: ConfigArgs,
    value: u8,
}

fn run_with_id(run: RunWithIdCommand) -> Result<()> {
    let kernel = std::fs::read(run.config.kernel).context("failed to read kernel file")?;

    mushroom::main(
        &kernel,
        GuestPolicy::new(1, 51)
            .with_allow_smt(true)
            .with_allow_migration_agent_association(true)
            .with_allow_debugging(false)
            .with_single_socket_only(true),
        Some(run.value),
    )?;

    Ok(())
}
