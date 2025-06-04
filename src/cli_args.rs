use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Preset {
    /// Allow all syscalls and log them
    Permissive,
    /// Block potentially dangerouse syscalls
    Restrictive,
    /// Allow some syscalls
    Default,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Use syscall filter preset
    #[arg(
        name = "preset",
        short = 'p',
        long = "preset",
        default_value = "default",
        value_enum
    )]
    pub preset: Preset,

    pub prog: Vec<String>,
}
