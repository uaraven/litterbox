use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Profile {
    /// Allow all syscalls and log them
    Permissive,
    /// Block potentially dangerous syscalls
    Restrictive,
    /// Allow some syscalls
    Default,
    /// Custom syscall filter profile
    Custom,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LogFormat {
    /// Output logs in a plain text format
    Text,
    /// Output logs in a JSONL format
    Jsonl,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Use syscall filter profile
    #[arg(
        name = "profile",
        short = 'p',
        long = "profile",
        default_value = "default",
        required = false,
        value_enum
    )]
    pub profile: Profile,

    #[arg(
        required = false,
        long = "filter",
        short = 'f',
        help = "Path to the filter configuration file."
    )]
    pub filter_config: Option<String>,

    #[arg(
        long = "output",
        short = 'o',
        required = false,
        help = "Output file for syscall logs. If not specified, logs will be printed to stdout."
    )]
    pub output: Option<String>,

    #[arg(
        long = "log-format",
        required = false,
        default_value = "text",
        help = "Format of the logs. Defaults to text format."
    )]
    pub log_format: Option<LogFormat>,

    #[arg(required = true, num_args = 1..)]
    pub prog: Vec<String>,
}
