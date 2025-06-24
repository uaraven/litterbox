/*
 * Litterbox - A sandboxing and tracing tool
 *
 * Copyright (c) 2025  Oles Voronin
 *
 * This program is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this
 * program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

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
