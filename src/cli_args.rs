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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum LogFormat {
    /// Output logs in a plain text format
    Text,
    /// Output logs in a JSONL format
    Jsonl,
}

#[derive(Debug, Clone, Parser)]
#[command(author, version, about)]
pub(crate) struct Args {
    #[arg(
        long = "sandbox",
        help = "Run in sandbox mode, blocking most destructive file operations, network access and spawning processes",
        conflicts_with = "filter",
        default_value_t = false
    )]
    pub sandbox: bool,

    #[arg(
        long = "allow-write",
        help = "List of directories to allow write access to in sandbox mode"
    )]
    pub allow_write: Vec<String>,

    #[arg(
        long = "allow-connect",
        help = "List of IP addresses (or masks) to allow connections to and from in sandbox mode"
    )]
    pub allow_connect: Vec<String>,

    #[arg(
        long = "allow-spawn",
        help = "List of programs to allow spawning in sandbox mode"
    )]
    pub allow_spawn: Vec<String>,

    #[arg(
        long = "filter",
        help = "Run in filter mode, allowing only syscalls specified in the filter file",
        conflicts_with = "sandbox",
        default_value_t = false
    )]
    pub filter: bool,

    #[arg(long = "filter-file", help = "JSON file containing filter definition")]
    pub filter_file: Option<String>,

    #[arg(short='l', long="log-format", help= "Format of the logs, either 'text' or 'jsonl'", value_enum, default_value_t = LogFormat::Text
    )]
    pub log_format: LogFormat,

    #[arg(
        short = 'o',
        long = "output",
        help = "Output file to write logs to, defaults to stdout"
    )]
    pub output: Option<String>,

    #[arg(
        short = 'v',
        long = "verbose",
        help = "Verbose output",
        default_value_t = false
    )]
    pub verbose: bool,

    #[arg(required=true, num_args=1.., help="Program to run in litterbox and its arguments. Must be separated from litterbox arguments with '--'"
    )]
    pub program: Vec<String>,
}
