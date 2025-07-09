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
use std::fmt::Display;

use crate::{
    FilteringLogger, TextLogger,
    cli_args::{self, Args},
    filters::dto::load_syscall_filter,
    loggers::{jsonl_logger::JsonlLogger, syscall_logger::SyscallLogger},
    sandbox::sandbox_filter::create_sandbox_filters,
};

pub struct FilterError {
    pub message: String,
}

impl Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

pub fn filters_from_args(cli: Args) -> Result<FilteringLogger, FilterError> {
    let logger: Box<dyn SyscallLogger> = match cli.log_format {
        cli_args::LogFormat::Text => Box::new(TextLogger::default()),
        cli_args::LogFormat::Jsonl => Box::new(JsonlLogger::default()),
    };
    if cli.sandbox {
        create_sandbox_filters(
            logger,
            cli.allow_write.iter().map(String::as_str).collect(),
            cli.allow_connect.iter().map(String::as_str).collect(),
            cli.allow_spawn.iter().map(String::as_str).collect(),
        )
        .map_err(|e| FilterError { message: e.message })
    } else if cli.filter {
        if let Some(file_path) = cli.filter_file {
            load_syscall_filter(&file_path, Some(logger))
                .map_err(|e| FilterError { message: e.message })
        } else {
            Err(FilterError {
                message: "Filter file must be specified when --filter is used".to_string(),
            })
        }
    } else {
        Err(FilterError {
            message: "Cannot specify both --sandbox and --filter".to_string(),
        })
    }
}
