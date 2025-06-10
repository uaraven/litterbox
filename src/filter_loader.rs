use std::fmt::Display;

use crate::{
    FilteringLogger, TextLogger,
    cli_args::{self, Cli},
    filters::dto::{self},
    loggers::{jsonl_logger::JsonlLogger, syscall_logger::SyscallLogger},
    preconfigured::{default, permissive, restrictive},
};

pub struct Error {
    pub msg: String,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

pub fn filters_from_args(cli: Cli) -> Result<FilteringLogger, Error> {
    let logger: Box<dyn SyscallLogger> = match cli.log_format {
        Some(cli_args::LogFormat::Text) => Box::new(TextLogger::default()),
        Some(cli_args::LogFormat::Jsonl) => Box::new(JsonlLogger::default()),
        _ => Box::new(TextLogger::default()),
    };
    match cli.filter_config {
        Some(filter_config_path) => {
            if cli.profile != cli_args::Profile::Default
                && cli.profile != cli_args::Profile::Permissive
            {
                return Err(Error {
                    msg: "Cannot specify a filter config with a profile".to_string(),
                });
            }
            match dto::load_syscall_filter(&filter_config_path, Some(logger)) {
                Ok(filtering_logger) => {
                    return Ok(filtering_logger);
                }
                Err(e) => return Err(Error { msg: e.message }),
            };
        }
        None => {
            if cli.profile == cli_args::Profile::Restrictive {
                return Ok(restrictive::restrictive_filters(logger));
            } else if cli.profile == cli_args::Profile::Permissive {
                return Ok(permissive::permissive_filters(logger));
            } else if cli.profile == cli_args::Profile::Default {
                return Ok(default::default_filters(logger));
            }
            return Err(Error {
                msg: "No filter config specified and no profile selected".to_string(),
            });
        }
    };
}
