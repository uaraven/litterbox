use crate::{
    FilteringLogger, TextLogger,
    cli_args::{self, Cli},
    filters::dto::{self},
    loggers::{jsonl_logger::JsonlLogger, syscall_logger::SyscallLogger},
};

pub struct Error(String);

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
                return Err(Error(
                    "Cannot specify a filter config with a profile".to_string(),
                ));
            }
            match dto::load_syscall_filter(&filter_config_path, Some(logger)) {
                Ok(filtering_logger) => {
                    return Ok(filtering_logger);
                }
                Err(e) => return Err(Error(e.message)),
            };
        }
        None => {
            return Err(Error(
                "No filter config specified and no profile selected".to_string(),
            ));
        }
    };
}
