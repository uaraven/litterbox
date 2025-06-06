use std::collections::{HashMap, HashSet};

use serde::{Deserialize, de::Error};

use crate::{
    FilteringLogger, filter_listener::SyscallFilterTrigger, loggers::syscall_logger::SyscallLogger,
};

use super::{
    flag_matcher::FlagMatcher,
    path_matcher::{PathMatchOp, PathMatcher},
    syscall_filter::{FilterAction, FilterOutcome, SyscallFilter},
    utils::syscall_id_by_name,
};

#[derive(Debug)]
pub(crate) struct ParsingError {
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FilterOutcomeDto {
    pub tag: String,
    pub log: bool,
    pub action: String,
    pub block_syscall_error: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SyscallFilterDto {
    pub syscall_names: Vec<String>,
    pub args: HashMap<u8, Vec<u64>>,
    pub paths: Vec<String>,
    pub path_op: String,
    pub flags: Vec<String>,
    pub match_path_created_by_process: bool,
    pub outcome: FilterOutcomeDto,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SyscallFilterTriggerDto {
    pub syscall_id: i64,
    pub file_path: Option<String>,
}

impl SyscallFilterTriggerDto {
    pub fn to_trigger(&self) -> SyscallFilterTrigger {
        SyscallFilterTrigger {
            syscall_id: self.syscall_id,
            file_path: self.file_path.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SyscallFilterConfig {
    pub filters: Vec<SyscallFilterDto>,
    pub trigger: Option<SyscallFilterTriggerDto>,
}

/// Load the syscall filter configuration from a JSON file and validates the filters.
///
fn load_config_from_file(path: &str) -> Result<SyscallFilterConfig, ParsingError> {
    let config: Result<SyscallFilterConfig, ParsingError> = match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).map_err(|e| ParsingError {
            message: format!("Failed to parse JSON: {}", e),
        }),
        Err(e) => Err(ParsingError {
            message: format!("Failed to read file {}: {}", path, e),
        }),
    };
    // validate the filters
    if let Ok(conf) = &config {
        for filter in &conf.filters {
            if let Err(e) = filter.to_syscall_filter() {
                return Err(ParsingError {
                    message: format!("Failed to parse filter: {}", e.message),
                });
            }
        }
    }
    config
}

pub(crate) fn load_syscall_filter(
    path: &str,
    logger: Option<Box<dyn SyscallLogger>>,
) -> Result<FilteringLogger, ParsingError> {
    let config = load_config_from_file(path)?;
    let filters = config
        .filters
        .iter()
        .filter_map(|f| f.to_syscall_filter().ok())
        .collect::<Vec<_>>();
    Ok(FilteringLogger::new(
        filters,
        config.trigger.map(|t| t.to_trigger()),
        logger,
    ))
}

impl SyscallFilterDto {
    pub fn from_json(json: String) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json.as_str())
    }

    pub fn parse_path_op(&self) -> Result<PathMatchOp, ParsingError> {
        match self.path_op.as_str() {
            "exact" => Ok(PathMatchOp::Exact),
            "prefix" => Ok(PathMatchOp::Prefix),
            "suffix" => Ok(PathMatchOp::Suffix),
            "contains" => Ok(PathMatchOp::Contains),
            _ => Err(ParsingError {
                message: format!("Invalid path match operation: {}", self.path_op),
            }),
        }
    }

    pub fn parse_outcome_action(&self) -> Result<FilterAction, ParsingError> {
        match self.outcome.action.as_str() {
            "allow" => Ok(FilterAction::Allow),
            "block" => {
                if let Some(error_code) = self.outcome.block_syscall_error {
                    Ok(FilterAction::Block(error_code))
                } else {
                    Err(ParsingError {
                        message: "Block action requires a syscall error code".to_string(),
                    })
                }
            }
            _ => Err(ParsingError {
                message: format!("Invalid outcome action: {}", self.outcome.action),
            }),
        }
    }

    pub fn to_syscall_filter(&self) -> Result<SyscallFilter, ParsingError> {
        let syscall_ids = self
            .syscall_names
            .iter()
            .map(|f| syscall_id_by_name(f.as_str()))
            .filter(|f| f.is_some())
            .map(|f| f.unwrap() as i64)
            .collect::<HashSet<_>>();

        let arg_map = self
            .args
            .iter()
            .map(|(k, v)| (*k, v.iter().cloned().collect()))
            .collect();

        let path_match_op = self.parse_path_op()?;
        let outcome_action = self.parse_outcome_action()?;

        Ok(SyscallFilter {
            syscall: syscall_ids,
            args: arg_map,
            path_matcher: if !self.paths.is_empty() {
                Some(PathMatcher::new(
                    self.paths.clone(),
                    path_match_op,
                    self.match_path_created_by_process,
                ))
            } else {
                None
            },
            flag_matcher: if !self.flags.is_empty() {
                Some(FlagMatcher::new(self.flags.clone()))
            } else {
                None
            },
            outcome: FilterOutcome {
                action: outcome_action,
                tag: if self.outcome.tag.is_empty() {
                    None
                } else {
                    Some(self.outcome.tag.clone())
                },
                log: self.outcome.log,
            },
        })
    }
}
