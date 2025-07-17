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
use std::collections::HashSet;

use serde::Deserialize;

use super::{
    flag_matcher::FlagMatcher,
    path_matcher::PathMatcher,
    syscall_filter::{FilterAction, FilterOutcome, SyscallFilter},
    utils::syscall_id_by_name,
};
use crate::{
    filters::{
        address_matcher::AddressMatcher, argument_matcher::{ArgValue, ArgumentMatcher}, context_matcher::ContextMatcher, str_matcher::StrMatchOp, syscall_filter::SyscallMatcher
    },
    loggers::syscall_logger::SyscallLogger,
    FilteringLogger,
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
pub(crate) struct AddressMatcherDto {
    pub addresses: Vec<String>,
    pub compare_op: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct PathMatcherDto {
    pub paths: Vec<String>,
    pub compare_op: String,
    pub match_created_by_process: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ArgValueDto {
    pub value: u64,
    pub op: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ArgMatcherDto {
    pub arg_index: u8,
    pub values: Vec<ArgValueDto>,
}

impl ArgMatcherDto {
    pub fn to_argument_matcher(&self) -> Result<ArgumentMatcher, ParsingError> {
        let matchers = self
            .values
            .iter()
            .map(|v| {
                match v.op.as_str() {
                    "eq" => Ok(ArgValue::Equal(v.value)),
                    "bitset" => Ok(ArgValue::BitSet(v.value)),
                    _ => Err(ParsingError {
                        message: format!("Invalid argument matcher operation: {}", v.op),
                    }),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ArgumentMatcher::new(self.arg_index, matchers))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SyscallMatcherDto {
    pub syscall_names: Vec<String>,
    pub args: Vec<ArgMatcherDto>,
    pub paths: Option<PathMatcherDto>,
    pub addresses: Option<AddressMatcherDto>,
    pub flags: Vec<String>,
}

impl SyscallMatcherDto {
    pub fn to_syscall_matcher(&self) -> Result<SyscallMatcher, ParsingError> {
        let syscall_ids = self
            .syscall_names
            .iter()
            .map(|f| syscall_id_by_name(f.as_str()))
            .filter(|f| f.is_some())
            .map(|f| f.unwrap() as i64)
            .collect::<HashSet<_>>();

        let arg_matcher_list = self
            .args
            .iter()
            .map(|arg_matcher_dto| arg_matcher_dto.to_argument_matcher())
            .collect::<Result<Vec<_>, _>>()?;
       

        let context_matcher = if let Some(path_matcher) = &self.paths {
            let path_match_op = parse_compare_op(path_matcher.compare_op.as_str())?;
            Some(ContextMatcher::PathMatcher(PathMatcher::new(
                path_matcher.paths.clone(),
                path_match_op,
                path_matcher.match_created_by_process,
            )))
        } else if let Some(address_matcher) = &self.addresses {
            let addr_match_op = parse_compare_op(address_matcher.compare_op.as_str())?;
            Some(ContextMatcher::AddressMatcher(AddressMatcher::new(
                address_matcher.addresses.clone(),
                addr_match_op,
                address_matcher.port,
            )))
        } else {
            None
        };

        let matcher = SyscallMatcher {
            syscall: syscall_ids,
            args: arg_matcher_list,
            context_matcher: context_matcher,
            flag_matcher: if !self.flags.is_empty() {
                Some(FlagMatcher::new(self.flags.clone()))
            } else {
                None
            },
        };
        Ok(matcher)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SyscallFilterDto {
    pub matcher: SyscallMatcherDto,
    pub outcome: FilterOutcomeDto,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SyscallFilterConfig {
    pub filters: Vec<SyscallFilterDto>,
    pub trigger: Option<SyscallMatcherDto>,
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
    let trigger = match config.trigger {
        Some(trigger) => {
            let matcher = trigger.to_syscall_matcher()?;
            Some(matcher)
        }
        None => None,
    };

    Ok(FilteringLogger::new(filters, trigger, logger))
}

pub(crate) fn parse_compare_op(compare_op: &str) -> Result<StrMatchOp, ParsingError> {
    match compare_op {
        "exact" => Ok(StrMatchOp::Exact),
        "prefix" => Ok(StrMatchOp::Prefix),
        "suffix" => Ok(StrMatchOp::Suffix),
        "contains" => Ok(StrMatchOp::Contains),
        _ => Err(ParsingError {
            message: format!("Invalid path match operation: {}", compare_op),
        }),
    }
}

impl SyscallFilterDto {
    pub fn from_json(json: String) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json.as_str())
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
        let outcome_action = self.parse_outcome_action()?;

        Ok(SyscallFilter {
            matcher: self.matcher.to_syscall_matcher()?,
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
