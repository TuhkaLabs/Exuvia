//! Domain types, path handling and the safety policy shared by every Exuvia front end.
//!
//! This crate is deliberately free of platform code. Everything that touches the
//! operating system lives in `exuvia-platform`; everything that could delete user
//! data is gated by the [`safety::SafetyPolicy`] defined here.

pub mod error;
pub mod model;
pub mod path;
pub mod safety;

pub use error::{ExuviaError, Result};
pub use model::{
    default_selected, AppSource, Architecture, Confidence, InstalledApp, MatchReason,
    ResidueCategory, ResidueItem, ResidueKind, ScanResult, UninstallInfo, UninstallMode,
};
pub use path::{
    expand_env, home_dir, human_size, is_reparse_or_symlink, is_within, lexical_absolute,
    name_variants, normalize_name, normalize_path_key, publisher_variants, resolve_path,
};
pub use safety::{SafetyPolicy, SafetyTarget, SafetyViolation};
