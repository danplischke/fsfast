//! Core traits and types shared by every fsfast backend.
//!
//! * [`FileSystem`], [`ReadHandle`], [`WriteHandle`]: the backend contract.
//! * [`FileInfo`]: metadata, carrying reference-implementation-compatible
//!   native fields for the Python `info()` dict.
//! * [`Error`]/[`ErrorKind`]: one error model, mapped to Python exceptions.
//! * [`OptionReader`]: strict `storage_options` parsing.
//! * [`ByteRange`], [`coalesce_ranges`]: range arithmetic.
//!
//! Backend crates expose a constructor with the signature
//! `fn from_options(opts: fsfast_core::Options) -> fsfast_core::Result<Self>`
//! so the Python bindings can build any backend from keyword arguments.

pub mod error;
pub mod fs;
pub mod info;
pub mod options;
pub mod path;
pub mod range;
pub mod value;

pub use async_trait::async_trait;
pub use bytes::Bytes;

pub use error::{Detail, Error, ErrorKind, Result};
pub use fs::{
    Capabilities, FileSystem, FindOptions, IoHints, ReadHandle, ReadOptions, WriteHandle,
    WriteMode, WriteOptions, copy_via_stream, find_bfs, read_ranges_coalesced,
};
pub use info::{FileInfo, FileType};
pub use options::{OptionReader, Options};
pub use range::{ByteRange, CoalescedRange, coalesce_ranges, split_range};
pub use value::Value;

/// Shared, type-erased filesystem handle as used by the bindings.
pub type DynFileSystem = std::sync::Arc<dyn FileSystem>;
