//! # `elf`
//!
//! The `elf` crate provides an interface for reading ELF object files.
//!
//! # Capabilities
//!
//! ### Zero-alloc parser:
//! This crate implements parsing in a way that avoids all heap allocations. ELF structures
//! are parsed and stored on the stack and provided by patterns such as lazily parsed iterators
//! that yield stack allocated structures. The structures are copy-converted as
//! needed from the underlying file data into Rust's native struct representation.
//!
//! ### Endian-aware:
//! This crate properly handles translating between file and host endianness
//! when parsing the ELF contents.
//!
//! ### Lazy parsing:
//! This crate strives for lazy evaluation and parsing when possible.
//! [File::open_stream()][File::open_stream] reads, parses and validates the ELF
//! File Header, then stops there. All other i/o and parsing is deferred to
//! being performed on-demand by other methods on [File]. For example,
//! [File::symbol_table()](File::symbol_table) reads the data for the symbol
//! table and associated string table then returns them with types like
//! [SymbolTable](symbol::SymbolTable) and
//! [StringTable](string_table::StringTable) which simply act as an
//! interpretation layer on top of `&[u8]`s, where parsing of
//! [Symbol](symbol::Symbol)s and strings take place only when they are
//! requested.
//!
//! ### Lazy i/o:
//! This crate provides two ways of parsing ELF files:
//! * From a `&[u8]` into which the user has already read the full contents of the file
//! * From a Read + Seek (such as a `std::file::File`) where file contents are read
//!   lazily on-demand based on what the user wants to inspect.
//!
//! These allow you to decide what tradeoff you want to make. If you're going to be working
//! with the whole file at once, then the byte slice approach is probably worthwhile to minimize
//! i/o overhead by streaming the whole file into memory at once. If you're only going to
//! be inspecting part of the file, then the Read + Seek approach would help avoid the
//! overhead of reading a bunch of unused file data just to parse out a few things.
//!
//! ### No unsafe code:
//! Many of the other rust ELF parsers out there contain bits of unsafe code
//! deep down or in dependencies to reinterpret/transmute byte contents as
//! structures in order to drive zero-copy parsing. They're slick, and there's
//! typically appropriate checking to validate the assumptions to make that
//! unsafe code work, but nevertheless it introduces unsafe code blocks (albeit
//! small ones). This crate strives to serve as an alternate implementation with
//! zero unsafe code blocks.
//!
//! ### no_std option:
//! Only disables the std:: Read + Seek interface and limits the library to the
//! `&[u8]` parsing impl. All other ELF parsing functionality is still available!
//!

#![cfg_attr(not(feature = "std"), no_std)]

pub mod compression;
pub mod dynamic;
pub mod file;
pub mod gabi;
pub mod gnu_symver;
pub mod hash;
pub mod note;
pub mod relocation;
pub mod section;
pub mod segment;
pub mod string_table;
pub mod symbol;

#[cfg(feature = "to_str")]
pub mod to_str;

mod parse;

pub use file::File;
#[cfg(feature = "std")]
pub use parse::CachedReadBytes;
pub use parse::ParseError;
