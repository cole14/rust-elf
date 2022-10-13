//! # `elf`
//!
//! The `elf` crate provides an interface for reading ELF object files.
//!
//! # Capabilities
//!
//! **Contains no unsafe code**: Many of the other rust ELF parsers out there
//! contain bits of unsafe code deep down or in dependencies to
//! reinterpret/transmute byte contents as structures in order to drive
//! zero-copy parsing. They're slick, and that also introduces unsafe code
//! blocks (albeit small ones). This crate strives to serve as an alternate
//! implementation with zero unsafe code blocks.
//!
//! **Endian-aware**: This crate properly handles translating between file and
//! host endianness when parsing the ELF contents.
//!
//! **Lazy parsing**: This crate strives for lazy evaluation and parsing when
//! possible. For example, the [SymbolTable](symbol::SymbolTable) simply
//! acts as an interpretation layer on top of a `&[u8]`. Parsing of
//! [Symbol](symbol::Symbol)s takes place only when symbols are requested.
//!
//! **Tiny compiled library size**: At the time of writing this, the release lib
//! was only ~640KB!
//!
//! # Future plans
//!
//! **Add no_std option**: Currently, the main impediment to a no_std option is the
//! use of allocating datastructures, such as the parsed section contents' Vec<u8>.
//!
//! **Lazily loading section contents**: Currently, all of the section data is read
//! from the input stream into allocated Vec<u8> when the stream is opened. This can
//! be unnecessarily expensive for use-cases that don't need to inspect all the section
//! contents.
//!
//! A potential future vision for both of these issues is to rework the parsing
//! code's reader trait implementations to provide two options:
//!
//! * A wrapper around a `&[u8]` which already contains the full ELF contents. This
//!   could be used for a no_std option where we want to simply parse out the ELF
//!   structures from the existing data without needing to heap-allocate buffers
//!   in which to store the reads.
//! * An allocating CachedReader type which wraps a stream which can allocate
//!   and remember Vec<u8> buffers in which to land the data from file reads.
//!
//! The former no_std option is useful when you need no_std, however it forces
//! the user to invoke the performance penalty of reading the entire file
//! contents up front.
//!
//! The latter option is useful for use-cases that only want to interpret parts
//! of an ELF object, where allocating buffers to store the reads is a much
//! smaller cost than reading in the whole large object contents.
//!

pub mod file;
pub mod gabi;
pub mod section;
pub mod segment;
pub mod string_table;
pub mod symbol;

mod parse;

pub use file::File;
