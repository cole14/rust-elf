//! The `elf` crate provides an interface for reading ELF object files.
//!
//! # Capabilities
//!
//! ### no_std option:
//! This crate provides an elf parsing interface which does not allocate or use any std
//! features, so it can be used in `no_std` environments such as kernels and bootloaders.
//! The no_std variant merely disables the additional stream-oriented `std:: Read + Seek` interface.
//! All core parsing functionality is the same!
//!
//! ### Zero-alloc parser:
//! This crate implements parsing in a way that avoids heap allocations. ELF structures
//! are parsed and stored on the stack and provided by patterns such as lazily parsed iterators
//! that yield stack allocated rust types. The structures are copy-converted as
//! needed from the underlying file data into Rust's native struct representation.
//!
//! ### Endian-aware:
//! This crate handles translating between file and host endianness when
//! parsing the ELF contents and provides four endian parsing implementations
//! optimized to support the different common use-cases for an ELF parsing library.
//! Parsing is generic across the specifications and each trait impl represents a
//! specification that encapsulates an interface for parsing integers from some
//! set of allowed byte orderings.
//!
//! * [AnyEndian](endian::AnyEndian): Dynamically parsing either byte order at runtime based on the type of ELF object being parsed.
//! * [BigEndian](endian::BigEndian)/[LittleEndian](endian::LittleEndian): For tools that know they only want to parse a single given byte order known at compile time.
//! * [NativeEndian](type@endian::NativeEndian): For tools that know they want to parse the same byte order as the compilation target's byte order.
//!
//! When the limited specifications are used, errors are properly returned when asked to parse an ELF file
//! with an unexpected byte ordering.
//!
//! ### Lazy parsing:
//! This crate strives for lazy evaluation and parsing when possible. ELF structures are
//! generally provided through lazy-parsing interface types such as `ParsingIterator`s and `ParsingTable`s
//! which defer interpreting the raw ELF bytes for a given structure until they're needed.
//!
//! The `ParsingIterator`s are also nice in that you can easily zip/enumerate/filter/collect them
//! how you wish. Do you know that you want to do multiple passes over pairs from different tables? Just
//! zip/collect them into another type so you only parse each entry once!
//!
//! ### Some zero-copy interfaces
//! The StringTable, for instance, yields `&[u8]` and `&str` backed by the raw string table bytes.
//!
//! The [ElfBytes] parser type also does not make raw copies of any of the underlying file data to back
//! the parser lazy parser interfaces `ParsingIterator` and `ParsingTable`. They merely wrap byte slices
//! internally, though the parsing of a struct into the rust type does entail copying of the bytes in the
//! parsed rust-native format.
//!
//! Depending on the use-case, it can be more efficient to restructure the raw ELF into different layouts
//! for more efficient interpretation, and `ParsingIterator`s make that easy and rustily-intuitive.
//!
//! ### Stream-based lazy i/o interface
//! The [ElfStream] parser type takes a `std:: Read + Seek` (such as `std::fs::File`) where ranges of
//! file contents are read lazily on-demand based on what the user wants to parse.
//!
//! This, alongside the bytes-oriented interface, allow you to decide which tradeoffs
//! you want to make. If you're going to be working with the whole file contents,
//! then the byte slice approach is probably worthwhile to minimize i/o overhead by
//! streaming the whole file into memory at once. If you're only going to be
//! inspecting part of the file, then the [ElfStream] approach would help avoid the
//! overhead of reading a bunch of unused file data just to parse out a few things, (like
//! grabbing the `.gnu.note.build-id`)
//!
//! ### Fuzz Tested
//! Various parts of the library are fuzz tested for panics and crashes (see `fuzz/`).
//!
//! Memory safety is a core goal, as is providing a safe interface that errors on bad data
//! over crashing/panicking. Checked integer math is used where appropriate, and ParseErrors are
//! returned when bad/corrupted ELF structures are encountered.
//!
//! ### No unsafe code:
//! With memory safety a core goal, this crate contains zero unsafe code blocks, so you
//! can trust in rust's memory safety guarantees without also having to trust this
//! library developer as having truly been "right" in why some unsafe block is safe. 💃
//!
//! Many of the other rust ELF parsers out there contain bits of unsafe code deep
//! down or in dependencies to reinterpret/transmute byte contents as structures in
//! order to drive zero-copy parsing. They're slick, and there's typically
//! appropriate checking to validate the assumptions to make that unsafe code work,
//! but nevertheless it introduces unsafe code blocks at the core of the parsers. This
//! crate strives to serve as an alternate implementation with zero unsafe blocks.
//!
//! ### Tiny library with no dependencies and fast compilation times
//! ✨ Release-target compilation times on this developer's 2021 m1 macbook are sub-second. ✨

#![cfg_attr(not(feature = "std"), no_std)]

pub mod abi;
pub mod compression;
pub mod dynamic;
pub mod file;
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

pub mod endian;
mod parse;

mod elf_bytes;
pub use elf_bytes::CommonElfSections;
pub use elf_bytes::ElfBytes;

#[cfg(feature = "std")]
mod elf_stream;
#[cfg(feature = "std")]
pub use elf_stream::ElfStream;

pub use parse::ParseError;
