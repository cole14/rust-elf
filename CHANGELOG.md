# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)

## [0.7.4] - 2023-11-22

### Bug Fixes

- Fix note parsing for notes with n_namesz == (align * x + 1)

## [0.7.3] - 2023-10-09

### New Features

- Derive Debug on LittleEndian and BigEndian

### Misc Improvements

- Enable #![forbid(unsafe_code)]
- Enable #![deny(missing_debug_implementations)]
- Enable #![warn(rust_2018_idioms)]
- Fix doc comment on file::Class
- Fix README example so it compiles

## [0.7.2] - 2023-02-15

### New Features

- Implement core::error::Error for ParsingError accessible via a new non-default "nightly" cargo feature
- Add abi constants for note descriptor types (n_type)
- Add C-style struct definitions for various abi structs (Elf[32|64]_Ehdr etc). These aren't used by the parser, but are useful definitions for folks wanting to manually muck with elf bytes.

### Bug Fixes

- Fix an 'attempt to shift right with overflow' panic in the GnuHashTable if nshift is wider than the bloom filter word size

### Misc Improvements

- Add doc comments for EM_* abi constants
- Tweak formatting and update language for various doc comments

## [0.7.1] - 2023-01-08

### Bug Fixes

- Fix a divide by zero panic in GnuHashTable.find() for tables with nbloom = 0

## [0.7.0] - 2022-11-14

### New Features

- Add new ElfBytes type with better ergonomics for parsing from a &[u8]
- Add GnuHashTable which interprets the contents of a SHT_GNU_HASH section
- Add convenience method section_header_by_name to ElfBytes and ElfStream
- Add GnuBuildIdNote and parsing for NT_GNU_BUILD_ID note contents
- Add GnuAbiTagNote and parsing for NT_GNU_ABI_TAG note contents
- Add ElfBytes::symbol_version_table() to get the GNU extension symbol version table.
- Add ElfBytes::find_common_data() to efficiently discover common ELF structures
- Add a new endian-aware integer parsing trait impl
- Add ParsingTable.is_empty()
- Add abi constants for powerpc and powerpc64
- Add abi constants for RISC-V
- Add abi constants for x86_64
- Add abi constants for ARM32 and ARM64 (AARCH64)
- Add abi constant for GNU-extension ELF note name ELF_NOTE_GNU
- Add abi constant for PT_GNU_PROPERTY
- Add abi constants for SHN_ABS and SHN_COMMON
- Add elf::to_str::d_tag_to_str()
- Add elf::to_str::note_abi_tag_os_to_str()

### Changed Interfaces

- Rename elf::File -> elf::ElfStream and make it specific to the Read + Seek interface
- Rename gabi -> abi since it also includes extension constants
- Make ELF structures generic across the new endian-aware integer parsing trait EndianParse
- Refactor parsed Note type to be a typed enum
- Rename ElfStream::dynamic_section() -> dynamic() to match ElfBytes
- Change ElfStream::dynamic() to yield a DynamicTable just like in ElfBytes
- Standardize ElfBytes' interfaces for the .dynamic contents to return a DynamicTable
- Export the parsing utilities ParsingTable, ParsingIterator in the public interface
- Refactor section_headers_with_strtab to work with files that have shdrs but no shstrtab
- Remove redundant hash arg from SysVHashTable.find()
- Expose Class in the public interface alongside FileHeader
- Remove opinionated Display impl for file::Class
- Remove section_data_as_symbol_table() from public ElfBytes interface
- Change SymbolVersionTable::new() to take Options instead of Default-empty iterators
- Change ElfStream to parse out the ProgramHeaders into an allocated vec as part of ElfStream::open_stream()
- Change ElfStream to parse out the SectionHeaders into an allocated Vec as part of ElfStream::open_stream()

### Bug Fixes

- Properly parse program header table when ehdr.e_phnum > 0xffff
- Fix OOM in ElfStream parsing when parsing corrupted files
- Fix a divide by zero panic in SysVHashTable.find() for empty tables

### Misc Improvements

- Add more fuzz testing
- Add some simple parsing smoke tests for the various sample architecture objects
- Add sample object and testing with > 0xff00 section headers
- Add a lot more doc comments to each of the modules

## [0.6.1] - 2022-11-05

### New Features
- Expose Class and Endian in the public interface. These types are exposed in the FileHeader type and so they should also be accessible for users to inspect.

## [0.6.0] - 2022-11-01

### New Features

- Add fuzz targets for parts of our ELF parsing interface via cargo-fuzz
- Add SysVHashTable which interprets the contents of a SHT_HASH section
- Add StringTable::get_raw() to get an uninterpreted &[u8]
- Add ParsingTable.len() method to get the number of elements in the table
- Add some note n_type constants for GNU extension notes.
- Add default "to_str" feature to get &str for gabi constant names

### Changed Interfaces

- Change File::segments() to return a ParsingTable instead of just a ParsingIterator
- Change File's SectionHeader interfaces to provide a ParsingTable instead of just a ParsingIterator
- Remove deprecated File::section_data_for_header() in favor of File::section_data()
- Remove FileHeader wrapper types OSABI, Architecture, and ObjectFileType
- Remove ProgramHeader wrapper types ProgType and ProgFlag
- Remove Symbol wrapper types SymbolType SymbolBind SymbolVis
- Remove wrapper type SectionType
- Remove unhelpful SectionFlag wrapper type
- Remove Display impl for FileHeader, SectionHeader, ProgramHeader, Symbol
- Remove ParseError::UnsupportedElfVersion in favor of more general ParseError::UnsupportedVersion

### Bug Fixes

- Fix divide by zero panic when parsing a note with alignment of 0 (Error instead of panic)
- Use checked integer math all over the parsing code (Error instead of panic or overflow)
- Fix note parsing for 8-byte aligned .note.gnu.property sections (Successfully parse instead of Erroring)
- Add size validation when parsing tables with entsizes (Error instead of panic)

## [0.5.0] - 2022-10-30

### New Features

- Add File::symbol_version_table() interface to get the GNU extension symbol versioning table
- Add Symbol.is_undefined() helper to check if a symbol is defined in this object
- Add File::section_data() which opportunistically parses the CompressionHeader if present

### Bug Fixes

- Fix StringTable to return a ParseError on index out of bounds instead of panicking
- Fix File::section_data_as_rels to properly parse Rels (not Relas)

## [0.4.0] - 2022-10-24

### New Features

- Add .note section and segment parsing
- Add .dynamic section and segment parsing
- Add .rel and .rela section parsing
- Add File::section_headers_with_strtab to get both a header iter and strtab concurrently.

### Changed Interfaces

- The ReadBytesAt trait was changed to be implemented for an owned CachedReadBytes. This means that File::open_stream now expects to move-own the CachedReadBytes as opposed to taking a mutable reference.

## [0.3.1] - 2022-10-21

### New Features
- Add File::section_data_for_header() to get raw section data for a given section

### Bug fixes
- Fix section header table parsing when ehdr.e_shnum > 0xff00

## [0.3.0] - 2022-10-20

### New Features
- Add a `no_std` option by fully moving the parser over to lazy zero-alloc parsing patterns.

<!-- next-url -->
[0.7.4]: https://github.com/cole14/rust-elf/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/cole14/rust-elf/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/cole14/rust-elf/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/cole14/rust-elf/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/cole14/rust-elf/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/cole14/rust-elf/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/cole14/rust-elf/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/cole14/rust-elf/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cole14/rust-elf/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/cole14/rust-elf/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/cole14/rust-elf/compare/v0.2.0...v0.3.0
