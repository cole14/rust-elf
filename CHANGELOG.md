# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)

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