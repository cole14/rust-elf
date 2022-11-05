//! Provides an interface for parsing ELF files from `&[u8]`
//!
//! Example usage of the bytes-based interface:
//!
//! ```
//! use elf::abi::PT_LOAD;
//! use elf::elf_bytes::from_bytes;
//! use elf::endian::AnyEndian;
//! use elf::segment::ProgramHeader;
//! use elf::to_str::p_type_to_string;
//!
//! let path = std::path::PathBuf::from("tests/samples/test1");
//! let file_data = std::fs::read(path).unwrap();
//!
//! let slice = file_data.as_slice();
//! let file = from_bytes::<AnyEndian>(slice).unwrap();
//!
//! // Get a lazy-parsing type for the segment table
//! if let Some(phdr_table) = file.segments() {
//!     // This table lets us parse specific indexes on-demand without parsing the whole table
//!     let phdr3 = phdr_table.get(3).unwrap();
//!     println!("Program Header 3 is of type: {}", p_type_to_string(phdr3.p_type));
//!
//!     // It can also yield an iterator on which we can do normal iterator things, like filtering
//!     // for all the segments of a specific type. Parsing is done on each iter.next() call, so
//!     // if you end iteration early, it won't parse the rest of the table.
//!     let load_phdrs: Vec<ProgramHeader> = phdr_table
//!         .iter()
//!         .filter(|phdr|{phdr.p_type == PT_LOAD})
//!         .collect();
//!     println!("First load segment is at: {}", load_phdrs[0].p_vaddr);
//! }
//! ```
use core::ops::Range;

use crate::abi;
use crate::compression::CompressionHeader;
use crate::dynamic::{DynIterator, DynamicTable};
use crate::endian::EndianParse;
use crate::file::FileHeader;
use crate::hash::SysVHashTable;
use crate::note::NoteIterator;
use crate::parse::{Class, ParseAt, ParseError};
use crate::relocation::{RelIterator, RelaIterator};
use crate::section::{SectionHeader, SectionHeaderTable};
use crate::segment::{ProgramHeader, SegmentTable};
use crate::string_table::StringTable;
use crate::symbol::{Symbol, SymbolTable};

//  _____ _     _____ ____        _
// | ____| |   |  ___| __ ) _   _| |_ ___  ___
// |  _| | |   | |_  |  _ \| | | | __/ _ \/ __|
// | |___| |___|  _| | |_) | |_| | ||  __/\__ \
// |_____|_____|_|   |____/ \__, |\__\___||___/
//                          |___/
//

/// Parse the ELF [FileHeader] and construct a lazy-parsing [ElfBytes] from the given bytes.
///
/// This provides an interface for zero-alloc lazy parsing of ELF structures from a byte slice containing
/// the complete ELF file contents. The various ELF structures are parsed on-demand into the native Rust
/// representation.
///
/// The only ELF structure that is fully parsed as part of this method is the FileHeader.
///
/// A lazy-parsing SectionHeaderTable is constructed, but the entries are not parsed. Constructing this table
/// simply reads the FileHeader's shoff/shnum fields and creates a subslice to bound the data for the shdrs but
/// does not actually parse the contents.
pub fn from_bytes<'data, E: EndianParse>(
    data: &'data [u8],
) -> Result<ElfBytes<'data, E>, ParseError> {
    ElfBytes::minimal_parse(data)
}

/// Find the location (if any) of the section headers in the given data buffer and take a
/// subslice of their data and wrap it in a lazy-parsing SectionHeaderTable.
/// If shnum > SHN_LORESERVE (0xff00), then this will additionally parse out shdr[0] to calculate
/// the full table size, but all other parsing of SectionHeaders is deferred.
fn find_shdrs<'data, E: EndianParse>(
    endian: E,
    ehdr: &FileHeader,
    data: &'data [u8],
) -> Result<Option<SectionHeaderTable<'data, E>>, ParseError> {
    // It's Ok to have no section headers
    if ehdr.e_shoff == 0 {
        return Ok(None);
    }

    // If the number of sections is greater than or equal to SHN_LORESERVE (0xff00),
    // e_shnum is zero and the actual number of section header table entries
    // is contained in the sh_size field of the section header at index 0.
    let shoff: usize = ehdr.e_shoff.try_into()?;
    let mut shnum = ehdr.e_shnum as usize;
    if shnum == 0 {
        let mut offset = shoff;
        let shdr0 = SectionHeader::parse_at(endian, ehdr.class, &mut offset, data)?;
        shnum = shdr0.sh_size.try_into()?;
    }

    // Validate shentsize before trying to read the table so that we can error early for corrupted files
    let entsize = SectionHeader::validate_entsize(ehdr.class, ehdr.e_shentsize as usize)?;

    let size = entsize
        .checked_mul(shnum)
        .ok_or(ParseError::IntegerOverflow)?;
    let end = shoff.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
    let buf = data.get_bytes(shoff..end)?;
    Ok(Some(SectionHeaderTable::new(endian, ehdr.class, buf)))
}

/// Find the location (if any) of the program headers in the given data buffer and take a
/// subslice of their data and wrap it in a lazy-parsing SegmentTable.
fn find_phdrs<'data, E: EndianParse>(
    endian: E,
    ehdr: &FileHeader,
    data: &'data [u8],
) -> Result<Option<SegmentTable<'data, E>>, ParseError> {
    match ehdr.get_phdrs_data_range()? {
        Some((start, end)) => {
            let buf = data.get_bytes(start..end)?;
            Ok(Some(SegmentTable::new(endian, ehdr.class, buf)))
        }
        None => Ok(None),
    }
}

/// This struct collects the common sections found in ELF objects
#[derive(Default)]
pub struct CommonElfSections<'data, E: EndianParse> {
    // .symtab section
    pub symtab: Option<SymbolTable<'data, E>>,
    // strtab for .symtab
    pub symtab_strs: Option<StringTable<'data>>,

    // .dynsym section
    pub dynsyms: Option<SymbolTable<'data, E>>,
    // strtab for .dynsym
    pub dynsyms_strs: Option<StringTable<'data>>,

    // .dynamic section or PT_DYNAMIC segment (both point to the same table)
    pub dynamic: Option<DynamicTable<'data, E>>,

    // .hash section
    pub sysv_hash: Option<SysVHashTable<'data, E>>,
}

/// This type encapsulates the bytes-oriented interface for parsing ELF objects from `&[u8]`.
///
/// This parser is no_std and zero-alloc, returning lazy-parsing interfaces wrapped around
/// subslices of the provided ELF bytes `&[u8]`.
///
/// Example usage:
/// ```
/// use elf::endian::AnyEndian;
/// use elf::elf_bytes::ElfBytes;
///
/// let path = std::path::PathBuf::from("tests/samples/hello.so");
/// let file_data = std::fs::read(path).unwrap();
///
/// let slice = file_data.as_slice();
/// let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
///
/// // Get all the common ELF sections (if any). We have a lot of ELF work to do!
/// let common_sections = file.find_common_sections().unwrap();
/// // ... do some stuff with the symtab, dynsyms etc
/// ```
pub struct ElfBytes<'data, E: EndianParse> {
    ehdr: FileHeader,
    data: &'data [u8],
    endian: E,
    shdrs: Option<SectionHeaderTable<'data, E>>,
    phdrs: Option<SegmentTable<'data, E>>,
}

impl<'data, E: EndianParse> ElfBytes<'data, E> {
    /// Do the minimal parsing work to get an [ElfBytes] handle from a byte slice containing an ELF object.
    ///
    /// This parses the ELF [FileHeader], and locates (but does not parse) the
    /// Section Header Table and Segment Table.
    ///
    // N.B. I thought about calling this "sparse_parse", but it felt too silly for a serious lib like this
    pub fn minimal_parse(data: &'data [u8]) -> Result<Self, ParseError> {
        let ident_buf = data.get_bytes(0..abi::EI_NIDENT)?;
        let ident = FileHeader::parse_ident(ident_buf)?;

        let tail_start = abi::EI_NIDENT;
        let tail_end = match ident.1 {
            Class::ELF32 => tail_start + crate::file::ELF32_EHDR_TAILSIZE,
            Class::ELF64 => tail_start + crate::file::ELF64_EHDR_TAILSIZE,
        };
        let tail_buf = data.get_bytes(tail_start..tail_end)?;

        let ehdr = FileHeader::parse_tail(ident, tail_buf)?;
        let endian = E::from_ei_data(ehdr.ei_data)?;

        let shdrs = find_shdrs(endian, &ehdr, data)?;
        let phdrs = find_phdrs(endian, &ehdr, data)?;
        Ok(ElfBytes {
            ehdr,
            data,
            endian,
            shdrs,
            phdrs,
        })
    }

    /// Get this Elf object's zero-alloc lazy-parsing [SegmentTable] (if any).
    ///
    /// This table parses [ProgramHeader]s on demand and does not make any internal heap allocations
    /// when parsing.
    pub fn segments(&self) -> Option<SegmentTable<'data, E>> {
        self.phdrs
    }

    /// Get this Elf object's zero-alloc lazy-parsing [SectionHeaderTable] (if any).
    ///
    /// This table parses [SectionHeader]s on demand and does not make any internal heap allocations
    /// when parsing.
    pub fn section_headers(&self) -> Option<SectionHeaderTable<'data, E>> {
        self.shdrs
    }

    /// Get this ELF object's [SectionHeaderTable] alongside its corresponding [StringTable].
    ///
    /// This is useful if you want to know the string name of sections.
    ///
    /// Example usage:
    /// ```
    /// use elf::endian::AnyEndian;
    /// use elf::elf_bytes::ElfBytes;
    /// use elf::section::SectionHeader;
    ///
    /// let path = std::path::PathBuf::from("tests/samples/hello.so");
    /// let file_data = std::fs::read(path).unwrap();
    ///
    /// let slice = file_data.as_slice();
    /// let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
    ///
    /// // Get the section header table alongside its string table
    /// let (shdrs, strtab) = file
    ///     .section_headers_with_strtab()
    ///     .expect("shdrs offsets should be valid")
    ///     .expect("File should have shdrs");
    ///
    /// // Parse the shdrs and collect them alongside their names
    /// let with_names: Vec<(&str, SectionHeader)> = shdrs
    ///     .iter()
    ///     .map(|shdr| {
    ///         (
    ///             strtab.get(shdr.sh_name as usize).expect("Failed to get section name"),
    ///             shdr,
    ///         )
    ///     })
    ///     .collect();
    /// ```
    pub fn section_headers_with_strtab(
        &self,
    ) -> Result<Option<(SectionHeaderTable<'data, E>, StringTable<'data>)>, ParseError> {
        // It's Ok to have no section headers
        let shdrs = match self.section_headers() {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        // If the section name string table section index is greater than or
        // equal to SHN_LORESERVE (0xff00), e_shstrndx has the value SHN_XINDEX
        // (0xffff) and the actual index of the section name string table section
        // is contained in the sh_link field of the section header at index 0.
        let mut shstrndx = self.ehdr.e_shstrndx as usize;
        if self.ehdr.e_shstrndx == abi::SHN_XINDEX {
            let shdr_0 = shdrs.get(0)?;
            shstrndx = shdr_0.sh_link as usize;
        }

        let strtab = shdrs.get(shstrndx)?;
        let (strtab_start, strtab_end) = strtab.get_data_range()?;
        let strtab_buf = self.data.get_bytes(strtab_start..strtab_end)?;
        Ok(Some((shdrs, StringTable::new(strtab_buf))))
    }

    /// Efficiently locate the set of common sections found in ELF files by doing a single iteration
    /// over the SectionHeaders table.
    ///
    /// This is useful for those who know they're going to be accessing multiple common sections, like
    /// symbol tables, string tables. Many of these can also be accessed by the more targeted
    /// helpers like [ElfBytes::symbol_table] or [ElfBytes::dynamic], though those each do their own
    /// internal searches through the shdrs to find the section.
    pub fn find_common_sections(&self) -> Result<CommonElfSections<'data, E>, ParseError> {
        let mut result: CommonElfSections<'data, E> = CommonElfSections::default();

        // Iterate once over the shdrs to collect up any known sections
        if let Some(shdrs) = self.shdrs {
            for shdr in shdrs.iter() {
                match shdr.sh_type {
                    abi::SHT_SYMTAB => {
                        let strtab_shdr = shdrs.get(shdr.sh_link as usize)?;
                        let (symtab, strtab) =
                            self.section_data_as_symbol_table(&shdr, &strtab_shdr)?;

                        result.symtab = Some(symtab);
                        result.symtab_strs = Some(strtab);
                    }
                    abi::SHT_DYNSYM => {
                        let strtab_shdr = shdrs.get(shdr.sh_link as usize)?;
                        let (symtab, strtab) =
                            self.section_data_as_symbol_table(&shdr, &strtab_shdr)?;

                        result.dynsyms = Some(symtab);
                        result.dynsyms_strs = Some(strtab);
                    }
                    abi::SHT_DYNAMIC => {
                        let (start, end) = shdr.get_data_range()?;
                        let buf = self.data.get_bytes(start..end)?;
                        result.dynamic = Some(DynamicTable::new(self.endian, self.ehdr.class, buf));
                    }
                    abi::SHT_HASH => {
                        let (start, end) = shdr.get_data_range()?;
                        let buf = self.data.get_bytes(start..end)?;
                        result.sysv_hash =
                            Some(SysVHashTable::new(self.endian, self.ehdr.class, buf)?);
                    }
                    _ => {
                        continue;
                    }
                }
            }
        }

        // If we didn't find SHT_DYNAMIC from the section headers, try the program headers
        if result.dynamic.is_none() {
            if let Some(phdrs) = self.phdrs {
                if let Some(dyn_phdr) = phdrs.iter().find(|phdr| phdr.p_type == abi::PT_DYNAMIC) {
                    let (start, end) = dyn_phdr.get_file_data_range()?;
                    let buf = self.data.get_bytes(start..end)?;
                    result.dynamic = Some(DynamicTable::new(self.endian, self.ehdr.class, buf));
                }
            }
        }

        Ok(result)
    }

    /// Get the section data for a given [SectionHeader], alongside an optional compression context.
    ///
    /// This library does not do any decompression for the user, but merely returns the raw compressed
    /// section data if the section is compressed alongside its ELF compression structure describing the
    /// compression algorithm used.
    ///
    /// Users who wish to work with compressed sections must pick their compression library of choice
    /// and do the decompression themselves. The only two options supported by the ELF spec for section
    /// compression are: [abi::ELFCOMPRESS_ZLIB] and [abi::ELFCOMPRESS_ZSTD].
    pub fn section_data(
        &self,
        shdr: &SectionHeader,
    ) -> Result<(&'data [u8], Option<CompressionHeader>), ParseError> {
        if shdr.sh_type == abi::SHT_NOBITS {
            return Ok((&[], None));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.data.get_bytes(start..end)?;

        if shdr.sh_flags & abi::SHF_COMPRESSED as u64 == 0 {
            Ok((buf, None))
        } else {
            let mut offset = 0;
            let chdr = CompressionHeader::parse_at(self.endian, self.ehdr.class, &mut offset, buf)?;
            let compressed_buf = buf.get(offset..).ok_or(ParseError::SliceReadError((
                offset,
                shdr.sh_size.try_into()?,
            )))?;
            Ok((compressed_buf, Some(chdr)))
        }
    }

    /// Get the section data for a given [SectionHeader], and interpret it as a [StringTable]
    ///
    /// Returns a ParseError if the section is not of type [abi::SHT_STRTAB]
    pub fn section_data_as_strtab(
        &self,
        shdr: &SectionHeader,
    ) -> Result<StringTable<'data>, ParseError> {
        if shdr.sh_type != abi::SHT_STRTAB {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_STRTAB,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(StringTable::new(buf))
    }

    /// Get the section data for a given [SectionHeader], and interpret it as an
    /// iterator over no-addend relocations [Rel](crate::relocation::Rel)
    ///
    /// Returns a ParseError if the section is not of type [abi::SHT_REL]
    pub fn section_data_as_rels(
        &self,
        shdr: &SectionHeader,
    ) -> Result<RelIterator<'data, E>, ParseError> {
        if shdr.sh_type != abi::SHT_REL {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_REL,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(RelIterator::new(self.endian, self.ehdr.class, buf))
    }

    /// Get the section data for a given [SectionHeader], and interpret it as an
    /// iterator over relocations with addends [Rela](crate::relocation::Rela)
    ///
    /// Returns a ParseError if the section is not of type [abi::SHT_RELA]
    pub fn section_data_as_relas(
        &self,
        shdr: &SectionHeader,
    ) -> Result<RelaIterator<'data, E>, ParseError> {
        if shdr.sh_type != abi::SHT_RELA {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_RELA,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(RelaIterator::new(self.endian, self.ehdr.class, buf))
    }

    /// Get the section data for a given [SectionHeader], and interpret it as an
    /// iterator over [Note](crate::note::Note)s
    ///
    /// Returns a ParseError if the section is not of type [abi::SHT_NOTE]
    pub fn section_data_as_notes(
        &self,
        shdr: &SectionHeader,
    ) -> Result<NoteIterator<'data, E>, ParseError> {
        if shdr.sh_type != abi::SHT_NOTE {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_NOTE,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(NoteIterator::new(
            self.endian,
            self.ehdr.class,
            shdr.sh_addralign as usize,
            buf,
        ))
    }

    /// Get the segment's file data for a given segment/[ProgramHeader].
    ///
    /// This is the segment's data as found in the file.
    pub fn segment_data(&self, phdr: &ProgramHeader) -> Result<&'data [u8], ParseError> {
        let (start, end) = phdr.get_file_data_range()?;
        Ok(self.data.get_bytes(start..end)?)
    }

    /// Get the segment's file data for a given [ProgramHeader], and interpret it as an
    /// iterator over [Note](crate::note::Note)s
    ///
    /// Returns a ParseError if the section is not of type [abi::PT_NOTE]
    pub fn segment_data_as_notes(
        &self,
        phdr: &ProgramHeader,
    ) -> Result<NoteIterator<'data, E>, ParseError> {
        if phdr.p_type != abi::PT_NOTE {
            return Err(ParseError::UnexpectedSegmentType((
                phdr.p_type,
                abi::PT_NOTE,
            )));
        }

        let buf = self.segment_data(phdr)?;
        Ok(NoteIterator::new(
            self.endian,
            self.ehdr.class,
            phdr.p_align as usize,
            buf,
        ))
    }

    /// Get the .dynamic section or [abi::PT_DYNAMIC] segment contents.
    pub fn dynamic(&self) -> Result<Option<DynIterator<'data, E>>, ParseError> {
        // If we have section headers, look for the SHT_DYNAMIC section
        if let Some(shdrs) = self.section_headers() {
            if let Some(shdr) = shdrs.iter().find(|shdr| shdr.sh_type == abi::SHT_DYNAMIC) {
                let (start, end) = shdr.get_data_range()?;
                let buf = self.data.get_bytes(start..end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
            }
        // Otherwise, look up the PT_DYNAMIC segment (if any)
        } else if let Some(phdrs) = self.segments() {
            if let Some(phdr) = phdrs.iter().find(|phdr| phdr.p_type == abi::PT_DYNAMIC) {
                let (start, end) = phdr.get_file_data_range()?;
                let buf = self.data.get_bytes(start..end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
            }
        }

        Ok(None)
    }

    /// Get the section data for a given pair of [SectionHeader] for the symbol table and its linked strtab,
    /// and interpret them as [SymbolTable] and [StringTable].
    ///
    /// This mostly a helper method and its probably easier to use [ElfBytes::symbol_table] or
    /// [ElfBytes::dynamic_symbol_table] or [ElfBytes::find_common_sections]
    pub fn section_data_as_symbol_table(
        &self,
        shdr: &SectionHeader,
        strtab_shdr: &SectionHeader,
    ) -> Result<(SymbolTable<'data, E>, StringTable<'data>), ParseError> {
        // Validate entsize before trying to read the table so that we can error early for corrupted files
        Symbol::validate_entsize(self.ehdr.class, shdr.sh_entsize.try_into()?)?;

        // Load the section bytes for the symtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let (symtab_start, symtab_end) = shdr.get_data_range()?;
        let symtab_buf = self.data.get_bytes(symtab_start..symtab_end)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let (strtab_start, strtab_end) = strtab_shdr.get_data_range()?;
        let strtab_buf = self.data.get_bytes(strtab_start..strtab_end)?;

        let symtab = SymbolTable::new(self.endian, self.ehdr.class, symtab_buf);
        let strtab = StringTable::new(strtab_buf);
        Ok((symtab, strtab))
    }

    /// Get the ELF file's `.symtab` and associated strtab (if any)
    pub fn symbol_table(
        &self,
    ) -> Result<Option<(SymbolTable<'data, E>, StringTable<'data>)>, ParseError> {
        let shdrs = match self.section_headers() {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match shdrs.iter().find(|shdr| shdr.sh_type == abi::SHT_SYMTAB) {
            Some(shdr) => shdr,
            None => {
                return Ok(None);
            }
        };

        let strtab_shdr = shdrs.get(symtab_shdr.sh_link as usize)?;
        Ok(Some(self.section_data_as_symbol_table(
            &symtab_shdr,
            &strtab_shdr,
        )?))
    }

    /// Get the ELF file's `.dynsym` and associated strtab (if any)
    pub fn dynamic_symbol_table(
        &self,
    ) -> Result<Option<(SymbolTable<'data, E>, StringTable<'data>)>, ParseError> {
        let shdrs = match self.section_headers() {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match shdrs.iter().find(|shdr| shdr.sh_type == abi::SHT_DYNSYM) {
            Some(shdr) => shdr,
            None => {
                return Ok(None);
            }
        };

        let strtab_shdr = shdrs.get(symtab_shdr.sh_link as usize)?;
        Ok(Some(self.section_data_as_symbol_table(
            &symtab_shdr,
            &strtab_shdr,
        )?))
    }
}

// Simple convenience extension trait to wrap get() with .ok_or(SliceReadError)
trait ReadBytesExt<'data> {
    fn get_bytes(self, range: Range<usize>) -> Result<&'data [u8], ParseError>;
}

impl<'data> ReadBytesExt<'data> for &'data [u8] {
    fn get_bytes(self, range: Range<usize>) -> Result<&'data [u8], ParseError> {
        let start = range.start;
        let end = range.end;
        self.get(range)
            .ok_or(ParseError::SliceReadError((start, end)))
    }
}

//  _            _
// | |_ ___  ___| |_ ___
// | __/ _ \/ __| __/ __|
// | ||  __/\__ \ |_\__ \
//  \__\___||___/\__|___/
//

#[cfg(test)]
mod read_bytes_tests {
    use super::ParseError;
    use super::ReadBytesExt;

    #[test]
    fn get_bytes_works() {
        let data = &[0u8, 1, 2, 3];
        let subslice = data.get_bytes(1..3).expect("should be within range");
        assert_eq!(subslice, [1, 2]);
    }

    #[test]
    fn get_bytes_out_of_range_errors() {
        let data = &[0u8, 1, 2, 3];
        let err = data.get_bytes(3..9).expect_err("should be out of range");
        assert!(
            matches!(err, ParseError::SliceReadError((3, 9))),
            "Unexpected Error type found: {err}"
        );
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::abi::{SHT_GNU_HASH, SHT_NOBITS, SHT_NOTE, SHT_NULL, SHT_REL, SHT_RELA, SHT_STRTAB};
    use crate::dynamic::Dyn;
    use crate::endian::AnyEndian;
    use crate::note::Note;
    use crate::relocation::Rela;
    use crate::segment::ProgramHeader;

    #[test]
    fn simultaenous_segments_parsing() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        // With the bytes interface, we should be able to get multiple lazy-parsing types concurrently,
        // since the trait is implemented for shared references.
        //
        // Get the segment table
        let iter = file.segments().expect("File should have a segment table");

        // Concurrently get the segment table again as an iterator and collect the headers into a vec
        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .iter()
            .collect();

        let expected_phdr = ProgramHeader {
            p_type: abi::PT_PHDR,
            p_offset: 64,
            p_vaddr: 4194368,
            p_paddr: 4194368,
            p_filesz: 448,
            p_memsz: 448,
            p_flags: 5,
            p_align: 8,
        };

        // Assert we parsed the first header correctly
        assert_eq!(segments[0], expected_phdr);

        // Now use the original lazy-parsing table to parse out the first entry
        assert_eq!(
            iter.get(0).expect("should be able to parse phdr"),
            expected_phdr
        )
    }

    #[test]
    fn segments() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .iter()
            .collect();
        assert_eq!(
            segments[0],
            ProgramHeader {
                p_type: abi::PT_PHDR,
                p_offset: 64,
                p_vaddr: 4194368,
                p_paddr: 4194368,
                p_filesz: 448,
                p_memsz: 448,
                p_flags: 5,
                p_align: 8,
            }
        );
    }

    #[test]
    fn section_headers() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdrs = file
            .section_headers()
            .expect("File should have a section table");

        let shdrs_vec: Vec<SectionHeader> = shdrs.iter().collect();

        assert_eq!(shdrs_vec[4].sh_type, SHT_GNU_HASH);
    }

    #[test]
    fn section_headers_with_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let (shdrs, strtab) = file
            .section_headers_with_strtab()
            .expect("shdrs should be parsable")
            .expect("File should have shdrs");

        let with_names: Vec<(&str, SectionHeader)> = shdrs
            .iter()
            .map(|shdr| {
                (
                    strtab
                        .get(shdr.sh_name as usize)
                        .expect("Failed to get section name"),
                    shdr,
                )
            })
            .collect();

        let (name, shdr) = with_names[4];
        assert_eq!(name, ".gnu.hash");
        assert_eq!(shdr.sh_type, abi::SHT_GNU_HASH);
    }

    #[test]
    fn find_common_sections() {
        let path = std::path::PathBuf::from("tests/samples/hello.so");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let elf_scns = file.find_common_sections().expect("file should parse");

        // hello.so should find everything
        assert!(elf_scns.symtab.is_some());
        assert!(elf_scns.symtab_strs.is_some());
        assert!(elf_scns.dynsyms.is_some());
        assert!(elf_scns.dynsyms_strs.is_some());
        assert!(elf_scns.dynamic.is_some());
        assert!(elf_scns.sysv_hash.is_some());
    }

    #[test]
    fn section_data() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .get(26)
            .expect("shdr should be parsable");

        assert_eq!(shdr.sh_type, SHT_NOBITS);

        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");

        assert_eq!(chdr, None);
        assert_eq!(data, &[]);
    }

    // Test all the different section_data_as* with a section of the wrong type
    #[test]
    fn section_data_as_wrong_type() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        // Section 0 is SHT_NULL, so all of the section_data_as* should error on it
        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .get(0)
            .expect("shdr should be parsable");

        let err = file
            .section_data_as_strtab(&shdr)
            .expect_err("shdr0 should be the wrong type");
        assert!(
            matches!(
                err,
                ParseError::UnexpectedSectionType((SHT_NULL, SHT_STRTAB))
            ),
            "Unexpected Error type found: {err}"
        );

        let err = file
            .section_data_as_rels(&shdr)
            .expect_err("shdr0 should be the wrong type");
        assert!(
            matches!(err, ParseError::UnexpectedSectionType((SHT_NULL, SHT_REL))),
            "Unexpected Error type found: {err}"
        );

        let err = file
            .section_data_as_relas(&shdr)
            .expect_err("shdr0 should be the wrong type");
        assert!(
            matches!(err, ParseError::UnexpectedSectionType((SHT_NULL, SHT_RELA))),
            "Unexpected Error type found: {err}"
        );

        let err = file
            .section_data_as_notes(&shdr)
            .expect_err("shdr0 should be the wrong type");
        assert!(
            matches!(err, ParseError::UnexpectedSectionType((SHT_NULL, SHT_NOTE))),
            "Unexpected Error type found: {err}"
        );
    }

    #[test]
    fn section_data_as_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .get(file.ehdr.e_shstrndx as usize)
            .expect("shdr should be parsable");

        let strtab = file
            .section_data_as_strtab(&shdr)
            .expect("Failed to read strtab");

        assert_eq!(
            strtab.get(1).expect("Failed to get strtab entry"),
            ".symtab"
        );
    }

    #[test]
    fn section_data_as_relas() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .get(10)
            .expect("Failed to get rela shdr");

        let mut relas = file
            .section_data_as_relas(&shdr)
            .expect("Failed to read relas section");
        assert_eq!(
            relas.next().expect("Failed to get rela entry"),
            Rela {
                r_offset: 6293704,
                r_sym: 1,
                r_type: 7,
                r_addend: 0,
            }
        );
        assert_eq!(
            relas.next().expect("Failed to get rela entry"),
            Rela {
                r_offset: 6293712,
                r_sym: 2,
                r_type: 7,
                r_addend: 0,
            }
        );
        assert!(relas.next().is_none());
    }

    #[test]
    fn section_data_as_notes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .get(2)
            .expect("Failed to get note shdr");

        let mut notes = file
            .section_data_as_notes(&shdr)
            .expect("Failed to read note section");
        assert_eq!(
            notes.next().expect("Failed to get first note"),
            Note {
                n_type: 1,
                name: "GNU",
                desc: &[0, 0, 0, 0, 2, 0, 0, 0, 6, 0, 0, 0, 32, 0, 0, 0]
            }
        );
        assert!(notes.next().is_none());
    }

    #[test]
    fn segment_data_as_notes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let phdr = file
            .segments()
            .expect("File should have segmetn table")
            .get(5)
            .expect("Failed to get notes phdr");

        let mut notes = file
            .segment_data_as_notes(&phdr)
            .expect("Failed to read notes segment");
        assert_eq!(
            notes.next().expect("Failed to get first note"),
            Note {
                n_type: 1,
                name: "GNU",
                desc: &[0, 0, 0, 0, 2, 0, 0, 0, 6, 0, 0, 0, 32, 0, 0, 0]
            }
        );
        assert_eq!(
            notes.next().expect("Failed to get second note"),
            Note {
                n_type: 3,
                name: "GNU",
                desc: &[
                    0x77, 0x41, 0x9F, 0x0D, 0xA5, 0x10, 0x83, 0x0C, 0x57, 0xA7, 0xC8, 0xCC, 0xB0,
                    0xEE, 0x85, 0x5F, 0xEE, 0xD3, 0x76, 0xA3
                ],
            }
        );
        assert!(notes.next().is_none());
    }

    #[test]
    fn dynamic() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let mut dynamic = file
            .dynamic()
            .expect("Failed to parse .dynamic")
            .expect("Failed to find .dynamic");
        assert_eq!(
            dynamic.next().expect("Failed to get dyn entry"),
            Dyn {
                d_tag: abi::DT_NEEDED,
                d_un: 1
            }
        );
        assert_eq!(
            dynamic.next().expect("Failed to get dyn entry"),
            Dyn {
                d_tag: abi::DT_INIT,
                d_un: 4195216
            }
        );
    }

    #[test]
    fn symbol_table() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let (symtab, strtab) = file
            .symbol_table()
            .expect("Failed to read symbol table")
            .expect("Failed to find symbol table");
        let symbol = symtab.get(30).expect("Failed to get symbol");
        assert_eq!(
            symbol,
            Symbol {
                st_name: 19,
                st_value: 6293200,
                st_size: 0,
                st_shndx: 21,
                st_info: 1,
                st_other: 0,
            }
        );
        assert_eq!(
            strtab
                .get(symbol.st_name as usize)
                .expect("Failed to get name from strtab"),
            "__JCR_LIST__"
        );
    }

    #[test]
    fn dynamic_symbol_table() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let (symtab, strtab) = file
            .dynamic_symbol_table()
            .expect("Failed to read symbol table")
            .expect("Failed to find symbol table");
        let symbol = symtab.get(1).expect("Failed to get symbol");
        assert_eq!(
            symbol,
            Symbol {
                st_name: 11,
                st_value: 0,
                st_size: 0,
                st_shndx: 0,
                st_info: 18,
                st_other: 0,
            }
        );
        assert_eq!(
            strtab
                .get(symbol.st_name as usize)
                .expect("Failed to get name from strtab"),
            "memset"
        );
    }
}
