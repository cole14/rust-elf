//! This module provides an interface for parsing ELF files
//!
//! Example usage of the bytes-based interface:
//!
//! ```
//! use elf::gabi::PT_LOAD;
//! use elf::elf::from_bytes;
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
//! // Get a lazy-parsing type for the segment table into `phdr_table`
//! if let Some(phdr_table) = file.segments().unwrap() {
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

use crate::compression::CompressionHeader;
use crate::dynamic::DynIterator;
use crate::endian::EndianParse;
use crate::file::FileHeader;
use crate::gabi;
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
pub fn from_bytes<'data, E: EndianParse>(
    data: &'data [u8],
) -> Result<ElfBytes<'data, E>, ParseError> {
    let ident_buf = data.get_bytes(0..gabi::EI_NIDENT)?;
    let ident = FileHeader::parse_ident(ident_buf)?;

    let tail_start = gabi::EI_NIDENT;
    let tail_end = match ident.1 {
        Class::ELF32 => tail_start + crate::file::ELF32_EHDR_TAILSIZE,
        Class::ELF64 => tail_start + crate::file::ELF64_EHDR_TAILSIZE,
    };
    let tail_buf = data.get_bytes(tail_start..tail_end)?;

    let ehdr = FileHeader::parse_tail(ident, tail_buf)?;
    let endian = E::from_ei_data(ehdr.ei_data)?;
    Ok(ElfBytes { ehdr, data, endian })
}

pub struct ElfBytes<'data, E: EndianParse> {
    ehdr: FileHeader,
    data: &'data [u8],
    endian: E,
}

impl<'data, E: EndianParse> ElfBytes<'data, E> {
    pub fn segments(&self) -> Result<Option<SegmentTable<'data, E>>, ParseError> {
        match self.ehdr.get_phdrs_data_range()? {
            Some((start, end)) => {
                let buf = self.data.get_bytes(start..end)?;
                Ok(Some(SegmentTable::new(self.endian, self.ehdr.class, buf)))
            }
            None => Ok(None),
        }
    }

    pub fn section_headers(&self) -> Result<Option<SectionHeaderTable<'data, E>>, ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok(None);
        }

        // If the number of sections is greater than or equal to SHN_LORESERVE (0xff00),
        // e_shnum is zero and the actual number of section header table entries
        // is contained in the sh_size field of the section header at index 0.
        let shoff: usize = self.ehdr.e_shoff.try_into()?;
        let mut shnum = self.ehdr.e_shnum as usize;
        if shnum == 0 {
            let mut offset = shoff;
            let shdr0 =
                SectionHeader::parse_at(self.endian, self.ehdr.class, &mut offset, self.data)?;
            shnum = shdr0.sh_size.try_into()?;
        }

        // Validate shentsize before trying to read the table so that we can error early for corrupted files
        let entsize =
            SectionHeader::validate_entsize(self.ehdr.class, self.ehdr.e_shentsize as usize)?;

        let size = entsize
            .checked_mul(shnum)
            .ok_or(ParseError::IntegerOverflow)?;
        let end = shoff.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
        let buf = self.data.get_bytes(shoff..end)?;
        Ok(Some(SectionHeaderTable::new(
            self.endian,
            self.ehdr.class,
            buf,
        )))
    }

    pub fn section_headers_with_strtab(
        &self,
    ) -> Result<Option<(SectionHeaderTable<'data, E>, StringTable<'data>)>, ParseError> {
        // It's Ok to have no section headers
        let shdrs = match self.section_headers()? {
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
        if self.ehdr.e_shstrndx == gabi::SHN_XINDEX {
            let shdr_0 = shdrs.get(0)?;
            shstrndx = shdr_0.sh_link as usize;
        }

        let strtab = shdrs.get(shstrndx)?;
        let (strtab_start, strtab_end) = strtab.get_data_range()?;
        let strtab_buf = self.data.get_bytes(strtab_start..strtab_end)?;
        Ok(Some((shdrs, StringTable::new(strtab_buf))))
    }

    pub fn section_data(
        &self,
        shdr: &SectionHeader,
    ) -> Result<(&'data [u8], Option<CompressionHeader>), ParseError> {
        if shdr.sh_type == gabi::SHT_NOBITS {
            return Ok((&[], None));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.data.get_bytes(start..end)?;

        if shdr.sh_flags & gabi::SHF_COMPRESSED as u64 == 0 {
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

    pub fn section_data_as_strtab(
        &self,
        shdr: &SectionHeader,
    ) -> Result<StringTable<'data>, ParseError> {
        if shdr.sh_type != gabi::SHT_STRTAB {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_STRTAB,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(StringTable::new(buf))
    }

    pub fn section_data_as_rels(
        &self,
        shdr: &SectionHeader,
    ) -> Result<RelIterator<'data, E>, ParseError> {
        if shdr.sh_type != gabi::SHT_REL {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_REL,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(RelIterator::new(self.endian, self.ehdr.class, buf))
    }

    pub fn section_data_as_relas(
        &self,
        shdr: &SectionHeader,
    ) -> Result<RelaIterator<'data, E>, ParseError> {
        if shdr.sh_type != gabi::SHT_RELA {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_RELA,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(RelaIterator::new(self.endian, self.ehdr.class, buf))
    }

    pub fn section_data_as_notes(
        &self,
        shdr: &SectionHeader,
    ) -> Result<NoteIterator<'data, E>, ParseError> {
        if shdr.sh_type != gabi::SHT_NOTE {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_NOTE,
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

    pub fn segment_data(&self, phdr: &ProgramHeader) -> Result<&'data [u8], ParseError> {
        let (start, end) = phdr.get_file_data_range()?;
        Ok(self.data.get_bytes(start..end)?)
    }

    pub fn segment_data_as_notes(
        &self,
        phdr: &ProgramHeader,
    ) -> Result<NoteIterator<'data, E>, ParseError> {
        if phdr.p_type != gabi::PT_NOTE {
            return Err(ParseError::UnexpectedSegmentType((
                phdr.p_type,
                gabi::PT_NOTE,
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

    /// Get the .dynamic section or PT_DYNAMIC segment contents.
    pub fn dynamic(&self) -> Result<Option<DynIterator<'data, E>>, ParseError> {
        // If we have section headers, look for the SHT_DYNAMIC section
        if let Some(shdrs) = self.section_headers()? {
            if let Some(shdr) = shdrs.iter().find(|shdr| shdr.sh_type == gabi::SHT_DYNAMIC) {
                let (start, end) = shdr.get_data_range()?;
                let buf = self.data.get_bytes(start..end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
            }
        // Otherwise, look up the PT_DYNAMIC segment (if any)
        } else if let Some(phdrs) = self.segments()? {
            if let Some(phdr) = phdrs.iter().find(|phdr| phdr.p_type == gabi::PT_DYNAMIC) {
                let (start, end) = phdr.get_file_data_range()?;
                let buf = self.data.get_bytes(start..end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
            }
        }

        Ok(None)
    }

    pub fn section_data_as_symbol_table(
        &self,
        shdr: &SectionHeader,
        strtab_shdr: &SectionHeader,
    ) -> Result<Option<(SymbolTable<'data, E>, StringTable<'data>)>, ParseError> {
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
        Ok(Some((symtab, strtab)))
    }

    pub fn symbol_table(
        &self,
    ) -> Result<Option<(SymbolTable<'data, E>, StringTable<'data>)>, ParseError> {
        let shdrs = match self.section_headers()? {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match shdrs.iter().find(|shdr| shdr.sh_type == gabi::SHT_SYMTAB) {
            Some(shdr) => shdr,
            None => {
                return Ok(None);
            }
        };

        let strtab_shdr = shdrs.get(symtab_shdr.sh_link as usize)?;
        self.section_data_as_symbol_table(&symtab_shdr, &strtab_shdr)
    }

    pub fn dynamic_symbol_table(
        &self,
    ) -> Result<Option<(SymbolTable<'data, E>, StringTable<'data>)>, ParseError> {
        let shdrs = match self.section_headers()? {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match shdrs.iter().find(|shdr| shdr.sh_type == gabi::SHT_DYNSYM) {
            Some(shdr) => shdr,
            None => {
                return Ok(None);
            }
        };

        let strtab_shdr = shdrs.get(symtab_shdr.sh_link as usize)?;
        self.section_data_as_symbol_table(&symtab_shdr, &strtab_shdr)
    }
}

// Simple convenience extension trait to wrap get() with .ok_or(SliceReadError)
trait ReadBytesExt<'data> {
    fn get_bytes(self, range: Range<usize>) -> Result<&'data [u8], ParseError>;
}

impl<'data> ReadBytesExt<'data> for &'data [u8] {
    fn get_bytes(self, range: Range<usize>) -> Result<&'data [u8], ParseError> {
        self.get(range)
            .ok_or(ParseError::SliceReadError((0, gabi::EI_NIDENT)))
    }
}

//  _____ _     _____ ____  _
// | ____| |   |  ___/ ___|| |_ _ __ ___  __ _ _ __ ___
// |  _| | |   | |_  \___ \| __| '__/ _ \/ _` | '_ ` _ \
// | |___| |___|  _|  ___) | |_| | |  __/ (_| | | | | | |
// |_____|_____|_|   |____/ \__|_|  \___|\__,_|_| |_| |_|

#[cfg(feature = "std")]
pub fn from_stream<'data, E: EndianParse, R: std::io::Read + std::io::Seek>(
    reader: R,
) -> Result<ElfStream<E, R>, ParseError> {
    let mut cr = CachingReader::new(reader);
    cr.load_bytes(0..gabi::EI_NIDENT)?;
    let ident_buf = cr.get_bytes(0..gabi::EI_NIDENT);
    let ident = FileHeader::parse_ident(ident_buf)?;

    let tail_start = gabi::EI_NIDENT;
    let tail_end = match ident.1 {
        Class::ELF32 => tail_start + crate::file::ELF32_EHDR_TAILSIZE,
        Class::ELF64 => tail_start + crate::file::ELF64_EHDR_TAILSIZE,
    };
    cr.load_bytes(tail_start..tail_end)?;
    let tail_buf = cr.get_bytes(tail_start..tail_end);

    let ehdr = FileHeader::parse_tail(ident, tail_buf)?;
    let endian = E::from_ei_data(ehdr.ei_data)?;
    Ok(ElfStream {
        reader: cr,
        ehdr,
        endian,
    })
}

#[cfg(feature = "std")]
pub struct ElfStream<E: EndianParse, R: std::io::Read + std::io::Seek> {
    ehdr: FileHeader,
    reader: CachingReader<R>,
    endian: E,
}

#[cfg(feature = "std")]
impl<E: EndianParse, R: std::io::Read + std::io::Seek> ElfStream<E, R> {
    pub fn segments(&mut self) -> Result<Option<SegmentTable<E>>, ParseError> {
        match self.ehdr.get_phdrs_data_range()? {
            Some((start, end)) => {
                self.reader.load_bytes(start..end)?;
                let buf = self.reader.get_bytes(start..end);
                Ok(Some(SegmentTable::new(self.endian, self.ehdr.class, buf)))
            }
            None => Ok(None),
        }
    }

    pub fn section_headers(&mut self) -> Result<Option<SectionHeaderTable<E>>, ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok(None);
        }

        // Validate shentsize before trying to read the table so that we can error early for corrupted files
        let entsize =
            SectionHeader::validate_entsize(self.ehdr.class, self.ehdr.e_shentsize as usize)?;

        // If the number of sections is greater than or equal to SHN_LORESERVE (0xff00),
        // e_shnum is zero and the actual number of section header table entries
        // is contained in the sh_size field of the section header at index 0.
        let shoff: usize = self.ehdr.e_shoff.try_into()?;
        let mut shnum = self.ehdr.e_shnum as usize;
        if shnum == 0 {
            let mut offset = 0;
            let shdr0_buf = self.reader.read_bytes(shoff, entsize)?;
            let shdr0 =
                SectionHeader::parse_at(self.endian, self.ehdr.class, &mut offset, shdr0_buf)?;
            shnum = shdr0.sh_size.try_into()?;
        }

        let size = entsize
            .checked_mul(shnum)
            .ok_or(ParseError::IntegerOverflow)?;
        let end = shoff.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
        let buf = self.reader.read_bytes(shoff, end)?;
        Ok(Some(SectionHeaderTable::new(
            self.endian,
            self.ehdr.class,
            buf,
        )))
    }

    pub fn section_headers_with_strtab(
        &mut self,
    ) -> Result<Option<(SectionHeaderTable<E>, StringTable)>, ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok(None);
        }

        // Validate shentsize before trying to read the table so that we can error early for corrupted files
        let entsize =
            SectionHeader::validate_entsize(self.ehdr.class, self.ehdr.e_shentsize as usize)?;

        let shoff: usize = self.ehdr.e_shoff.try_into()?;

        // If the number of sections and the section name string table section
        // index are greater than or equal to SHN_LORESERVE (0xff00), e_shnum and e_shstrndx
        // can have the value 0 or SHN_XINDEX (0xffff) and their actual values
        // are contained in the sh_info or sh_link field of the section header at index 0.
        let mut shstrndx = self.ehdr.e_shstrndx as usize;
        let mut shnum = self.ehdr.e_shnum as usize;
        if shnum == 0 || self.ehdr.e_shstrndx == gabi::SHN_XINDEX {
            let shdr0_buf = self.reader.read_bytes(shoff, entsize)?;
            let mut offset = 0;
            let shdr_0 =
                SectionHeader::parse_at(self.endian, self.ehdr.class, &mut offset, shdr0_buf)?;

            if shnum == 0 {
                shnum = shdr_0.sh_info as usize;
            }

            // N.B. just because shnum > SHN_LORESERVE doesn't mean shstrndx is also > SHN_XINDEX
            if self.ehdr.e_shstrndx == gabi::SHN_XINDEX {
                shstrndx = shdr_0.sh_link as usize;
            }
        }

        // Load the section header table bytes
        let shdrs_size = entsize
            .checked_mul(shnum)
            .ok_or(ParseError::IntegerOverflow)?;
        let shdrs_end = shoff
            .checked_add(shdrs_size)
            .ok_or(ParseError::IntegerOverflow)?;
        self.reader.load_bytes(shoff..shdrs_end)?;

        // Temporarily get the section header table bytes we just loaded so we can parse out the shstrndx shdr
        let strtab_shdr = {
            let shdrs_buf = self.reader.get_bytes(shoff..shdrs_end);
            let strtab_shdr_start = entsize
                .checked_mul(shstrndx)
                .ok_or(ParseError::IntegerOverflow)?;
            let mut offset = strtab_shdr_start;
            SectionHeader::parse_at(self.endian, self.ehdr.class, &mut offset, shdrs_buf)?
        };

        // Load the strtab section bytes
        let (strtab_start, strtab_end) = strtab_shdr.get_data_range()?;
        self.reader.load_bytes(strtab_start..strtab_end)?;

        let shdrs_buf = self.reader.get_bytes(shoff..shdrs_end);
        let strtab_buf = self.reader.get_bytes(strtab_start..strtab_end);
        Ok(Some((
            SectionHeaderTable::new(self.endian, self.ehdr.class, shdrs_buf),
            StringTable::new(strtab_buf),
        )))
    }

    pub fn section_data(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<(&[u8], Option<CompressionHeader>), ParseError> {
        if shdr.sh_type == gabi::SHT_NOBITS {
            return Ok((&[], None));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;

        if shdr.sh_flags & gabi::SHF_COMPRESSED as u64 == 0 {
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

    pub fn section_data_as_strtab(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<StringTable, ParseError> {
        if shdr.sh_type != gabi::SHT_STRTAB {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_STRTAB,
            )));
        }

        let (buf, _) = self.section_data(shdr)?;
        Ok(StringTable::new(buf))
    }

    pub fn section_data_as_rels(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<RelIterator<E>, ParseError> {
        if shdr.sh_type != gabi::SHT_REL {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_REL,
            )));
        }

        let endian = self.endian;
        let class = self.ehdr.class;
        let (buf, _) = self.section_data(shdr)?;
        Ok(RelIterator::new(endian, class, buf))
    }

    pub fn section_data_as_relas(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<RelaIterator<E>, ParseError> {
        if shdr.sh_type != gabi::SHT_RELA {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_RELA,
            )));
        }

        let endian = self.endian;
        let class = self.ehdr.class;
        let (buf, _) = self.section_data(shdr)?;
        Ok(RelaIterator::new(endian, class, buf))
    }

    pub fn section_data_as_notes(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<NoteIterator<E>, ParseError> {
        if shdr.sh_type != gabi::SHT_NOTE {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_NOTE,
            )));
        }

        let endian = self.endian;
        let class = self.ehdr.class;
        let align = shdr.sh_addralign.try_into()?;
        let (buf, _) = self.section_data(shdr)?;
        Ok(NoteIterator::new(endian, class, align, buf))
    }

    pub fn segment_data(&mut self, phdr: &ProgramHeader) -> Result<&[u8], ParseError> {
        let (start, end) = phdr.get_file_data_range()?;
        Ok(self.reader.read_bytes(start, end)?)
    }

    pub fn segment_data_as_notes(
        &mut self,
        phdr: &ProgramHeader,
    ) -> Result<NoteIterator<E>, ParseError> {
        if phdr.p_type != gabi::PT_NOTE {
            return Err(ParseError::UnexpectedSegmentType((
                phdr.p_type,
                gabi::PT_NOTE,
            )));
        }

        let endian = self.endian;
        let class = self.ehdr.class;
        let buf = self.segment_data(phdr)?;
        Ok(NoteIterator::new(endian, class, phdr.p_align as usize, buf))
    }

    /// Get the .dynamic section or PT_DYNAMIC segment contents.
    pub fn dynamic(&mut self) -> Result<Option<DynIterator<E>>, ParseError> {
        // If we have section headers, look for the SHT_DYNAMIC section
        if let Some(shdrs) = self.section_headers()? {
            if let Some(shdr) = shdrs.iter().find(|shdr| shdr.sh_type == gabi::SHT_DYNAMIC) {
                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.read_bytes(start, end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
            }
        // Otherwise, look up the PT_DYNAMIC segment (if any)
        } else if let Some(phdrs) = self.segments()? {
            if let Some(phdr) = phdrs.iter().find(|phdr| phdr.p_type == gabi::PT_DYNAMIC) {
                let (start, end) = phdr.get_file_data_range()?;
                let buf = self.reader.read_bytes(start, end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
            }
        }

        Ok(None)
    }

    pub fn section_data_as_symbol_table(
        &mut self,
        shdr: &SectionHeader,
        strtab_shdr: &SectionHeader,
    ) -> Result<Option<(SymbolTable<E>, StringTable)>, ParseError> {
        // Validate entsize before trying to read the table so that we can error early for corrupted files
        Symbol::validate_entsize(self.ehdr.class, shdr.sh_entsize.try_into()?)?;

        // Load the section bytes for the symtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let (symtab_start, symtab_end) = shdr.get_data_range()?;
        self.reader.load_bytes(symtab_start..symtab_end)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let (strtab_start, strtab_end) = strtab_shdr.get_data_range()?;
        self.reader.load_bytes(strtab_start..strtab_end)?;

        let symtab_buf = self.reader.get_bytes(symtab_start..symtab_end);
        let strtab_buf = self.reader.get_bytes(strtab_start..strtab_end);
        let symtab = SymbolTable::new(self.endian, self.ehdr.class, symtab_buf);
        let strtab = StringTable::new(strtab_buf);
        Ok(Some((symtab, strtab)))
    }

    pub fn symbol_table(&mut self) -> Result<Option<(SymbolTable<E>, StringTable)>, ParseError> {
        let shdrs = match self.section_headers()? {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match shdrs.iter().find(|shdr| shdr.sh_type == gabi::SHT_SYMTAB) {
            Some(shdr) => shdr,
            None => {
                return Ok(None);
            }
        };

        let strtab_shdr = shdrs.get(symtab_shdr.sh_link as usize)?;
        self.section_data_as_symbol_table(&symtab_shdr, &strtab_shdr)
    }

    pub fn dynamic_symbol_table(
        &mut self,
    ) -> Result<Option<(SymbolTable<E>, StringTable)>, ParseError> {
        let shdrs = match self.section_headers()? {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match shdrs.iter().find(|shdr| shdr.sh_type == gabi::SHT_DYNSYM) {
            Some(shdr) => shdr,
            None => {
                return Ok(None);
            }
        };

        let strtab_shdr = shdrs.get(symtab_shdr.sh_link as usize)?;
        self.section_data_as_symbol_table(&symtab_shdr, &strtab_shdr)
    }
}

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::io::{Read, Seek, SeekFrom};

#[cfg(feature = "std")]
struct CachingReader<R: Read + Seek> {
    reader: R,
    bufs: HashMap<(usize, usize), Box<[u8]>>,
}

#[cfg(feature = "std")]
impl<R: Read + Seek> CachingReader<R> {
    pub fn new(reader: R) -> Self {
        CachingReader {
            reader,
            bufs: HashMap::<(usize, usize), Box<[u8]>>::default(),
        }
    }

    pub fn read_bytes(&mut self, start: usize, end: usize) -> Result<&[u8], ParseError> {
        self.load_bytes(start..end)?;
        Ok(self.get_bytes(start..end))
    }

    pub fn get_bytes(&self, range: Range<usize>) -> &[u8] {
        // It's a programmer error to call get_bytes without first calling load_bytes, so
        // we want to panic here.
        self.bufs
            .get(&(range.start, range.end))
            .expect("load_bytes must be called before get_bytes for every range")
    }

    pub fn load_bytes(&mut self, range: Range<usize>) -> Result<(), ParseError> {
        if self.bufs.contains_key(&(range.start, range.end)) {
            return Ok(());
        }

        // Seek before allocating so we error early on bad read requests.
        self.reader.seek(SeekFrom::Start(range.start as u64))?;
        let mut bytes = vec![0; range.len()].into_boxed_slice();
        self.reader.read_exact(&mut bytes)?;
        self.bufs.insert((range.start, range.end), bytes);
        Ok(())
    }
}

//  _            _
// | |_ ___  ___| |_ ___
// | __/ _ \/ __| __/ __|
// | ||  __/\__ \ |_\__ \
//  \__\___||___/\__|___/
//

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::dynamic::Dyn;
    use crate::endian::AnyEndian;
    use crate::gabi::{
        SHT_GNU_HASH, SHT_NOBITS, SHT_NOTE, SHT_NULL, SHT_REL, SHT_RELA, SHT_STRTAB,
    };
    use crate::note::Note;
    use crate::relocation::Rela;
    use crate::segment::ProgramHeader;

    #[test]
    fn bytes_test_for_simultaenous_segments_parsing() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        // With the bytes interface, we should be able to get multiple lazy-parsing types concurrently,
        // since the trait is implemented for shared references.
        //
        // Get the segment table
        let iter = file
            .segments()
            .expect("File should have a segment table")
            .expect("Segment table should be parsable");

        // Concurrently get the segment table again as an iterator and collect the headers into a vec
        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .expect("Segment table should be parsable")
            .iter()
            .collect();

        let expected_phdr = ProgramHeader {
            p_type: gabi::PT_PHDR,
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
    fn stream_test_for_segments() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .expect("Segment table should be parsable")
            .iter()
            .collect();
        assert_eq!(
            segments[0],
            ProgramHeader {
                p_type: gabi::PT_PHDR,
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
    fn bytes_test_for_segments() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .expect("Segment table should be parsable")
            .iter()
            .collect();
        assert_eq!(
            segments[0],
            ProgramHeader {
                p_type: gabi::PT_PHDR,
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
    fn stream_test_for_section_headers() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let shdrs = file
            .section_headers()
            .expect("File should have a section table")
            .expect("Failed to get shdrs");

        let shdrs_vec: Vec<SectionHeader> = shdrs.iter().collect();

        assert_eq!(shdrs_vec[4].sh_type, SHT_GNU_HASH);
    }

    #[test]
    fn bytes_test_for_section_headers() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdrs = file
            .section_headers()
            .expect("File should have a section table")
            .expect("Failed to get shdrs");

        let shdrs_vec: Vec<SectionHeader> = shdrs.iter().collect();

        assert_eq!(shdrs_vec[4].sh_type, SHT_GNU_HASH);
    }

    #[test]
    fn stream_test_for_section_headers_with_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

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
        assert_eq!(shdr.sh_type, gabi::SHT_GNU_HASH);
    }

    #[test]
    fn bytes_test_for_section_headers_with_strtab() {
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
        assert_eq!(shdr.sh_type, gabi::SHT_GNU_HASH);
    }

    #[test]
    fn stream_test_for_section_data() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
            .get(26)
            .expect("shdr should be parsable");

        assert_eq!(shdr.sh_type, SHT_NOBITS);

        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");

        assert_eq!(chdr, None);
        assert_eq!(data, &[]);
    }

    #[test]
    fn bytes_test_for_section_data() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
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
    fn stream_test_for_section_data_as_wrong_type() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        // Section 0 is SHT_NULL, so all of the section_data_as* should error on it
        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
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

    // Test all the different section_data_as* with a section of the wrong type
    #[test]
    fn bytes_test_for_section_data_as_wrong_type() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        // Section 0 is SHT_NULL, so all of the section_data_as* should error on it
        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
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
    fn stream_test_for_section_data_as_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let shstrndx = file.ehdr.e_shstrndx as usize;
        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
            .get(shstrndx)
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
    fn bytes_test_for_section_data_as_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
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
    fn stream_test_for_section_data_as_relas() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
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
    fn bytes_test_for_section_data_as_relas() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
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
    fn stream_test_for_section_data_as_notes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
            .get(2)
            .expect("Failed to get rela shdr");

        let mut notes = file
            .section_data_as_notes(&shdr)
            .expect("Failed to read relas section");
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
    fn bytes_test_for_section_data_as_notes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let shdr = file
            .section_headers()
            .expect("File should have section table")
            .expect("shdrs should be readable")
            .get(2)
            .expect("Failed to get rela shdr");

        let mut notes = file
            .section_data_as_notes(&shdr)
            .expect("Failed to read relas section");
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
    fn stream_test_for_segment_data_as_notes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let phdr = file
            .segments()
            .expect("File should have section table")
            .expect("shdrs should be readable")
            .get(5)
            .expect("Failed to get rela shdr");

        let mut notes = file
            .segment_data_as_notes(&phdr)
            .expect("Failed to read relas section");
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
    fn bytes_test_for_segment_data_as_notes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(slice).expect("Open test1");

        let phdr = file
            .segments()
            .expect("File should have section table")
            .expect("shdrs should be readable")
            .get(5)
            .expect("Failed to get rela shdr");

        let mut notes = file
            .segment_data_as_notes(&phdr)
            .expect("Failed to read relas section");
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
    fn stream_test_for_dynamic() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

        let mut dynamic = file
            .dynamic()
            .expect("Failed to parse .dynamic")
            .expect("Failed to find .dynamic");
        assert_eq!(
            dynamic.next().expect("Failed to get dyn entry"),
            Dyn {
                d_tag: gabi::DT_NEEDED,
                d_un: 1
            }
        );
        assert_eq!(
            dynamic.next().expect("Failed to get dyn entry"),
            Dyn {
                d_tag: gabi::DT_INIT,
                d_un: 4195216
            }
        );
    }

    #[test]
    fn bytes_test_for_dynamic() {
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
                d_tag: gabi::DT_NEEDED,
                d_un: 1
            }
        );
        assert_eq!(
            dynamic.next().expect("Failed to get dyn entry"),
            Dyn {
                d_tag: gabi::DT_INIT,
                d_un: 4195216
            }
        );
    }

    #[test]
    fn stream_test_for_symbol_table() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

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
    fn bytes_test_for_symbol_table() {
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
    fn stream_test_for_dynamic_symbol_table() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");

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

    #[test]
    fn bytes_test_for_dynamic_symbol_table() {
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
