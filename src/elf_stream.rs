use core::ops::Range;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use crate::abi;
use crate::compression::CompressionHeader;
use crate::dynamic::DynamicTable;
use crate::endian::EndianParse;
use crate::file::{parse_ident, Class};
use crate::gnu_symver::{
    SymbolVersionTable, VerDefIterator, VerNeedIterator, VersionIndex, VersionIndexTable,
};
use crate::note::NoteIterator;
use crate::parse::{ParseAt, ParseError};
use crate::relocation::{RelIterator, RelaIterator};
use crate::section::{SectionHeader, SectionHeaderTable};
use crate::segment::ProgramHeader;
use crate::segment::SegmentTable;
use crate::string_table::StringTable;
use crate::symbol::{Symbol, SymbolTable};

use crate::file::FileHeader;

/// This type encapsulates the stream-oriented interface for parsing ELF objects from
/// a `Read + Seek`.
#[derive(Debug)]
pub struct ElfStream<E: EndianParse, S: std::io::Read + std::io::Seek> {
    pub ehdr: FileHeader<E>,
    shdrs: Vec<SectionHeader>,
    phdrs: Vec<ProgramHeader>,
    reader: CachingReader<S>,
}

/// Read the stream bytes backing the section headers table and parse them all into their Rust native type.
///
/// Returns a [ParseError] if the data bytes for the section table cannot be read.
/// i.e. if the ELF [FileHeader]'s e_shnum, e_shoff, e_shentsize are invalid and point
/// to a range in the file data that does not actually exist, or if any of the headers failed to parse.
fn parse_section_headers<E: EndianParse, S: Read + Seek>(
    ehdr: &FileHeader<E>,
    reader: &mut CachingReader<S>,
) -> Result<Vec<SectionHeader>, ParseError> {
    // It's Ok to have no section headers
    if ehdr.e_shoff == 0 {
        return Ok(Vec::default());
    }

    // Validate shentsize before trying to read the table so that we can error early for corrupted files
    let entsize = SectionHeader::validate_entsize(ehdr.class, ehdr.e_shentsize as usize)?;

    // If the number of sections is greater than or equal to SHN_LORESERVE (0xff00),
    // e_shnum is zero and the actual number of section header table entries
    // is contained in the sh_size field of the section header at index 0.
    let shoff: usize = ehdr.e_shoff.try_into()?;
    let mut shnum = ehdr.e_shnum as usize;
    if shnum == 0 {
        let end = shoff
            .checked_add(entsize)
            .ok_or(ParseError::IntegerOverflow)?;
        let mut offset = 0;
        let data = reader.read_bytes(shoff, end)?;
        let shdr0 = SectionHeader::parse_at(ehdr.endianness, ehdr.class, &mut offset, data)?;
        shnum = shdr0.sh_size.try_into()?;
    }

    let size = entsize
        .checked_mul(shnum)
        .ok_or(ParseError::IntegerOverflow)?;
    let end = shoff.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
    let buf = reader.read_bytes(shoff, end)?;
    let shdr_vec = SectionHeaderTable::new(ehdr.endianness, ehdr.class, buf)
        .iter()
        .collect();
    Ok(shdr_vec)
}

fn parse_program_headers<E: EndianParse, S: Read + Seek>(
    ehdr: &FileHeader<E>,
    reader: &mut CachingReader<S>,
) -> Result<Vec<ProgramHeader>, ParseError> {
    // It's Ok to have no program headers
    if ehdr.e_phoff == 0 {
        return Ok(Vec::default());
    }

    // If the number of segments is greater than or equal to PN_XNUM (0xffff),
    // e_phnum is set to PN_XNUM, and the actual number of program header table
    // entries is contained in the sh_info field of the section header at index 0.
    let mut phnum = ehdr.e_phnum as usize;
    if phnum == abi::PN_XNUM as usize {
        let shoff: usize = ehdr.e_shoff.try_into()?;
        let end = shoff
            .checked_add(SectionHeader::size_for(ehdr.class))
            .ok_or(ParseError::IntegerOverflow)?;
        let data = reader.read_bytes(shoff, end)?;
        let mut offset = 0;
        let shdr0 = SectionHeader::parse_at(ehdr.endianness, ehdr.class, &mut offset, data)?;
        phnum = shdr0.sh_info.try_into()?;
    }

    // Validate phentsize before trying to read the table so that we can error early for corrupted files
    let entsize = ProgramHeader::validate_entsize(ehdr.class, ehdr.e_phentsize as usize)?;

    let phoff: usize = ehdr.e_phoff.try_into()?;
    let size = entsize
        .checked_mul(phnum)
        .ok_or(ParseError::IntegerOverflow)?;
    let end = phoff.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
    let buf = reader.read_bytes(phoff, end)?;
    let phdrs_vec = SegmentTable::new(ehdr.endianness, ehdr.class, buf)
        .iter()
        .collect();
    Ok(phdrs_vec)
}

impl<E: EndianParse, S: std::io::Read + std::io::Seek> ElfStream<E, S> {
    /// Do a minimal amount of parsing work to open an [ElfStream] handle from a Read+Seek containing an ELF object.
    ///
    /// This parses the ELF [FileHeader], [SectionHeader] table, and [ProgramHeader] (segments) table.
    /// All other file data (section data, segment data) is left unread and unparsed.
    pub fn open_stream(reader: S) -> Result<ElfStream<E, S>, ParseError> {
        let mut cr = CachingReader::new(reader)?;
        let ident_buf = cr.read_bytes(0, abi::EI_NIDENT)?;
        let ident = parse_ident(ident_buf)?;

        let tail_start = abi::EI_NIDENT;
        let tail_end = match ident.1 {
            Class::ELF32 => tail_start + crate::file::ELF32_EHDR_TAILSIZE,
            Class::ELF64 => tail_start + crate::file::ELF64_EHDR_TAILSIZE,
        };
        let tail_buf = cr.read_bytes(tail_start, tail_end)?;

        let ehdr = FileHeader::parse_tail(ident, tail_buf)?;

        let shdrs = parse_section_headers(&ehdr, &mut cr)?;
        let phdrs = parse_program_headers(&ehdr, &mut cr)?;

        // We parsed out the ehdr and shdrs into their own allocated containers, so there's no need to keep
        // around their backing data anymore.
        cr.clear_cache();

        Ok(ElfStream {
            ehdr,
            shdrs,
            phdrs,
            reader: cr,
        })
    }

    /// Get the parsed section headers table
    pub fn segments(&self) -> &Vec<ProgramHeader> {
        &self.phdrs
    }

    /// Get the parsed section headers table
    pub fn section_headers(&self) -> &Vec<SectionHeader> {
        &self.shdrs
    }

    /// Get an lazy-parsing table for the Section Headers in the file and its associated StringTable.
    ///
    /// The underlying ELF bytes backing the section headers table and string
    /// table are read all at once when the table is requested, but parsing is
    /// deferred to be lazily parsed on demand on each table.get(), strtab.get(), or
    /// table.iter().next() call.
    ///
    /// Returns a [ParseError] if the data bytes for these tables cannot be
    /// read i.e. if the ELF [FileHeader]'s
    /// [e_shnum](FileHeader#structfield.e_shnum),
    /// [e_shoff](FileHeader#structfield.e_shoff),
    /// [e_shentsize](FileHeader#structfield.e_shentsize),
    /// [e_shstrndx](FileHeader#structfield.e_shstrndx) are invalid and point
    /// to a ranges in the file data that does not actually exist.
    pub fn section_headers_with_strtab(
        &mut self,
    ) -> Result<(&Vec<SectionHeader>, Option<StringTable<'_>>), ParseError> {
        // It's Ok to have no section headers
        if self.shdrs.is_empty() {
            return Ok((&self.shdrs, None));
        }

        // It's Ok to not have a string table
        if self.ehdr.e_shstrndx == abi::SHN_UNDEF {
            return Ok((&self.shdrs, None));
        }

        // If the section name string table section index is greater than or
        // equal to SHN_LORESERVE (0xff00), e_shstrndx has the value SHN_XINDEX
        // (0xffff) and the actual index of the section name string table section
        // is contained in the sh_link field of the section header at index 0.
        let mut shstrndx = self.ehdr.e_shstrndx as usize;
        if self.ehdr.e_shstrndx == abi::SHN_XINDEX {
            shstrndx = self.shdrs[0].sh_link as usize;
        }

        // We have a strtab, so wrap it in a zero-copy StringTable
        let strtab = self
            .shdrs
            .get(shstrndx)
            .ok_or(ParseError::BadOffset(shstrndx as u64))?;
        let (strtab_start, strtab_end) = strtab.get_data_range()?;
        let strtab_buf = self.reader.read_bytes(strtab_start, strtab_end)?;
        let strtab = StringTable::new(strtab_buf);
        Ok((&self.shdrs, Some(strtab)))
    }

    /// Find the parsed section header with the given name (if any).
    ///
    /// Returns a ParseError if the section headers string table can't be read
    ///
    /// Example to get the ELF file's ABI-tag note
    /// ```
    /// use elf::ElfStream;
    /// use elf::endian::AnyEndian;
    /// use elf::section::SectionHeader;
    /// use elf::note::Note;
    /// use elf::note::NoteGnuAbiTag;
    ///
    /// let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
    /// let io = std::fs::File::open(path).expect("Could not open file.");
    /// let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

    /// let shdr: SectionHeader = *file
    ///     .section_header_by_name(".note.ABI-tag")
    ///     .expect("section table should be parseable")
    ///     .expect("file should have a .note.ABI-tag section");
    ///
    /// let notes: Vec<_> = file
    ///     .section_data_as_notes(&shdr)
    ///     .expect("Should be able to get note section data")
    ///     .collect();
    /// assert_eq!(
    ///     notes[0],
    ///     Note::GnuAbiTag(NoteGnuAbiTag {
    ///         os: 0,
    ///         major: 2,
    ///         minor: 6,
    ///         subminor: 32
    ///     }));
    /// ```
    pub fn section_header_by_name(
        &mut self,
        name: &str,
    ) -> Result<Option<&SectionHeader>, ParseError> {
        let (shdrs, strtab) = match self.section_headers_with_strtab()? {
            (shdr, Some(strtab)) => (shdr, strtab),
            // We can't look up shdrs by name if there's no strtab.
            // (hint: try looking it up by its sh_type).
            _ => {
                return Ok(None);
            }
        };

        Ok(shdrs.iter().find(|shdr| {
            let sh_name = match strtab.get(shdr.sh_name as usize) {
                Ok(name) => name,
                _ => {
                    return false;
                }
            };
            name == sh_name
        }))
    }

    /// Read the section data for the given [SectionHeader](SectionHeader).
    /// Returns both the secion data and an optional CompressionHeader.
    ///
    /// No compression header signals that the section contents are uncompressed and can be used as-is.
    ///
    /// Some(chdr) signals that the section contents are compressed and need to be uncompressed via the
    /// compression algorithm described in [ch_type](CompressionHeader#structfield.ch_type).
    /// The returned buffer represents the compressed section bytes as found in the file, without the
    /// CompressionHeader.
    ///
    /// It is up to the user to perform the decompression themselves with the compression library of
    /// their choosing.
    ///
    /// SHT_NOBITS sections yield an empty slice.
    pub fn section_data(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<(&[u8], Option<CompressionHeader>), ParseError> {
        if shdr.sh_type == abi::SHT_NOBITS {
            return Ok((&[], None));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;

        if shdr.sh_flags & abi::SHF_COMPRESSED as u64 == 0 {
            Ok((buf, None))
        } else {
            let mut offset = 0;
            let chdr = CompressionHeader::parse_at(
                self.ehdr.endianness,
                self.ehdr.class,
                &mut offset,
                buf,
            )?;
            let compressed_buf = buf.get(offset..).ok_or(ParseError::SliceReadError((
                offset,
                shdr.sh_size.try_into()?,
            )))?;
            Ok((compressed_buf, Some(chdr)))
        }
    }

    /// Read the section data for the given
    /// [SectionHeader](SectionHeader) and interpret it in-place as a
    /// [StringTable](StringTable).
    ///
    /// Returns a [ParseError] if the
    /// [sh_type](SectionHeader#structfield.sh_type) is not
    /// [SHT_STRTAB](abi::SHT_STRTAB).
    pub fn section_data_as_strtab(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<StringTable<'_>, ParseError> {
        if shdr.sh_type != abi::SHT_STRTAB {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_STRTAB,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(StringTable::new(buf))
    }

    fn get_symbol_table_of_type(
        &mut self,
        symtab_type: u32,
    ) -> Result<Option<(SymbolTable<'_, E>, StringTable<'_>)>, ParseError> {
        if self.shdrs.is_empty() {
            return Ok(None);
        }

        // Get the symtab header for the symtab. The gABI states there can be zero or one per ELF file.
        match self.shdrs.iter().find(|shdr| shdr.sh_type == symtab_type) {
            Some(shdr) => {
                // Load the section bytes for the symtab
                // (we want immutable references to both the symtab and its strtab concurrently)
                let (symtab_start, symtab_end) = shdr.get_data_range()?;
                self.reader.load_bytes(symtab_start..symtab_end)?;

                // Load the section bytes for the strtab
                // (we want immutable references to both the symtab and its strtab concurrently)
                let strtab = self
                    .shdrs
                    .get(shdr.sh_link as usize)
                    .ok_or(ParseError::BadOffset(shdr.sh_link as u64))?;
                let (strtab_start, strtab_end) = strtab.get_data_range()?;
                self.reader.load_bytes(strtab_start..strtab_end)?;

                // Validate entsize before trying to read the table so that we can error early for corrupted files
                Symbol::validate_entsize(self.ehdr.class, shdr.sh_entsize.try_into()?)?;
                let symtab = SymbolTable::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    self.reader.get_bytes(symtab_start..symtab_end),
                );
                let strtab = StringTable::new(self.reader.get_bytes(strtab_start..strtab_end));
                Ok(Some((symtab, strtab)))
            }
            None => Ok(None),
        }
    }

    /// Get the symbol table (section of type SHT_SYMTAB) and its associated string table.
    ///
    /// The gABI specifies that ELF object files may have zero or one sections of type SHT_SYMTAB.
    pub fn symbol_table(
        &mut self,
    ) -> Result<Option<(SymbolTable<'_, E>, StringTable<'_>)>, ParseError> {
        self.get_symbol_table_of_type(abi::SHT_SYMTAB)
    }

    /// Get the dynamic symbol table (section of type SHT_DYNSYM) and its associated string table.
    ///
    /// The gABI specifies that ELF object files may have zero or one sections of type SHT_DYNSYM.
    pub fn dynamic_symbol_table(
        &mut self,
    ) -> Result<Option<(SymbolTable<'_, E>, StringTable<'_>)>, ParseError> {
        self.get_symbol_table_of_type(abi::SHT_DYNSYM)
    }

    /// Get the .dynamic section/segment contents.
    pub fn dynamic(&mut self) -> Result<Option<DynamicTable<'_, E>>, ParseError> {
        // If we have section headers, then look it up there
        if !self.shdrs.is_empty() {
            if let Some(shdr) = self
                .shdrs
                .iter()
                .find(|shdr| shdr.sh_type == abi::SHT_DYNAMIC)
            {
                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.read_bytes(start, end)?;
                return Ok(Some(DynamicTable::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    buf,
                )));
            }
        // Otherwise, look up the PT_DYNAMIC segment (if any)
        } else if !self.phdrs.is_empty() {
            if let Some(phdr) = self
                .phdrs
                .iter()
                .find(|phdr| phdr.p_type == abi::PT_DYNAMIC)
            {
                let (start, end) = phdr.get_file_data_range()?;
                let buf = self.reader.read_bytes(start, end)?;
                return Ok(Some(DynamicTable::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    buf,
                )));
            }
        }
        Ok(None)
    }

    /// Read the section data for the various GNU Symbol Versioning sections (if any)
    /// and return them in a [SymbolVersionTable] that which can interpret them in-place to
    /// yield [SymbolRequirement](crate::gnu_symver::SymbolRequirement)s
    /// and [SymbolDefinition](crate::gnu_symver::SymbolDefinition)s
    ///
    /// This is a GNU extension and not all objects use symbol versioning.
    /// Returns an empty Option if the object does not use symbol versioning.
    pub fn symbol_version_table(
        &mut self,
    ) -> Result<Option<SymbolVersionTable<'_, E>>, ParseError> {
        // No sections means no GNU symbol versioning sections, which is ok
        if self.shdrs.is_empty() {
            return Ok(None);
        }

        let mut versym_opt: Option<SectionHeader> = None;
        let mut needs_opt: Option<SectionHeader> = None;
        let mut defs_opt: Option<SectionHeader> = None;
        // Find the GNU Symbol versioning sections (if any)
        for shdr in self.shdrs.iter() {
            if shdr.sh_type == abi::SHT_GNU_VERSYM {
                versym_opt = Some(*shdr);
            } else if shdr.sh_type == abi::SHT_GNU_VERNEED {
                needs_opt = Some(*shdr);
            } else if shdr.sh_type == abi::SHT_GNU_VERDEF {
                defs_opt = Some(*shdr);
            }

            // If we've found all three sections, then we're done
            if versym_opt.is_some() && needs_opt.is_some() && defs_opt.is_some() {
                break;
            }
        }

        // No VERSYM section means the object doesn't use symbol versioning, which is ok.
        if versym_opt.is_none() {
            return Ok(None);
        }

        // Load the versym table
        let versym_shdr = versym_opt.unwrap();
        // Validate VERSYM entsize before trying to read the table so that we can error early for corrupted files
        VersionIndex::validate_entsize(self.ehdr.class, versym_shdr.sh_entsize.try_into()?)?;
        let (versym_start, versym_end) = versym_shdr.get_data_range()?;
        self.reader.load_bytes(versym_start..versym_end)?;

        // Get the VERNEED string shdr and load the VERNEED section data (if any)
        let needs_shdrs = match needs_opt {
            Some(shdr) => {
                let (start, end) = shdr.get_data_range()?;
                self.reader.load_bytes(start..end)?;

                let strs_shdr = self
                    .shdrs
                    .get(shdr.sh_link as usize)
                    .ok_or(ParseError::BadOffset(shdr.sh_link as u64))?;
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                self.reader.load_bytes(strs_start..strs_end)?;

                Some((shdr, strs_shdr))
            }
            // It's possible to have symbol versioning with no NEEDs if we're an object that only
            // exports defined symbols.
            None => None,
        };

        // Get the VERDEF string shdr and load the VERDEF section data (if any)
        let defs_shdrs = match defs_opt {
            Some(shdr) => {
                let (start, end) = shdr.get_data_range()?;
                self.reader.load_bytes(start..end)?;

                let strs_shdr = self
                    .shdrs
                    .get(shdr.sh_link as usize)
                    .ok_or(ParseError::BadOffset(shdr.sh_link as u64))?;
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                self.reader.load_bytes(strs_start..strs_end)?;

                Some((shdr, strs_shdr))
            }
            // It's possible to have symbol versioning with no DEFs if we're an object that doesn't
            // export any symbols but does use dynamic symbols from other objects.
            None => None,
        };

        // Wrap the VERNEED section and strings data in an iterator and string table
        let verneeds = match needs_shdrs {
            Some((shdr, strs_shdr)) => {
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                let strs_buf = self.reader.get_bytes(strs_start..strs_end);

                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.get_bytes(start..end);
                Some((
                    VerNeedIterator::new(
                        self.ehdr.endianness,
                        self.ehdr.class,
                        shdr.sh_info as u64,
                        0,
                        buf,
                    ),
                    StringTable::new(strs_buf),
                ))
            }
            // If there's no NEEDs, then construct empty wrappers for them
            None => None,
        };

        // Wrap the VERDEF section and strings data in an iterator and string table
        let verdefs = match defs_shdrs {
            Some((shdr, strs_shdr)) => {
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                let strs_buf = self.reader.get_bytes(strs_start..strs_end);

                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.get_bytes(start..end);
                Some((
                    VerDefIterator::new(
                        self.ehdr.endianness,
                        self.ehdr.class,
                        shdr.sh_info as u64,
                        0,
                        buf,
                    ),
                    StringTable::new(strs_buf),
                ))
            }
            // If there's no DEFs, then construct empty wrappers for them
            None => None,
        };

        // Wrap the versym section data in a parsing table
        let version_ids = VersionIndexTable::new(
            self.ehdr.endianness,
            self.ehdr.class,
            self.reader.get_bytes(versym_start..versym_end),
        );

        // whew, we're done here!
        Ok(Some(SymbolVersionTable::new(
            version_ids,
            verneeds,
            verdefs,
        )))
    }

    /// Read the section data for the given
    /// [SectionHeader](SectionHeader) and interpret it in-place as a
    /// [RelIterator](RelIterator).
    ///
    /// Returns a [ParseError] if the
    /// [sh_type](SectionHeader#structfield.sh_type) is not
    /// [SHT_REL](abi::SHT_REL).
    pub fn section_data_as_rels(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<RelIterator<'_, E>, ParseError> {
        if shdr.sh_type != abi::SHT_REL {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_REL,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(RelIterator::new(self.ehdr.endianness, self.ehdr.class, buf))
    }

    /// Read the section data for the given
    /// [SectionHeader](SectionHeader) and interpret it in-place as a
    /// [RelaIterator](RelaIterator).
    ///
    /// Returns a [ParseError] if the
    /// [sh_type](SectionHeader#structfield.sh_type) is not
    /// [SHT_RELA](abi::SHT_RELA).
    pub fn section_data_as_relas(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<RelaIterator<'_, E>, ParseError> {
        if shdr.sh_type != abi::SHT_RELA {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_RELA,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(RelaIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            buf,
        ))
    }

    /// Read the section data for the given
    /// [SectionHeader](SectionHeader) and interpret it in-place as a
    /// [NoteIterator](NoteIterator).
    ///
    /// Returns a [ParseError] if the
    /// [sh_type](SectionHeader#structfield.sh_type) is not
    /// [SHT_RELA](abi::SHT_NOTE).
    pub fn section_data_as_notes(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<NoteIterator<'_, E>, ParseError> {
        if shdr.sh_type != abi::SHT_NOTE {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_NOTE,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(NoteIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            shdr.sh_addralign as usize,
            buf,
        ))
    }

    /// Read the segment data for the given
    /// [Segment](ProgramHeader) and interpret it in-place as a
    /// [NoteIterator](NoteIterator).
    ///
    /// Returns a [ParseError] if the
    /// [p_type](ProgramHeader#structfield.p_type) is not
    /// [PT_RELA](abi::PT_NOTE).
    pub fn segment_data_as_notes(
        &mut self,
        phdr: &ProgramHeader,
    ) -> Result<NoteIterator<'_, E>, ParseError> {
        if phdr.p_type != abi::PT_NOTE {
            return Err(ParseError::UnexpectedSegmentType((
                phdr.p_type,
                abi::PT_NOTE,
            )));
        }

        let (start, end) = phdr.get_file_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(NoteIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            phdr.p_align as usize,
            buf,
        ))
    }
}

#[derive(Debug)]
struct CachingReader<R: Read + Seek> {
    reader: R,
    stream_len: u64,
    bufs: HashMap<(usize, usize), Box<[u8]>>,
}

impl<R: Read + Seek> CachingReader<R> {
    fn new(mut reader: R) -> Result<Self, ParseError> {
        // Cache the size of the stream so that we can err (rather than OOM) on invalid
        // huge read requests.
        let stream_len = reader.seek(SeekFrom::End(0))?;
        Ok(CachingReader {
            reader,
            stream_len,
            bufs: HashMap::<(usize, usize), Box<[u8]>>::default(),
        })
    }

    fn read_bytes(&mut self, start: usize, end: usize) -> Result<&[u8], ParseError> {
        self.load_bytes(start..end)?;
        Ok(self.get_bytes(start..end))
    }

    fn get_bytes(&self, range: Range<usize>) -> &[u8] {
        // It's a programmer error to call get_bytes without first calling load_bytes, so
        // we want to panic here.
        self.bufs
            .get(&(range.start, range.end))
            .expect("load_bytes must be called before get_bytes for every range")
    }

    fn load_bytes(&mut self, range: Range<usize>) -> Result<(), ParseError> {
        if self.bufs.contains_key(&(range.start, range.end)) {
            return Ok(());
        }

        // Verify that the read range doesn't go past the end of the stream (corrupted files)
        let end = range.end as u64;
        if end > self.stream_len {
            return Err(ParseError::BadOffset(end));
        }

        self.reader.seek(SeekFrom::Start(range.start as u64))?;
        let mut bytes = vec![0; range.len()].into_boxed_slice();
        self.reader.read_exact(&mut bytes)?;
        self.bufs.insert((range.start, range.end), bytes);
        Ok(())
    }

    fn clear_cache(&mut self) {
        self.bufs.clear()
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::dynamic::Dyn;
    use crate::endian::AnyEndian;
    use crate::hash::SysVHashTable;
    use crate::note::{Note, NoteGnuAbiTag, NoteGnuBuildId};
    use crate::relocation::Rela;
    use crate::symbol::Symbol;

    #[test]
    fn test_open_stream() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");
        assert_eq!(file.ehdr.e_type, abi::ET_EXEC);
    }

    #[test]
    fn section_headers_with_strtab() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let (shdrs, strtab) = file
            .section_headers_with_strtab()
            .expect("Failed to get shdrs");
        let (shdrs, strtab) = (shdrs, strtab.unwrap());

        let shdr_4 = &shdrs[4];
        let name = strtab
            .get(shdr_4.sh_name as usize)
            .expect("Failed to get section name");

        assert_eq!(name, ".gnu.hash");
        assert_eq!(shdr_4.sh_type, abi::SHT_GNU_HASH);
    }

    #[test]
    fn shnum_and_shstrndx_in_shdr0() {
        let path = std::path::PathBuf::from("sample-objects/shnum.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let (shdrs, strtab) = file
            .section_headers_with_strtab()
            .expect("shdrs should be parsable");
        let (shdrs, strtab) = (shdrs, strtab.unwrap());

        let shdrs_len = shdrs.len();
        assert_eq!(shdrs_len, 0xFF15);

        let shdr = shdrs.get(shdrs_len - 1).unwrap();
        let name = strtab
            .get(shdr.sh_name as usize)
            .expect("Failed to get section name");

        assert_eq!(name, ".shstrtab");
        assert_eq!(shdr.sh_type, abi::SHT_STRTAB);
    }

    #[test]
    fn section_header_by_name() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr: SectionHeader = *file
            .section_header_by_name(".gnu.hash")
            .expect("section table should be parseable")
            .expect("file should have .gnu.hash section");

        assert_eq!(shdr.sh_type, abi::SHT_GNU_HASH);

        let shdr = file
            .section_header_by_name(".not.found")
            .expect("section table should be parseable");

        assert_eq!(shdr, None);
    }

    #[test]
    fn section_data_for_nobits() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file.section_headers()[26];
        assert_eq!(shdr.sh_type, abi::SHT_NOBITS);
        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");
        assert_eq!(chdr, None);
        assert_eq!(data, &[]);
    }

    #[test]
    fn section_data() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file.section_headers()[7];
        assert_eq!(shdr.sh_type, abi::SHT_GNU_VERSYM);
        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");
        assert_eq!(chdr, None);
        assert_eq!(data, [0, 0, 2, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn section_data_as_strtab() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file.section_headers()[file.ehdr.e_shstrndx as usize];
        let strtab = file
            .section_data_as_strtab(&shdr)
            .expect("Failed to read strtab");
        assert_eq!(
            strtab.get(1).expect("Failed to get strtab entry"),
            ".symtab"
        );
    }

    #[test]
    fn segments() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let segments = file.segments();
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
        )
    }

    #[test]
    fn segments_phnum_in_shdr0() {
        let path = std::path::PathBuf::from("sample-objects/phnum.m68k.so");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        assert_eq!(
            file.segments()[0],
            ProgramHeader {
                p_type: abi::PT_PHDR,
                p_offset: 92,
                p_vaddr: 0,
                p_paddr: 0,
                p_filesz: 32,
                p_memsz: 32,
                p_flags: 0x20003,
                p_align: 0x40000,
            }
        );
    }

    #[test]
    fn symbol_table() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

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
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

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
    fn dynamic() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let mut dynamic = file
            .dynamic()
            .expect("Failed to parse .dynamic")
            .expect("Failed to find .dynamic")
            .iter();
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
    fn section_data_as_rels() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file.section_headers()[10];
        file.section_data_as_rels(&shdr)
            .expect_err("Expected error parsing non-REL scn as RELs");
    }

    #[test]
    fn section_data_as_relas() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file.section_headers()[10];
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
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file.section_headers()[2];
        let mut notes = file
            .section_data_as_notes(&shdr)
            .expect("Failed to read relas section");
        assert_eq!(
            notes.next().expect("Failed to get first note"),
            Note::GnuAbiTag(NoteGnuAbiTag {
                os: 0,
                major: 2,
                minor: 6,
                subminor: 32
            })
        );
        assert!(notes.next().is_none());
    }

    #[test]
    fn segment_data_as_notes() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let phdrs = file.segments();
        let note_phdr = phdrs[5];
        let mut notes = file
            .segment_data_as_notes(&note_phdr)
            .expect("Failed to read relas section");
        assert_eq!(
            notes.next().expect("Failed to get first note"),
            Note::GnuAbiTag(NoteGnuAbiTag {
                os: 0,
                major: 2,
                minor: 6,
                subminor: 32
            })
        );
        assert_eq!(
            notes.next().expect("Failed to get second note"),
            Note::GnuBuildId(NoteGnuBuildId(&[
                119, 65, 159, 13, 165, 16, 131, 12, 87, 167, 200, 204, 176, 238, 133, 95, 238, 211,
                118, 163
            ]))
        );
        assert!(notes.next().is_none());
    }

    #[test]
    fn symbol_version_table() {
        let path = std::path::PathBuf::from("sample-objects/symver.x86_64.so");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let vst = file
            .symbol_version_table()
            .expect("Failed to parse GNU symbol versions")
            .expect("Failed to find GNU symbol versions");

        let req = vst
            .get_requirement(2)
            .expect("Failed to parse NEED")
            .expect("Failed to find NEED");
        assert_eq!(req.file, "libc.so.6");
        assert_eq!(req.name, "GLIBC_2.2.5");
        assert_eq!(req.hash, 0x9691A75);

        let req = vst.get_requirement(3).expect("Failed to parse NEED");
        assert!(req.is_none());

        let req = vst.get_requirement(4).expect("Failed to parse NEED");
        assert!(req.is_none());

        let req = vst
            .get_requirement(5)
            .expect("Failed to parse NEED")
            .expect("Failed to find NEED");
        assert_eq!(req.file, "libc.so.6");
        assert_eq!(req.name, "GLIBC_2.2.5");
        assert_eq!(req.hash, 0x9691A75);

        let def = vst
            .get_definition(3)
            .expect("Failed to parse DEF")
            .expect("Failed to find DEF");
        assert_eq!(def.hash, 0xC33237F);
        assert_eq!(def.flags, 1);
        assert!(!def.hidden);
        let def_names: Vec<&str> = def.names.map(|res| res.expect("should parse")).collect();
        assert_eq!(def_names, &["hello.so"]);

        let def = vst
            .get_definition(7)
            .expect("Failed to parse DEF")
            .expect("Failed to find DEF");
        assert_eq!(def.hash, 0x1570B62);
        assert_eq!(def.flags, 0);
        assert!(def.hidden);
        let def_names: Vec<&str> = def.names.map(|res| res.expect("should parse")).collect();
        assert_eq!(def_names, &["HELLO_1.42"]);
    }

    #[test]
    fn sysv_hash_table() {
        let path = std::path::PathBuf::from("sample-objects/symver.x86_64.so");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        // Look up the SysV hash section header
        let hash_shdr = *file
            .section_header_by_name(".hash")
            .expect("Failed to find sysv hash section")
            .expect("Failed to find sysv hash section");

        // We don't have a file interface for getting the SysV hash section yet, so clone the section bytes
        // So we can use them to back a SysVHashTable
        let (data, _) = file
            .section_data(&hash_shdr)
            .expect("Failed to get hash section data");
        let data_copy: Vec<u8> = data.into();
        let hash_table =
            SysVHashTable::new(file.ehdr.endianness, file.ehdr.class, data_copy.as_ref())
                .expect("Failed to parse hash table");

        // Get the dynamic symbol table.
        let (symtab, strtab) = file
            .dynamic_symbol_table()
            .expect("Failed to read symbol table")
            .expect("Failed to find symbol table");

        // Verify that these three symbols all collide in the hash table's buckets
        assert_eq!(crate::hash::sysv_hash(b"use_memset_v2"), 0x8080542);
        assert_eq!(crate::hash::sysv_hash(b"__gmon_start__"), 0xF4D007F);
        assert_eq!(crate::hash::sysv_hash(b"memset"), 0x73C49C4);
        assert_eq!(crate::hash::sysv_hash(b"use_memset_v2") % 3, 0);
        assert_eq!(crate::hash::sysv_hash(b"__gmon_start__") % 3, 0);
        assert_eq!(crate::hash::sysv_hash(b"memset") % 3, 0);

        // Use the hash table to find a given symbol in it.
        let (sym_idx, sym) = hash_table
            .find(b"memset", &symtab, &strtab)
            .expect("Failed to parse hash")
            .expect("Failed to find hash");

        // Verify that we got the same symbol from the hash table we expected
        assert_eq!(sym_idx, 2);
        assert_eq!(strtab.get(sym.st_name as usize).unwrap(), "memset");
        assert_eq!(
            sym,
            symtab.get(sym_idx).expect("Failed to get expected sym")
        );
    }
}

#[cfg(test)]
mod arch_tests {
    use super::*;
    use crate::endian::AnyEndian;

    // Basic smoke test which parses out symbols and headers for a given sample object of a given architecture
    macro_rules! arch_test {
        ( $arch:expr, $e_machine:expr, $endian:expr) => {{
            let path_str = format!("sample-objects/symver.{}.so", $arch);
            let path = std::path::PathBuf::from(path_str);
            let io = std::fs::File::open(path).expect("file should exist");
            let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("should parse");

            assert_eq!(file.ehdr.e_machine, $e_machine);
            assert_eq!(file.ehdr.endianness, $endian);

            let (shdrs, strtab) = file.section_headers_with_strtab().expect("should parse");
            let (shdrs, strtab) = (shdrs, strtab.unwrap());
            let _: Vec<_> = shdrs
                .iter()
                .map(|shdr| {
                    (
                        strtab.get(shdr.sh_name as usize).expect("should parse"),
                        shdr,
                    )
                })
                .collect();

            if let Some((symtab, strtab)) = file.symbol_table().expect("should parse") {
                let _: Vec<_> = symtab
                    .iter()
                    .map(|sym| (strtab.get(sym.st_name as usize).expect("should parse"), sym))
                    .collect();
            }

            if let Some((symtab, strtab)) = file.dynamic_symbol_table().expect("should parse") {
                let _: Vec<_> = symtab
                    .iter()
                    .map(|sym| (strtab.get(sym.st_name as usize).expect("should parse"), sym))
                    .collect();
            }

            let note_phdrs: Vec<_> = file.segments()
                .iter()
                .filter(|phdr| phdr.p_type == abi::PT_NOTE)
                .map(|phdr| *phdr)
                .collect();
            for phdr in note_phdrs {
                let _: Vec<_> = file
                    .segment_data_as_notes(&phdr)
                    .expect("should parse")
                    .collect();
            }
        }};
    }

    #[test]
    fn x86_64() {
        arch_test!("x86_64", abi::EM_X86_64, AnyEndian::Little);
    }

    #[test]
    fn m68k() {
        arch_test!("m68k", abi::EM_68K, AnyEndian::Big);
    }

    #[test]
    fn aarch64() {
        arch_test!("aarch64", abi::EM_AARCH64, AnyEndian::Little);
    }

    #[test]
    fn armhf() {
        arch_test!("armhf", abi::EM_ARM, AnyEndian::Little);
    }

    #[test]
    fn powerpc64() {
        arch_test!("powerpc64", abi::EM_PPC64, AnyEndian::Big);
    }

    #[test]
    fn powerpc64le() {
        arch_test!("powerpc64le", abi::EM_PPC64, AnyEndian::Little);
    }

    #[test]
    fn riscv64() {
        arch_test!("riscv64", abi::EM_RISCV, AnyEndian::Little);
    }
}
