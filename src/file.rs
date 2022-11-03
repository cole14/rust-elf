use crate::compression::CompressionHeader;
use crate::dynamic::DynIterator;
use crate::gabi;
use crate::gnu_symver::{
    SymbolVersionTable, VerDefIterator, VerNeedIterator, VersionIndex, VersionIndexTable,
};
use crate::note::NoteIterator;
use crate::parse::{
    parse_u16_at, parse_u32_at, parse_u64_at, Class, Endian, ParseAt, ParseError, ReadBytesAt,
};
use crate::relocation::{RelIterator, RelaIterator};
use crate::section::{SectionHeader, SectionHeaderTable};
use crate::segment::{ProgramHeader, SegmentTable};
use crate::string_table::StringTable;
use crate::symbol::{Symbol, SymbolTable};

pub struct File<R: ReadBytesAt> {
    reader: R,
    pub ehdr: FileHeader,
}

impl<R: ReadBytesAt> File<R> {
    pub fn open_stream(mut reader: R) -> Result<File<R>, ParseError> {
        let ehdr = FileHeader::parse(&mut reader)?;

        Ok(File { reader, ehdr })
    }

    /// Get an lazy-parsing table for the Segments (ELF Program Headers) in the file.
    ///
    /// The underlying ELF bytes backing the program headers table are read all at once
    /// when the table is requested, but parsing is deferred to be lazily
    /// parsed on demand on each table.get() call or table.iter().next() call.
    ///
    /// Returns a [ParseError] if the data bytes for the segment table cannot be
    /// read i.e. if the ELF [FileHeader]'s
    /// [e_phnum](FileHeader#structfield.e_phnum),
    /// [e_phoff](FileHeader#structfield.e_phoff),
    /// [e_phentsize](FileHeader#structfield.e_phentsize) are invalid and point
    /// to a range in the file data that does not actually exist.
    pub fn segments(&mut self) -> Result<SegmentTable, ParseError> {
        match self.ehdr.get_phdrs_data_range()? {
            Some((start, end)) => {
                let buf = self.reader.read_bytes_at(start..end)?;
                Ok(SegmentTable::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    buf,
                ))
            }
            // If the file doesn't have a program header table, return an empty table
            //
            // Note: It'd be more intuitive if this interface returned a
            // Result<Option<SegmentTable>, ParseError> instead so that users could match on None
            // instead of getting a real but empty table. I'm going to defer that change for
            // a release where I can bundle other such breaking interface changes together.
            None => Ok(SegmentTable::new(
                self.ehdr.endianness,
                self.ehdr.class,
                &[],
            )),
        }
    }

    fn shnum(&mut self) -> Result<u64, ParseError> {
        // If the number of sections is greater than or equal to SHN_LORESERVE (0xff00),
        // e_shnum is zero and the actual number of section header table entries
        // is contained in the sh_size field of the section header at index 0.
        let mut shnum = self.ehdr.e_shnum as u64;
        if self.ehdr.e_shoff > 0 && self.ehdr.e_shnum == 0 {
            let shdr_0 = self.section_header_by_index(0)?;
            shnum = shdr_0.sh_size;
        }
        Ok(shnum)
    }

    fn shstrndx(&mut self) -> Result<u32, ParseError> {
        // If the section name string table section index is greater than or
        // equal to SHN_LORESERVE (0xff00), e_shstrndx has the value SHN_XINDEX
        // (0xffff) and the actual index of the section name string table section
        // is contained in the sh_link field of the section header at index 0.
        let mut shstrndx = self.ehdr.e_shstrndx as u32;
        if self.ehdr.e_shstrndx == gabi::SHN_XINDEX {
            let shdr_0 = self.section_header_by_index(0)?;
            shstrndx = shdr_0.sh_link;
        }
        Ok(shstrndx)
    }

    /// Helper method for reading a particular section header without the need to know the whole
    /// section table size. Useful for reading header[0] to get shnum or shstrndx.
    fn section_header_by_index(&mut self, index: usize) -> Result<SectionHeader, ParseError> {
        if self.ehdr.e_shnum > 0 && index >= self.ehdr.e_shnum as usize {
            return Err(ParseError::BadOffset(index as u64));
        }

        // Validate shentsize before trying to read so that we can error early for corrupted files
        let entsize =
            SectionHeader::validate_entsize(self.ehdr.class, self.ehdr.e_shentsize as usize)?;

        let shoff: usize = self.ehdr.e_shoff.try_into()?;
        let entry_off = index
            .checked_mul(entsize)
            .ok_or(ParseError::IntegerOverflow)?;
        let start = shoff
            .checked_add(entry_off)
            .ok_or(ParseError::IntegerOverflow)?;
        let end = start
            .checked_add(entsize)
            .ok_or(ParseError::IntegerOverflow)?;
        let buf = self.reader.read_bytes_at(start..end)?;
        let mut offset = 0;
        SectionHeader::parse_at(self.ehdr.endianness, self.ehdr.class, &mut offset, buf)
    }

    /// Get an lazy-parsing table for the Section Headers in the file.
    ///
    /// The underlying ELF bytes backing the section headers table are read all at once
    /// when the table is requested, but parsing is deferred to be lazily
    /// parsed on demand on each table.get() call or table.iter().next() call.
    ///
    /// Returns a [ParseError] if the data bytes for the section table cannot be
    /// read i.e. if the ELF [FileHeader]'s
    /// [e_shnum](FileHeader#structfield.e_shnum),
    /// [e_shoff](FileHeader#structfield.e_shoff),
    /// [e_shentsize](FileHeader#structfield.e_shentsize) are invalid and point
    /// to a range in the file data that does not actually exist.
    pub fn section_headers(&mut self) -> Result<SectionHeaderTable, ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok(SectionHeaderTable::new(
                self.ehdr.endianness,
                self.ehdr.class,
                &[],
            ));
        }

        // Get the number of section headers (could be in ehdr or shdrs[0])
        let shnum: usize = self.shnum()?.try_into()?;

        // Validate shentsize before trying to read the table so that we can error early for corrupted files
        let entsize =
            SectionHeader::validate_entsize(self.ehdr.class, self.ehdr.e_shentsize as usize)?;

        let start: usize = self.ehdr.e_shoff.try_into()?;
        let size = entsize
            .checked_mul(shnum)
            .ok_or(ParseError::IntegerOverflow)?;
        let end = start.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
        let buf = self.reader.read_bytes_at(start..end)?;
        Ok(SectionHeaderTable::new(
            self.ehdr.endianness,
            self.ehdr.class,
            buf,
        ))
    }

    /// Get an lazy-parsing table for the Section Headers in the file and its associated StringTable.
    ///
    /// The underlying ELF bytes backing the section headers table  and string
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
    ) -> Result<(SectionHeaderTable, StringTable), ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok((
                SectionHeaderTable::new(self.ehdr.endianness, self.ehdr.class, &[]),
                StringTable::default(),
            ));
        }

        // Load the section header table bytes (we want concurrent referneces to strtab too)
        let shnum: usize = self.shnum()?.try_into()?;

        // Validate shentsize before trying to read the table so that we can error early for corrupted files
        let entsize =
            SectionHeader::validate_entsize(self.ehdr.class, self.ehdr.e_shentsize as usize)?;
        let shdrs_start: usize = self.ehdr.e_shoff.try_into()?;
        let shdrs_size = entsize
            .checked_mul(shnum)
            .ok_or(ParseError::IntegerOverflow)?;
        let shdrs_end = shdrs_start
            .checked_add(shdrs_size)
            .ok_or(ParseError::IntegerOverflow)?;
        self.reader.load_bytes_at(shdrs_start..shdrs_end)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        // Get the index of section headers' strtab (could be in ehdr or shdrs[0])
        let shstrndx: usize = self.shstrndx()?.try_into()?;

        let strtab = self.section_header_by_index(shstrndx)?;
        let (strtab_start, strtab_end) = strtab.get_data_range()?;
        self.reader.load_bytes_at(strtab_start..strtab_end)?;

        // Return the (symtab, strtab)
        let shdrs = SectionHeaderTable::new(
            self.ehdr.endianness,
            self.ehdr.class,
            self.reader.get_loaded_bytes_at(shdrs_start..shdrs_end),
        );
        let strtab = StringTable::new(self.reader.get_loaded_bytes_at(strtab_start..strtab_end));
        Ok((shdrs, strtab))
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
        if shdr.sh_type == gabi::SHT_NOBITS {
            return Ok((&[], None));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes_at(start..end)?;

        if shdr.sh_flags & gabi::SHF_COMPRESSED as u64 == 0 {
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
    /// [SHT_STRTAB](gabi::SHT_STRTAB).
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

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes_at(start..end)?;
        Ok(StringTable::new(buf))
    }

    fn get_symbol_table_of_type(
        &mut self,
        symtab_type: u32,
    ) -> Result<Option<(SymbolTable, StringTable)>, ParseError> {
        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match self
            .section_headers()?
            .iter()
            .find(|shdr| shdr.sh_type == symtab_type)
        {
            Some(shdr) => shdr,
            None => return Ok(None),
        };

        // Load the section bytes for the symtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let (symtab_start, symtab_end) = symtab_shdr.get_data_range()?;
        self.reader.load_bytes_at(symtab_start..symtab_end)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let strtab = self.section_header_by_index(symtab_shdr.sh_link as usize)?;
        let (strtab_start, strtab_end) = strtab.get_data_range()?;
        self.reader.load_bytes_at(strtab_start..strtab_end)?;

        // Validate entsize before trying to read the table so that we can error early for corrupted files
        Symbol::validate_entsize(self.ehdr.class, symtab_shdr.sh_entsize.try_into()?)?;
        let symtab = SymbolTable::new(
            self.ehdr.endianness,
            self.ehdr.class,
            self.reader.get_loaded_bytes_at(symtab_start..symtab_end),
        );
        let strtab = StringTable::new(self.reader.get_loaded_bytes_at(strtab_start..strtab_end));
        Ok(Some((symtab, strtab)))
    }

    /// Get the symbol table (section of type SHT_SYMTAB) and its associated string table.
    ///
    /// The GABI specifies that ELF object files may have zero or one sections of type SHT_SYMTAB.
    pub fn symbol_table(&mut self) -> Result<Option<(SymbolTable, StringTable)>, ParseError> {
        self.get_symbol_table_of_type(gabi::SHT_SYMTAB)
    }

    /// Get the dynamic symbol table (section of type SHT_DYNSYM) and its associated string table.
    ///
    /// The GABI specifies that ELF object files may have zero or one sections of type SHT_DYNSYM.
    pub fn dynamic_symbol_table(
        &mut self,
    ) -> Result<Option<(SymbolTable, StringTable)>, ParseError> {
        self.get_symbol_table_of_type(gabi::SHT_DYNSYM)
    }

    /// Get the .dynamic section/segment contents.
    pub fn dynamic_section(&mut self) -> Result<Option<DynIterator>, ParseError> {
        // If we have section headers, then look it up there
        if self.ehdr.e_shoff > 0 {
            if let Some(shdr) = self
                .section_headers()?
                .iter()
                .find(|shdr| shdr.sh_type == gabi::SHT_DYNAMIC)
            {
                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.read_bytes_at(start..end)?;
                return Ok(Some(DynIterator::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    buf,
                )));
            }
        } else {
            if let Some(phdr) = self
                .segments()?
                .iter()
                .find(|phdr| phdr.p_type == gabi::PT_DYNAMIC)
            {
                let (start, end) = phdr.get_file_data_range()?;
                let buf = self.reader.read_bytes_at(start..end)?;
                return Ok(Some(DynIterator::new(
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
    pub fn symbol_version_table(&mut self) -> Result<Option<SymbolVersionTable>, ParseError> {
        let mut versym_opt: Option<SectionHeader> = None;
        let mut needs_opt: Option<SectionHeader> = None;
        let mut defs_opt: Option<SectionHeader> = None;
        // Find the GNU Symbol versioning sections (if any)
        for shdr in self.section_headers()? {
            if shdr.sh_type == gabi::SHT_GNU_VERSYM {
                versym_opt = Some(shdr);
            } else if shdr.sh_type == gabi::SHT_GNU_VERNEED {
                needs_opt = Some(shdr);
            } else if shdr.sh_type == gabi::SHT_GNU_VERDEF {
                defs_opt = Some(shdr);
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
        self.reader.load_bytes_at(versym_start..versym_end)?;

        // Get the VERNEED string shdr and load the VERNEED section data (if any)
        let needs_shdrs = match needs_opt {
            Some(shdr) => {
                let (start, end) = shdr.get_data_range()?;
                self.reader.load_bytes_at(start..end)?;

                let strs_shdr = self.section_header_by_index(shdr.sh_link as usize)?;
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                self.reader.load_bytes_at(strs_start..strs_end)?;

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
                self.reader.load_bytes_at(start..end)?;

                let strs_shdr = self.section_header_by_index(shdr.sh_link as usize)?;
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                self.reader.load_bytes_at(strs_start..strs_end)?;

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
                let strs_buf = self.reader.get_loaded_bytes_at(strs_start..strs_end);

                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.get_loaded_bytes_at(start..end);
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
                let strs_buf = self.reader.get_loaded_bytes_at(strs_start..strs_end);

                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.get_loaded_bytes_at(start..end);
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
            self.reader.get_loaded_bytes_at(versym_start..versym_end),
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
    /// [SHT_REL](gabi::SHT_REL).
    pub fn section_data_as_rels(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<RelIterator, ParseError> {
        if shdr.sh_type != gabi::SHT_REL {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_REL,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes_at(start..end)?;
        Ok(RelIterator::new(self.ehdr.endianness, self.ehdr.class, buf))
    }

    /// Read the section data for the given
    /// [SectionHeader](SectionHeader) and interpret it in-place as a
    /// [RelaIterator](RelaIterator).
    ///
    /// Returns a [ParseError] if the
    /// [sh_type](SectionHeader#structfield.sh_type) is not
    /// [SHT_RELA](gabi::SHT_RELA).
    pub fn section_data_as_relas(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<RelaIterator, ParseError> {
        if shdr.sh_type != gabi::SHT_RELA {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_RELA,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes_at(start..end)?;
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
    /// [SHT_RELA](gabi::SHT_NOTE).
    pub fn section_data_as_notes(
        &mut self,
        shdr: &SectionHeader,
    ) -> Result<NoteIterator, ParseError> {
        if shdr.sh_type != gabi::SHT_NOTE {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                gabi::SHT_NOTE,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes_at(start..end)?;
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
    /// [PT_RELA](gabi::PT_NOTE).
    pub fn segment_data_as_notes(
        &mut self,
        phdr: &ProgramHeader,
    ) -> Result<NoteIterator, ParseError> {
        if phdr.p_type != gabi::PT_NOTE {
            return Err(ParseError::UnexpectedSegmentType((
                phdr.p_type,
                gabi::PT_NOTE,
            )));
        }

        let (start, end) = phdr.get_file_data_range()?;
        let buf = self.reader.read_bytes_at(start..end)?;
        Ok(NoteIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            phdr.p_align as usize,
            buf,
        ))
    }
}

/// Encapsulates the contents of the ELF File Header
///
/// The ELF File Header starts off every ELF file and both identifies the
/// file contents and informs how to interpret said contents. This includes
/// the width of certain fields (32-bit vs 64-bit), the data endianness, the
/// file type, and more.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    /// 32-bit vs 64-bit
    pub class: Class,
    /// little vs big endian
    pub endianness: Endian,
    /// elf version
    pub version: u32,
    /// OS ABI
    pub osabi: u8,
    /// Version of the OS ABI
    pub abiversion: u8,
    /// ELF file type
    pub e_type: u16,
    /// Target machine architecture
    pub e_machine: u16,
    /// Virtual address of program entry point
    /// This member gives the virtual address to which the system first transfers control,
    /// thus starting the process. If the file has no associated entry point, this member holds zero.
    ///
    /// Note: Type is Elf32_Addr or Elf64_Addr which are either 4 or 8 bytes. We aren't trying to zero-copy
    /// parse the FileHeader since there's only one per file and its only ~45 bytes anyway, so we use
    /// u64 for the three Elf*_Addr and Elf*_Off fields here.
    pub e_entry: u64,
    /// This member holds the program header table's file offset in bytes. If the file has no program header
    /// table, this member holds zero.
    pub e_phoff: u64,
    /// This member holds the section header table's file offset in bytes. If the file has no section header
    /// table, this member holds zero.
    pub e_shoff: u64,
    /// This member holds processor-specific flags associated with the file. Flag names take the form EF_machine_flag.
    pub e_flags: u32,
    /// This member holds the ELF header's size in bytes.
    pub e_ehsize: u16,
    /// This member holds the size in bytes of one entry in the file's program header table; all entries are the same size.
    pub e_phentsize: u16,
    /// This member holds the number of entries in the program header table. Thus the product of e_phentsize and e_phnum
    /// gives the table's size in bytes. If a file has no program header table, e_phnum holds the value zero.
    pub e_phnum: u16,
    /// This member holds a section header's size in bytes. A section header is one entry in the section header table;
    /// all entries are the same size.
    pub e_shentsize: u16,
    /// This member holds the number of entries in the section header table. Thus the product of e_shentsize and e_shnum
    /// gives the section header table's size in bytes. If a file has no section header table, e_shnum holds the value zero.
    ///
    /// If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), this member has the value zero and
    /// the actual number of section header table entries is contained in the sh_size field of the section header at index 0.
    /// (Otherwise, the sh_size member of the initial entry contains 0.)
    pub e_shnum: u16,
    /// This member holds the section header table index of the entry associated with the section name string table. If the
    /// file has no section name string table, this member holds the value SHN_UNDEF.
    ///
    /// If the section name string table section index is greater than or equal to SHN_LORESERVE (0xff00), this member has
    /// the value SHN_XINDEX (0xffff) and the actual index of the section name string table section is contained in the
    /// sh_link field of the section header at index 0. (Otherwise, the sh_link member of the initial entry contains 0.)
    pub e_shstrndx: u16,
}

const ELF32_EHDR_TAILSIZE: usize = 36;
const ELF64_EHDR_TAILSIZE: usize = 48;

// Read the platform-independent ident bytes
impl FileHeader {
    fn verify_ident(buf: &[u8]) -> Result<(), ParseError> {
        // Verify the magic number
        let magic = buf.split_at(gabi::EI_CLASS).0;
        if magic != gabi::ELFMAGIC {
            return Err(ParseError::BadMagic([
                magic[0], magic[1], magic[2], magic[3],
            ]));
        }

        let class = buf[gabi::EI_CLASS];
        if class != gabi::ELFCLASS32 && class != gabi::ELFCLASS64 {
            return Err(ParseError::UnsupportedElfClass(class));
        }

        // Verify ELF Version
        let version = buf[gabi::EI_VERSION];
        if version != gabi::EV_CURRENT {
            return Err(ParseError::UnsupportedVersion((
                version as u64,
                gabi::EV_CURRENT as u64,
            )));
        }

        // Verify endianness is something we know how to parse
        let endian = buf[gabi::EI_DATA];
        if endian != gabi::ELFDATA2LSB && endian != gabi::ELFDATA2MSB {
            return Err(ParseError::UnsupportedElfEndianness(endian));
        }

        return Ok(());
    }

    pub fn parse<R: ReadBytesAt>(reader: &mut R) -> Result<Self, ParseError> {
        let class: Class;
        let endian: Endian;
        let osabi: u8;
        let abiversion: u8;

        {
            let ident = reader.read_bytes_at(0..gabi::EI_NIDENT)?;
            Self::verify_ident(ident)?;

            class = if ident[gabi::EI_CLASS] == gabi::ELFCLASS32 {
                Class::ELF32
            } else {
                Class::ELF64
            };

            endian = if ident[gabi::EI_DATA] == gabi::ELFDATA2LSB {
                Endian::Little
            } else {
                Endian::Big
            };

            osabi = ident[gabi::EI_OSABI];
            abiversion = ident[gabi::EI_ABIVERSION];
        }

        let start = gabi::EI_NIDENT;
        let size = match class {
            Class::ELF32 => ELF32_EHDR_TAILSIZE,
            Class::ELF64 => ELF64_EHDR_TAILSIZE,
        };
        let data = reader.read_bytes_at(start..start + size)?;

        let mut offset = 0;
        let e_type = parse_u16_at(endian, &mut offset, data)?;
        let e_machine = parse_u16_at(endian, &mut offset, data)?;
        let version = parse_u32_at(endian, &mut offset, data)?;

        let e_entry: u64;
        let e_phoff: u64;
        let e_shoff: u64;

        if class == Class::ELF32 {
            e_entry = parse_u32_at(endian, &mut offset, data)? as u64;
            e_phoff = parse_u32_at(endian, &mut offset, data)? as u64;
            e_shoff = parse_u32_at(endian, &mut offset, data)? as u64;
        } else {
            e_entry = parse_u64_at(endian, &mut offset, data)?;
            e_phoff = parse_u64_at(endian, &mut offset, data)?;
            e_shoff = parse_u64_at(endian, &mut offset, data)?;
        }

        let e_flags = parse_u32_at(endian, &mut offset, data)?;
        let e_ehsize = parse_u16_at(endian, &mut offset, data)?;
        let e_phentsize = parse_u16_at(endian, &mut offset, data)?;
        let e_phnum = parse_u16_at(endian, &mut offset, data)?;
        let e_shentsize = parse_u16_at(endian, &mut offset, data)?;
        let e_shnum = parse_u16_at(endian, &mut offset, data)?;
        let e_shstrndx = parse_u16_at(endian, &mut offset, data)?;

        return Ok(FileHeader {
            class,
            endianness: endian,
            version,
            e_type,
            e_machine,
            osabi,
            abiversion,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        });
    }

    /// Calculate the (start, end) range in bytes for where the ProgramHeader table resides in
    /// this ELF file containing this FileHeader.
    ///
    /// Returns Ok(None) if the file does not contain any ProgramHeaders.
    /// Returns a ParseError if the range could not fit in the system's usize or encountered overflow
    pub(crate) fn get_phdrs_data_range(self) -> Result<Option<(usize, usize)>, ParseError> {
        if self.e_phnum == 0 {
            return Ok(None);
        }

        // Validate ph entsize. We do this when calculating the range before so that we can error
        // early for corrupted files.
        let entsize = ProgramHeader::validate_entsize(self.class, self.e_phentsize as usize)?;

        let start: usize = self.e_phoff.try_into()?;
        let size = entsize
            .checked_mul(self.e_phnum as usize)
            .ok_or(ParseError::IntegerOverflow)?;
        let end = start.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
        Ok(Some((start, end)))
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::dynamic::Dyn;
    use crate::hash::SysVHashTable;
    use crate::note::Note;
    use crate::parse::CachedReadBytes;
    use crate::relocation::Rela;
    use crate::symbol::Symbol;

    #[test]
    fn test_open_stream_with_cachedreadbytes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let c_io = CachedReadBytes::new(io);
        let file = File::open_stream(c_io).expect("Open test1");
        assert_eq!(file.ehdr.e_type, gabi::ET_EXEC);
    }

    #[test]
    fn test_open_stream_with_byte_slice() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = File::open_stream(slice).expect("Open test1");
        assert_eq!(file.ehdr.e_type, gabi::ET_EXEC);
    }

    #[test]
    fn section_header_by_index() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(file.ehdr.e_shstrndx as usize)
            .expect("Failed to parse shdr");
        assert_eq!(
            shdr,
            SectionHeader {
                sh_name: 17,
                sh_type: 3,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 4532,
                sh_size: 268,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 1,
                sh_entsize: 0,
            }
        );
    }

    #[test]
    fn section_headers_with_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let (shdrs, strtab) = file
            .section_headers_with_strtab()
            .expect("Failed to get shdrs");

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
    fn section_data_for_nobits() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(26)
            .expect("Failed to get .gnu.version section");
        assert_eq!(shdr.sh_type, gabi::SHT_NOBITS);
        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");
        assert_eq!(chdr, None);
        assert_eq!(data, &[]);
    }

    #[test]
    fn section_data() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(7)
            .expect("Failed to get .gnu.version section");
        assert_eq!(shdr.sh_type, gabi::SHT_GNU_VERSYM);
        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");
        assert_eq!(chdr, None);
        assert_eq!(data, [0, 0, 2, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn section_data_as_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(file.ehdr.e_shstrndx as usize)
            .expect("Failed to parse shdr");
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
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("Failed to read segments")
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
        )
    }

    #[test]
    fn symbol_table() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
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
        let mut file = File::open_stream(slice).expect("Open test1");
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
    fn dynamic_section() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let mut dynamic = file
            .dynamic_section()
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
    fn section_data_as_rels() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(10)
            .expect("Failed to get rela shdr");
        file.section_data_as_rels(&shdr)
            .expect_err("Expected error parsing non-REL scn as RELs");
    }

    #[test]
    fn section_data_as_relas() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(10)
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
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(2)
            .expect("Failed to get .note.ABI-tag shdr");
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
    fn segment_data_as_notes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let phdrs: Vec<ProgramHeader> = file
            .segments()
            .expect("Failed to get .note.ABI-tag shdr")
            .iter()
            .collect();
        let mut notes = file
            .segment_data_as_notes(&phdrs[5])
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
                    119, 65, 159, 13, 165, 16, 131, 12, 87, 167, 200, 204, 176, 238, 133, 95, 238,
                    211, 118, 163
                ]
            }
        );
        assert!(notes.next().is_none());
    }

    #[test]
    fn symbol_version_table() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file =
            File::open_stream(CachedReadBytes::new(io)).expect("Failed to open ELF stream");
        let vst = file
            .symbol_version_table()
            .expect("Failed to parse GNU symbol versions")
            .expect("Failed to find GNU symbol versions");

        let req1 = vst
            .get_requirement(1)
            .expect("Failed to parse NEED")
            .expect("Failed to find NEED");
        assert_eq!(req1.file, "libc.so.6");
        assert_eq!(req1.name, "GLIBC_2.2.5");
        assert_eq!(req1.hash, 0x9691A75);

        let req2 = vst
            .get_requirement(2)
            .expect("Failed to parse NEED")
            .expect("Failed to find NEED");
        assert_eq!(req2.file, "libc.so.6");
        assert_eq!(req2.name, "GLIBC_2.2.5");
        assert_eq!(req2.hash, 0x9691A75);

        let req3 = vst.get_requirement(3).expect("Failed to parse NEED");
        assert!(req3.is_none());
    }

    #[test]
    fn sysv_hash_table() {
        let path = std::path::PathBuf::from("tests/samples/hello.so");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");

        // Look up the SysV hash section header
        let hash_shdr = file
            .section_headers()
            .expect("Failed to parse shdrs")
            .iter()
            .find(|shdr| shdr.sh_type == gabi::SHT_HASH)
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
            .find(b"memset", 0x73C49C4, &symtab, &strtab)
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
mod parse_tests {
    use super::*;

    #[test]
    fn test_verify_ident_valid() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        FileHeader::verify_ident(&mut data.as_ref()).expect("Expected Ok result");
    }

    #[test]
    fn test_verify_ident_invalid_mag0() {
        let data: [u8; gabi::EI_NIDENT] = [
            0xFF,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = FileHeader::verify_ident(&mut data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_verify_ident_invalid_mag1() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            0xFF,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = FileHeader::verify_ident(&mut data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_verify_ident_invalid_mag2() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            0xFF,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = FileHeader::verify_ident(&mut data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_verify_ident_invalid_mag3() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            0xFF,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = FileHeader::verify_ident(&mut data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_ident_invalid_version() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            42,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = FileHeader::verify_ident(&mut data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::UnsupportedVersion((42, 1))),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_parse_ehdr32_works() {
        let mut data = [0u8; gabi::EI_NIDENT + ELF32_EHDR_TAILSIZE]; // Vec<u8> = vec![
        data[0] = gabi::ELFMAG0;
        data[1] = gabi::ELFMAG1;
        data[2] = gabi::ELFMAG2;
        data[3] = gabi::ELFMAG3;
        data[4] = gabi::ELFCLASS32;
        data[5] = gabi::ELFDATA2LSB;
        data[6] = gabi::EV_CURRENT;
        data[7] = gabi::ELFOSABI_LINUX;
        data[8] = 7;
        for n in 0..ELF32_EHDR_TAILSIZE {
            data[gabi::EI_NIDENT + n] = n as u8;
        }

        assert_eq!(
            FileHeader::parse(&mut data.as_ref()).unwrap(),
            FileHeader {
                class: Class::ELF32,
                endianness: Endian::Little,
                version: 0x7060504,
                osabi: gabi::ELFOSABI_LINUX,
                abiversion: 7,
                e_type: 0x100,
                e_machine: 0x302,
                e_entry: 0x0B0A0908,
                e_phoff: 0x0F0E0D0C,
                e_shoff: 0x13121110,
                e_flags: 0x17161514,
                e_ehsize: 0x1918,
                e_phentsize: 0x1B1A,
                e_phnum: 0x1D1C,
                e_shentsize: 0x1F1E,
                e_shnum: 0x2120,
                e_shstrndx: 0x2322,
            }
        );
    }

    #[test]
    fn test_parse_ehdr32_fuzz_too_short() {
        let mut data: Vec<u8> = vec![
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        data.resize(gabi::EI_NIDENT + ELF32_EHDR_TAILSIZE, 0u8);

        for n in 0..ELF32_EHDR_TAILSIZE {
            let mut buf = data.as_mut_slice().split_at(gabi::EI_NIDENT + n).0.as_ref();
            let result = FileHeader::parse(&mut buf).expect_err("Expected an error");
            assert!(
                matches!(result, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_ehdr64_works() {
        let mut data: Vec<u8> = vec![
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS64,
            gabi::ELFDATA2MSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        data.resize(gabi::EI_NIDENT + ELF64_EHDR_TAILSIZE, 0u8);
        for n in 0u8..ELF64_EHDR_TAILSIZE as u8 {
            data[gabi::EI_NIDENT + n as usize] = n;
        }

        let slice = &mut data.as_slice();
        assert_eq!(
            FileHeader::parse(slice).unwrap(),
            FileHeader {
                class: Class::ELF64,
                endianness: Endian::Big,
                version: 0x04050607,
                osabi: gabi::ELFOSABI_LINUX,
                abiversion: 7,
                e_type: 0x0001,
                e_machine: 0x0203,
                e_entry: 0x08090A0B0C0D0E0F,
                e_phoff: 0x1011121314151617,
                e_shoff: 0x18191A1B1C1D1E1F,
                e_flags: 0x20212223,
                e_ehsize: 0x2425,
                e_phentsize: 0x2627,
                e_phnum: 0x2829,
                e_shentsize: 0x2A2B,
                e_shnum: 0x2C2D,
                e_shstrndx: 0x2E2F,
            }
        );
    }

    #[test]
    fn test_parse_ehdr64_fuzz_too_short() {
        let mut data: Vec<u8> = vec![
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS64,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        data.resize(gabi::EI_NIDENT + ELF64_EHDR_TAILSIZE, 0u8);

        for n in 0..ELF64_EHDR_TAILSIZE {
            let mut buf = data.as_mut_slice().split_at(gabi::EI_NIDENT + n).0;
            let result = FileHeader::parse(&mut buf).expect_err("Expected an error");
            assert!(
                matches!(result, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {result:?}"
            );
        }
    }
}
