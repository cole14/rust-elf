use crate::compression::CompressionHeader;
use crate::dynamic::DynIterator;
use crate::gabi;
use crate::note::NoteIterator;
use crate::parse::{Class, Endian, EndianParseExt, ParseAt, ParseError, ReadBytesAt};
use crate::relocation::{RelIterator, RelaIterator};
use crate::section::{SectionHeader, SectionHeaderIterator, SectionType};
use crate::segment::ProgramHeader;
use crate::segment::SegmentIterator;
use crate::string_table::StringTable;
use crate::symbol::SymbolTable;

pub struct File<R: ReadBytesAt> {
    reader: R,
    pub ehdr: FileHeader,
}

impl<R: ReadBytesAt> File<R> {
    pub fn open_stream(mut reader: R) -> Result<File<R>, ParseError> {
        let ehdr = FileHeader::parse(&mut reader)?;

        Ok(File { reader, ehdr })
    }

    /// Get an iterator over the Segments (ELF Program Headers) in the file
    ///
    /// The underlying ELF bytes backing the segment table is read all at once
    /// when the iterator is requested, but parsing is deferred to be lazily
    /// parsed on demand on each Iterator::next() call.
    ///
    /// Returns a [ParseError] if the data bytes for the segment table cannot be
    /// read i.e. if the ELF [FileHeader]'s
    /// [e_phnum](FileHeader#structfield.e_phnum),
    /// [e_phoff](FileHeader#structfield.e_phoff),
    /// [e_phentsize](FileHeader#structfield.e_phentsize) are invalid and point
    /// to a range in the file data that does not actually exist.
    pub fn segments(&mut self) -> Result<SegmentIterator, ParseError> {
        if self.ehdr.e_phnum == 0 {
            return Ok(SegmentIterator::new(
                self.ehdr.endianness,
                self.ehdr.class,
                &[],
            ));
        }

        let start = self.ehdr.e_phoff as usize;
        let size = self.ehdr.e_phentsize as usize * self.ehdr.e_phnum as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
        Ok(SegmentIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            buf,
        ))
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

    /// Get an iterator over the Section Headers in the file.
    ///
    /// The underlying ELF bytes backing the section headers table are read all at once
    /// when the iterator is requested, but parsing is deferred to be lazily
    /// parsed on demand on each Iterator::next() call.
    ///
    /// Returns a [ParseError] if the data bytes for the segment table cannot be
    /// read i.e. if the ELF [FileHeader]'s
    /// [e_shnum](FileHeader#structfield.e_shnum),
    /// [e_shoff](FileHeader#structfield.e_shoff),
    /// [e_shentsize](FileHeader#structfield.e_shentsize) are invalid and point
    /// to a range in the file data that does not actually exist.
    pub fn section_headers(&mut self) -> Result<SectionHeaderIterator, ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok(SectionHeaderIterator::new(
                self.ehdr.endianness,
                self.ehdr.class,
                &[],
            ));
        }

        // Get the number of section headers (could be in ehdr or shdrs[0])
        let shnum = self.shnum()?;

        let start = self.ehdr.e_shoff as usize;
        let size = self.ehdr.e_shentsize as usize * shnum as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
        Ok(SectionHeaderIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            buf,
        ))
    }

    /// Read and parse the [SectionHeader](SectionHeader) at the given
    /// index into the section table.
    pub fn section_header_by_index(&mut self, index: usize) -> Result<SectionHeader, ParseError> {
        if self.ehdr.e_shnum > 0 && index >= self.ehdr.e_shnum as usize {
            return Err(ParseError::BadOffset(index as u64));
        }

        let start = self.ehdr.e_shoff as usize + (index * self.ehdr.e_shentsize as usize);
        let size = self.ehdr.e_shentsize as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
        let mut offset = 0;
        SectionHeader::parse_at(self.ehdr.endianness, self.ehdr.class, &mut offset, &buf)
    }

    /// Get an iterator over the Section Headers and its associated StringTable.
    ///
    /// The underlying ELF bytes backing the section headers and string table
    /// are read all at once as part of this method. Parsing of section headers and
    /// names from the string table are deferred to be done lazily on demand on
    /// each Iterator::next() and StringTable.get() call.
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
    ) -> Result<(SectionHeaderIterator, StringTable), ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok((
                SectionHeaderIterator::new(self.ehdr.endianness, self.ehdr.class, &[]),
                StringTable::default(),
            ));
        }

        // Load the section header table bytes (we want concurrent referneces to strtab too)
        let shnum = self.shnum()?;
        let shdrs_start = self.ehdr.e_shoff as usize;
        let shdrs_size = self.ehdr.e_shentsize as usize * shnum as usize;
        self.reader
            .load_bytes_at(shdrs_start..shdrs_start + shdrs_size)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        // Get the index of section headers' strtab (could be in ehdr or shdrs[0])
        let shstrndx = self.shstrndx()?;

        let strtab = self.section_header_by_index(shstrndx as usize)?;
        let strtab_start = strtab.sh_offset as usize;
        let strtab_size = strtab.sh_size as usize;
        self.reader
            .load_bytes_at(strtab_start..strtab_start + strtab_size)?;

        // Return the (symtab, strtab)
        let shdrs = SectionHeaderIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            self.reader
                .get_loaded_bytes_at(shdrs_start..shdrs_start + shdrs_size),
        );
        let strtab = StringTable::new(
            self.reader
                .get_loaded_bytes_at(strtab_start..strtab_start + strtab_size),
        );
        Ok((shdrs, strtab))
    }

    /// Read the section data for the given [SectionHeader](SectionHeader).
    ///
    /// This returns the data as-is from the file. SHT_NOBITS sections yield an empty slice.
    #[deprecated(note = "Deprecated in favor of File::section_data()")]
    pub fn section_data_for_header(&mut self, shdr: &SectionHeader) -> Result<&[u8], ParseError> {
        if shdr.sh_type == gabi::SHT_NOBITS {
            return Ok(&[]);
        }

        let start = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
        Ok(buf)
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

        let start = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;

        if shdr.sh_flags.0 & gabi::SHF_COMPRESSED as u64 == 0 {
            Ok((buf, None))
        } else {
            let mut offset = 0;
            let chdr = CompressionHeader::parse_at(
                self.ehdr.endianness,
                self.ehdr.class,
                &mut offset,
                &buf,
            )?;
            let compressed_buf = buf
                .get(offset..)
                .ok_or(ParseError::SliceReadError((offset, shdr.sh_size as usize)))?;
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
                shdr.sh_type.0,
                gabi::SHT_STRTAB,
            )));
        }
        let start = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
        Ok(StringTable::new(buf))
    }

    /// Read and return the string table for the section headers.
    ///
    /// If the file has no section header string table, then an empty
    /// [StringTable](StringTable) is returned.
    ///
    /// This is a convenience wrapper for interpreting the section at
    /// [FileHeader.e_shstrndx](FileHeader#structfield.e_shstrndx) as
    /// a [StringTable](StringTable) via
    /// [section_data_as_strtab()](File::section_data_as_strtab).
    pub fn section_strtab(&mut self) -> Result<StringTable, ParseError> {
        if self.ehdr.e_shstrndx == gabi::SHN_UNDEF {
            return Ok(StringTable::default());
        }

        // Get the index of section headers' strtab (could be in ehdr or shdrs[0])
        let shstrndx = self.shstrndx()?;

        let strtab_shdr = self.section_header_by_index(shstrndx as usize)?;
        self.section_data_as_strtab(&strtab_shdr)
    }

    fn get_symbol_table_of_type(
        &mut self,
        symtab_type: SectionType,
    ) -> Result<Option<(SymbolTable, StringTable)>, ParseError> {
        // Get the symtab header for the symtab. The GABI states there can be zero or one per ELF file.
        let symtab_shdr = match self
            .section_headers()?
            .find(|shdr| shdr.sh_type == symtab_type)
        {
            Some(shdr) => shdr,
            None => return Ok(None),
        };

        // Load the section bytes for the symtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let symtab_start = symtab_shdr.sh_offset as usize;
        let symtab_size = symtab_shdr.sh_size as usize;
        self.reader
            .load_bytes_at(symtab_start..symtab_start + symtab_size)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let strtab = self.section_header_by_index(symtab_shdr.sh_link as usize)?;
        let strtab_start = strtab.sh_offset as usize;
        let strtab_size = strtab.sh_size as usize;
        self.reader
            .load_bytes_at(strtab_start..strtab_start + strtab_size)?;

        // Return the (symtab, strtab)
        let symtab = SymbolTable::new(
            self.ehdr.endianness,
            self.ehdr.class,
            symtab_shdr.sh_entsize,
            self.reader
                .get_loaded_bytes_at(symtab_start..symtab_start + symtab_size),
        )?;
        let strtab = StringTable::new(
            self.reader
                .get_loaded_bytes_at(strtab_start..strtab_start + strtab_size),
        );
        Ok(Some((symtab, strtab)))
    }

    /// Get the symbol table (section of type SHT_SYMTAB) and its associated string table.
    ///
    /// The GABI specifies that ELF object files may have zero or one sections of type SHT_SYMTAB.
    pub fn symbol_table(&mut self) -> Result<Option<(SymbolTable, StringTable)>, ParseError> {
        self.get_symbol_table_of_type(SectionType(gabi::SHT_SYMTAB))
    }

    /// Get the dynamic symbol table (section of type SHT_DYNSYM) and its associated string table.
    ///
    /// The GABI specifies that ELF object files may have zero or one sections of type SHT_DYNSYM.
    pub fn dynamic_symbol_table(
        &mut self,
    ) -> Result<Option<(SymbolTable, StringTable)>, ParseError> {
        self.get_symbol_table_of_type(SectionType(gabi::SHT_DYNSYM))
    }

    /// Get the .dynamic section/segment contents.
    pub fn dynamic_section(&mut self) -> Result<Option<DynIterator>, ParseError> {
        // If we have section headers, then look it up there
        if self.ehdr.e_shoff > 0 {
            if let Some(shdr) = self
                .section_headers()?
                .find(|shdr| shdr.sh_type == gabi::SHT_DYNAMIC)
            {
                let start = shdr.sh_offset as usize;
                let size = shdr.sh_size as usize;
                let buf = self.reader.read_bytes_at(start..start + size)?;
                return Ok(Some(DynIterator::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    buf,
                )));
            }
        } else {
            if let Some(phdr) = self
                .segments()?
                .find(|phdr| phdr.p_type == gabi::PT_DYNAMIC)
            {
                let start = phdr.p_offset as usize;
                let size = phdr.p_filesz as usize;
                let buf = self.reader.read_bytes_at(start..start + size)?;
                return Ok(Some(DynIterator::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    buf,
                )));
            }
        }
        Ok(None)
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
                shdr.sh_type.0,
                gabi::SHT_REL,
            )));
        }
        let start = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
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
                shdr.sh_type.0,
                gabi::SHT_RELA,
            )));
        }
        let start = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
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
                shdr.sh_type.0,
                gabi::SHT_NOTE,
            )));
        }
        let start = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
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
                phdr.p_type.0,
                gabi::PT_NOTE,
            )));
        }
        let start = phdr.p_offset as usize;
        let size = phdr.p_filesz as usize;
        let buf = self.reader.read_bytes_at(start..start + size)?;
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
    pub osabi: OSABI,
    /// Version of the OS ABI
    pub abiversion: u8,
    /// ELF file type
    pub elftype: ObjectFileType,
    /// Target machine architecture
    pub arch: Architecture,
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
            return Err(ParseError::UnsupportedElfVersion(version));
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
        let osabi: OSABI;
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

            osabi = OSABI(ident[gabi::EI_OSABI]);
            abiversion = ident[gabi::EI_ABIVERSION];
        }

        let start = gabi::EI_NIDENT;
        let size = match class {
            Class::ELF32 => ELF32_EHDR_TAILSIZE,
            Class::ELF64 => ELF64_EHDR_TAILSIZE,
        };
        let data = reader.read_bytes_at(start..start + size)?;

        let mut offset = 0;
        let elftype = ObjectFileType(data.parse_u16_at(endian, &mut offset)?);
        let arch = Architecture(data.parse_u16_at(endian, &mut offset)?);
        let version = data.parse_u32_at(endian, &mut offset)?;

        let e_entry: u64;
        let e_phoff: u64;
        let e_shoff: u64;

        if class == Class::ELF32 {
            e_entry = data.parse_u32_at(endian, &mut offset)? as u64;
            e_phoff = data.parse_u32_at(endian, &mut offset)? as u64;
            e_shoff = data.parse_u32_at(endian, &mut offset)? as u64;
        } else {
            e_entry = data.parse_u64_at(endian, &mut offset)?;
            e_phoff = data.parse_u64_at(endian, &mut offset)?;
            e_shoff = data.parse_u64_at(endian, &mut offset)?;
        }

        let e_flags = data.parse_u32_at(endian, &mut offset)?;
        let e_ehsize = data.parse_u16_at(endian, &mut offset)?;
        let e_phentsize = data.parse_u16_at(endian, &mut offset)?;
        let e_phnum = data.parse_u16_at(endian, &mut offset)?;
        let e_shentsize = data.parse_u16_at(endian, &mut offset)?;
        let e_shnum = data.parse_u16_at(endian, &mut offset)?;
        let e_shstrndx = data.parse_u16_at(endian, &mut offset)?;

        return Ok(FileHeader {
            class,
            endianness: endian,
            version,
            elftype,
            arch,
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
}

impl core::fmt::Display for FileHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "File Header for {} {} Elf {} for {} {}",
            self.class, self.endianness, self.elftype, self.osabi, self.arch
        )
    }
}

/// Represents the ELF file OS ABI
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct OSABI(pub u8);

impl core::fmt::Debug for OSABI {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl core::fmt::Display for OSABI {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self.0 {
            gabi::ELFOSABI_SYSV => "UNIX System V",
            gabi::ELFOSABI_HPUX => "HP-UX",
            gabi::ELFOSABI_NETBSD => "NetBSD",
            gabi::ELFOSABI_LINUX => "Linux with GNU extensions",
            gabi::ELFOSABI_SOLARIS => "Solaris",
            gabi::ELFOSABI_AIX => "AIX",
            gabi::ELFOSABI_IRIX => "SGI Irix",
            gabi::ELFOSABI_FREEBSD => "FreeBSD",
            gabi::ELFOSABI_TRU64 => "Compaq TRU64 UNIX",
            gabi::ELFOSABI_MODESTO => "Novell Modesto",
            gabi::ELFOSABI_OPENBSD => "OpenBSD",
            gabi::ELFOSABI_OPENVMS => "Open VMS",
            gabi::ELFOSABI_NSK => "Hewlett-Packard Non-Stop Kernel",
            gabi::ELFOSABI_AROS => "Amiga Research OS",
            gabi::ELFOSABI_FENIXOS => "The FenixOS highly scalable multi-core OS",
            gabi::ELFOSABI_CLOUDABI => "Nuxi CloudABI",
            gabi::ELFOSABI_OPENVOS => "Stratus Technologies OpenVOS",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file type (object, executable, shared lib, core)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ObjectFileType(pub u16);

impl core::fmt::Debug for ObjectFileType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl core::fmt::Display for ObjectFileType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self.0 {
            gabi::ET_NONE => "No file type",
            gabi::ET_REL => "Relocatable file",
            gabi::ET_EXEC => "Executable file",
            gabi::ET_DYN => "Shared object file",
            gabi::ET_CORE => "Core file",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file machine architecture
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Architecture(pub u16);

impl core::fmt::Debug for Architecture {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl core::fmt::Display for Architecture {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self.0 {
            gabi::EM_NONE => "No machine",
            gabi::EM_M32 => "AT&T WE 32100",
            gabi::EM_SPARC => "SPARC",
            gabi::EM_386 => "Intel 80386",
            gabi::EM_68K => "Motorola 68000",
            gabi::EM_88K => "Motorola 88000",
            gabi::EM_IAMCU => "Intel MCU",
            gabi::EM_860 => "Intel 80860",
            gabi::EM_MIPS => "MIPS I Architecture",
            gabi::EM_S370 => "IBM System/370 Processor",
            gabi::EM_MIPS_RS3_LE => "MIPS RS3000 Little-endian",
            gabi::EM_PARISC => "Hewlett-Packard PA-RISC",
            gabi::EM_VPP500 => "Fujitsu VPP500",
            gabi::EM_SPARC32PLUS => "Enhanced instruction set SPARC",
            gabi::EM_960 => "Intel 80960",
            gabi::EM_PPC => "PowerPC",
            gabi::EM_PPC64 => "64-bit PowerPC",
            gabi::EM_S390 => "IBM System/390 Processor",
            gabi::EM_SPU => "IBM SPU/SPC",
            gabi::EM_V800 => "NEC V800",
            gabi::EM_FR20 => "Fujitsu FR20",
            gabi::EM_RH32 => "TRW RH-32",
            gabi::EM_RCE => "Motorola RCE",
            gabi::EM_ARM => "ARM 32-bit architecture (AARCH32)",
            gabi::EM_ALPHA => "Digital Alpha",
            gabi::EM_SH => "Hitachi SH",
            gabi::EM_SPARCV9 => "SPARC Version 9",
            gabi::EM_TRICORE => "Siemens TriCore embedded processor",
            gabi::EM_ARC => "Argonaut RISC Core, Argonaut Technologies Inc.",
            gabi::EM_H8_300 => "Hitachi H8/300",
            gabi::EM_H8_300H => "Hitachi H8/300H",
            gabi::EM_H8S => "Hitachi H8S",
            gabi::EM_H8_500 => "Hitachi H8/500",
            gabi::EM_IA_64 => "Intel IA-64 processor architecture",
            gabi::EM_MIPS_X => "Stanford MIPS-X",
            gabi::EM_COLDFIRE => "Motorola ColdFire",
            gabi::EM_68HC12 => "Motorola M68HC12",
            gabi::EM_MMA => "Fujitsu MMA Multimedia Accelerator",
            gabi::EM_PCP => "Siemens PCP",
            gabi::EM_NCPU => "Sony nCPU embedded RISC processor",
            gabi::EM_NDR1 => "Denso NDR1 microprocessor",
            gabi::EM_STARCORE => "Motorola Star*Core processor",
            gabi::EM_ME16 => "Toyota ME16 processor",
            gabi::EM_ST100 => "STMicroelectronics ST100 processor",
            gabi::EM_TINYJ => "Advanced Logic Corp. TinyJ embedded processor family",
            gabi::EM_X86_64 => "AMD x86-64 architecture",
            gabi::EM_PDSP => "Sony DSP Processor",
            gabi::EM_PDP10 => "Digital Equipment Corp. PDP-10",
            gabi::EM_PDP11 => "Digital Equipment Corp. PDP-11",
            gabi::EM_FX66 => "Siemens FX66 microcontroller",
            gabi::EM_ST9PLUS => "STMicroelectronics ST9+ 8/16 bit microcontroller",
            gabi::EM_ST7 => "STMicroelectronics ST7 8-bit microcontroller",
            gabi::EM_68HC16 => "Motorola MC68HC16 Microcontroller",
            gabi::EM_68HC11 => "Motorola MC68HC11 Microcontroller",
            gabi::EM_68HC08 => "Motorola MC68HC08 Microcontroller",
            gabi::EM_68HC05 => "Motorola MC68HC05 Microcontroller",
            gabi::EM_SVX => "Silicon Graphics SVx",
            gabi::EM_ST19 => "STMicroelectronics ST19 8-bit microcontroller",
            gabi::EM_VAX => "Digital VAX",
            gabi::EM_CRIS => "Axis Communications 32-bit embedded processor",
            gabi::EM_JAVELIN => "Infineon Technologies 32-bit embedded processor",
            gabi::EM_FIREPATH => "Element 14 64-bit DSP Processor",
            gabi::EM_ZSP => "LSI Logic 16-bit DSP Processor",
            gabi::EM_MMIX => "Donald Knuth's educational 64-bit processor",
            gabi::EM_HUANY => "Harvard University machine-independent object files",
            gabi::EM_PRISM => "SiTera Prism",
            gabi::EM_AVR => "Atmel AVR 8-bit microcontroller",
            gabi::EM_FR30 => "Fujitsu FR30",
            gabi::EM_D10V => "Mitsubishi D10V",
            gabi::EM_D30V => "Mitsubishi D30V",
            gabi::EM_V850 => "NEC v850",
            gabi::EM_M32R => "Mitsubishi M32R",
            gabi::EM_MN10300 => "Matsushita MN10300",
            gabi::EM_MN10200 => "Matsushita MN10200",
            gabi::EM_PJ => "picoJava",
            gabi::EM_OPENRISC => "OpenRISC 32-bit embedded processor",
            gabi::EM_ARC_COMPACT => {
                "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)"
            }
            gabi::EM_XTENSA => "Tensilica Xtensa Architecture",
            gabi::EM_VIDEOCORE => "Alphamosaic VideoCore processor",
            gabi::EM_TMM_GPP => "Thompson Multimedia General Purpose Processor",
            gabi::EM_NS32K => "National Semiconductor 32000 series",
            gabi::EM_TPC => "Tenor Network TPC processor",
            gabi::EM_SNP1K => "Trebia SNP 1000 processor",
            gabi::EM_ST200 => "STMicroelectronics (www.st.com) ST200 microcontroller",
            gabi::EM_IP2K => "Ubicom IP2xxx microcontroller family",
            gabi::EM_MAX => "MAX Processor",
            gabi::EM_CR => "National Semiconductor CompactRISC microprocessor",
            gabi::EM_F2MC16 => "Fujitsu F2MC16",
            gabi::EM_MSP430 => "Texas Instruments embedded microcontroller msp430",
            gabi::EM_BLACKFIN => "Analog Devices Blackfin (DSP) processor",
            gabi::EM_SE_C33 => "S1C33 Family of Seiko Epson processors",
            gabi::EM_SEP => "Sharp embedded microprocessor",
            gabi::EM_ARCA => "Arca RISC Microprocessor",
            gabi::EM_UNICORE => {
                "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University"
            }
            gabi::EM_EXCESS => "eXcess: 16/32/64-bit configurable embedded CPU",
            gabi::EM_DXP => "Icera Semiconductor Inc. Deep Execution Processor",
            gabi::EM_ALTERA_NIOS2 => "Altera Nios II soft-core processor",
            gabi::EM_CRX => "National Semiconductor CompactRISC CRX microprocessor",
            gabi::EM_XGATE => "Motorola XGATE embedded processor",
            gabi::EM_C166 => "Infineon C16x/XC16x processor",
            gabi::EM_M16C => "Renesas M16C series microprocessors",
            gabi::EM_DSPIC30F => "Microchip Technology dsPIC30F Digital Signal Controller",
            gabi::EM_CE => "Freescale Communication Engine RISC core",
            gabi::EM_M32C => "Renesas M32C series microprocessors",
            gabi::EM_TSK3000 => "Altium TSK3000 core",
            gabi::EM_RS08 => "Freescale RS08 embedded processor",
            gabi::EM_SHARC => "Analog Devices SHARC family of 32-bit DSP processors",
            gabi::EM_ECOG2 => "Cyan Technology eCOG2 microprocessor",
            gabi::EM_SCORE7 => "Sunplus S+core7 RISC processor",
            gabi::EM_DSP24 => "New Japan Radio (NJR) 24-bit DSP Processor",
            gabi::EM_VIDEOCORE3 => "Broadcom VideoCore III processor",
            gabi::EM_LATTICEMICO32 => "RISC processor for Lattice FPGA architecture",
            gabi::EM_SE_C17 => "Seiko Epson C17 family",
            gabi::EM_TI_C6000 => "The Texas Instruments TMS320C6000 DSP family",
            gabi::EM_TI_C2000 => "The Texas Instruments TMS320C2000 DSP family",
            gabi::EM_TI_C5500 => "The Texas Instruments TMS320C55x DSP family",
            gabi::EM_TI_ARP32 => {
                "Texas Instruments Application Specific RISC Processor, 32bit fetch"
            }
            gabi::EM_TI_PRU => "Texas Instruments Programmable Realtime Unit",
            gabi::EM_MMDSP_PLUS => "STMicroelectronics 64bit VLIW Data Signal Processor",
            gabi::EM_CYPRESS_M8C => "Cypress M8C microprocessor",
            gabi::EM_R32C => "Renesas R32C series microprocessors",
            gabi::EM_TRIMEDIA => "NXP Semiconductors TriMedia architecture family",
            gabi::EM_QDSP6 => "QUALCOMM DSP6 Processor",
            gabi::EM_8051 => "Intel 8051 and variants",
            gabi::EM_STXP7X => {
                "STMicroelectronics STxP7x family of configurable and extensible RISC processors"
            }
            gabi::EM_NDS32 => "Andes Technology compact code size embedded RISC processor family",
            gabi::EM_ECOG1X => "Cyan Technology eCOG1X family",
            gabi::EM_MAXQ30 => "Dallas Semiconductor MAXQ30 Core Micro-controllers",
            gabi::EM_XIMO16 => "New Japan Radio (NJR) 16-bit DSP Processor",
            gabi::EM_MANIK => "M2000 Reconfigurable RISC Microprocessor",
            gabi::EM_CRAYNV2 => "Cray Inc. NV2 vector architecture",
            gabi::EM_RX => "Renesas RX family",
            gabi::EM_METAG => "Imagination Technologies META processor architecture",
            gabi::EM_MCST_ELBRUS => "MCST Elbrus general purpose hardware architecture",
            gabi::EM_ECOG16 => "Cyan Technology eCOG16 family",
            gabi::EM_CR16 => "National Semiconductor CompactRISC CR16 16-bit microprocessor",
            gabi::EM_ETPU => "Freescale Extended Time Processing Unit",
            gabi::EM_SLE9X => "Infineon Technologies SLE9X core",
            gabi::EM_L10M => "Intel L10M",
            gabi::EM_K10M => "Intel K10M",
            gabi::EM_AARCH64 => "ARM 64-bit architecture (AARCH64)",
            gabi::EM_AVR32 => "Atmel Corporation 32-bit microprocessor family",
            gabi::EM_STM8 => "STMicroeletronics STM8 8-bit microcontroller",
            gabi::EM_TILE64 => "Tilera TILE64 multicore architecture family",
            gabi::EM_TILEPRO => "Tilera TILEPro multicore architecture family",
            gabi::EM_MICROBLAZE => "Xilinx MicroBlaze 32-bit RISC soft processor core",
            gabi::EM_CUDA => "NVIDIA CUDA architecture",
            gabi::EM_TILEGX => "Tilera TILE-Gx multicore architecture family",
            gabi::EM_CLOUDSHIELD => "CloudShield architecture family",
            gabi::EM_COREA_1ST => "KIPO-KAIST Core-A 1st generation processor family",
            gabi::EM_COREA_2ND => "KIPO-KAIST Core-A 2nd generation processor family",
            gabi::EM_ARC_COMPACT2 => "Synopsys ARCompact V2",
            gabi::EM_OPEN8 => "Open8 8-bit RISC soft processor core",
            gabi::EM_RL78 => "Renesas RL78 family",
            gabi::EM_VIDEOCORE5 => "Broadcom VideoCore V processor",
            gabi::EM_78KOR => "Renesas 78KOR family",
            gabi::EM_56800EX => "Freescale 56800EX Digital Signal Controller (DSC)",
            gabi::EM_BA1 => "Beyond BA1 CPU architecture",
            gabi::EM_BA2 => "Beyond BA2 CPU architecture",
            gabi::EM_XCORE => "XMOS xCORE processor family",
            gabi::EM_MCHP_PIC => "Microchip 8-bit PIC(r) family",
            gabi::EM_INTEL205 => "Reserved by Intel",
            gabi::EM_INTEL206 => "Reserved by Intel",
            gabi::EM_INTEL207 => "Reserved by Intel",
            gabi::EM_INTEL208 => "Reserved by Intel",
            gabi::EM_INTEL209 => "Reserved by Intel",
            gabi::EM_KM32 => "KM211 KM32 32-bit processor",
            gabi::EM_KMX32 => "KM211 KMX32 32-bit processor",
            gabi::EM_KMX16 => "KM211 KMX16 16-bit processor",
            gabi::EM_KMX8 => "KM211 KMX8 8-bit processor",
            gabi::EM_KVARC => "KM211 KVARC processor",
            gabi::EM_CDP => "Paneve CDP architecture family",
            gabi::EM_COGE => "Cognitive Smart Memory Processor",
            gabi::EM_COOL => "Bluechip Systems CoolEngine",
            gabi::EM_NORC => "Nanoradio Optimized RISC",
            gabi::EM_CSR_KALIMBA => "CSR Kalimba architecture family",
            gabi::EM_Z80 => "Zilog Z80",
            gabi::EM_VISIUM => "Controls and Data Services VISIUMcore processor",
            gabi::EM_FT32 => "FTDI Chip FT32 high performance 32-bit RISC architecture",
            gabi::EM_MOXIE => "Moxie processor family",
            gabi::EM_AMDGPU => "AMD GPU architecture",
            gabi::EM_RISCV => "RISC-V",
            gabi::EM_BPF => "Linux BPF",
            _ => "Unknown Machine",
        };
        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::dynamic::Dyn;
    use crate::note::Note;
    use crate::parse::CachedReadBytes;
    use crate::relocation::Rela;
    use crate::section::SectionFlag;
    use crate::segment::{ProgFlag, ProgType};
    use crate::symbol::Symbol;

    #[test]
    fn test_open_stream_with_cachedreadbytes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let c_io = CachedReadBytes::new(io);
        let file = File::open_stream(c_io).expect("Open test1");
        assert_eq!(file.ehdr.elftype, ObjectFileType(gabi::ET_EXEC));
    }

    #[test]
    fn test_open_stream_with_byte_slice() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = File::open_stream(slice).expect("Open test1");
        assert_eq!(file.ehdr.elftype, ObjectFileType(gabi::ET_EXEC));
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
                sh_type: SectionType(3),
                sh_flags: SectionFlag(0),
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
    fn section_data_for_header() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(7)
            .expect("Failed to get .gnu.version section");
        assert_eq!(shdr.sh_type, gabi::SHT_GNU_VERSYM);
        #[allow(deprecated)]
        let data = file
            .section_data_for_header(&shdr)
            .expect("Failed to get section data");
        assert_eq!(data, [0, 0, 2, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn section_data_for_header_for_nobits() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let shdr = file
            .section_header_by_index(26)
            .expect("Failed to get nobits section");
        assert_eq!(shdr.sh_type, gabi::SHT_NOBITS);
        #[allow(deprecated)]
        let data = file
            .section_data_for_header(&shdr)
            .expect("Failed to get section data");
        assert_eq!(data, &[]);
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
    fn section_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let mut file = File::open_stream(slice).expect("Open test1");
        let strtab = file.section_strtab().expect("Failed to read strtab");
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
        let segments: Vec<ProgramHeader> =
            file.segments().expect("Failed to read segments").collect();
        assert_eq!(
            segments[0],
            ProgramHeader {
                p_type: ProgType(gabi::PT_PHDR),
                p_offset: 64,
                p_vaddr: 4194368,
                p_paddr: 4194368,
                p_filesz: 448,
                p_memsz: 448,
                p_flags: ProgFlag(5),
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
            matches!(result, ParseError::UnsupportedElfVersion(42)),
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
                osabi: OSABI(gabi::ELFOSABI_LINUX),
                abiversion: 7,
                elftype: ObjectFileType(0x100),
                arch: Architecture(0x302),
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
                osabi: OSABI(gabi::ELFOSABI_LINUX),
                abiversion: 7,
                elftype: ObjectFileType(0x0001),
                arch: Architecture(0x0203),
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
