use core::ops::Range;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

use crate::abi;
use crate::compression::CompressionHeader;
use crate::dynamic::DynIterator;
use crate::endian::EndianParse;
use crate::gnu_symver::{
    SymbolVersionTable, VerDefIterator, VerNeedIterator, VersionIndex, VersionIndexTable,
};
use crate::note::NoteIterator;
use crate::parse::{Class, ParseAt, ParseError};
use crate::relocation::{RelIterator, RelaIterator};
use crate::section::{SectionHeader, SectionHeaderTable};
use crate::segment::ProgramHeader;
use crate::segment::SegmentTable;
use crate::string_table::StringTable;
use crate::symbol::{Symbol, SymbolTable};

use crate::file::FileHeader;

pub struct ElfStream<E: EndianParse, S: std::io::Read + std::io::Seek> {
    pub ehdr: FileHeader,
    reader: CachingReader<S>,
    endian: E,
}

impl<E: EndianParse, S: std::io::Read + std::io::Seek> ElfStream<E, S> {
    pub fn open_stream(reader: S) -> Result<ElfStream<E, S>, ParseError> {
        let mut cr = CachingReader::new(reader);
        cr.load_bytes(0..abi::EI_NIDENT)?;
        let ident_buf = cr.get_bytes(0..abi::EI_NIDENT);
        let ident = FileHeader::parse_ident(ident_buf)?;

        let tail_start = abi::EI_NIDENT;
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
        if self.ehdr.e_shstrndx == abi::SHN_XINDEX {
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
        let buf = self.reader.read_bytes(start, end)?;
        let mut offset = 0;
        SectionHeader::parse_at(self.endian, self.ehdr.class, &mut offset, buf)
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
    pub fn section_headers(&mut self) -> Result<SectionHeaderTable<E>, ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok(SectionHeaderTable::new(self.endian, self.ehdr.class, &[]));
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
        let buf = self.reader.read_bytes(start, end)?;
        Ok(SectionHeaderTable::new(self.endian, self.ehdr.class, buf))
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
    ) -> Result<(SectionHeaderTable<E>, StringTable), ParseError> {
        // It's Ok to have no section headers
        if self.ehdr.e_shoff == 0 {
            return Ok((
                SectionHeaderTable::new(self.endian, self.ehdr.class, &[]),
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
        self.reader.load_bytes(shdrs_start..shdrs_end)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        // Get the index of section headers' strtab (could be in ehdr or shdrs[0])
        let shstrndx: usize = self.shstrndx()?.try_into()?;

        let strtab = self.section_header_by_index(shstrndx)?;
        let (strtab_start, strtab_end) = strtab.get_data_range()?;
        self.reader.load_bytes(strtab_start..strtab_end)?;

        // Return the (symtab, strtab)
        let shdrs = SectionHeaderTable::new(
            self.endian,
            self.ehdr.class,
            self.reader.get_bytes(shdrs_start..shdrs_end),
        );
        let strtab = StringTable::new(self.reader.get_bytes(strtab_start..strtab_end));
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
        if shdr.sh_type == abi::SHT_NOBITS {
            return Ok((&[], None));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;

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
    ) -> Result<StringTable, ParseError> {
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
    ) -> Result<Option<(SymbolTable<E>, StringTable)>, ParseError> {
        // Get the symtab header for the symtab. The gABI states there can be zero or one per ELF file.
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
        self.reader.load_bytes(symtab_start..symtab_end)?;

        // Load the section bytes for the strtab
        // (we want immutable references to both the symtab and its strtab concurrently)
        let strtab = self.section_header_by_index(symtab_shdr.sh_link as usize)?;
        let (strtab_start, strtab_end) = strtab.get_data_range()?;
        self.reader.load_bytes(strtab_start..strtab_end)?;

        // Validate entsize before trying to read the table so that we can error early for corrupted files
        Symbol::validate_entsize(self.ehdr.class, symtab_shdr.sh_entsize.try_into()?)?;
        let symtab = SymbolTable::new(
            self.endian,
            self.ehdr.class,
            self.reader.get_bytes(symtab_start..symtab_end),
        );
        let strtab = StringTable::new(self.reader.get_bytes(strtab_start..strtab_end));
        Ok(Some((symtab, strtab)))
    }

    /// Get the symbol table (section of type SHT_SYMTAB) and its associated string table.
    ///
    /// The gABI specifies that ELF object files may have zero or one sections of type SHT_SYMTAB.
    pub fn symbol_table(&mut self) -> Result<Option<(SymbolTable<E>, StringTable)>, ParseError> {
        self.get_symbol_table_of_type(abi::SHT_SYMTAB)
    }

    /// Get the dynamic symbol table (section of type SHT_DYNSYM) and its associated string table.
    ///
    /// The gABI specifies that ELF object files may have zero or one sections of type SHT_DYNSYM.
    pub fn dynamic_symbol_table(
        &mut self,
    ) -> Result<Option<(SymbolTable<E>, StringTable)>, ParseError> {
        self.get_symbol_table_of_type(abi::SHT_DYNSYM)
    }

    /// Get the .dynamic section/segment contents.
    pub fn dynamic_section(&mut self) -> Result<Option<DynIterator<E>>, ParseError> {
        // If we have section headers, then look it up there
        if self.ehdr.e_shoff > 0 {
            if let Some(shdr) = self
                .section_headers()?
                .iter()
                .find(|shdr| shdr.sh_type == abi::SHT_DYNAMIC)
            {
                let (start, end) = shdr.get_data_range()?;
                let buf = self.reader.read_bytes(start, end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
            }
        // Otherwise, look up the PT_DYNAMIC segment (if any)
        } else if let Some(phdrs) = self.segments()? {
            if let Some(phdr) = phdrs.iter().find(|phdr| phdr.p_type == abi::PT_DYNAMIC) {
                let (start, end) = phdr.get_file_data_range()?;
                let buf = self.reader.read_bytes(start, end)?;
                return Ok(Some(DynIterator::new(self.endian, self.ehdr.class, buf)));
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
    pub fn symbol_version_table(&mut self) -> Result<Option<SymbolVersionTable<E>>, ParseError> {
        let mut versym_opt: Option<SectionHeader> = None;
        let mut needs_opt: Option<SectionHeader> = None;
        let mut defs_opt: Option<SectionHeader> = None;
        // Find the GNU Symbol versioning sections (if any)
        for shdr in self.section_headers()? {
            if shdr.sh_type == abi::SHT_GNU_VERSYM {
                versym_opt = Some(shdr);
            } else if shdr.sh_type == abi::SHT_GNU_VERNEED {
                needs_opt = Some(shdr);
            } else if shdr.sh_type == abi::SHT_GNU_VERDEF {
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
        self.reader.load_bytes(versym_start..versym_end)?;

        // Get the VERNEED string shdr and load the VERNEED section data (if any)
        let needs_shdrs = match needs_opt {
            Some(shdr) => {
                let (start, end) = shdr.get_data_range()?;
                self.reader.load_bytes(start..end)?;

                let strs_shdr = self.section_header_by_index(shdr.sh_link as usize)?;
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

                let strs_shdr = self.section_header_by_index(shdr.sh_link as usize)?;
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
                    VerNeedIterator::new(self.endian, self.ehdr.class, shdr.sh_info as u64, 0, buf),
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
                    VerDefIterator::new(self.endian, self.ehdr.class, shdr.sh_info as u64, 0, buf),
                    StringTable::new(strs_buf),
                ))
            }
            // If there's no DEFs, then construct empty wrappers for them
            None => None,
        };

        // Wrap the versym section data in a parsing table
        let version_ids = VersionIndexTable::new(
            self.endian,
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
    ) -> Result<RelIterator<E>, ParseError> {
        if shdr.sh_type != abi::SHT_REL {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_REL,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(RelIterator::new(self.endian, self.ehdr.class, buf))
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
    ) -> Result<RelaIterator<E>, ParseError> {
        if shdr.sh_type != abi::SHT_RELA {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_RELA,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(RelaIterator::new(self.endian, self.ehdr.class, buf))
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
    ) -> Result<NoteIterator<E>, ParseError> {
        if shdr.sh_type != abi::SHT_NOTE {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_NOTE,
            )));
        }

        let (start, end) = shdr.get_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(NoteIterator::new(
            self.endian,
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
    ) -> Result<NoteIterator<E>, ParseError> {
        if phdr.p_type != abi::PT_NOTE {
            return Err(ParseError::UnexpectedSegmentType((
                phdr.p_type,
                abi::PT_NOTE,
            )));
        }

        let (start, end) = phdr.get_file_data_range()?;
        let buf = self.reader.read_bytes(start, end)?;
        Ok(NoteIterator::new(
            self.endian,
            self.ehdr.class,
            phdr.p_align as usize,
            buf,
        ))
    }
}

struct CachingReader<R: Read + Seek> {
    reader: R,
    bufs: HashMap<(usize, usize), Box<[u8]>>,
}

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

#[cfg(test)]
mod interface_tests {
    use super::*;
    use crate::dynamic::Dyn;
    use crate::endian::AnyEndian;
    use crate::hash::SysVHashTable;
    use crate::note::Note;
    use crate::relocation::Rela;
    use crate::symbol::Symbol;

    #[test]
    fn test_open_stream_with_cachedreadbytes() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");
        assert_eq!(file.ehdr.e_type, abi::ET_EXEC);
    }

    #[test]
    fn section_header_by_index() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

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
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

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
        assert_eq!(shdr.sh_type, abi::SHT_GNU_HASH);
    }

    #[test]
    fn section_data_for_nobits() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file
            .section_header_by_index(26)
            .expect("Failed to get .gnu.version section");
        assert_eq!(shdr.sh_type, abi::SHT_NOBITS);
        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");
        assert_eq!(chdr, None);
        assert_eq!(data, &[]);
    }

    #[test]
    fn section_data() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file
            .section_header_by_index(7)
            .expect("Failed to get .gnu.version section");
        assert_eq!(shdr.sh_type, abi::SHT_GNU_VERSYM);
        let (data, chdr) = file
            .section_data(&shdr)
            .expect("Failed to get section data");
        assert_eq!(chdr, None);
        assert_eq!(data, [0, 0, 2, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn section_data_as_strtab() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

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
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("Failed to read segments")
            .expect("file should have segments")
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
        )
    }

    #[test]
    fn symbol_table() {
        let path = std::path::PathBuf::from("tests/samples/test1");
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
        let path = std::path::PathBuf::from("tests/samples/test1");
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
    fn dynamic_section() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let mut dynamic = file
            .dynamic_section()
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
    fn section_data_as_rels() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let shdr = file
            .section_header_by_index(10)
            .expect("Failed to get rela shdr");
        file.section_data_as_rels(&shdr)
            .expect_err("Expected error parsing non-REL scn as RELs");
    }

    #[test]
    fn section_data_as_relas() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

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
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

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
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        let phdrs: Vec<ProgramHeader> = file
            .segments()
            .expect("Failed to get .note.ABI-tag shdr")
            .expect("File should have headers")
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
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");
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
        let io = std::fs::File::open(path).expect("Could not open file.");
        let mut file = ElfStream::<AnyEndian, _>::open_stream(io).expect("Open test1");

        // Look up the SysV hash section header
        let hash_shdr = file
            .section_headers()
            .expect("Failed to parse shdrs")
            .iter()
            .find(|shdr| shdr.sh_type == abi::SHT_HASH)
            .expect("Failed to find sysv hash section");

        // We don't have a file interface for getting the SysV hash section yet, so clone the section bytes
        // So we can use them to back a SysVHashTable
        let (data, _) = file
            .section_data(&hash_shdr)
            .expect("Failed to get hash section data");
        let data_copy: Vec<u8> = data.into();
        let hash_table = SysVHashTable::new(file.endian, file.ehdr.class, data_copy.as_ref())
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
