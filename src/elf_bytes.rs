use crate::abi;
use crate::compression::CompressionHeader;
use crate::dynamic::{Dyn, DynamicTable};
use crate::endian::EndianParse;
use crate::file::{parse_ident, Class, FileHeader};
use crate::gnu_symver::{
    SymbolVersionTable, VerDefIterator, VerNeedIterator, VersionIndex, VersionIndexTable,
};
use crate::hash::{GnuHashTable, SysVHashTable};
use crate::note::NoteIterator;
use crate::parse::{ParseAt, ParseError, ReadBytesExt};
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

/// This type encapsulates the bytes-oriented interface for parsing ELF objects from `&[u8]`.
///
/// This parser is no_std and zero-alloc, returning lazy-parsing interfaces wrapped around
/// subslices of the provided ELF bytes `&[u8]`. The various ELF structures are
/// parsed on-demand into a native Rust representation.
///
/// Example usage:
/// ```
/// use elf::abi::PT_LOAD;
/// use elf::endian::AnyEndian;
/// use elf::ElfBytes;
/// use elf::segment::ProgramHeader;
///
/// let path = std::path::PathBuf::from("sample-objects/symver.x86_64.so");
/// let file_data = std::fs::read(path).unwrap();
///
/// let slice = file_data.as_slice();
/// let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
///
/// // Get all the common ELF sections (if any). We have a lot of ELF work to do!
/// let common_sections = file.find_common_data().unwrap();
/// // ... do some stuff with the symtab, dynsyms etc
///
/// // It can also yield iterators on which we can do normal iterator things, like filtering
/// // for all the segments of a specific type. Parsing is done on each iter.next() call, so
/// // if you end iteration early, it won't parse the rest of the table.
/// let first_load_phdr: Option<ProgramHeader> = file.segments().unwrap()
///     .iter()
///     .find(|phdr|{phdr.p_type == PT_LOAD});
/// println!("First load segment is at: {}", first_load_phdr.unwrap().p_vaddr);
///
/// // Or if you do things like this to get a vec of only the PT_LOAD segments.
/// let all_load_phdrs: Vec<ProgramHeader> = file.segments().unwrap()
///     .iter()
///     .filter(|phdr|{phdr.p_type == PT_LOAD})
///     .collect();
/// println!("There are {} PT_LOAD segments", all_load_phdrs.len());
/// ```
#[derive(Debug)]
pub struct ElfBytes<'data, E: EndianParse> {
    pub ehdr: FileHeader<E>,
    data: &'data [u8],
    shdrs: Option<SectionHeaderTable<'data, E>>,
    phdrs: Option<SegmentTable<'data, E>>,
}

/// Find the location (if any) of the section headers in the given data buffer and take a
/// subslice of their data and wrap it in a lazy-parsing SectionHeaderTable.
/// If shnum > SHN_LORESERVE (0xff00), then this will additionally parse out shdr[0] to calculate
/// the full table size, but all other parsing of SectionHeaders is deferred.
fn find_shdrs<'data, E: EndianParse>(
    ehdr: &FileHeader<E>,
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
        let shdr0 = SectionHeader::parse_at(ehdr.endianness, ehdr.class, &mut offset, data)?;
        shnum = shdr0.sh_size.try_into()?;
    }

    // Validate shentsize before trying to read the table so that we can error early for corrupted files
    let entsize = SectionHeader::validate_entsize(ehdr.class, ehdr.e_shentsize as usize)?;

    let size = entsize
        .checked_mul(shnum)
        .ok_or(ParseError::IntegerOverflow)?;
    let end = shoff.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
    let buf = data.get_bytes(shoff..end)?;
    Ok(Some(SectionHeaderTable::new(
        ehdr.endianness,
        ehdr.class,
        buf,
    )))
}

/// Find the location (if any) of the program headers in the given data buffer and take a
/// subslice of their data and wrap it in a lazy-parsing SegmentTable.
fn find_phdrs<'data, E: EndianParse>(
    ehdr: &FileHeader<E>,
    data: &'data [u8],
) -> Result<Option<SegmentTable<'data, E>>, ParseError> {
    // It's Ok to have no program headers
    if ehdr.e_phoff == 0 {
        return Ok(None);
    }

    // If the number of segments is greater than or equal to PN_XNUM (0xffff),
    // e_phnum is set to PN_XNUM, and the actual number of program header table
    // entries is contained in the sh_info field of the section header at index 0.
    let mut phnum = ehdr.e_phnum as usize;
    if phnum == abi::PN_XNUM as usize {
        let shoff: usize = ehdr.e_shoff.try_into()?;
        let mut offset = shoff;
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
    let buf = data.get_bytes(phoff..end)?;
    Ok(Some(SegmentTable::new(ehdr.endianness, ehdr.class, buf)))
}

/// This struct collects the common sections found in ELF objects
#[derive(Debug, Default)]
pub struct CommonElfData<'data, E: EndianParse> {
    /// .symtab section
    pub symtab: Option<SymbolTable<'data, E>>,
    /// strtab for .symtab
    pub symtab_strs: Option<StringTable<'data>>,

    /// .dynsym section
    pub dynsyms: Option<SymbolTable<'data, E>>,
    /// strtab for .dynsym
    pub dynsyms_strs: Option<StringTable<'data>>,

    /// .dynamic section or PT_DYNAMIC segment (both point to the same table)
    pub dynamic: Option<DynamicTable<'data, E>>,

    /// .hash section
    pub sysv_hash: Option<SysVHashTable<'data, E>>,

    /// .gnu.hash section
    pub gnu_hash: Option<GnuHashTable<'data, E>>,
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
        let ident = parse_ident(ident_buf)?;

        let tail_start = abi::EI_NIDENT;
        let tail_end = match ident.1 {
            Class::ELF32 => tail_start + crate::file::ELF32_EHDR_TAILSIZE,
            Class::ELF64 => tail_start + crate::file::ELF64_EHDR_TAILSIZE,
        };
        let tail_buf = data.get_bytes(tail_start..tail_end)?;

        let ehdr = FileHeader::parse_tail(ident, tail_buf)?;

        let shdrs = find_shdrs(&ehdr, data)?;
        let phdrs = find_phdrs(&ehdr, data)?;
        Ok(ElfBytes {
            ehdr,
            data,
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
    /// use std::collections::HashMap;
    /// use elf::endian::AnyEndian;
    /// use elf::ElfBytes;
    /// use elf::note::Note;
    /// use elf::note::NoteGnuBuildId;
    /// use elf::section::SectionHeader;
    ///
    /// let path = std::path::PathBuf::from("sample-objects/symver.x86_64.so");
    /// let file_data = std::fs::read(path).unwrap();
    ///
    /// let slice = file_data.as_slice();
    /// let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
    ///
    /// // Get the section header table alongside its string table
    /// let (shdrs_opt, strtab_opt) = file
    ///     .section_headers_with_strtab()
    ///     .expect("shdrs offsets should be valid");
    /// let (shdrs, strtab) = (
    ///     shdrs_opt.expect("Should have shdrs"),
    ///     strtab_opt.expect("Should have strtab")
    /// );
    ///
    /// // Parse the shdrs and collect them into a map keyed on their zero-copied name
    /// let with_names: HashMap<&str, SectionHeader> = shdrs
    ///     .iter()
    ///     .map(|shdr| {
    ///         (
    ///             strtab.get(shdr.sh_name as usize).expect("Failed to get section name"),
    ///             shdr,
    ///         )
    ///     })
    ///     .collect();
    ///
    /// // Get the zero-copy parsed type for the the build id note
    /// let build_id_note_shdr: &SectionHeader = with_names
    ///     .get(".note.gnu.build-id")
    ///     .expect("Should have build id note section");
    /// let notes: Vec<_> = file
    ///     .section_data_as_notes(build_id_note_shdr)
    ///     .expect("Should be able to get note section data")
    ///     .collect();
    /// println!("{:?}", notes[0]);
    /// ```
    pub fn section_headers_with_strtab(
        &self,
    ) -> Result<
        (
            Option<SectionHeaderTable<'data, E>>,
            Option<StringTable<'data>>,
        ),
        ParseError,
    > {
        // It's Ok to have no section headers
        let shdrs = match self.section_headers() {
            Some(shdrs) => shdrs,
            None => {
                return Ok((None, None));
            }
        };

        // It's Ok to not have a string table
        if self.ehdr.e_shstrndx == abi::SHN_UNDEF {
            return Ok((Some(shdrs), None));
        }

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
        Ok((Some(shdrs), Some(StringTable::new(strtab_buf))))
    }

    /// Parse section headers until one is found with the given name
    ///
    /// Example to get the ELF file's ABI-tag note
    /// ```
    /// use elf::ElfBytes;
    /// use elf::endian::AnyEndian;
    /// use elf::section::SectionHeader;
    /// use elf::note::Note;
    /// use elf::note::NoteGnuAbiTag;
    ///
    /// let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
    /// let file_data = std::fs::read(path).unwrap();
    /// let slice = file_data.as_slice();
    /// let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
    ///
    /// let shdr: SectionHeader = file
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
    pub fn section_header_by_name(&self, name: &str) -> Result<Option<SectionHeader>, ParseError> {
        let (shdrs, strtab) = match self.section_headers_with_strtab()? {
            (Some(shdrs), Some(strtab)) => (shdrs, strtab),
            _ => {
                // If we don't have shdrs, or don't have a strtab, we can't find a section by its name
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

    /// Efficiently locate the set of common sections found in ELF files by doing a single iteration
    /// over the SectionHeaders table.
    ///
    /// This is useful for those who know they're going to be accessing multiple common sections, like
    /// symbol tables, string tables. Many of these can also be accessed by the more targeted
    /// helpers like [ElfBytes::symbol_table] or [ElfBytes::dynamic], though those each do their own
    /// internal searches through the shdrs to find the section.
    pub fn find_common_data(&self) -> Result<CommonElfData<'data, E>, ParseError> {
        let mut result: CommonElfData<'data, E> = CommonElfData::default();

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
                        result.dynamic = Some(self.section_data_as_dynamic(&shdr)?);
                    }
                    abi::SHT_HASH => {
                        let (start, end) = shdr.get_data_range()?;
                        let buf = self.data.get_bytes(start..end)?;
                        result.sysv_hash = Some(SysVHashTable::new(
                            self.ehdr.endianness,
                            self.ehdr.class,
                            buf,
                        )?);
                    }
                    abi::SHT_GNU_HASH => {
                        let (start, end) = shdr.get_data_range()?;
                        let buf = self.data.get_bytes(start..end)?;
                        result.gnu_hash = Some(GnuHashTable::new(
                            self.ehdr.endianness,
                            self.ehdr.class,
                            buf,
                        )?);
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
                    result.dynamic = Some(DynamicTable::new(
                        self.ehdr.endianness,
                        self.ehdr.class,
                        buf,
                    ));
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
        Ok(RelIterator::new(self.ehdr.endianness, self.ehdr.class, buf))
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
        Ok(RelaIterator::new(
            self.ehdr.endianness,
            self.ehdr.class,
            buf,
        ))
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
            self.ehdr.endianness,
            self.ehdr.class,
            shdr.sh_addralign as usize,
            buf,
        ))
    }

    /// Internal helper to get the section data for an SHT_DYNAMIC section as a .dynamic section table.
    /// See [ElfBytes::dynamic] or [ElfBytes::find_common_data] for the public interface
    fn section_data_as_dynamic(
        &self,
        shdr: &SectionHeader,
    ) -> Result<DynamicTable<'data, E>, ParseError> {
        if shdr.sh_type != abi::SHT_DYNAMIC {
            return Err(ParseError::UnexpectedSectionType((
                shdr.sh_type,
                abi::SHT_DYNAMIC,
            )));
        }

        // Validate entsize before trying to read the table so that we can error early for corrupted files
        Dyn::validate_entsize(self.ehdr.class, shdr.sh_entsize.try_into()?)?;
        let (buf, _) = self.section_data(shdr)?;
        Ok(DynamicTable::new(
            self.ehdr.endianness,
            self.ehdr.class,
            buf,
        ))
    }

    /// Get the segment's file data for a given segment/[ProgramHeader].
    ///
    /// This is the segment's data as found in the file.
    pub fn segment_data(&self, phdr: &ProgramHeader) -> Result<&'data [u8], ParseError> {
        let (start, end) = phdr.get_file_data_range()?;
        self.data.get_bytes(start..end)
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
            self.ehdr.endianness,
            self.ehdr.class,
            phdr.p_align as usize,
            buf,
        ))
    }

    /// Get the .dynamic section or [abi::PT_DYNAMIC] segment contents.
    pub fn dynamic(&self) -> Result<Option<DynamicTable<'data, E>>, ParseError> {
        // If we have section headers, look for the SHT_DYNAMIC section
        if let Some(shdrs) = self.section_headers() {
            if let Some(shdr) = shdrs.iter().find(|shdr| shdr.sh_type == abi::SHT_DYNAMIC) {
                return Ok(Some(self.section_data_as_dynamic(&shdr)?));
            }
        // Otherwise, look up the PT_DYNAMIC segment (if any)
        } else if let Some(phdrs) = self.segments() {
            if let Some(phdr) = phdrs.iter().find(|phdr| phdr.p_type == abi::PT_DYNAMIC) {
                let (start, end) = phdr.get_file_data_range()?;
                let buf = self.data.get_bytes(start..end)?;
                return Ok(Some(DynamicTable::new(
                    self.ehdr.endianness,
                    self.ehdr.class,
                    buf,
                )));
            }
        }

        Ok(None)
    }

    /// Helper method to get the section data for a given pair of [SectionHeader] for the symbol
    /// table and its linked strtab, and interpret them as [SymbolTable] and [StringTable].
    fn section_data_as_symbol_table(
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

        let symtab = SymbolTable::new(self.ehdr.endianness, self.ehdr.class, symtab_buf);
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

    /// Locate the section data for the various GNU Symbol Versioning sections (if any)
    /// and return them in a [SymbolVersionTable] that which can interpret them in-place to
    /// yield [SymbolRequirement](crate::gnu_symver::SymbolRequirement)s
    /// and [SymbolDefinition](crate::gnu_symver::SymbolDefinition)s
    ///
    /// This is a GNU extension and not all objects use symbol versioning.
    /// Returns an empty Option if the object does not use symbol versioning.
    pub fn symbol_version_table(&self) -> Result<Option<SymbolVersionTable<'data, E>>, ParseError> {
        // No sections means no GNU symbol versioning sections, which is ok
        let shdrs = match self.section_headers() {
            Some(shdrs) => shdrs,
            None => {
                return Ok(None);
            }
        };

        let mut versym_opt: Option<SectionHeader> = None;
        let mut needs_opt: Option<SectionHeader> = None;
        let mut defs_opt: Option<SectionHeader> = None;
        // Find the GNU Symbol versioning sections (if any)
        for shdr in shdrs.iter() {
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

        let versym_shdr = match versym_opt {
            Some(shdr) => shdr,
            // No VERSYM section means the object doesn't use symbol versioning, which is ok.
            None => {
                return Ok(None);
            }
        };

        // Load the versym table
        // Validate VERSYM entsize before trying to read the table so that we can error early for corrupted files
        VersionIndex::validate_entsize(self.ehdr.class, versym_shdr.sh_entsize.try_into()?)?;
        let (versym_start, versym_end) = versym_shdr.get_data_range()?;
        let version_ids = VersionIndexTable::new(
            self.ehdr.endianness,
            self.ehdr.class,
            self.data.get_bytes(versym_start..versym_end)?,
        );

        // Wrap the VERNEED section and strings data in an iterator and string table (if any)
        let verneeds = match needs_opt {
            Some(shdr) => {
                let (start, end) = shdr.get_data_range()?;
                let needs_buf = self.data.get_bytes(start..end)?;

                let strs_shdr = shdrs.get(shdr.sh_link as usize)?;
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                let strs_buf = self.data.get_bytes(strs_start..strs_end)?;

                Some((
                    VerNeedIterator::new(
                        self.ehdr.endianness,
                        self.ehdr.class,
                        shdr.sh_info as u64,
                        0,
                        needs_buf,
                    ),
                    StringTable::new(strs_buf),
                ))
            }
            // It's possible to have symbol versioning with no NEEDs if we're an object that only
            // exports defined symbols.
            None => None,
        };

        // Wrap the VERDEF section and strings data in an iterator and string table (if any)
        let verdefs = match defs_opt {
            Some(shdr) => {
                let (start, end) = shdr.get_data_range()?;
                let defs_buf = self.data.get_bytes(start..end)?;

                let strs_shdr = shdrs.get(shdr.sh_link as usize)?;
                let (strs_start, strs_end) = strs_shdr.get_data_range()?;
                let strs_buf = self.data.get_bytes(strs_start..strs_end)?;

                Some((
                    VerDefIterator::new(
                        self.ehdr.endianness,
                        self.ehdr.class,
                        shdr.sh_info as u64,
                        0,
                        defs_buf,
                    ),
                    StringTable::new(strs_buf),
                ))
            }
            // It's possible to have symbol versioning with no NEEDs if we're an object that only
            // exports defined symbols.
            None => None,
        };

        // whew, we're done here!
        Ok(Some(SymbolVersionTable::new(
            version_ids,
            verneeds,
            verdefs,
        )))
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
    use crate::abi::{SHT_GNU_HASH, SHT_NOBITS, SHT_NOTE, SHT_NULL, SHT_REL, SHT_RELA, SHT_STRTAB};
    use crate::dynamic::Dyn;
    use crate::endian::AnyEndian;
    use crate::hash::sysv_hash;
    use crate::note::{Note, NoteGnuAbiTag, NoteGnuBuildId};
    use crate::relocation::Rela;
    use crate::segment::ProgramHeader;

    #[test]
    fn simultaenous_segments_parsing() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
    fn segments_phnum_in_shdr0() {
        let path = std::path::PathBuf::from("sample-objects/phnum.m68k.so");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .iter()
            .collect();
        assert_eq!(
            segments[0],
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
    fn section_headers() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

        let shdrs = file
            .section_headers()
            .expect("File should have a section table");

        let shdrs_vec: Vec<SectionHeader> = shdrs.iter().collect();

        assert_eq!(shdrs_vec[4].sh_type, SHT_GNU_HASH);
    }

    #[test]
    fn section_headers_with_strtab() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

        let (shdrs, strtab) = file
            .section_headers_with_strtab()
            .expect("shdrs should be parsable");
        let (shdrs, strtab) = (shdrs.unwrap(), strtab.unwrap());

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
    fn shnum_and_shstrndx_in_shdr0() {
        let path = std::path::PathBuf::from("sample-objects/shnum.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();

        let (shdrs, strtab) = file
            .section_headers_with_strtab()
            .expect("shdrs should be parsable");
        let (shdrs, strtab) = (shdrs.unwrap(), strtab.unwrap());

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
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

        let shdr = file
            .section_header_by_name(".gnu.hash")
            .expect("section table should be parseable")
            .expect("file should have .gnu.hash section");

        assert_eq!(shdr.sh_type, SHT_GNU_HASH);

        let shdr = file
            .section_header_by_name(".not.found")
            .expect("section table should be parseable");

        assert_eq!(shdr, None);
    }

    #[test]
    fn find_common_data() {
        let path = std::path::PathBuf::from("sample-objects/symver.x86_64.so");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

        let elf_scns = file.find_common_data().expect("file should parse");

        // hello.so should find everything
        assert!(elf_scns.symtab.is_some());
        assert!(elf_scns.symtab_strs.is_some());
        assert!(elf_scns.dynsyms.is_some());
        assert!(elf_scns.dynsyms_strs.is_some());
        assert!(elf_scns.dynamic.is_some());
        assert!(elf_scns.sysv_hash.is_some());
        assert!(elf_scns.gnu_hash.is_some());
    }

    #[test]
    fn section_data() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
    fn dynamic() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
    fn symbol_table() {
        let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
    fn symbol_version_table() {
        let path = std::path::PathBuf::from("sample-objects/symver.x86_64.so");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

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
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");

        // Look up the SysV hash section header
        let common = file.find_common_data().expect("should parse");
        let hash_table = common.sysv_hash.expect("should have .hash section");

        // Get the dynamic symbol table.
        let (symtab, strtab) = file
            .dynamic_symbol_table()
            .expect("Failed to read symbol table")
            .expect("Failed to find symbol table");

        // Verify that these three symbols all collide in the hash table's buckets
        assert_eq!(sysv_hash(b"use_memset_v2"), 0x8080542);
        assert_eq!(sysv_hash(b"__gmon_start__"), 0xF4D007F);
        assert_eq!(sysv_hash(b"memset"), 0x73C49C4);
        assert_eq!(sysv_hash(b"use_memset_v2") % 3, 0);
        assert_eq!(sysv_hash(b"__gmon_start__") % 3, 0);
        assert_eq!(sysv_hash(b"memset") % 3, 0);

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

    #[test]
    fn gnu_hash_table() {
        let path = std::path::PathBuf::from("sample-objects/symver.x86_64.so");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();

        // Look up the SysV hash section header
        let common = file.find_common_data().unwrap();
        let hash_table = common.gnu_hash.expect("should have .gnu.hash section");

        // Get the dynamic symbol table.
        let (symtab, strtab) = (common.dynsyms.unwrap(), common.dynsyms_strs.unwrap());

        // manually look one up by explicit name to make sure the above loop is doing something
        let (sym_idx, sym) = hash_table
            .find(b"use_memset", &symtab, &strtab)
            .expect("Failed to parse hash")
            .expect("Failed to find hash");

        // Verify that we got the same symbol from the hash table we expected
        assert_eq!(sym_idx, 9);
        assert_eq!(strtab.get(sym.st_name as usize).unwrap(), "use_memset");
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
            let file_data = std::fs::read(path).expect("file should exist");
            let slice = file_data.as_slice();
            let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("should parse");

            assert_eq!(file.ehdr.e_machine, $e_machine);
            assert_eq!(file.ehdr.endianness, $endian);

            let (shdrs, strtab) = file.section_headers_with_strtab().expect("should parse");
            let (shdrs, strtab) = (shdrs.unwrap(), strtab.unwrap());
            let _: Vec<_> = shdrs
                .iter()
                .map(|shdr| {
                    (
                        strtab.get(shdr.sh_name as usize).expect("should parse"),
                        shdr,
                    )
                })
                .collect();

            let common = file.find_common_data().expect("should parse");

            // parse out all the normal symbol table symbols with their names
            {
                let symtab = common.symtab.unwrap();
                let strtab = common.symtab_strs.unwrap();
                let _: Vec<_> = symtab
                    .iter()
                    .map(|sym| (strtab.get(sym.st_name as usize).expect("should parse"), sym))
                    .collect();
            }

            // parse out all the dynamic symbols and look them up in the gnu hash table
            {
                let symtab = common.dynsyms.unwrap();
                let strtab = common.dynsyms_strs.unwrap();
                let symbols_with_names: Vec<_> = symtab
                    .iter()
                    .map(|sym| (strtab.get_raw(sym.st_name as usize).expect("should parse"), sym))
                    .collect();

                let hash_table = common.gnu_hash.unwrap();

                // look up each entry that should be in the hash table and make sure its there
                let start_idx = hash_table.hdr.table_start_idx as usize;
                for sym_idx in 0..symtab.len() {
                    let (symbol_name, symbol) = symbols_with_names.get(sym_idx).unwrap();

                    let result = hash_table
                        .find(symbol_name, &symtab, &strtab)
                        .expect("Failed to parse hash");

                    if sym_idx < start_idx {
                        assert_eq!(result, None);
                    } else {
                        let (hash_sym_idx, hash_symbol) = result.unwrap();

                        // Verify that we got the same symbol from the hash table we expected
                        assert_eq!(sym_idx, hash_sym_idx);
                        assert_eq!(
                            strtab.get_raw(hash_symbol.st_name as usize).unwrap(),
                            *symbol_name
                        );
                        assert_eq!(*symbol, hash_symbol);
                    }
                }
            }

            let phdrs = file.segments().unwrap();
            let note_phdrs: Vec<_> = phdrs
                .iter()
                .filter(|phdr| phdr.p_type == abi::PT_NOTE)
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
