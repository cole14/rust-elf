//! Parsing GNU extension sections for dynamic symbol versioning `.gnu.version.*`
use crate::abi;
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ParsingTable};
use crate::string_table::StringTable;

#[derive(Debug, PartialEq, Eq)]
pub struct SymbolRequirement<'data> {
    pub file: &'data str,
    pub name: &'data str,
    pub hash: u32,
    pub flags: u16,
    pub hidden: bool,
}

#[derive(Debug)]
pub struct SymbolDefinition<'data, E: EndianParse> {
    pub hash: u32,
    pub flags: u16,
    pub names: SymbolNamesIterator<'data, E>,
    pub hidden: bool,
}

#[derive(Debug)]
pub struct SymbolNamesIterator<'data, E: EndianParse> {
    vda_iter: VerDefAuxIterator<'data, E>,
    strtab: &'data StringTable<'data>,
}

impl<'data, E: EndianParse> SymbolNamesIterator<'data, E> {
    pub fn new(vda_iter: VerDefAuxIterator<'data, E>, strtab: &'data StringTable<'data>) -> Self {
        SymbolNamesIterator { vda_iter, strtab }
    }
}

impl<'data, E: EndianParse> Iterator for SymbolNamesIterator<'data, E> {
    type Item = Result<&'data str, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        let vda = self.vda_iter.next();
        match vda {
            Some(vda) => Some(self.strtab.get(vda.vda_name as usize)),
            None => None,
        }
    }
}

#[derive(Debug)]
pub struct SymbolVersionTable<'data, E: EndianParse> {
    version_ids: VersionIndexTable<'data, E>,

    verneeds: Option<(VerNeedIterator<'data, E>, StringTable<'data>)>,
    verdefs: Option<(VerDefIterator<'data, E>, StringTable<'data>)>,
}

impl<'data, E: EndianParse> SymbolVersionTable<'data, E> {
    pub fn new(
        version_ids: VersionIndexTable<'data, E>,
        verneeds: Option<(VerNeedIterator<'data, E>, StringTable<'data>)>,
        verdefs: Option<(VerDefIterator<'data, E>, StringTable<'data>)>,
    ) -> Self {
        SymbolVersionTable {
            version_ids,
            verneeds,
            verdefs,
        }
    }

    pub fn get_requirement(
        &self,
        sym_idx: usize,
    ) -> Result<Option<SymbolRequirement<'_>>, ParseError> {
        let (verneeds, verneed_strs) = match self.verneeds {
            Some(verneeds) => verneeds,
            None => {
                return Ok(None);
            }
        };

        let ver_ndx = self.version_ids.get(sym_idx)?;
        let iter = verneeds;
        for (vn, vna_iter) in iter {
            for vna in vna_iter {
                if vna.vna_other != ver_ndx.index() {
                    continue;
                }

                let file = verneed_strs.get(vn.vn_file as usize)?;
                let name = verneed_strs.get(vna.vna_name as usize)?;
                let hash = vna.vna_hash;
                let hidden = ver_ndx.is_hidden();
                return Ok(Some(SymbolRequirement {
                    file,
                    name,
                    hash,
                    flags: vna.vna_flags,
                    hidden,
                }));
            }
        }

        // Maybe we should treat this as a ParseError instead of returning an
        // empty Option? This can only happen if .gnu.versions[N] contains an
        // index that doesn't exist, which is likely a file corruption or
        // programmer error (i.e asking for a requirement for a defined symbol)
        Ok(None)
    }

    pub fn get_definition(
        &self,
        sym_idx: usize,
    ) -> Result<Option<SymbolDefinition<'_, E>>, ParseError> {
        let (ref verdefs, ref verdef_strs) = match self.verdefs {
            Some(ref verdefs) => verdefs,
            None => {
                return Ok(None);
            }
        };

        let ver_ndx = self.version_ids.get(sym_idx)?;
        let iter = *verdefs;
        for (vd, vda_iter) in iter {
            if vd.vd_ndx != ver_ndx.index() {
                continue;
            }

            let flags = vd.vd_flags;
            let hash = vd.vd_hash;
            let hidden = ver_ndx.is_hidden();
            return Ok(Some(SymbolDefinition {
                hash,
                flags,
                names: SymbolNamesIterator {
                    vda_iter,
                    strtab: verdef_strs,
                },
                hidden,
            }));
        }

        // Maybe we should treat this as a ParseError instead of returning an
        // empty Option? This can only happen if .gnu.versions[N] contains an
        // index that doesn't exist, which is likely a file corruption or
        // programmer error (i.e asking for a definition for an undefined symbol)
        Ok(None)
    }
}

////////////////////////////////////////////////////////////////////
//                                                 _              //
//       __ _ _ __  _   _      __   _____ _ __ ___(_) ___  _ __   //
//      / _` | '_ \| | | |     \ \ / / _ \ '__/ __| |/ _ \| '_ \  //
//  _  | (_| | | | | |_| |  _   \ V /  __/ |  \__ \ | (_) | | | | //
// (_)  \__, |_| |_|\__,_| (_)   \_/ \___|_|  |___/_|\___/|_| |_| //
//      |___/                                                     //
////////////////////////////////////////////////////////////////////

pub type VersionIndexTable<'data, E> = ParsingTable<'data, E, VersionIndex>;

/// The special GNU extension section .gnu.version has a section type of SHT_GNU_VERSYM.
/// This section shall have the same number of entries as the Dynamic Symbol Table in
/// the .dynsym section. The .gnu.version section shall contain an array of
/// elements of type Elfxx_Half (both of which are 16-bit unsigned integers).
///
/// The .gnu.version section and VersionIndex values act as a lookup table for specifying
/// the version defined for or required by the corresponding symbol in the Dynamic Symbol Table.
///
/// For example, the symbol at index N in the .dynsym Symbol Table will have a VersionIndex
/// value located in the versym table at .gnu.version\[N\] which identifies
/// structures in the .gnu.version_d and .gnu.version_r sections. These values
/// are located in identifiers provided by the the vna_other member of the VerNeedAux
/// structure or the vd_ndx member of the VerDef structure.
#[derive(Debug, PartialEq, Eq)]
pub struct VersionIndex(pub u16);

impl VersionIndex {
    pub fn index(&self) -> u16 {
        self.0 & abi::VER_NDX_VERSION
    }

    pub fn is_local(&self) -> bool {
        self.index() == abi::VER_NDX_LOCAL
    }

    pub fn is_global(&self) -> bool {
        self.index() == abi::VER_NDX_GLOBAL
    }

    pub fn is_hidden(&self) -> bool {
        (self.0 & abi::VER_NDX_HIDDEN) != 0
    }
}

impl ParseAt for VersionIndex {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(VersionIndex(endian.parse_u16_at(offset, data)?))
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        core::mem::size_of::<u16>()
    }
}

///////////////////////////////////////////////////////////////////////////////
//                                                 _                      _  //
//       __ _ _ __  _   _      __   _____ _ __ ___(_) ___  _ __        __| | //
//      / _` | '_ \| | | |     \ \ / / _ \ '__/ __| |/ _ \| '_ \      / _` | //
//  _  | (_| | | | | |_| |  _   \ V /  __/ |  \__ \ | (_) | | | |    | (_| | //
// (_)  \__, |_| |_|\__,_| (_)   \_/ \___|_|  |___/_|\___/|_| |_|_____\__,_| //
//      |___/                                                   |_____|      //
///////////////////////////////////////////////////////////////////////////////

/// The special GNU extension section .gnu.version_d has a section type of SHT_GNU_VERDEF
/// This section shall contain symbol version definitions. The number of entries
/// in this section shall be contained in the DT_VERDEFNUM entry of the Dynamic
/// Section .dynamic, and also the sh_info member of the section header.
/// The sh_link member of the section header shall point to the section that
/// contains the strings referenced by this section.
///
/// The .gnu.version_d section shall contain an array of VerDef structures
/// optionally followed by an array of VerDefAux structures.
#[derive(Debug, PartialEq, Eq)]
pub struct VerDef {
    /// Version information flag bitmask.
    pub vd_flags: u16,
    /// VersionIndex value referencing the SHT_GNU_VERSYM section.
    pub vd_ndx: u16,
    /// Number of associated verdaux array entries.
    pub vd_cnt: u16,
    /// Version name hash value (ELF hash function).
    pub vd_hash: u32,
    /// Offset in bytes to a corresponding entry in an array of VerDefAux structures.
    vd_aux: u32,
    /// Offset to the next VerDef entry, in bytes.
    vd_next: u32,
}

impl ParseAt for VerDef {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        let vd_version = endian.parse_u16_at(offset, data)?;
        if vd_version != abi::VER_DEF_CURRENT {
            return Err(ParseError::UnsupportedVersion((
                vd_version as u64,
                abi::VER_DEF_CURRENT as u64,
            )));
        }

        Ok(VerDef {
            vd_flags: endian.parse_u16_at(offset, data)?,
            vd_ndx: endian.parse_u16_at(offset, data)?,
            vd_cnt: endian.parse_u16_at(offset, data)?,
            vd_hash: endian.parse_u32_at(offset, data)?,
            vd_aux: endian.parse_u32_at(offset, data)?,
            vd_next: endian.parse_u32_at(offset, data)?,
        })
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        ELFVERDEFSIZE
    }
}

const ELFVERDEFSIZE: usize = 20;

#[derive(Debug, Clone, Copy)]
pub struct VerDefIterator<'data, E: EndianParse> {
    endian: E,
    class: Class,
    /// The number of entries in this iterator is given by the .dynamic DT_VERDEFNUM entry
    /// and also in the .gnu.version_d section header's sh_info field.
    count: u64,
    data: &'data [u8],
    offset: usize,
}

impl<'data, E: EndianParse> VerDefIterator<'data, E> {
    pub fn new(
        endian: E,
        class: Class,
        count: u64,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerDefIterator {
            endian,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data, E: EndianParse> Iterator for VerDefIterator<'data, E> {
    type Item = (VerDef, VerDefAuxIterator<'data, E>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() || self.count == 0 {
            return None;
        }

        let mut start = self.offset;
        let vd = VerDef::parse_at(self.endian, self.class, &mut start, self.data).ok()?;
        let vda_iter = VerDefAuxIterator::new(
            self.endian,
            self.class,
            vd.vd_cnt,
            self.offset + vd.vd_aux as usize,
            self.data,
        );

        // If offset overflows, silently end iteration
        match self.offset.checked_add(vd.vd_next as usize) {
            Some(new_off) => self.offset = new_off,
            None => self.count = 0,
        }
        self.count -= 1;

        // Silently end iteration early if the next link stops pointing somewhere new
        // TODO: Make this an error condition by allowing the iterator to yield a ParseError
        if self.count > 0 && vd.vd_next == 0 {
            self.count = 0
        }
        Some((vd, vda_iter))
    }
}

/// Version Definition Auxiliary Entries from the .gnu.version_d section
#[derive(Debug, PartialEq, Eq)]
pub struct VerDefAux {
    /// Offset to the version or dependency name string in the linked string table, in bytes.
    pub vda_name: u32,
    /// Offset to the next VerDefAux entry, in bytes.
    vda_next: u32,
}

impl ParseAt for VerDefAux {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(VerDefAux {
            vda_name: endian.parse_u32_at(offset, data)?,
            vda_next: endian.parse_u32_at(offset, data)?,
        })
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        8
    }
}

#[derive(Debug)]
pub struct VerDefAuxIterator<'data, E: EndianParse> {
    endian: E,
    class: Class,
    count: u16,
    data: &'data [u8],
    offset: usize,
}

impl<'data, E: EndianParse> VerDefAuxIterator<'data, E> {
    pub fn new(
        endian: E,
        class: Class,
        count: u16,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerDefAuxIterator {
            endian,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data, E: EndianParse> Iterator for VerDefAuxIterator<'data, E> {
    type Item = VerDefAux;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() || self.count == 0 {
            return None;
        }

        // N.B. This offset handling is maybe unnecessary, but faithful to the
        // spec. As far as I've observed, VerDefAux entries for a VerDef are all
        // encoded sequentially after the VerDef, so we could likely just
        // use the normal pattern here and pass in &mut self.offset here.
        //
        // The spec claims that "The section shall contain an array of
        // Elfxx_Verdef structures, optionally followed by an array of
        // Elfxx_Verdaux structures." This reads a bit ambiguously
        // (is there one big array of Verdefs followed by one big array of
        // Verdauxs?). If so, the vd_next and vda_next links seem unnecessary
        // given the vd_cnt field. In practice, it appears that all the VerDefAux
        // fields for a given VerDef are sequentially following the VerDef, meaning
        // they're contiguous, but intersersed. The _next fields could theoretically
        // give non-contiguous linked-list-like configurations, though (but only linking
        // forward, not backward, since the link is a u32).
        //
        // The vd_next and vda_next fields are also not "pointers" i.e. offsets from
        // the start of the section, but rather "increments" in telling how far to
        // advance from where you just read the containing struct for where you should
        // read the next. Given the sequentially-following nature described, these vd_next
        // and vda_next fields end up being 0x14 and 0x8 (the size of the VerDef and
        // VerDefAux structs).
        //
        // So observationally, we could likely get away with using self.offset and count here
        // and ignoring the vda_next field, but that'd break things if they weren't contiguous.
        let mut start = self.offset;
        let vda = VerDefAux::parse_at(self.endian, self.class, &mut start, self.data).ok()?;

        // If offset overflows, silently end iteration
        match self.offset.checked_add(vda.vda_next as usize) {
            Some(new_off) => self.offset = new_off,
            None => self.count = 0,
        }
        self.count -= 1;

        // Silently end iteration early if the next link stops pointing somewhere new
        // TODO: Make this an error condition by allowing the iterator to yield a ParseError
        if self.count > 0 && vda.vda_next == 0 {
            self.count = 0
        }
        Some(vda)
    }
}

///////////////////////////////////////////////////////////////////////////////
//                                                 _                         //
//       __ _ _ __  _   _      __   _____ _ __ ___(_) ___  _ __        _ __  //
//      / _` | '_ \| | | |     \ \ / / _ \ '__/ __| |/ _ \| '_ \      | '__| //
//  _  | (_| | | | | |_| |  _   \ V /  __/ |  \__ \ | (_) | | | |     | |    //
// (_)  \__, |_| |_|\__,_| (_)   \_/ \___|_|  |___/_|\___/|_| |_|_____|_|    //
//      |___/                                                   |_____|      //
///////////////////////////////////////////////////////////////////////////////

/// The GNU extension section .gnu.version_r has a section type of SHT_GNU_VERNEED.
/// This section contains required symbol version definitions. The number of
/// entries in this section shall be contained in the DT_VERNEEDNUM entry of the
/// Dynamic Section .dynamic and also the sh_info member of the section header.
/// The sh_link member of the section header shall point to the referenced
/// string table section.
///
/// The section shall contain an array of VerNeed structures optionally
/// followed by an array of VerNeedAux structures.
#[derive(Debug, PartialEq, Eq)]
pub struct VerNeed {
    /// Number of associated verneed array entries.
    pub vn_cnt: u16,
    /// Offset to the file name string in the linked string table, in bytes.
    pub vn_file: u32,
    /// Offset to a corresponding entry in the VerNeedAux array, in bytes.
    vn_aux: u32,
    /// Offset to the next VerNeed entry, in bytes.
    vn_next: u32,
}

impl ParseAt for VerNeed {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        let vd_version = endian.parse_u16_at(offset, data)?;
        if vd_version != abi::VER_NEED_CURRENT {
            return Err(ParseError::UnsupportedVersion((
                vd_version as u64,
                abi::VER_DEF_CURRENT as u64,
            )));
        }
        Ok(VerNeed {
            vn_cnt: endian.parse_u16_at(offset, data)?,
            vn_file: endian.parse_u32_at(offset, data)?,
            vn_aux: endian.parse_u32_at(offset, data)?,
            vn_next: endian.parse_u32_at(offset, data)?,
        })
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        ELFVERNEEDSIZE
    }
}

const ELFVERNEEDSIZE: usize = 16;

#[derive(Debug, Copy, Clone)]
pub struct VerNeedIterator<'data, E: EndianParse> {
    endian: E,
    class: Class,
    /// The number of entries in this iterator is given by the .dynamic DT_VERNEEDNUM entry
    /// and also in the .gnu.version_r section header's sh_info field.
    count: u64,
    data: &'data [u8],
    offset: usize,
}

impl<'data, E: EndianParse> VerNeedIterator<'data, E> {
    pub fn new(
        endian: E,
        class: Class,
        count: u64,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerNeedIterator {
            endian,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data, E: EndianParse> Iterator for VerNeedIterator<'data, E> {
    type Item = (VerNeed, VerNeedAuxIterator<'data, E>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() || self.count == 0 {
            return None;
        }

        let mut start = self.offset;
        let vn = VerNeed::parse_at(self.endian, self.class, &mut start, self.data).ok()?;
        let vna_iter = VerNeedAuxIterator::new(
            self.endian,
            self.class,
            vn.vn_cnt,
            self.offset + vn.vn_aux as usize,
            self.data,
        );

        // If offset overflows, silently end iteration
        match self.offset.checked_add(vn.vn_next as usize) {
            Some(new_off) => self.offset = new_off,
            None => self.count = 0,
        }
        self.count -= 1;

        // Silently end iteration early if the next link stops pointing somewhere new
        // TODO: Make this an error condition by allowing the iterator to yield a ParseError
        if self.count > 0 && vn.vn_next == 0 {
            self.count = 0
        }
        Some((vn, vna_iter))
    }
}

/// Version Need Auxiliary Entries from the .gnu.version_r section
#[derive(Debug, PartialEq, Eq)]
pub struct VerNeedAux {
    /// Dependency name hash value (ELF hash function).
    pub vna_hash: u32,
    /// Dependency information flag bitmask.
    pub vna_flags: u16,
    /// VersionIndex value used in the .gnu.version symbol version array.
    pub vna_other: u16,
    /// Offset to the dependency name string in the linked string table, in bytes.
    pub vna_name: u32,
    /// Offset to the next vernaux entry, in bytes.
    vna_next: u32,
}

impl ParseAt for VerNeedAux {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(VerNeedAux {
            vna_hash: endian.parse_u32_at(offset, data)?,
            vna_flags: endian.parse_u16_at(offset, data)?,
            vna_other: endian.parse_u16_at(offset, data)?,
            vna_name: endian.parse_u32_at(offset, data)?,
            vna_next: endian.parse_u32_at(offset, data)?,
        })
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        16
    }
}

#[derive(Debug)]
pub struct VerNeedAuxIterator<'data, E: EndianParse> {
    endian: E,
    class: Class,
    count: u16,
    data: &'data [u8],
    offset: usize,
}

impl<'data, E: EndianParse> VerNeedAuxIterator<'data, E> {
    pub fn new(
        endian: E,
        class: Class,
        count: u16,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerNeedAuxIterator {
            endian,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data, E: EndianParse> Iterator for VerNeedAuxIterator<'data, E> {
    type Item = VerNeedAux;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() || self.count == 0 {
            return None;
        }

        let mut start = self.offset;
        let vna = VerNeedAux::parse_at(self.endian, self.class, &mut start, self.data).ok()?;

        // If offset overflows, silently end iteration
        match self.offset.checked_add(vna.vna_next as usize) {
            Some(new_off) => self.offset = new_off,
            None => self.count = 0,
        }
        self.count -= 1;

        // Silently end iteration early if the next link stops pointing somewhere new
        // TODO: Make this an error condition by allowing the iterator to yield a ParseError
        if self.count > 0 && vna.vna_next == 0 {
            self.count = 0
        }
        Some(vna)
    }
}

//////////////////////////////
//  _____         _         //
// |_   _|__  ___| |_ ___   //
//   | |/ _ \/ __| __/ __|  //
//   | |  __/\__ \ |_\__ \  //
//   |_|\___||___/\__|___/  //
//                          //
//////////////////////////////

#[cfg(test)]
mod iter_tests {
    use super::*;
    use crate::endian::LittleEndian;

    #[rustfmt::skip]
    const GNU_VERNEED_STRINGS: [u8; 65] = [
        // ZLIB_1.2.0 (0x1)
        0x00, 0x5a, 0x4c, 0x49, 0x42, 0x5f, 0x31, 0x2e, 0x32, 0x2e, 0x30, 0x00,
        // GLIBC_2.33 (0xC)
        0x47, 0x4c, 0x49, 0x42, 0x43, 0x5f, 0x32, 0x2e, 0x33, 0x33, 0x00,
        // GLIBC_2.2.5 (0x17)
        0x47, 0x4c, 0x49, 0x42, 0x43, 0x5f, 0x32, 0x2e, 0x32, 0x2e, 0x35, 0x00,
        // libz.so.1 (0x23)
        0x6c, 0x69, 0x62, 0x7a, 0x2e, 0x73, 0x6f, 0x2e, 0x31, 0x00,
        // libc.so.6 (0x2D)
        0x6c, 0x69, 0x62, 0x63, 0x2e, 0x73, 0x6f, 0x2e, 0x36, 0x00,
        // GLIBC_2.3 (0x37)
        0x47, 0x4c, 0x49, 0x42, 0x43, 0x5f, 0x32, 0x2e, 0x33, 0x00,
    ];

    #[rustfmt::skip]
    const GNU_VERNEED_DATA: [u8; 96] = [
    // {vn_version, vn_cnt,     vn_file,                vn_aux,                 vn_next               }
        0x01, 0x00, 0x01, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0xc0, 0xe5, 0x27, 0x08, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vn_version, vn_cnt,     vn_file,                vn_aux,                 vn_next               }
        0x01, 0x00, 0x03, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0x13, 0x69, 0x69, 0x0d, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0xb3, 0x91, 0x96, 0x06, 0x00, 0x00, 0x0b, 0x00, 0x17, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0x94, 0x91, 0x96, 0x06, 0x00, 0x00, 0x09, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn verneed_iter() {
        let iter = VerNeedIterator::new(LittleEndian, Class::ELF64, 2, 0, &GNU_VERNEED_DATA);
        let entries: Vec<(VerNeed, Vec<VerNeedAux>)> =
            iter.map(|(vn, iter)| (vn, iter.collect())).collect();

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn verneed_iter_early_termination_on_broken_next_link() {
        // set count = 3 even though there's only 2 entries
        let iter = VerNeedIterator::new(LittleEndian, Class::ELF64, 3, 0, &GNU_VERNEED_DATA);
        let entries: Vec<(VerNeed, Vec<VerNeedAux>)> =
            iter.map(|(vn, iter)| (vn, iter.collect())).collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn verneedaux_iter_one_entry() {
        let mut iter =
            VerNeedAuxIterator::new(LittleEndian, Class::ELF64, 1, 0x10, &GNU_VERNEED_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerNeedAux {
                vna_hash: 0x0827e5c0,
                vna_flags: 0,
                vna_other: 0x0a,
                vna_name: 0x01,
                vna_next: 0
            }
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn verneedaux_iter_multiple_entries() {
        let mut iter =
            VerNeedAuxIterator::new(LittleEndian, Class::ELF64, 3, 0x30, &GNU_VERNEED_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerNeedAux {
                vna_hash: 0x0d696913,
                vna_flags: 0,
                vna_other: 0x0c,
                vna_name: 0x0c,
                vna_next: 0x10
            }
        );
        let aux2 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux2,
            VerNeedAux {
                vna_hash: 0x069691b3,
                vna_flags: 0,
                vna_other: 0x0b,
                vna_name: 0x17,
                vna_next: 0x10
            }
        );
        let aux3 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux3,
            VerNeedAux {
                vna_hash: 0x06969194,
                vna_flags: 0,
                vna_other: 0x09,
                vna_name: 0x37,
                vna_next: 0
            }
        );
        assert!(iter.next().is_none());
    }

    // Hypothetical case where VerDefAux entries are non-contiguous
    #[test]
    fn verneedaux_iter_two_lists_interspersed() {
        #[rustfmt::skip]
        let data: [u8; 64] = [
        // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
            0xc0, 0xe5, 0x27, 0x08, 0x00, 0x00, 0x0a, 0x00, 0xcc, 0x0c, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
            0x13, 0x69, 0x69, 0x0d, 0x00, 0x00, 0x0c, 0x00, 0xd7, 0x0c, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
            0xb3, 0x91, 0x96, 0x06, 0x00, 0x00, 0x0b, 0x00, 0xe1, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
            0x94, 0x91, 0x96, 0x06, 0x00, 0x00, 0x09, 0x00, 0xec, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut iter1 = VerNeedAuxIterator::new(LittleEndian, Class::ELF64, 2, 0, &data);
        let mut iter2 = VerNeedAuxIterator::new(LittleEndian, Class::ELF64, 2, 0x10, &data);

        let aux1_1 = iter1.next().expect("Failed to parse");
        assert_eq!(
            aux1_1,
            VerNeedAux {
                vna_hash: 0x0827e5c0,
                vna_flags: 0,
                vna_other: 0x0a,
                vna_name: 0x0ccc,
                vna_next: 0x20,
            }
        );
        let aux2_1 = iter2.next().expect("Failed to parse");
        assert_eq!(
            aux2_1,
            VerNeedAux {
                vna_hash: 0x0d696913,
                vna_flags: 0,
                vna_other: 0x0c,
                vna_name: 0x0cd7,
                vna_next: 0x20
            }
        );
        let aux1_2 = iter1.next().expect("Failed to parse");
        assert_eq!(
            aux1_2,
            VerNeedAux {
                vna_hash: 0x069691b3,
                vna_flags: 0,
                vna_other: 0x0b,
                vna_name: 0x0ce1,
                vna_next: 0
            }
        );
        let aux2_2 = iter2.next().expect("Failed to parse");
        assert_eq!(
            aux2_2,
            VerNeedAux {
                vna_hash: 0x06969194,
                vna_flags: 0,
                vna_other: 0x09,
                vna_name: 0x0cec,
                vna_next: 0
            }
        );
        assert!(iter1.next().is_none());
        assert!(iter2.next().is_none());
    }

    #[test]
    fn verneedaux_iter_early_termination_on_broken_next_link() {
        // set count = 7 even though there's only 1 entry
        let iter = VerNeedAuxIterator::new(LittleEndian, Class::ELF64, 7, 0x10, &GNU_VERNEED_DATA);
        let entries: Vec<VerNeedAux> = iter.collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 1);
    }

    #[rustfmt::skip]
    const GNU_VERDEF_STRINGS: [u8; 34] = [
        // LIBCTF_1.0 (0x1)
        0x00, 0x4c, 0x49, 0x42, 0x43, 0x54, 0x46, 0x5f, 0x31, 0x2e, 0x30, 0x00,
        // LIBCTF_1.1 (0xC)
        0x4c, 0x49, 0x42, 0x43, 0x54, 0x46, 0x5f, 0x31, 0x2e, 0x31, 0x00,
        // LIBCTF_1.2 (0x17)
        0x4c, 0x49, 0x42, 0x43, 0x54, 0x46, 0x5f, 0x31, 0x2e, 0x32, 0x00,
    ];

    // Sample .gnu.version_d section contents
    #[rustfmt::skip]
    const GNU_VERDEF_DATA: [u8; 128] = [
    // {vd_version, vd_flags,   vd_ndx,     vd_cnt
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
    //  vd_hash,                vd_aux,
        0xb0, 0x7a, 0x07, 0x0b, 0x14, 0x00, 0x00, 0x00,
    //  vd_next},               {vda_name,
        0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //  vda_next},             {vd_version, vd_flags,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //  vd_ndx,     vd_cnt,     vd_hash,
        0x02, 0x00, 0x01, 0x00, 0x70, 0x2f, 0x8f, 0x08,
    //  vd_aux,                 vd_next},
        0x14, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
    // {vda_name,               vda_next},
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vd_version, vd_flags,   vd_ndx,     vd_cnt
        0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00,
    //  vd_hash,                vd_aux,
        0x71, 0x2f, 0x8f, 0x08, 0x14, 0x00, 0x00, 0x00,
    //  vd_next},               {vda_name,
        0x24, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
    //  vda_next},              {vda_name,
        0x08, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
    //  vda_next},             {vd_version, vd_flags,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //  vd_ndx,     vd_cnt,     vd_hash,
        0x04, 0x00, 0x02, 0x00, 0x72, 0x2f, 0x8f, 0x08,
    //  vd_aux,                 vd_next},
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vda_name,               vda_next},
        0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    // {vda_name,               vda_next},
        0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn verdef_iter() {
        let iter = VerDefIterator::new(LittleEndian, Class::ELF64, 4, 0, &GNU_VERDEF_DATA);
        let entries: Vec<(VerDef, Vec<VerDefAux>)> =
            iter.map(|(vd, iter)| (vd, iter.collect())).collect();

        assert_eq!(entries.len(), 4);

        assert_eq!(
            entries,
            vec![
                (
                    VerDef {
                        vd_flags: 1,
                        vd_ndx: 1,
                        vd_cnt: 1,
                        vd_hash: 0x0B077AB0,
                        vd_aux: 20,
                        vd_next: 28,
                    },
                    vec![VerDefAux {
                        vda_name: 0x1,
                        vda_next: 0
                    }]
                ),
                (
                    VerDef {
                        vd_flags: 0,
                        vd_ndx: 2,
                        vd_cnt: 1,
                        vd_hash: 0x088f2f70,
                        vd_aux: 20,
                        vd_next: 28,
                    },
                    vec![VerDefAux {
                        vda_name: 0xC,
                        vda_next: 0
                    }]
                ),
                (
                    VerDef {
                        vd_flags: 0,
                        vd_ndx: 3,
                        vd_cnt: 2,
                        vd_hash: 0x088f2f71,
                        vd_aux: 20,
                        vd_next: 36,
                    },
                    vec![
                        VerDefAux {
                            vda_name: 0x17,
                            vda_next: 8
                        },
                        VerDefAux {
                            vda_name: 0xC,
                            vda_next: 0
                        }
                    ]
                ),
                (
                    VerDef {
                        vd_flags: 0,
                        vd_ndx: 4,
                        vd_cnt: 2,
                        vd_hash: 0x088f2f72,
                        vd_aux: 20,
                        vd_next: 0,
                    },
                    vec![
                        VerDefAux {
                            vda_name: 0xC,
                            vda_next: 8
                        },
                        VerDefAux {
                            vda_name: 0x17,
                            vda_next: 0
                        }
                    ]
                ),
            ]
        );
    }

    #[test]
    fn verdef_iter_early_termination_on_broken_next_link() {
        // set count = 7 even though there's only 4 entries
        let iter = VerDefIterator::new(LittleEndian, Class::ELF64, 7, 0, &GNU_VERDEF_DATA);
        let entries: Vec<(VerDef, Vec<VerDefAux>)> =
            iter.map(|(vn, iter)| (vn, iter.collect())).collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn verdefaux_iter_one_entry() {
        let mut iter =
            VerDefAuxIterator::new(LittleEndian, Class::ELF64, 1, 0x14, &GNU_VERDEF_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerDefAux {
                vda_name: 0x01,
                vda_next: 0
            }
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn verdefaux_iter_multiple_entries() {
        let mut iter =
            VerDefAuxIterator::new(LittleEndian, Class::ELF64, 2, 0x4C, &GNU_VERDEF_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerDefAux {
                vda_name: 0x17,
                vda_next: 8
            }
        );
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerDefAux {
                vda_name: 0xC,
                vda_next: 0
            }
        );
        assert!(iter.next().is_none());
    }

    // Hypothetical case where VerDefAux entries are non-contiguous
    #[test]
    fn verdefaux_iter_two_lists_interspersed() {
        #[rustfmt::skip]
        let data: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // list 1 entry 1
            0xA1, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // list 2 entry 1
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // list 1 entry 2
            0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // list 2 entry 2
        ];

        let mut iter1 = VerDefAuxIterator::new(LittleEndian, Class::ELF64, 2, 0, &data);
        let mut iter2 = VerDefAuxIterator::new(LittleEndian, Class::ELF64, 2, 8, &data);

        let aux1_1 = iter1.next().expect("Failed to parse");
        assert_eq!(
            aux1_1,
            VerDefAux {
                vda_name: 0x0001,
                vda_next: 0x10,
            }
        );
        let aux2_1 = iter2.next().expect("Failed to parse");
        assert_eq!(
            aux2_1,
            VerDefAux {
                vda_name: 0x00A1,
                vda_next: 0x10,
            }
        );
        let aux1_2 = iter1.next().expect("Failed to parse");
        assert_eq!(
            aux1_2,
            VerDefAux {
                vda_name: 0x0002,
                vda_next: 0,
            }
        );
        let aux2_2 = iter2.next().expect("Failed to parse");
        assert_eq!(
            aux2_2,
            VerDefAux {
                vda_name: 0x00A2,
                vda_next: 0,
            }
        );
        assert!(iter1.next().is_none());
        assert!(iter2.next().is_none());
    }

    #[test]
    fn verdefaux_iter_early_termination_on_broken_next_link() {
        // set count = 7 even though there's only 1 entry
        let iter = VerDefAuxIterator::new(LittleEndian, Class::ELF64, 7, 0x14, &GNU_VERDEF_DATA);
        let entries: Vec<VerDefAux> = iter.collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn version_table() {
        let ver_idx_buf: [u8; 10] = [0x02, 0x00, 0x03, 0x00, 0x09, 0x00, 0x0A, 0x00, 0xff, 0xff];
        let version_ids = VersionIndexTable::new(LittleEndian, Class::ELF64, &ver_idx_buf);
        let verdefs = VerDefIterator::new(LittleEndian, Class::ELF64, 4, 0, &GNU_VERDEF_DATA);
        let verneed_strs = StringTable::new(&GNU_VERNEED_STRINGS);
        let verneeds = VerNeedIterator::new(LittleEndian, Class::ELF64, 2, 0, &GNU_VERNEED_DATA);
        let verdef_strs = StringTable::new(&GNU_VERDEF_STRINGS);

        let table = SymbolVersionTable::new(
            version_ids,
            Some((verneeds, verneed_strs)),
            Some((verdefs, verdef_strs)),
        );

        let def1 = table
            .get_definition(0)
            .expect("Failed to parse definition")
            .expect("Failed to find def");
        assert_eq!(def1.hash, 0x088f2f70);
        assert_eq!(def1.flags, 0);
        let def1_names: Vec<&str> = def1
            .names
            .map(|res| res.expect("Failed to parse"))
            .collect();
        assert_eq!(def1_names, ["LIBCTF_1.1"]);
        assert!(!def1.hidden);

        let def2 = table
            .get_definition(1)
            .expect("Failed to parse definition")
            .expect("Failed to find def");
        assert_eq!(def2.hash, 0x088f2f71);
        assert_eq!(def2.flags, 0);
        let def2_names: Vec<&str> = def2
            .names
            .map(|res| res.expect("Failed to parse"))
            .collect();
        assert_eq!(def2_names, ["LIBCTF_1.2", "LIBCTF_1.1"]);
        assert!(!def2.hidden);

        let req1 = table
            .get_requirement(2)
            .expect("Failed to parse definition")
            .expect("Failed to find req");
        assert_eq!(
            req1,
            SymbolRequirement {
                file: "libc.so.6",
                name: "GLIBC_2.3",
                hash: 0x6969194,
                flags: 0,
                hidden: false
            }
        );

        let req2 = table
            .get_requirement(3)
            .expect("Failed to parse definition")
            .expect("Failed to find req");
        assert_eq!(
            req2,
            SymbolRequirement {
                file: "libz.so.1",
                name: "ZLIB_1.2.0",
                hash: 0x827E5C0,
                flags: 0,
                hidden: false
            }
        );

        // The last version_index points to non-existent definitions. Maybe we should treat
        // this as a ParseError instead of returning an empty Option? This can only happen
        // if .gnu.versions[N] contains an index that doesn't exist, which is likely a file corruption
        // or programmer error (i.e asking for a definition for an undefined symbol)
        assert!(table.get_definition(4).expect("Failed to parse").is_none());
        assert!(table.get_requirement(4).expect("Failed to parse").is_none());
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_verndx32_lsb() {
        test_parse_for(LittleEndian, Class::ELF32, VersionIndex(0x0100));
    }

    #[test]
    fn parse_verndx32_msb() {
        test_parse_for(BigEndian, Class::ELF32, VersionIndex(0x0001));
    }

    #[test]
    fn parse_verndx64_lsb() {
        test_parse_for(LittleEndian, Class::ELF64, VersionIndex(0x0100));
    }

    #[test]
    fn parse_verndx64_msb() {
        test_parse_for(BigEndian, Class::ELF64, VersionIndex(0x0001));
    }

    #[test]
    fn parse_verndx32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VersionIndex>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_verndx32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VersionIndex>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_verndx64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VersionIndex>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_verndx64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VersionIndex>(BigEndian, Class::ELF64);
    }

    //
    // VerDef
    //
    #[test]
    fn parse_verdef32_lsb() {
        let mut data = [0u8; ELFVERDEFSIZE];
        for (n, elem) in data.iter_mut().enumerate().take(ELFVERDEFSIZE) {
            *elem = n as u8;
        }
        data[0] = 1;
        data[1] = 0;

        let mut offset = 0;
        let entry = VerDef::parse_at(LittleEndian, Class::ELF32, &mut offset, data.as_ref())
            .expect("Failed to parse VerDef");

        assert_eq!(
            entry,
            VerDef {
                vd_flags: 0x0302,
                vd_ndx: 0x0504,
                vd_cnt: 0x0706,
                vd_hash: 0x0B0A0908,
                vd_aux: 0x0F0E0D0C,
                vd_next: 0x13121110,
            }
        );
        assert_eq!(offset, ELFVERDEFSIZE);
    }

    #[test]
    fn parse_verdef32_fuzz_too_short() {
        let mut data = [0u8; ELFVERDEFSIZE];
        data[1] = 1;
        for n in 0..ELFVERDEFSIZE {
            let buf = data.split_at(n).0;
            let mut offset: usize = 0;
            let error = VerDef::parse_at(BigEndian, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verdef64_msb() {
        let mut data = [0u8; ELFVERDEFSIZE];
        for (n, elem) in data.iter_mut().enumerate().take(ELFVERDEFSIZE).skip(2) {
            *elem = n as u8;
        }
        data[1] = 1;

        let mut offset = 0;
        let entry = VerDef::parse_at(BigEndian, Class::ELF64, &mut offset, data.as_ref())
            .expect("Failed to parse VerDef");

        assert_eq!(
            entry,
            VerDef {
                vd_flags: 0x0203,
                vd_ndx: 0x0405,
                vd_cnt: 0x0607,
                vd_hash: 0x08090A0B,
                vd_aux: 0x0C0D0E0F,
                vd_next: 0x10111213,
            }
        );
        assert_eq!(offset, ELFVERDEFSIZE);
    }

    #[test]
    fn parse_verdef64_fuzz_too_short() {
        let mut data = [0u8; ELFVERDEFSIZE];
        data[1] = 1;
        for n in 0..ELFVERDEFSIZE {
            let buf = data.split_at(n).0;
            let mut offset: usize = 0;
            let error = VerDef::parse_at(BigEndian, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verdef_bad_version_errors() {
        let data = [0u8; ELFVERDEFSIZE];
        // version is 0, which is not 1, which is bad :)

        let mut offset = 0;
        let err = VerDef::parse_at(BigEndian, Class::ELF64, &mut offset, data.as_ref())
            .expect_err("Expected an error");
        assert!(
            matches!(err, ParseError::UnsupportedVersion((0, 1))),
            "Unexpected Error type found: {err}"
        );
    }

    //
    // VerDefAux
    //
    #[test]
    fn parse_verdefaux32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            VerDefAux {
                vda_name: 0x03020100,
                vda_next: 0x07060504,
            },
        );
    }

    #[test]
    fn parse_verdefaux32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            VerDefAux {
                vda_name: 0x00010203,
                vda_next: 0x04050607,
            },
        );
    }

    #[test]
    fn parse_verdefaux64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            VerDefAux {
                vda_name: 0x03020100,
                vda_next: 0x07060504,
            },
        );
    }

    #[test]
    fn parse_verdefaux64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            VerDefAux {
                vda_name: 0x00010203,
                vda_next: 0x04050607,
            },
        );
    }

    #[test]
    fn parse_verdefaux32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerDefAux>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_verdefaux32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerDefAux>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_verdefaux64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerDefAux>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_verdefaux64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerDefAux>(BigEndian, Class::ELF64);
    }

    //
    // VerNeed
    //
    #[test]
    fn parse_verneed32_lsb() {
        let mut data = [0u8; ELFVERNEEDSIZE];
        for (n, elem) in data.iter_mut().enumerate().take(ELFVERNEEDSIZE) {
            *elem = n as u8;
        }
        data[0] = 1;
        data[1] = 0;

        let mut offset = 0;
        let entry = VerNeed::parse_at(LittleEndian, Class::ELF32, &mut offset, data.as_ref())
            .expect("Failed to parse VerNeed");

        assert_eq!(
            entry,
            VerNeed {
                vn_cnt: 0x0302,
                vn_file: 0x07060504,
                vn_aux: 0x0B0A0908,
                vn_next: 0x0F0E0D0C,
            }
        );
        assert_eq!(offset, ELFVERNEEDSIZE);
    }

    #[test]
    fn parse_verneed32_fuzz_too_short() {
        let mut data = [0u8; ELFVERNEEDSIZE];
        data[1] = 1;
        for n in 0..ELFVERNEEDSIZE {
            let buf = data.split_at(n).0;
            let mut offset: usize = 0;
            let error = VerNeed::parse_at(BigEndian, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verneed64_msb() {
        let mut data = [0u8; ELFVERNEEDSIZE];
        for (n, elem) in data.iter_mut().enumerate().take(ELFVERNEEDSIZE) {
            *elem = n as u8;
        }
        data[1] = 1;

        let mut offset = 0;
        let entry = VerNeed::parse_at(BigEndian, Class::ELF64, &mut offset, data.as_ref())
            .expect("Failed to parse VerNeed");

        assert_eq!(
            entry,
            VerNeed {
                vn_cnt: 0x0203,
                vn_file: 0x04050607,
                vn_aux: 0x08090A0B,
                vn_next: 0x0C0D0E0F,
            }
        );
        assert_eq!(offset, ELFVERNEEDSIZE);
    }

    #[test]
    fn parse_verneed64_fuzz_too_short() {
        let mut data = [0u8; ELFVERNEEDSIZE];
        data[1] = 1;
        for n in 0..ELFVERNEEDSIZE {
            let buf = data.split_at(n).0;
            let mut offset: usize = 0;
            let error = VerNeed::parse_at(BigEndian, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    //
    // VerNeedAux
    //
    #[test]
    fn parse_verneedaux32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            VerNeedAux {
                vna_hash: 0x03020100,
                vna_flags: 0x0504,
                vna_other: 0x0706,
                vna_name: 0x0B0A0908,
                vna_next: 0x0F0E0D0C,
            },
        );
    }

    #[test]
    fn parse_verneedaux32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            VerNeedAux {
                vna_hash: 0x00010203,
                vna_flags: 0x0405,
                vna_other: 0x0607,
                vna_name: 0x08090A0B,
                vna_next: 0x0C0D0E0F,
            },
        );
    }

    #[test]
    fn parse_verneedaux64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            VerNeedAux {
                vna_hash: 0x03020100,
                vna_flags: 0x0504,
                vna_other: 0x0706,
                vna_name: 0x0B0A0908,
                vna_next: 0x0F0E0D0C,
            },
        );
    }

    #[test]
    fn parse_verneedaux64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            VerNeedAux {
                vna_hash: 0x00010203,
                vna_flags: 0x0405,
                vna_other: 0x0607,
                vna_name: 0x08090A0B,
                vna_next: 0x0C0D0E0F,
            },
        );
    }

    #[test]
    fn parse_verneedaux32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerNeedAux>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_verneedaux32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerNeedAux>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_verneedaux64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerNeedAux>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_verneedaux64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, VerNeedAux>(BigEndian, Class::ELF64);
    }
}

#[cfg(test)]
mod version_index_tests {
    use super::*;

    #[test]
    fn is_local() {
        let idx = VersionIndex(0);
        assert!(idx.is_local());
    }

    #[test]
    fn is_global() {
        let idx = VersionIndex(1);
        assert!(idx.is_global());
    }

    #[test]
    fn index_visible() {
        let idx = VersionIndex(42);
        assert_eq!(idx.index(), 42);
        assert!(!idx.is_hidden());
    }

    #[test]
    fn index_hidden() {
        let idx = VersionIndex(42 | abi::VER_NDX_HIDDEN);
        assert_eq!(idx.index(), 42);
        assert!(idx.is_hidden());
    }
}
