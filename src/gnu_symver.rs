use crate::gabi;
use crate::parse::{parse_u16_at, parse_u32_at, Class, Endian, ParseAt, ParseError, ParsingTable};

////////////////////////////////////////////////////////////////////
//                                                 _              //
//       __ _ _ __  _   _      __   _____ _ __ ___(_) ___  _ __   //
//      / _` | '_ \| | | |     \ \ / / _ \ '__/ __| |/ _ \| '_ \  //
//  _  | (_| | | | | |_| |  _   \ V /  __/ |  \__ \ | (_) | | | | //
// (_)  \__, |_| |_|\__,_| (_)   \_/ \___|_|  |___/_|\___/|_| |_| //
//      |___/                                                     //
////////////////////////////////////////////////////////////////////

pub type VersionTable<'data> = ParsingTable<'data, VersionIndex>;

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
#[derive(Debug, PartialEq)]
pub struct VersionIndex(pub u16);

impl VersionIndex {
    pub fn index(self) -> u16 {
        self.0
    }

    pub fn is_local(self) -> bool {
        self.0 == gabi::VER_NDX_LOCAL
    }

    pub fn is_global(self) -> bool {
        self.0 == gabi::VER_NDX_GLOBAL
    }
}

impl ParseAt for VersionIndex {
    fn parse_at(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(VersionIndex {
            0: parse_u16_at(endian, offset, data)?,
        })
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
#[derive(Debug, PartialEq)]
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
    fn parse_at(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        let vd_version = parse_u16_at(endian, offset, data)?;
        if vd_version != gabi::VER_DEF_CURRENT {
            return Err(ParseError::UnsupportedVersion((
                vd_version as u64,
                gabi::VER_DEF_CURRENT as u64,
            )));
        }

        Ok(VerDef {
            vd_flags: parse_u16_at(endian, offset, data)?,
            vd_ndx: parse_u16_at(endian, offset, data)?,
            vd_cnt: parse_u16_at(endian, offset, data)?,
            vd_hash: parse_u32_at(endian, offset, data)?,
            vd_aux: parse_u32_at(endian, offset, data)?,
            vd_next: parse_u32_at(endian, offset, data)?,
        })
    }
}

#[derive(Debug)]
pub struct VerDefIterator<'data> {
    endianness: Endian,
    class: Class,
    /// The number of entries in this iterator is given by the .dynamic DT_VERDEFNUM entry
    /// and also in the .gnu.version_d section header's sh_info field.
    count: u64,
    data: &'data [u8],
    offset: usize,
}

impl<'data> VerDefIterator<'data> {
    pub fn new(
        endianness: Endian,
        class: Class,
        count: u64,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerDefIterator {
            endianness,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data> Iterator for VerDefIterator<'data> {
    type Item = (VerDef, VerDefAuxIterator<'data>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() == 0 || self.count == 0 {
            return None;
        }

        let mut start = self.offset;
        let vd = VerDef::parse_at(self.endianness, self.class, &mut start, self.data).ok()?;
        let vda_iter = VerDefAuxIterator::new(
            self.endianness,
            self.class,
            vd.vd_cnt,
            self.offset + vd.vd_aux as usize,
            self.data,
        );

        self.offset += vd.vd_next as usize;
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
#[derive(Debug, PartialEq)]
pub struct VerDefAux {
    /// Offset to the version or dependency name string in the linked string table, in bytes.
    pub vda_name: u32,
    /// Offset to the next VerDefAux entry, in bytes.
    vda_next: u32,
}

impl ParseAt for VerDefAux {
    fn parse_at(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(VerDefAux {
            vda_name: parse_u32_at(endian, offset, data)?,
            vda_next: parse_u32_at(endian, offset, data)?,
        })
    }
}

#[derive(Debug)]
pub struct VerDefAuxIterator<'data> {
    endianness: Endian,
    class: Class,
    count: u16,
    data: &'data [u8],
    offset: usize,
}

impl<'data> VerDefAuxIterator<'data> {
    pub fn new(
        endianness: Endian,
        class: Class,
        count: u16,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerDefAuxIterator {
            endianness,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data> Iterator for VerDefAuxIterator<'data> {
    type Item = VerDefAux;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() == 0 || self.count == 0 {
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
        let vda = VerDefAux::parse_at(self.endianness, self.class, &mut start, self.data).ok()?;

        self.offset += vda.vda_next as usize;
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
#[derive(Debug, PartialEq)]
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
    fn parse_at(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        let vd_version = parse_u16_at(endian, offset, data)?;
        if vd_version != gabi::VER_NEED_CURRENT {
            return Err(ParseError::UnsupportedVersion((
                vd_version as u64,
                gabi::VER_DEF_CURRENT as u64,
            )));
        }
        Ok(VerNeed {
            vn_cnt: parse_u16_at(endian, offset, data)?,
            vn_file: parse_u32_at(endian, offset, data)?,
            vn_aux: parse_u32_at(endian, offset, data)?,
            vn_next: parse_u32_at(endian, offset, data)?,
        })
    }
}

#[derive(Debug)]
pub struct VerNeedIterator<'data> {
    endianness: Endian,
    class: Class,
    /// The number of entries in this iterator is given by the .dynamic DT_VERNEEDNUM entry
    /// and also in the .gnu.version_r section header's sh_info field.
    count: u64,
    data: &'data [u8],
    offset: usize,
}

impl<'data> VerNeedIterator<'data> {
    pub fn new(
        endianness: Endian,
        class: Class,
        count: u64,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerNeedIterator {
            endianness,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data> Iterator for VerNeedIterator<'data> {
    type Item = (VerNeed, VerNeedAuxIterator<'data>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() == 0 || self.count == 0 {
            return None;
        }

        let mut start = self.offset;
        let vn = VerNeed::parse_at(self.endianness, self.class, &mut start, self.data).ok()?;
        let vna_iter = VerNeedAuxIterator::new(
            self.endianness,
            self.class,
            vn.vn_cnt,
            self.offset + vn.vn_aux as usize,
            self.data,
        );

        self.offset += vn.vn_next as usize;
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
#[derive(Debug, PartialEq)]
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
    fn parse_at(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(VerNeedAux {
            vna_hash: parse_u32_at(endian, offset, &data)?,
            vna_flags: parse_u16_at(endian, offset, &data)?,
            vna_other: parse_u16_at(endian, offset, &data)?,
            vna_name: parse_u32_at(endian, offset, &data)?,
            vna_next: parse_u32_at(endian, offset, &data)?,
        })
    }
}

#[derive(Debug)]
pub struct VerNeedAuxIterator<'data> {
    endianness: Endian,
    class: Class,
    count: u16,
    data: &'data [u8],
    offset: usize,
}

impl<'data> VerNeedAuxIterator<'data> {
    pub fn new(
        endianness: Endian,
        class: Class,
        count: u16,
        starting_offset: usize,
        data: &'data [u8],
    ) -> Self {
        VerNeedAuxIterator {
            endianness,
            class,
            count,
            data,
            offset: starting_offset,
        }
    }
}

impl<'data> Iterator for VerNeedAuxIterator<'data> {
    type Item = VerNeedAux;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() == 0 || self.count == 0 {
            return None;
        }

        let mut start = self.offset;
        let vna = VerNeedAux::parse_at(self.endianness, self.class, &mut start, self.data).ok()?;
        self.offset += vna.vna_next as usize;
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

    #[rustfmt::skip]
    const GNU_VERNEED_DATA: [u8; 96] = [
    // {vn_version, vn_cnt,     vn_file,                vn_aux,                 vn_next               }
        0x01, 0x00, 0x01, 0x00, 0x8b, 0x0c, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0xc0, 0xe5, 0x27, 0x08, 0x00, 0x00, 0x0a, 0x00, 0xcc, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vn_version, vn_cnt,     vn_file,                vn_aux,                 vn_next               }
        0x01, 0x00, 0x03, 0x00, 0x95, 0x0c, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0x13, 0x69, 0x69, 0x0d, 0x00, 0x00, 0x0c, 0x00, 0xd7, 0x0c, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0xb3, 0x91, 0x96, 0x06, 0x00, 0x00, 0x0b, 0x00, 0xe1, 0x0c, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    // {vn_hash,                vn_flags,   vn_other,   vn_name,                vn_next               }
        0x94, 0x91, 0x96, 0x06, 0x00, 0x00, 0x09, 0x00, 0xec, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn verneed_iter() {
        let iter = VerNeedIterator::new(Endian::Little, Class::ELF64, 2, 0, &GNU_VERNEED_DATA);
        let entries: Vec<(VerNeed, Vec<VerNeedAux>)> =
            iter.map(|(vn, iter)| (vn, iter.collect())).collect();

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn verneed_iter_early_termination_on_broken_next_link() {
        // set count = 3 even though there's only 2 entries
        let iter = VerNeedIterator::new(Endian::Little, Class::ELF64, 3, 0, &GNU_VERNEED_DATA);
        let entries: Vec<(VerNeed, Vec<VerNeedAux>)> =
            iter.map(|(vn, iter)| (vn, iter.collect())).collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn verneedaux_iter_one_entry() {
        let mut iter =
            VerNeedAuxIterator::new(Endian::Little, Class::ELF64, 1, 0x10, &GNU_VERNEED_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerNeedAux {
                vna_hash: 0x0827e5c0,
                vna_flags: 0,
                vna_other: 0x0a,
                vna_name: 0x0ccc,
                vna_next: 0
            }
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn verneedaux_iter_two_entries() {
        let mut iter =
            VerNeedAuxIterator::new(Endian::Little, Class::ELF64, 3, 0x30, &GNU_VERNEED_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerNeedAux {
                vna_hash: 0x0d696913,
                vna_flags: 0,
                vna_other: 0x0c,
                vna_name: 0x0cd7,
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
                vna_name: 0x0ce1,
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
                vna_name: 0x0cec,
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

        let mut iter1 = VerNeedAuxIterator::new(Endian::Little, Class::ELF64, 2, 0, &data);
        let mut iter2 = VerNeedAuxIterator::new(Endian::Little, Class::ELF64, 2, 0x10, &data);

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
        let iter =
            VerNeedAuxIterator::new(Endian::Little, Class::ELF64, 7, 0x10, &GNU_VERNEED_DATA);
        let entries: Vec<VerNeedAux> = iter.collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 1);
    }

    // Sample .gnu.version_d section contents
    #[rustfmt::skip]
    const GNU_VERDEF_DATA: [u8; 128] = [
    // {vd_version, vd_flags,   vd_ndx,     vd_cnt
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
    //  vd_hash,                vd_aux,
        0xb0, 0x7a, 0x07, 0x0b, 0x14, 0x00, 0x00, 0x00,
    //  vd_next},               {vda_name,
        0x1c, 0x00, 0x00, 0x00, 0x9f, 0x0c, 0x00, 0x00,
    //  vda_next},             {vd_version, vd_flags,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //  vd_ndx,     vd_cnt,     vd_hash,
        0x02, 0x00, 0x01, 0x00, 0x70, 0x2f, 0x8f, 0x08,
    //  vd_aux,                 vd_next},
        0x14, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
    // {vda_name,               vda_next},
        0xab, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vd_version, vd_flags,   vd_ndx,     vd_cnt
        0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00,
    //  vd_hash,                vd_aux,
        0x71, 0x2f, 0x8f, 0x08, 0x14, 0x00, 0x00, 0x00,
    //  vd_next},               {vda_name,
        0x24, 0x00, 0x00, 0x00, 0xb6, 0x0c, 0x00, 0x00,
    //  vda_next},              {vda_name,
        0x08, 0x00, 0x00, 0x00, 0xab, 0x0c, 0x00, 0x00,
    //  vda_next},             {vd_version, vd_flags,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    //  vd_ndx,     vd_cnt,     vd_hash,
        0x04, 0x00, 0x02, 0x00, 0x72, 0x2f, 0x8f, 0x08,
    //  vd_aux,                 vd_next},
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // {vda_name,               vda_next},
        0xc1, 0x0c, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    // {vda_name,               vda_next},
        0xb6, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn verdef_iter() {
        let iter = VerDefIterator::new(Endian::Little, Class::ELF64, 4, 0, &GNU_VERDEF_DATA);
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
                        vda_name: 0xC9F,
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
                        vda_name: 0xCAB,
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
                            vda_name: 0xCB6,
                            vda_next: 8
                        },
                        VerDefAux {
                            vda_name: 0xCAB,
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
                            vda_name: 0xCC1,
                            vda_next: 8
                        },
                        VerDefAux {
                            vda_name: 0xCB6,
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
        let iter = VerDefIterator::new(Endian::Little, Class::ELF64, 7, 0, &GNU_VERDEF_DATA);
        let entries: Vec<(VerDef, Vec<VerDefAux>)> =
            iter.map(|(vn, iter)| (vn, iter.collect())).collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn verdefaux_iter_one_entry() {
        let mut iter =
            VerDefAuxIterator::new(Endian::Little, Class::ELF64, 1, 0x14, &GNU_VERDEF_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerDefAux {
                vda_name: 0x0C9F,
                vda_next: 0
            }
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn verdefaux_iter_two_entries() {
        let mut iter =
            VerDefAuxIterator::new(Endian::Little, Class::ELF64, 2, 0x4C, &GNU_VERDEF_DATA);
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerDefAux {
                vda_name: 0x0CB6,
                vda_next: 8
            }
        );
        let aux1 = iter.next().expect("Failed to parse");
        assert_eq!(
            aux1,
            VerDefAux {
                vda_name: 0x0CAB,
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

        let mut iter1 = VerDefAuxIterator::new(Endian::Little, Class::ELF64, 2, 0, &data);
        let mut iter2 = VerDefAuxIterator::new(Endian::Little, Class::ELF64, 2, 8, &data);

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
        let iter = VerDefAuxIterator::new(Endian::Little, Class::ELF64, 7, 0x14, &GNU_VERDEF_DATA);
        let entries: Vec<VerDefAux> = iter.collect();

        // TODO: make this a ParseError condition instead of silently returning only the good data.
        assert_eq!(entries.len(), 1);
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    const ELFVERNDXSIZE: usize = 2;

    #[test]
    fn parse_verndx32_lsb() {
        let mut data = [0u8; ELFVERNDXSIZE as usize];
        for n in 0..ELFVERNDXSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry =
            VersionIndex::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
                .expect("Failed to parse VersionIndex");

        assert_eq!(entry, VersionIndex { 0: 0x0100 });
        assert_eq!(offset, ELFVERNDXSIZE);
    }

    #[test]
    fn parse_verndx32_fuzz_too_short() {
        let data = [0u8; ELFVERNDXSIZE];
        for n in 0..ELFVERNDXSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VersionIndex::parse_at(Endian::Big, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verndx64_msb() {
        let mut data = [0u8; ELFVERNDXSIZE as usize];
        for n in 0..ELFVERNDXSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = VersionIndex::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
            .expect("Failed to parse VersionIndex");

        assert_eq!(entry, VersionIndex { 0: 0x0001 });
        assert_eq!(offset, ELFVERNDXSIZE);
    }

    #[test]
    fn parse_verndx64_fuzz_too_short() {
        let data = [0u8; ELFVERNDXSIZE];
        for n in 0..ELFVERNDXSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VersionIndex::parse_at(Endian::Big, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    //
    // VerDef
    //
    const ELFVERDEFSIZE: usize = 20;

    #[test]
    fn parse_verdef32_lsb() {
        let mut data = [0u8; ELFVERDEFSIZE as usize];
        for n in 0..ELFVERDEFSIZE {
            data[n as usize] = n as u8;
        }
        data[0] = 1;
        data[1] = 0;

        let mut offset = 0;
        let entry = VerDef::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
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
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerDef::parse_at(Endian::Big, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verdef64_msb() {
        let mut data = [0u8; ELFVERDEFSIZE as usize];
        for n in 2..ELFVERDEFSIZE {
            data[n as usize] = n as u8;
        }
        data[1] = 1;

        let mut offset = 0;
        let entry = VerDef::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
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
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerDef::parse_at(Endian::Big, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verdef_bad_version_errors() {
        let data = [0u8; ELFVERDEFSIZE as usize];
        // version is 0, which is not 1, which is bad :)

        let mut offset = 0;
        let err = VerDef::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
            .expect_err("Expected an error");
        assert!(
            matches!(err, ParseError::UnsupportedVersion((0, 1))),
            "Unexpected Error type found: {err}"
        );
    }

    //
    // VerDefAux
    //
    const ELFVERDEFAUXSIZE: usize = 8;

    #[test]
    fn parse_verdefaux32_lsb() {
        let mut data = [0u8; ELFVERDEFAUXSIZE as usize];
        for n in 0..ELFVERDEFAUXSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = VerDefAux::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
            .expect("Failed to parse VerDefAux");

        assert_eq!(
            entry,
            VerDefAux {
                vda_name: 0x03020100,
                vda_next: 0x07060504,
            }
        );
        assert_eq!(offset, ELFVERDEFAUXSIZE);
    }

    #[test]
    fn parse_verdefaux32_fuzz_too_short() {
        let data = [0u8; ELFVERDEFAUXSIZE];
        for n in 0..ELFVERDEFAUXSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerDefAux::parse_at(Endian::Big, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verdefaux64_msb() {
        let mut data = [0u8; ELFVERDEFAUXSIZE as usize];
        for n in 0..ELFVERDEFAUXSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = VerDefAux::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
            .expect("Failed to parse VerDefAux");

        assert_eq!(
            entry,
            VerDefAux {
                vda_name: 0x00010203,
                vda_next: 0x04050607,
            }
        );
        assert_eq!(offset, ELFVERDEFAUXSIZE);
    }

    #[test]
    fn parse_verdefaux64_fuzz_too_short() {
        let data = [0u8; ELFVERDEFAUXSIZE];
        for n in 0..ELFVERDEFAUXSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerDefAux::parse_at(Endian::Big, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    //
    // VerNeed
    //
    const ELFVERNEEDSIZE: usize = 16;

    #[test]
    fn parse_verneed32_lsb() {
        let mut data = [0u8; ELFVERNEEDSIZE as usize];
        for n in 0..ELFVERNEEDSIZE {
            data[n as usize] = n as u8;
        }
        data[0] = 1;
        data[1] = 0;

        let mut offset = 0;
        let entry = VerNeed::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
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
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerNeed::parse_at(Endian::Big, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verneed64_msb() {
        let mut data = [0u8; ELFVERNEEDSIZE as usize];
        for n in 0..ELFVERNEEDSIZE {
            data[n as usize] = n as u8;
        }
        data[1] = 1;

        let mut offset = 0;
        let entry = VerNeed::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
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
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerNeed::parse_at(Endian::Big, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    //
    // VerNeedAux
    //
    const VERNEEDAUXSIZE: usize = 16;

    #[test]
    fn parse_verneedaux32_lsb() {
        let mut data = [0u8; VERNEEDAUXSIZE as usize];
        for n in 0..VERNEEDAUXSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = VerNeedAux::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
            .expect("Failed to parse VerNeedAux");

        assert_eq!(
            entry,
            VerNeedAux {
                vna_hash: 0x03020100,
                vna_flags: 0x0504,
                vna_other: 0x0706,
                vna_name: 0x0B0A0908,
                vna_next: 0x0F0E0D0C,
            }
        );
        assert_eq!(offset, VERNEEDAUXSIZE);
    }

    #[test]
    fn parse_verneedaux32_fuzz_too_short() {
        let data = [0u8; VERNEEDAUXSIZE];
        for n in 0..VERNEEDAUXSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerNeedAux::parse_at(Endian::Big, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_verneedaux64_msb() {
        let mut data = [0u8; VERNEEDAUXSIZE as usize];
        for n in 0..VERNEEDAUXSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = VerNeedAux::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
            .expect("Failed to parse VerNeedAux");

        assert_eq!(
            entry,
            VerNeedAux {
                vna_hash: 0x00010203,
                vna_flags: 0x0405,
                vna_other: 0x0607,
                vna_name: 0x08090A0B,
                vna_next: 0x0C0D0E0F,
            }
        );
        assert_eq!(offset, VERNEEDAUXSIZE);
    }

    #[test]
    fn parse_verneedaux64_fuzz_too_short() {
        let data = [0u8; VERNEEDAUXSIZE];
        for n in 0..VERNEEDAUXSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerNeedAux::parse_at(Endian::Big, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }
}
