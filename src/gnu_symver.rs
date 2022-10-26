use crate::gabi;
use crate::parse::{Class, Endian, EndianParseExt, ParseAt, ParseError, ParsingIterator};

pub type VersionIndexIterator<'data> = ParsingIterator<'data, VersionIndex>;

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
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        Ok(VersionIndex {
            0: parser.parse_u16_at(endian, offset)?,
        })
    }
}

/// The special GNU extension section .gnu.version_d has a section type of SHT_GNU_VERDEF
/// This section shall contain symbol version definitions. The number of entries
/// in this section shall be contained in the DT_VERDEFNUM entry of the Dynamic
/// Section .dynamic. The sh_link member of the section header shall point to
/// the section that contains the strings referenced by this section.
///
/// The .gnu.version_d section shall contain an array of VerDef structures
/// optionally followed by an array of VerDefAux structures.
#[derive(Debug, PartialEq)]
pub struct VerDef {
    /// Version revision. This field shall be set to 1.
    pub vd_version: u16,
    /// Version information flag bitmask.
    pub vd_flags: u16,
    /// VersionIndex value referencing the SHT_GNU_VERSYM section.
    pub vd_ndx: u16,
    /// Number of associated verdaux array entries.
    pub vd_cnt: u16,
    /// Version name hash value (ELF hash function).
    pub vd_hash: u32,
    /// Offset in bytes to a corresponding entry in an array of VerDefAux structures.
    pub vd_aux: u32,
    /// Offset to the next VerDef entry, in bytes.
    pub vd_next: u32,
}

impl ParseAt for VerDef {
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        Ok(VerDef {
            vd_version: parser.parse_u16_at(endian, offset)?,
            vd_flags: parser.parse_u16_at(endian, offset)?,
            vd_ndx: parser.parse_u16_at(endian, offset)?,
            vd_cnt: parser.parse_u16_at(endian, offset)?,
            vd_hash: parser.parse_u32_at(endian, offset)?,
            vd_aux: parser.parse_u32_at(endian, offset)?,
            vd_next: parser.parse_u32_at(endian, offset)?,
        })
    }
}

/// Version Definition Auxiliary Entries from the .gnu.version_d section
#[derive(Debug, PartialEq)]
pub struct VerDefAux {
    /// Offset to the version or dependency name string in the linked string table, in bytes.
    pub vda_name: u32,
    /// Offset to the next VerDefAux entry, in bytes.
    pub vda_next: u32,
}

impl ParseAt for VerDefAux {
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        Ok(VerDefAux {
            vda_name: parser.parse_u32_at(endian, offset)?,
            vda_next: parser.parse_u32_at(endian, offset)?,
        })
    }
}

/// The GNU extension section .gnu.version_r has a section type of SHT_GNU_VERNEED.
/// This section contains required symbol version definitions. The number of
/// entries in this section shall be contained in the DT_VERNEEDNUM entry of the
/// Dynamic Section .dynamic. The sh_link member of the section header shall
/// point to the referenced string table section.
///
/// The section shall contain an array of VerNeed structures optionally
/// followed by an array of VerNeedAux structures.
#[derive(Debug, PartialEq)]
pub struct VerNeed {
    /// Version of structure. This value is currently set to 1.
    pub vn_version: u16,
    /// Number of associated verneed array entries.
    pub vn_cnt: u16,
    /// Offset to the file name string in the linked string table, in bytes.
    pub vn_file: u32,
    /// Offset to a corresponding entry in the VerNeedAux array, in bytes.
    pub vn_aux: u32,
    /// Offset to the next VerNeed entry, in bytes.
    pub vn_next: u32,
}

impl ParseAt for VerNeed {
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        Ok(VerNeed {
            vn_version: parser.parse_u16_at(endian, offset)?,
            vn_cnt: parser.parse_u16_at(endian, offset)?,
            vn_file: parser.parse_u32_at(endian, offset)?,
            vn_aux: parser.parse_u32_at(endian, offset)?,
            vn_next: parser.parse_u32_at(endian, offset)?,
        })
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
    pub vna_next: u32,
}

impl ParseAt for VerNeedAux {
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        _class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        Ok(VerNeedAux {
            vna_hash: parser.parse_u32_at(endian, offset)?,
            vna_flags: parser.parse_u16_at(endian, offset)?,
            vna_other: parser.parse_u16_at(endian, offset)?,
            vna_name: parser.parse_u32_at(endian, offset)?,
            vna_next: parser.parse_u32_at(endian, offset)?,
        })
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
            VersionIndex::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
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
            let error = VersionIndex::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
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
        let entry = VersionIndex::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
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
            let error = VersionIndex::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
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

        let mut offset = 0;
        let entry = VerDef::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
            .expect("Failed to parse VerDef");

        assert_eq!(
            entry,
            VerDef {
                vd_version: 0x0100,
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
        let data = [0u8; ELFVERDEFSIZE];
        for n in 0..ELFVERDEFSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerDef::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
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
        for n in 0..ELFVERDEFSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = VerDef::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
            .expect("Failed to parse VerDef");

        assert_eq!(
            entry,
            VerDef {
                vd_version: 0x0001,
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
        let data = [0u8; ELFVERDEFSIZE];
        for n in 0..ELFVERDEFSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerDef::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
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
        let entry = VerDefAux::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
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
            let error = VerDefAux::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
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
        let entry = VerDefAux::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
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
            let error = VerDefAux::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
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

        let mut offset = 0;
        let entry = VerNeed::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
            .expect("Failed to parse VerNeed");

        assert_eq!(
            entry,
            VerNeed {
                vn_version: 0x0100,
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
        let data = [0u8; ELFVERNEEDSIZE];
        for n in 0..ELFVERNEEDSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerNeed::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
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

        let mut offset = 0;
        let entry = VerNeed::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
            .expect("Failed to parse VerNeed");

        assert_eq!(
            entry,
            VerNeed {
                vn_version: 0x0001,
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
        let data = [0u8; ELFVERNEEDSIZE];
        for n in 0..ELFVERNEEDSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = VerNeed::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
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
        let entry = VerNeedAux::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
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
            let error = VerNeedAux::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
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
        let entry = VerNeedAux::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
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
            let error = VerNeedAux::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }
}
