use crate::gabi;
use crate::parse::{Class, Endian, EndianParseExt, ParseAt, ParseError, ParsingIterator};

pub type VersionIndexIterator<'data> = ParsingIterator<'data, VersionIndex>;

/// The special GNU extension section .gnu.version has a section type of SHT_GNU_versym.
/// This section shall have the same number of entries as the Dynamic Symbol Table in
/// the .dynsym section. The .gnu.version section shall contain an array of
/// elements of type Elfxx_Half (both of which are 16-bit unsigned integers).
///
/// The .gnu.version section and VersionIndex values act as a lookup table for specifying
/// the version defined for or required by the corresponding symbol in the Dynamic Symbol Table.
///
/// For example, the symbol at index N in the .dynsym Symbol Table will have a VersionIndex
/// value located in the versym table at .gnu.version[N] which identifies
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

#[cfg(test)]
mod parse_tests {
    use super::*;

    const ELFVERNDXSIZE: usize = 2;

    #[test]
    fn parse_verndx32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
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
        // All symbol tables are defined to have a zeroed out symbol at index 0.
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
}
