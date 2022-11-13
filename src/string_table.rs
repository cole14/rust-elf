//! Interpreting string table sections: `.strtab`, [SHT_STRTAB][crate::abi::SHT_STRTAB]
use crate::parse::ParseError;
use core::str::from_utf8;

#[derive(Debug, Default, Clone, Copy)]
pub struct StringTable<'data> {
    data: &'data [u8],
}

impl<'data> StringTable<'data> {
    pub fn new(data: &'data [u8]) -> Self {
        StringTable { data }
    }

    pub fn get_raw(&self, offset: usize) -> Result<&'data [u8], ParseError> {
        if self.data.is_empty() {
            return Err(ParseError::BadOffset(offset as u64));
        };

        let start = self
            .data
            .get(offset..)
            .ok_or(ParseError::BadOffset(offset as u64))?;
        let end = start
            .iter()
            .position(|&b| b == 0u8)
            .ok_or(ParseError::StringTableMissingNul(offset as u64))?;

        Ok(start.split_at(end).0)
    }

    pub fn get(&self, offset: usize) -> Result<&'data str, ParseError> {
        let raw_data = self.get_raw(offset)?;
        Ok(from_utf8(raw_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_table_errors() {
        let st = StringTable::default();
        assert!(matches!(st.get(0), Err(ParseError::BadOffset(0))));
        assert!(matches!(st.get(1), Err(ParseError::BadOffset(1))));
    }

    /// Note: ELF string tables are defined to always start with a NUL and use
    /// index 0 to give an empty string, so getting a string starting at a NUL
    /// should properly give an empty string.
    #[test]
    fn test_get_index_0_gives_empty_string() {
        let data = [0u8, 42u8, 0u8];
        let st = StringTable::new(&data);
        assert_eq!(st.get(0).unwrap(), "");
    }

    #[test]
    fn test_get_raw_works() {
        let data = [0u8, 0x45, 0x4C, 0x46, 0u8];
        let st = StringTable::new(&data);
        assert_eq!(st.get_raw(1).unwrap(), [0x45, 0x4c, 0x46]);
    }

    #[test]
    fn test_get_string_works() {
        let data = [0u8, 0x45, 0x4C, 0x46, 0u8];
        let st = StringTable::new(&data);
        assert_eq!(st.get(1).unwrap(), "ELF");
    }

    #[test]
    fn test_get_raw_index_out_of_bounds_errors() {
        let data = [0u8, 0x45, 0x4C, 0x46, 0u8];
        let st = StringTable::new(&data);
        let result = st.get_raw(7);
        assert!(
            matches!(result, Err(ParseError::BadOffset(7))),
            "Unexpected Error type found: {result:?}"
        );
    }

    #[test]
    fn test_get_index_out_of_bounds_errors() {
        let data = [0u8, 0x45, 0x4C, 0x46, 0u8];
        let st = StringTable::new(&data);
        let result = st.get(7);
        assert!(
            matches!(result, Err(ParseError::BadOffset(7))),
            "Unexpected Error type found: {result:?}"
        );
    }

    #[test]
    fn test_get_raw_with_malformed_table_no_trailing_nul() {
        let data = [0u8, 0x45, 0x4C, 0x46];
        let st = StringTable::new(&data);
        let result = st.get_raw(1);
        assert!(
            matches!(result, Err(ParseError::StringTableMissingNul(1))),
            "Unexpected Error type found: {result:?}"
        );
    }

    #[test]
    fn test_get_with_malformed_table_no_trailing_nul() {
        let data = [0u8, 0x45, 0x4C, 0x46];
        let st = StringTable::new(&data);
        let result = st.get(1);
        assert!(
            matches!(result, Err(ParseError::StringTableMissingNul(1))),
            "Unexpected Error type found: {result:?}"
        );
    }
}
