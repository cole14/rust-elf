use crate::parse::ParseError;
use core::str::from_utf8;

#[derive(Debug, Clone, Copy)]
pub struct StringTable<'data> {
    data: Option<&'data [u8]>,
}

impl<'data> StringTable<'data> {
    pub fn new(data: &'data [u8]) -> Self {
        StringTable { data: Some(data) }
    }

    pub fn get(&self, offset: usize) -> Result<&'data str, ParseError> {
        if self.data.is_none() {
            return Err(ParseError(format!(
                "Invalid offset into empty string table: {offset}"
            )));
        }

        let start = self.data.unwrap().split_at(offset).1;
        let end = start
            .iter()
            .position(|&b| b == 0u8)
            .ok_or(ParseError(format!(
                "Invalid string table contents. Could not find terminating NUL byte."
            )))?;

        let substr = start.split_at(end).0;
        let string = from_utf8(substr)?;
        Ok(string)
    }
}

impl<'data> Default for StringTable<'data> {
    fn default() -> Self {
        StringTable { data: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_table_errors() {
        let st = StringTable::default();
        assert!(st.get(0).is_err());
        assert!(st.get(1).is_err());
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
    fn test_get_string_works() {
        let data = [0u8, 0x45, 0x4C, 0x46, 0u8];
        let st = StringTable::new(&data);
        assert_eq!(st.get(1).unwrap(), "ELF");
    }

    #[test]
    fn test_get_with_malformed_table_no_trailing_nul() {
        let data = [0u8, 0x45, 0x4C, 0x46];
        let st = StringTable::new(&data);
        assert!(st.get(1).is_err());
    }
}
