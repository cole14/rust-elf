//! Parsing hash table sections for symbol tables: `.hash`, [SHT_HASH](crate::abi::SHT_HASH)
use crate::endian::EndianParse;
use crate::parse::{Class, ParseAt, ParseError, U32Table};
use crate::string_table::StringTable;
use crate::symbol::{Symbol, SymbolTable};

/// Header at the start of SysV Hash Table sections of type [SHT_HASH](crate::abi::SHT_HASH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysVHashHeader {
    pub nbucket: u32,
    pub nchain: u32,
}

impl ParseAt for SysVHashHeader {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(SysVHashHeader {
            nbucket: endian.parse_u32_at(offset, data)?,
            nchain: endian.parse_u32_at(offset, data)?,
        })
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        core::mem::size_of::<u32>() + core::mem::size_of::<u32>()
    }
}

/// Calculate the SysV hash value for a given symbol name.
pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.wrapping_mul(16).wrapping_add(*byte as u32);
        hash ^= (hash >> 24) & 0xf0;
    }
    hash & 0xfffffff
}

#[derive(Debug)]
pub struct SysVHashTable<'data, E: EndianParse> {
    buckets: U32Table<'data, E>,
    chains: U32Table<'data, E>,
}

/// This constructs a lazy-parsing type that keeps a reference to the provided data
/// bytes from which it lazily parses and interprets its contents.
impl<'data, E: EndianParse> SysVHashTable<'data, E> {
    /// Construct a SysVHashTable from given bytes. Keeps a reference to the data for lazy parsing.
    pub fn new(endian: E, class: Class, data: &'data [u8]) -> Result<Self, ParseError> {
        let mut offset = 0;
        let hdr = SysVHashHeader::parse_at(endian, class, &mut offset, data)?;

        let buckets_size = core::mem::size_of::<u32>()
            .checked_mul(hdr.nbucket.try_into()?)
            .ok_or(ParseError::IntegerOverflow)?;
        let buckets_end = offset
            .checked_add(buckets_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let buckets_buf = data
            .get(offset..buckets_end)
            .ok_or(ParseError::BadOffset(offset as u64))?;
        let buckets = U32Table::new(endian, class, buckets_buf);
        offset = buckets_end;

        let chains_size = core::mem::size_of::<u32>()
            .checked_mul(hdr.nchain.try_into()?)
            .ok_or(ParseError::IntegerOverflow)?;
        let chains_end = offset
            .checked_add(chains_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let chains_buf = data
            .get(offset..chains_end)
            .ok_or(ParseError::BadOffset(offset as u64))?;
        let chains = U32Table::new(endian, class, chains_buf);

        Ok(SysVHashTable { buckets, chains })
    }

    /// Use the hash table to find the symbol table entry with the given name and hash.
    pub fn find(
        &self,
        name: &[u8],
        hash: u32,
        symtab: &SymbolTable<'data, E>,
        strtab: &StringTable<'data>,
    ) -> Result<Option<(usize, Symbol)>, ParseError> {
        // empty hash tables don't have any entries. This avoids a divde by zero in the modulus calculation
        if self.buckets.len() == 0 {
            return Ok(None);
        }

        let start = (hash as usize) % self.buckets.len();
        let mut index = self.buckets.get(start)? as usize;

        // Bound the number of chain lookups by the chain size so we don't loop forever
        let mut i = 0;
        while index != 0 && i < self.chains.len() {
            let symbol = symtab.get(index)?;
            if strtab.get_raw(symbol.st_name as usize)? == name {
                return Ok(Some((index, symbol)));
            }

            index = self.chains.get(index)? as usize;
            i += 1;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod sysv_parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_sysvhdr32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            SysVHashHeader {
                nbucket: 0x03020100,
                nchain: 0x07060504,
            },
        );
    }

    #[test]
    fn parse_sysvhdr32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            SysVHashHeader {
                nbucket: 0x00010203,
                nchain: 0x04050607,
            },
        );
    }

    #[test]
    fn parse_sysvhdr64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            SysVHashHeader {
                nbucket: 0x03020100,
                nchain: 0x07060504,
            },
        );
    }

    #[test]
    fn parse_sysvhdr64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            SysVHashHeader {
                nbucket: 0x00010203,
                nchain: 0x04050607,
            },
        );
    }

    #[test]
    fn parse_sysvhdr32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SysVHashHeader>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_sysvhdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SysVHashHeader>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_sysvhdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SysVHashHeader>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_sysvhdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SysVHashHeader>(BigEndian, Class::ELF64);
    }
}
