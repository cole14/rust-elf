//! Parsing hash table sections for symbol tables: `.hash`, and `.gnu.hash`
use core::mem::size_of;

use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ParsingTable, ReadBytesExt};
use crate::string_table::StringTable;
use crate::symbol::{Symbol, SymbolTable};

impl ParseAt for u32 {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        endian.parse_u32_at(offset, data)
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        core::mem::size_of::<u32>()
    }
}

type U32Table<'data, E> = ParsingTable<'data, E, u32>;

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
        size_of::<u32>() + size_of::<u32>()
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

        let buckets_size = size_of::<u32>()
            .checked_mul(hdr.nbucket.try_into()?)
            .ok_or(ParseError::IntegerOverflow)?;
        let buckets_end = offset
            .checked_add(buckets_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let buckets_buf = data.get_bytes(offset..buckets_end)?;
        let buckets = U32Table::new(endian, class, buckets_buf);
        offset = buckets_end;

        let chains_size = size_of::<u32>()
            .checked_mul(hdr.nchain.try_into()?)
            .ok_or(ParseError::IntegerOverflow)?;
        let chains_end = offset
            .checked_add(chains_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let chains_buf = data.get_bytes(offset..chains_end)?;
        let chains = U32Table::new(endian, class, chains_buf);

        Ok(SysVHashTable { buckets, chains })
    }

    /// Use the hash table to find the symbol table entry with the given name and hash.
    pub fn find(
        &self,
        name: &[u8],
        symtab: &SymbolTable<'data, E>,
        strtab: &StringTable<'data>,
    ) -> Result<Option<(usize, Symbol)>, ParseError> {
        // empty hash tables don't have any entries. This avoids a divde by zero in the modulus calculation
        if self.buckets.is_empty() {
            return Ok(None);
        }

        let hash = sysv_hash(name);

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

/// Calculate the GNU hash for a given symbol name.
pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut hash = 5381u32;
    for byte in name {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
    }
    hash
}

/// Header at the start of a GNU extension Hash Table section of type [SHT_GNU_HASH](crate::abi::SHT_GNU_HASH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuHashHeader {
    pub nbucket: u32,
    /// The symbol table index of the first symbol in the hash table.
    /// (GNU hash sections omit symbols at the start of the table that wont be looked up)
    pub table_start_idx: u32,
    /// The number of words in the bloom filter. (must be a non-zero power of 2)
    pub nbloom: u32,
    /// The bit shift count for the bloom filter.
    pub nshift: u32,
}

impl ParseAt for GnuHashHeader {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(GnuHashHeader {
            nbucket: endian.parse_u32_at(offset, data)?,
            table_start_idx: endian.parse_u32_at(offset, data)?,
            nbloom: endian.parse_u32_at(offset, data)?,
            nshift: endian.parse_u32_at(offset, data)?,
        })
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        size_of::<u32>() + size_of::<u32>() + size_of::<u32>() + size_of::<u32>()
    }
}

type U64Table<'data, E> = ParsingTable<'data, E, u64>;

impl ParseAt for u64 {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        endian.parse_u64_at(offset, data)
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        core::mem::size_of::<u64>()
    }
}

#[derive(Debug)]
pub struct GnuHashTable<'data, E: EndianParse> {
    pub hdr: GnuHashHeader,

    endian: E,
    class: Class,
    bloom: &'data [u8],
    buckets: U32Table<'data, E>,
    chains: U32Table<'data, E>,
}

impl<'data, E: EndianParse> GnuHashTable<'data, E> {
    /// Construct a GnuHashTable from given bytes. Keeps a reference to the data for lazy parsing.
    pub fn new(endian: E, class: Class, data: &'data [u8]) -> Result<Self, ParseError> {
        let mut offset = 0;
        let hdr = GnuHashHeader::parse_at(endian, class, &mut offset, data)?;

        // length of the bloom filter in bytes. ELF32 is [u32; nbloom], ELF64 is [u64; nbloom].
        let nbloom: usize = hdr.nbloom as usize;
        let bloom_size = match class {
            Class::ELF32 => nbloom
                .checked_mul(size_of::<u32>())
                .ok_or(ParseError::IntegerOverflow)?,
            Class::ELF64 => nbloom
                .checked_mul(size_of::<u64>())
                .ok_or(ParseError::IntegerOverflow)?,
        };
        let bloom_end = offset
            .checked_add(bloom_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let bloom_buf = data.get_bytes(offset..bloom_end)?;
        offset = bloom_end;

        let buckets_size = size_of::<u32>()
            .checked_mul(hdr.nbucket.try_into()?)
            .ok_or(ParseError::IntegerOverflow)?;
        let buckets_end = offset
            .checked_add(buckets_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let buckets_buf = data.get_bytes(offset..buckets_end)?;
        let buckets = U32Table::new(endian, class, buckets_buf);
        offset = buckets_end;

        // the rest of the section is the chains
        let chains_buf = data
            .get(offset..)
            .ok_or(ParseError::SliceReadError((offset, data.len())))?;
        let chains = U32Table::new(endian, class, chains_buf);

        Ok(GnuHashTable {
            hdr,
            endian,
            class,
            bloom: bloom_buf,
            buckets,
            chains,
        })
    }

    /// Use the hash table to find the symbol table entry with the given name.
    pub fn find(
        &self,
        name: &[u8],
        symtab: &SymbolTable<'data, E>,
        strtab: &StringTable<'data>,
    ) -> Result<Option<(usize, Symbol)>, ParseError> {
        // empty hash tables don't have any entries. This avoids a divde by zero in the modulus calculation,
        // and also avoids a potential division by zero panic in the bloom filter index calculation.
        if self.buckets.is_empty() || self.hdr.nbloom == 0 {
            return Ok(None);
        }

        let hash = gnu_hash(name);

        // Test against bloom filter.
        let (bloom_width, filter) = match self.class {
            Class::ELF32 => {
                let bloom_width: u32 = 8 * size_of::<u32>() as u32; // 32
                let bloom_idx = (hash / (bloom_width)) % self.hdr.nbloom;
                let bloom_table = U32Table::new(self.endian, self.class, self.bloom);
                (bloom_width, bloom_table.get(bloom_idx as usize)? as u64)
            }
            Class::ELF64 => {
                let bloom_width: u32 = 8 * size_of::<u64>() as u32; // 64
                let bloom_idx = (hash / (bloom_width)) % self.hdr.nbloom;
                let bloom_table = U64Table::new(self.endian, self.class, self.bloom);
                (bloom_width, bloom_table.get(bloom_idx as usize)?)
            }
        };

        // Check bloom filter for both hashes - symbol is present in the hash table IFF both bits are set.
        if filter & (1 << (hash % bloom_width)) == 0 {
            return Ok(None);
        }
        let hash2 = hash
            .checked_shr(self.hdr.nshift)
            .ok_or(ParseError::IntegerOverflow)?;
        if filter & (1 << (hash2 % bloom_width)) == 0 {
            return Ok(None);
        }

        let table_start_idx = self.hdr.table_start_idx as usize;
        let chain_start_idx = self.buckets.get((hash as usize) % self.buckets.len())? as usize;
        if chain_start_idx < table_start_idx {
            // All symbols before table_start_idx don't exist in the hash table
            return Ok(None);
        }

        let chain_len = self.chains.len();
        for chain_idx in (chain_start_idx - table_start_idx)..chain_len {
            let chain_hash = self.chains.get(chain_idx)?;

            // compare the hashes by or'ing the 1's bit back on
            if hash | 1 == chain_hash | 1 {
                // we have a hash match!
                // let's see if this symtab[sym_idx].name is what we're looking for
                let sym_idx = chain_idx
                    .checked_add(table_start_idx)
                    .ok_or(ParseError::IntegerOverflow)?;
                let symbol = symtab.get(sym_idx)?;
                let r_sym_name = strtab.get_raw(symbol.st_name as usize)?;

                if r_sym_name == name {
                    return Ok(Some((sym_idx, symbol)));
                }
            }

            // the chain uses the 1's bit to signal chain comparison stoppage
            if chain_hash & 1 != 0 {
                break;
            }
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

#[cfg(test)]
mod gnu_parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn gnu_hash_tests() {
        // some known example hash values
        assert_eq!(gnu_hash(b""), 0x00001505);
        assert_eq!(gnu_hash(b"printf"), 0x156b2bb8);
        assert_eq!(gnu_hash(b"exit"), 0x7c967e3f);
        assert_eq!(gnu_hash(b"syscall"), 0xbac212a0);
    }

    #[test]
    fn parse_gnuhdr32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            GnuHashHeader {
                nbucket: 0x03020100,
                table_start_idx: 0x07060504,
                nbloom: 0x0B0A0908,
                nshift: 0x0F0E0D0C,
            },
        );
    }

    #[test]
    fn parse_gnuhdr32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            GnuHashHeader {
                nbucket: 0x00010203,
                table_start_idx: 0x04050607,
                nbloom: 0x008090A0B,
                nshift: 0x0C0D0E0F,
            },
        );
    }

    #[test]
    fn parse_gnuhdr64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            GnuHashHeader {
                nbucket: 0x03020100,
                table_start_idx: 0x07060504,
                nbloom: 0x0B0A0908,
                nshift: 0x0F0E0D0C,
            },
        );
    }

    #[test]
    fn parse_gnuhdr64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            GnuHashHeader {
                nbucket: 0x00010203,
                table_start_idx: 0x04050607,
                nbloom: 0x008090A0B,
                nshift: 0x0C0D0E0F,
            },
        );
    }

    #[test]
    fn parse_gnuhdr32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, GnuHashHeader>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_gnuhdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, GnuHashHeader>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_gnuhdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, GnuHashHeader>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_gnuhdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, GnuHashHeader>(BigEndian, Class::ELF64);
    }
}
