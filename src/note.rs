//! Parsing ELF notes: `.note.*`, [SHT_NOTE](crate::abi::SHT_NOTE), [PT_NOTE](crate::abi::PT_NOTE)
use crate::endian::EndianParse;
use crate::parse::{Class, ParseAt, ParseError};
use core::str::from_utf8;

#[derive(Debug)]
pub struct NoteIterator<'data, E: EndianParse> {
    endian: E,
    class: Class,
    align: usize,
    data: &'data [u8],
    offset: usize,
}

impl<'data, E: EndianParse> NoteIterator<'data, E> {
    pub fn new(endian: E, class: Class, align: usize, data: &'data [u8]) -> Self {
        NoteIterator {
            endian,
            class,
            align,
            data,
            offset: 0,
        }
    }
}

impl<'data, E: EndianParse> Iterator for NoteIterator<'data, E> {
    type Item = Note<'data>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() == 0 {
            return None;
        }

        Note::parse_at(
            self.endian,
            self.class,
            self.align,
            &mut self.offset,
            &self.data,
        )
        .ok()
    }
}

#[derive(Debug, PartialEq)]
pub struct Note<'data> {
    pub n_type: u64,
    pub name: &'data str,
    pub desc: &'data [u8],
}

impl<'data> Note<'data> {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        align: usize,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        // We don't know what to do if the section or segment header specified a zero alignment, so error
        // (this is likely a file corruption)
        if align == 0 {
            return Err(ParseError::UnexpectedAlignment(align));
        }

        // It looks like clang and gcc emit 32-bit notes for 64-bit files, so we
        // currently always parse all note headers as 32-bit.
        let nhdr = NoteHeader::parse_at(endian, Class::ELF32, offset, data)?;

        let name_start = *offset;
        let name_size: usize = nhdr.n_namesz.saturating_sub(1).try_into()?;
        let name_end = name_start
            .checked_add(name_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let name_buf = data
            .get(name_start..name_end)
            .ok_or(ParseError::SliceReadError((name_start, name_end)))?;
        let name = from_utf8(name_buf)?;
        *offset = name_end;

        // skip over padding if needed to get back to 4-byte alignment
        if *offset % align > 0 {
            *offset = (*offset)
                .checked_add(align - *offset % align)
                .ok_or(ParseError::IntegerOverflow)?;
        }

        let desc_start = *offset;
        let desc_size: usize = nhdr.n_descsz.try_into()?;
        let desc_end = desc_start
            .checked_add(desc_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let desc = data
            .get(desc_start..desc_end)
            .ok_or(ParseError::SliceReadError((desc_start, desc_end)))?;
        *offset = desc_end;

        // skip over padding if needed to get back to 4-byte alignment
        if *offset % align > 0 {
            *offset = (*offset)
                .checked_add(align - *offset % align)
                .ok_or(ParseError::IntegerOverflow)?;
        }

        Ok(Note {
            n_type: nhdr.n_type,
            name,
            desc: desc,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NoteHeader {
    pub n_namesz: u64,
    pub n_descsz: u64,
    pub n_type: u64,
}

impl ParseAt for NoteHeader {
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(NoteHeader {
                n_namesz: endian.parse_u32_at(offset, data)? as u64,
                n_descsz: endian.parse_u32_at(offset, data)? as u64,
                n_type: endian.parse_u32_at(offset, data)? as u64,
            }),
            Class::ELF64 => Ok(NoteHeader {
                n_namesz: endian.parse_u64_at(offset, data)?,
                n_descsz: endian.parse_u64_at(offset, data)?,
                n_type: endian.parse_u64_at(offset, data)?,
            }),
        }
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => 12,
            Class::ELF64 => 24,
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::abi;
    use crate::endian::{BigEndian, LittleEndian};

    #[test]
    fn parse_note_errors_with_zero_alignment() {
        // This is a .note.gnu.property section
        #[rustfmt::skip]
        let data = [
            0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x00,
            0x02, 0x00, 0x00, 0xc0, 0x04, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut offset = 0;
        Note::parse_at(LittleEndian, Class::ELF64, 0, &mut offset, &data)
            .expect_err("Should have gotten an alignment error");
    }
    #[test]
    fn parse_note_with_8_byte_alignment() {
        // This is a .note.gnu.property section, which has been seen generated with 8-byte alignment
        #[rustfmt::skip]
        let data = [
            0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x00,
            0x02, 0x00, 0x00, 0xc0, 0x04, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Even though the file class is ELF64, we parse it as a 32-bit struct. gcc/clang seem to output 32-bit notes
        // even though the gABI states that ELF64 files should contain 64-bit notes. Sometimes those notes are generated
        // in sections with 4-byte alignment, and other times with 8-byte alignment, as specified by shdr.sh_addralign.
        //
        // See https://raw.githubusercontent.com/wiki/hjl-tools/linux-abi/linux-abi-draft.pdf
        // Excerpt:
        //     All entries in a PT_NOTE segment have the same alignment which equals to the
        //     p_align field in program header.
        //     According to gABI, each note entry should be aligned to 4 bytes in 32-bit
        //     objects or 8 bytes in 64-bit objects. But .note.ABI-tag section (see Sec-
        //     tion 2.1.6) and .note.gnu.build-id section (see Section 2.1.4) are aligned
        //     to 4 bytes in both 32-bit and 64-bit objects. Note parser should use p_align for
        //     note alignment, instead of assuming alignment based on ELF file class.
        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF64, 8, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 5,
                name: abi::ELF_NOTE_GNU,
                desc: &[2, 0, 0, 192, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]
            }
        );
    }

    #[test]
    fn parse_note_for_elf64_expects_nhdr32() {
        let data = [
            0x04, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x47, 0x4e,
            0x55, 0x00, 0x77, 0x41, 0x9f, 0x0d, 0xa5, 0x10, 0x83, 0x0c, 0x57, 0xa7, 0xc8, 0xcc,
            0xb0, 0xee, 0x85, 0x5f, 0xee, 0xd3, 0x76, 0xa3,
        ];

        let mut offset = 0;
        // Even though the file class is ELF64, we parse it as a 32-bit struct. gcc/clang seem to output 32-bit notes
        // even though the gABI states that ELF64 files should contain 64-bit notes.
        let note = Note::parse_at(LittleEndian, Class::ELF64, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 3,
                name: "GNU",
                desc: &[
                    119, 65, 159, 13, 165, 16, 131, 12, 87, 167, 200, 204, 176, 238, 133, 95, 238,
                    211, 118, 163
                ]
            }
        );
    }

    #[test]
    fn parse_note_32_lsb() {
        let data = [
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00,
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 6,
                name: "",
                desc: &[32, 0],
            }
        );
        assert_eq!(offset, 16);
    }

    #[test]
    fn parse_note_32_lsb_with_name_padding() {
        let data = [
            0x03, 0x00, 0x00, 0x00, // namesz 3
            0x04, 0x00, 0x00, 0x00, // descsz 4
            0x01, 0x00, 0x00, 0x00, // type 1
            0x47, 0x4e, 0x00, 0x00, // name GN\0 + 1 pad byte
            0x01, 0x02, 0x03, 0x04,
        ]; // desc 01020304

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 1,
                name: "GN",
                desc: &[01, 02, 03, 04],
            }
        );
        assert_eq!(offset, 20);
    }

    #[test]
    fn parse_note_32_lsb_with_desc_padding() {
        let data = [
            0x04, 0x00, 0x00, 0x00, // namesz 3
            0x02, 0x00, 0x00, 0x00, // descsz 4
            0x01, 0x00, 0x00, 0x00, // type 1
            0x47, 0x4e, 0x55, 0x00, // name GNU\0
            0x01, 0x02, 0x00, 0x00, // desc 0102 + 2 pad bytes
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 1,
                name: abi::ELF_NOTE_GNU,
                desc: &[01, 02],
            }
        );
        assert_eq!(offset, 20);
    }

    #[test]
    fn parse_note_32_lsb_with_no_name() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // namesz 0
            0x02, 0x00, 0x00, 0x00, // descsz 2
            0x01, 0x00, 0x00, 0x00, // type 1
            0x20, 0x00, 0x00, 0x00, // desc 20, 00 + 2 pad bytes
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 1,
                name: "",
                desc: &[0x20, 0],
            }
        );
        assert_eq!(offset, 16);
    }

    #[test]
    fn parse_note_32_lsb_with_no_desc() {
        let data = [
            0x04, 0x00, 0x00, 0x00, // namesz 4
            0x00, 0x00, 0x00, 0x00, // descsz 0
            0x01, 0x00, 0x00, 0x00, // type 1
            0x47, 0x4e, 0x55, 0x00, // name GNU\0
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 1,
                name: abi::ELF_NOTE_GNU,
                desc: &[],
            }
        );
        assert_eq!(offset, 16);
    }

    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_nhdr32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            NoteHeader {
                n_namesz: 0x03020100,
                n_descsz: 0x07060504,
                n_type: 0x0B0A0908,
            },
        );
    }

    #[test]
    fn parse_nhdr32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            NoteHeader {
                n_namesz: 0x00010203,
                n_descsz: 0x04050607,
                n_type: 0x08090A0B,
            },
        );
    }

    #[test]
    fn parse_nhdr64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            NoteHeader {
                n_namesz: 0x0706050403020100,
                n_descsz: 0x0F0E0D0C0B0A0908,
                n_type: 0x1716151413121110,
            },
        );
    }

    #[test]
    fn parse_nhdr64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            NoteHeader {
                n_namesz: 0x0001020304050607,
                n_descsz: 0x08090A0B0C0D0E0F,
                n_type: 0x1011121314151617,
            },
        );
    }

    #[test]
    fn parse_nhdr32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, NoteHeader>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_nhdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, NoteHeader>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_nhdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, NoteHeader>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_nhdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, NoteHeader>(BigEndian, Class::ELF64);
    }
}
