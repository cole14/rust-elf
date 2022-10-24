use crate::parse::{Class, Endian, EndianParseExt, ParseAt, ParseError};
use core::str::from_utf8;

#[derive(Debug)]
pub struct NoteIterator<'data> {
    endianness: Endian,
    class: Class,
    align: usize,
    data: &'data [u8],
    offset: usize,
}

impl<'data> NoteIterator<'data> {
    pub fn new(endianness: Endian, class: Class, align: usize, data: &'data [u8]) -> Self {
        NoteIterator {
            endianness,
            class,
            align,
            data,
            offset: 0,
        }
    }
}

impl<'data> Iterator for NoteIterator<'data> {
    type Item = Note<'data>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() == 0 {
            return None;
        }

        Note::parse_at(
            self.endianness,
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
    fn parse_at(
        endian: Endian,
        _class: Class,
        align: usize,
        offset: &mut usize,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        // It looks like clang and gcc emit 32-bit notes for 64-bit files, so we
        // currently always parse all note headers as 32-bit.
        let align = align;
        if align != 4 {
            return Err(ParseError::UnexpectedAlignment(align));
        }

        let nhdr = NoteHeader::parse_at(endian, Class::ELF32, offset, &data)?;

        let name_start = *offset;
        let name_end = name_start + nhdr.n_namesz.saturating_sub(1) as usize;
        let name_buf = data
            .get(name_start..name_end)
            .ok_or(ParseError::SliceReadError((name_start, name_end)))?;
        let name = from_utf8(name_buf)?;
        *offset += nhdr.n_namesz as usize;

        // skip over padding if needed to get back to 4-byte alignment
        if *offset % align > 0 {
            *offset += align - *offset % align;
        }

        let desc_start = *offset;
        let desc_end = desc_start + nhdr.n_descsz as usize;
        let desc = data
            .get(desc_start..desc_end)
            .ok_or(ParseError::SliceReadError((desc_start, desc_end)))?;
        *offset += nhdr.n_descsz as usize;

        // skip over padding if needed to get back to 4-byte alignment
        if *offset % align > 0 {
            *offset += align - *offset % align;
        }

        Ok(Note {
            n_type: nhdr.n_type,
            name,
            desc: desc,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoteHeader {
    pub n_namesz: u64,
    pub n_descsz: u64,
    pub n_type: u64,
}

impl ParseAt for NoteHeader {
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(NoteHeader {
                n_namesz: parser.parse_u32_at(endian, offset)? as u64,
                n_descsz: parser.parse_u32_at(endian, offset)? as u64,
                n_type: parser.parse_u32_at(endian, offset)? as u64,
            }),
            Class::ELF64 => Ok(NoteHeader {
                n_namesz: parser.parse_u64_at(endian, offset)?,
                n_descsz: parser.parse_u64_at(endian, offset)?,
                n_type: parser.parse_u64_at(endian, offset)?,
            }),
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parse_note_errors_for_non_4_byte_alignment() {
        let data = [];

        let mut offset = 0;
        // Even though the file class is ELF64, we parse it as a 32-bit struct. gcc/clang seem to output 32-bit notes
        // even though the GABI states that ELF64 files should contain 64-bit notes. When it does this, it still
        // correctly sets the shdr.sh_addralign to 4, so if we see 8 then that means we're parsing a file with
        // actual 64-bit notes.
        Note::parse_at(Endian::Little, Class::ELF64, 8, &mut offset, &data)
            .expect_err("Expected alignment error");
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
        // even though the GABI states that ELF64 files should contain 64-bit notes.
        let note = Note::parse_at(Endian::Little, Class::ELF64, 4, &mut offset, &data)
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
        let note = Note::parse_at(Endian::Little, Class::ELF32, 4, &mut offset, &data)
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
        let note = Note::parse_at(Endian::Little, Class::ELF32, 4, &mut offset, &data)
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
        let note = Note::parse_at(Endian::Little, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 1,
                name: "GNU",
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
        let note = Note::parse_at(Endian::Little, Class::ELF32, 4, &mut offset, &data)
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
        let note = Note::parse_at(Endian::Little, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note {
                n_type: 1,
                name: "GNU",
                desc: &[],
            }
        );
        assert_eq!(offset, 16);
    }

    const ELF32NOTESIZE: usize = 12;
    const ELF64NOTESIZE: usize = 24;

    #[test]
    fn parse_nhdr32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF32NOTESIZE as usize];
        for n in 0..ELF32NOTESIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = NoteHeader::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
            .expect("Failed to parse NoteHeader");

        assert_eq!(
            entry,
            NoteHeader {
                n_namesz: 0x03020100,
                n_descsz: 0x07060504,
                n_type: 0x0B0A0908,
            }
        );
        assert_eq!(offset, ELF32NOTESIZE);
    }

    #[test]
    fn parse_nhdr32_fuzz_too_short() {
        let data = [0u8; ELF32NOTESIZE];
        for n in 0..ELF32NOTESIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = NoteHeader::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_nhdr64_msb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF64NOTESIZE as usize];
        for n in 0..ELF64NOTESIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = NoteHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
            .expect("Failed to parse NoteHeader");

        assert_eq!(
            entry,
            NoteHeader {
                n_namesz: 0x0001020304050607,
                n_descsz: 0x08090A0B0C0D0E0F,
                n_type: 0x1011121314151617,
            }
        );
        assert_eq!(offset, ELF64NOTESIZE);
    }

    #[test]
    fn parse_nhdr64_fuzz_too_short() {
        let data = [0u8; ELF64NOTESIZE];
        for n in 0..ELF64NOTESIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = NoteHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }
}
