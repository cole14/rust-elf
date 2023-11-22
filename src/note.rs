//! Parsing ELF notes: `.note.*`, [SHT_NOTE](crate::abi::SHT_NOTE), [PT_NOTE](crate::abi::PT_NOTE)
//!
//! Example for getting the GNU ABI-tag note:
//! ```
//! use elf::ElfBytes;
//! use elf::endian::AnyEndian;
//! use elf::note::Note;
//! use elf::note::NoteGnuAbiTag;
//!
//! let path = std::path::PathBuf::from("sample-objects/basic.x86_64");
//! let file_data = std::fs::read(path).expect("Could not read file.");
//! let slice = file_data.as_slice();
//! let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");
//!
//! let shdr = file
//!     .section_header_by_name(".note.ABI-tag")
//!     .expect("section table should be parseable")
//!     .expect("file should have a .note.ABI-tag section");
//!
//! let notes: Vec<_> = file
//!     .section_data_as_notes(&shdr)
//!     .expect("Should be able to get note section data")
//!     .collect();
//! assert_eq!(
//!     notes[0],
//!     Note::GnuAbiTag(NoteGnuAbiTag {
//!         os: 0,
//!         major: 2,
//!         minor: 6,
//!         subminor: 32
//!     })
//! );
//! ```
use crate::abi;
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ReadBytesExt};
use core::mem::size_of;
use core::str::from_utf8;

/// This enum contains parsed Note variants which can be matched on
#[derive(Debug, PartialEq, Eq)]
pub enum Note<'data> {
    /// (name: [abi::ELF_NOTE_GNU], n_type: [abi::NT_GNU_ABI_TAG])
    GnuAbiTag(NoteGnuAbiTag),
    /// (name: [abi::ELF_NOTE_GNU], n_type: [abi::NT_GNU_BUILD_ID])
    GnuBuildId(NoteGnuBuildId<'data>),
    /// All other notes that we don't know how to parse
    Unknown(NoteAny<'data>),
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
        let name_buf_size: usize = nhdr.n_namesz.saturating_sub(1).try_into()?;
        let name_buf_end = name_start
            .checked_add(name_buf_size)
            .ok_or(ParseError::IntegerOverflow)?;
        let name_buf = data.get_bytes(name_start..name_buf_end)?;
        let name = from_utf8(name_buf)?;

        // move forward for entire namesz, including the NUL byte we left out of our str
        *offset = (*offset)
            .checked_add(nhdr.n_namesz.try_into()?)
            .ok_or(ParseError::IntegerOverflow)?;

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
        let raw_desc = data.get_bytes(desc_start..desc_end)?;
        *offset = desc_end;

        // skip over padding if needed to get back to 4-byte alignment
        if *offset % align > 0 {
            *offset = (*offset)
                .checked_add(align - *offset % align)
                .ok_or(ParseError::IntegerOverflow)?;
        }

        // Interpret the note contents to try to return a known note variant
        match name {
            abi::ELF_NOTE_GNU => match nhdr.n_type {
                abi::NT_GNU_ABI_TAG => {
                    let mut offset = 0;
                    Ok(Note::GnuAbiTag(NoteGnuAbiTag::parse_at(
                        endian,
                        _class,
                        &mut offset,
                        raw_desc,
                    )?))
                }
                abi::NT_GNU_BUILD_ID => Ok(Note::GnuBuildId(NoteGnuBuildId(raw_desc))),
                _ => Ok(Note::Unknown(NoteAny {
                    n_type: nhdr.n_type,
                    name,
                    desc: raw_desc,
                })),
            },
            _ => Ok(Note::Unknown(NoteAny {
                n_type: nhdr.n_type,
                name,
                desc: raw_desc,
            })),
        }
    }
}

/// Contains four 4-byte integers.
/// The first 4-byte integer specifies the os. The second, third, and fourth
/// 4-byte integers contain the earliest compatible kernel version.
/// For example, if the 3 integers are 6, 0, and 7, this signifies a 6.0.7 kernel.
///
/// (see: <https://raw.githubusercontent.com/wiki/hjl-tools/linux-abi/linux-abi-draft.pdf>)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteGnuAbiTag {
    pub os: u32,
    pub major: u32,
    pub minor: u32,
    pub subminor: u32,
}

impl ParseAt for NoteGnuAbiTag {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(NoteGnuAbiTag {
            os: endian.parse_u32_at(offset, data)?,
            major: endian.parse_u32_at(offset, data)?,
            minor: endian.parse_u32_at(offset, data)?,
            subminor: endian.parse_u32_at(offset, data)?,
        })
    }

    fn size_for(_class: Class) -> usize {
        size_of::<u32>() * 4
    }
}

/// Contains a build ID note which is unique among the set of meaningful contents
/// for ELF files and identical when the output file would otherwise have been identical.
/// This is a zero-copy type which merely contains a slice of the note data from which it was parsed.
///
/// (see: <https://raw.githubusercontent.com/wiki/hjl-tools/linux-abi/linux-abi-draft.pdf>)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteGnuBuildId<'data>(pub &'data [u8]);

/// Contains the raw fields found in any ELF note. Used for notes that we don't know
/// how to parse into more specific types.
#[derive(Debug, PartialEq, Eq)]
pub struct NoteAny<'data> {
    pub n_type: u64,
    pub name: &'data str,
    pub desc: &'data [u8],
}

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
        if self.data.is_empty() {
            return None;
        }

        Note::parse_at(
            self.endian,
            self.class,
            self.align,
            &mut self.offset,
            self.data,
        )
        .ok()
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
    fn parse_nt_gnu_abi_tag() {
        #[rustfmt::skip]
        let data = [
            0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");

        assert_eq!(
            note,
            Note::GnuAbiTag(NoteGnuAbiTag {
                os: abi::ELF_NOTE_GNU_ABI_TAG_OS_LINUX,
                major: 2,
                minor: 6,
                subminor: 32
            })
        );
    }

    #[test]
    fn parse_desc_gnu_build_id() {
        let data = [
            0x04, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x47, 0x4e,
            0x55, 0x00, 0x77, 0x41, 0x9f, 0x0d, 0xa5, 0x10, 0x83, 0x0c, 0x57, 0xa7, 0xc8, 0xcc,
            0xb0, 0xee, 0x85, 0x5f, 0xee, 0xd3, 0x76, 0xa3,
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");

        assert_eq!(
            note,
            Note::GnuBuildId(NoteGnuBuildId(&[
                0x77, 0x41, 0x9f, 0x0d, 0xa5, 0x10, 0x83, 0x0c, 0x57, 0xa7, 0xc8, 0xcc, 0xb0, 0xee,
                0x85, 0x5f, 0xee, 0xd3, 0x76, 0xa3,
            ]))
        );
    }

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
            Note::Unknown(NoteAny {
                n_type: 5,
                name: abi::ELF_NOTE_GNU,
                desc: &[
                    0x2, 0x0, 0x0, 0xc0, 0x4, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                ]
            })
        );
    }

    #[test]
    fn parse_note_with_8_byte_alignment_unaligned_namesz() {
        let data = [
            0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // namesz 5, descsz 2
            0x42, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x55, // type 42 (unknown), name GNUU
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NUL + 7 pad for 8 alignment
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // desc 0102 + 6 pad for alignment
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 8, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note::Unknown(NoteAny {
                n_type: 0x42,
                name: &"GNUU",
                desc: &[0x01, 0x02],
            })
        );
        assert_eq!(offset, 32);
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
            Note::GnuBuildId(NoteGnuBuildId(&[
                0x77, 0x41, 0x9f, 0x0d, 0xa5, 0x10, 0x83, 0x0c, 0x57, 0xa7, 0xc8, 0xcc, 0xb0, 0xee,
                0x85, 0x5f, 0xee, 0xd3, 0x76, 0xa3,
            ]))
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
            Note::Unknown(NoteAny {
                n_type: 6,
                name: "",
                desc: &[0x20, 0x0],
            })
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
            Note::Unknown(NoteAny {
                n_type: 1,
                name: "GN",
                desc: &[0x01, 0x02, 0x03, 0x04],
            })
        );
        assert_eq!(offset, 20);
    }

    #[test]
    fn parse_note_32_lsb_with_desc_padding() {
        let data = [
            0x04, 0x00, 0x00, 0x00, // namesz 4
            0x02, 0x00, 0x00, 0x00, // descsz 2
            0x42, 0x00, 0x00, 0x00, // type 42 (unknown)
            0x47, 0x4e, 0x55, 0x00, // name GNU\0
            0x01, 0x02, 0x00, 0x00, // desc 0102 + 2 pad bytes
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note::Unknown(NoteAny {
                n_type: 0x42,
                name: abi::ELF_NOTE_GNU,
                desc: &[0x01, 0x02],
            })
        );
        assert_eq!(offset, 20);
    }

    #[test]
    fn parse_note_32_lsb_with_no_name() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // namesz 0
            0x02, 0x00, 0x00, 0x00, // descsz 2
            0x42, 0x00, 0x00, 0x00, // type 42 (unknown)
            0x20, 0x00, 0x00, 0x00, // desc 20, 00 + 2 pad bytes
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note::Unknown(NoteAny {
                n_type: 0x42,
                name: "",
                desc: &[0x20, 0x0],
            })
        );
        assert_eq!(offset, 16);
    }

    #[test]
    fn parse_note_32_lsb_with_no_desc() {
        let data = [
            0x04, 0x00, 0x00, 0x00, // namesz 4
            0x00, 0x00, 0x00, 0x00, // descsz 0
            0x42, 0x00, 0x00, 0x00, // type 42 (unknown)
            0x47, 0x4e, 0x55, 0x00, // name GNU\0
        ];

        let mut offset = 0;
        let note = Note::parse_at(LittleEndian, Class::ELF32, 4, &mut offset, &data)
            .expect("Failed to parse");
        assert_eq!(
            note,
            Note::Unknown(NoteAny {
                n_type: 0x42,
                name: abi::ELF_NOTE_GNU,
                desc: &[],
            })
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
