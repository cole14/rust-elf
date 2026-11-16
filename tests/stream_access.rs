#![cfg(feature = "std")]

use elf::endian::AnyEndian;
use elf::ElfStream;
use std::io::{Read, Seek, SeekFrom};

#[test]
fn read_into_caller_buffer_and_resume_parsing() {
    let bytes = std::fs::read("sample-objects/basic.x86_64").unwrap();
    let io = std::fs::File::open("sample-objects/basic.x86_64").unwrap();
    let mut elf = ElfStream::<AnyEndian, _>::open_stream(io).unwrap();
    assert_eq!(
        elf.inner_stream().metadata().unwrap().len(),
        bytes.len() as u64
    );

    let segment = *elf
        .segments()
        .iter()
        .find(|ph| ph.p_type == elf::abi::PT_LOAD)
        .unwrap();
    let mut buffer = vec![0; segment.p_filesz as usize];
    let stream = elf.inner_stream_mut();
    stream.seek(SeekFrom::Start(segment.p_offset)).unwrap();
    stream.read_exact(&mut buffer).unwrap();
    assert_eq!(
        buffer,
        bytes[segment.p_offset as usize..(segment.p_offset + segment.p_filesz) as usize]
    );

    // A cache miss must seek correctly after a direct read.
    let shstr = elf.section_headers()[elf.ehdr.e_shstrndx as usize];
    assert_eq!(
        elf.section_data_as_strtab(&shstr).unwrap().get(1).unwrap(),
        ".symtab"
    );

    // A cached parser read must remain usable after moving the stream to EOF.
    elf.inner_stream_mut().seek(SeekFrom::End(0)).unwrap();
    assert_eq!(
        elf.section_data_as_strtab(&shstr).unwrap().get(1).unwrap(),
        ".symtab"
    );
    let mut byte = [0];
    assert_eq!(elf.inner_stream_mut().read(&mut byte).unwrap(), 0);

    // A later cache miss also seeks correctly, and release still returns the stream.
    let text = *elf.section_header_by_name(".text").unwrap().unwrap();
    let expected = &bytes[text.sh_offset as usize..(text.sh_offset + text.sh_size) as usize];
    assert_eq!(elf.section_data(&text).unwrap().0, expected);
    let mut io = elf.release();
    io.seek(SeekFrom::Start(0)).unwrap();
    let mut magic = [0; 4];
    io.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"\x7fELF");
}
