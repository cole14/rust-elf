#![no_main]

use libfuzzer_sys::fuzz_target;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use elf::note::Note;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = ElfBytes::<AnyEndian>::minimal_parse(data) {
        if let Some(shdrs) = file.section_headers() {
            if let Some(shdr) = shdrs.iter().find(|shdr|{shdr.sh_type == elf::abi::SHT_NOTE}) {
                if let Ok(notes) = file.section_data_as_notes(&shdr) {
                    let _: Vec<Note> = notes.collect();
                }
            }
        }
    }
});
