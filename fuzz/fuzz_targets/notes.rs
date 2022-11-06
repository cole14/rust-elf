#![no_main]

use elf::endian::AnyEndian;
use elf::note::Note;
use elf::ElfBytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = ElfBytes::<AnyEndian>::minimal_parse(data) {
        if let Some(shdrs) = file.section_headers() {
            if let Some(shdr) = shdrs.iter().find(|shdr| shdr.sh_type == elf::abi::SHT_NOTE) {
                if let Ok(notes) = file.section_data_as_notes(&shdr) {
                    let _: Vec<Note> = notes.collect();
                }
            }
        }
    }
});
