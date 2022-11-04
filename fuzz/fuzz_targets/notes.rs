#![no_main]

use libfuzzer_sys::fuzz_target;
use elf::File;
use elf::note::Note;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut file) = File::open_stream(data) {
        if let Ok(shdrs) = file.section_headers() {
            if let Some(shdr) = shdrs.iter().find(|shdr|{shdr.sh_type == elf::abi::SHT_NOTE}) {
                if let Ok(notes) = file.section_data_as_notes(&shdr) {
                    let _: Vec<Note> = notes.collect();
                }
            }
        }
    }
});
