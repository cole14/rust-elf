#![no_main]

use libfuzzer_sys::fuzz_target;
use elf::File;
use elf::section::SectionHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut file) = File::open_stream(data) {
        if let Ok((shdrs, strtab)) = file.section_headers_with_strtab() {
            let _: Vec<(&str, SectionHeader)> = shdrs
                .iter()
                .map(|shdr| {
                    (
                        strtab.get(shdr.sh_name as usize).unwrap_or("unknown"),
                        shdr,
                    )
                })
                .collect();
        }
    }
});
