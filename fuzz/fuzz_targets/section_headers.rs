#![no_main]

use libfuzzer_sys::fuzz_target;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use elf::section::SectionHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = ElfBytes::<AnyEndian>::minimal_parse(data) {
        if let Ok(Some((shdrs, strtab))) = file.section_headers_with_strtab() {
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
