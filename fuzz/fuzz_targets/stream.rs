#![no_main]

use elf::endian::AnyEndian;
use elf::ElfStream;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cur = std::io::Cursor::new(data);
    if let Ok(mut file) = ElfStream::<AnyEndian, _>::open_stream(&mut cur) {
        // parse the symbol table
        if let Ok(Some((symtab, _))) = file.symbol_table() {
            let _: Vec<_> = symtab.iter().collect();
        }

        // parse any notes
        if let Some(shdr) = file
            .section_headers()
            .iter()
            .find(|shdr| shdr.sh_type == elf::abi::SHT_NOTE)
        {
            let shdr = *shdr;
            if let Ok(notes) = file.section_data_as_notes(&shdr) {
                let _: Vec<_> = notes.collect();
            }
        }
    }
});
