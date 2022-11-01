#![no_main]

use libfuzzer_sys::fuzz_target;
use elf::File;
use elf::symbol::Symbol;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut file) = File::open_stream(data) {
        if let Ok(Some((dynsym, _))) = file.dynamic_symbol_table() {
            let symbols: Vec<Symbol> = dynsym.iter().collect();

            if let Ok(Some(table)) = file.symbol_version_table() {
                for (idx, _) in symbols.iter().enumerate() {
                    if let Ok(Some(def)) = table.get_definition(idx) {
                        let _: Vec<&str> = def.names.map(|name|{name.unwrap_or("unknown")}).collect();
                    }

                    if let Ok(Some(_)) = table.get_requirement(idx) {

                    }
                }
            }
        }
    }
});
