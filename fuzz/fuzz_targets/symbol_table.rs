#![no_main]

use elf::endian::AnyEndian;
use elf::symbol::Symbol;
use elf::ElfBytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = ElfBytes::<AnyEndian>::minimal_parse(data) {
        if let Ok(Some((symtab, strtab))) = file.symbol_table() {
            let _: Vec<(&str, Symbol)> = symtab
                .iter()
                .map(|sym| (strtab.get(sym.st_name as usize).unwrap_or("unknown"), sym))
                .collect();
        }

        if let Ok(Some((dynsym, dynstr))) = file.dynamic_symbol_table() {
            let _: Vec<(&str, Symbol)> = dynsym
                .iter()
                .map(|sym| (dynstr.get(sym.st_name as usize).unwrap_or("unknown"), sym))
                .collect();
        }
    }
});
