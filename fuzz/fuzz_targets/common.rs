#![no_main]

use elf::endian::AnyEndian;
use elf::ElfBytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = ElfBytes::<AnyEndian>::minimal_parse(data) {
        if let Some(shdrs) = file.section_headers() {
            let _: Vec<_> = shdrs.iter().collect();
        }

        if let Ok(common) = file.find_common_data() {
            // parse the symbol table
            if let Some(symtab) = common.symtab {
                let _: Vec<_> = symtab.iter().collect();
            }

            // parse the dynamic symbol table
            if let Some(dynsyms) = common.dynsyms {
                if let Some(dynstrs) = common.dynsyms_strs {
                    let sym_names: Vec<&[u8]> = dynsyms
                        .iter()
                        .map(|sym| dynstrs.get_raw(sym.st_name as usize).unwrap_or(b"unk"))
                        .collect();

                    // use the hash table
                    if let Some(hash) = common.sysv_hash {
                        for name in sym_names.iter() {
                            let _ = hash.find(name, &dynsyms, &dynstrs);
                        }
                    }

                    // use the gnu hash table
                    if let Some(hash) = common.gnu_hash {
                        for name in sym_names.iter() {
                            let _ = hash.find(name, &dynsyms, &dynstrs);
                        }
                    }
                }
            }

            // parse the .dynamic table
            if let Some(dyns) = common.dynamic {
                let _: Vec<_> = dyns.iter().collect();
            }
        }
    }
});
