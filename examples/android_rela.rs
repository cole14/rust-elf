use elf::{ abi, endian, ElfBytes};

fn main() {
    let path = std::path::Path::new("sample-objects/android_cpp.aarch64.so");
    let raw_file = std::fs::read(path).unwrap();
    let file =
        ElfBytes::<endian::AnyEndian>::minimal_parse(raw_file.as_slice()).expect("parse elf file");

    let rel_sh = file.section_headers().unwrap().iter().find(|seg|{seg.sh_type == abi::SHT_ANDROID_RELA}).unwrap();
    
    let android_rela = file.section_date_as_android_relas(&rel_sh).unwrap();
    
    for rela in android_rela{
        match rela{
            Ok(rela) => {
                println!("type: {}, sym: {}, offset: {}, addend: {}", rela.r_type, rela.r_sym, rela.r_offset, rela.r_addend);
            },
            Err(e) => {
                println!("error: {:?}", e);
                break;
            }
        }
    }
}