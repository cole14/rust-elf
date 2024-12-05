use elf::{ abi, endian, ElfBytes, relocation::aps2};

fn main() {
    let path = std::path::Path::new("sample-objects/android_cpp.arm.so");
    let raw_file = std::fs::read(path).unwrap();
    let file =
        ElfBytes::<endian::AnyEndian>::minimal_parse(raw_file.as_slice()).expect("parse elf file");

    let rel = file.dynamic().unwrap().unwrap().iter().find(|d| d.d_tag == abi::DT_ANDROID_REL).unwrap();
    let rel_sz = file.dynamic().unwrap().unwrap().iter().find(|d| d.d_tag == abi::DT_ANDROID_RELSZ).unwrap();
    let rel_offset = addr_to_offset(&file, rel.d_ptr()).unwrap();

    let rel_data = raw_file.as_slice().get(rel_offset..rel_offset+rel_sz.d_val() as usize).unwrap();

    let android_rel = aps2::AndroidRelIterator::new(file.ehdr.class, rel_data).unwrap();
    
    for rel in android_rel{
        match rel{
            Ok(rel) => {
                println!("type: {}, sym: {}, offset: {}", rel.r_type, rel.r_sym, rel.r_offset);
            },
            Err(e) => {
                println!("error: {:?}", e);
                break;
            }
        }
    }
}
fn addr_to_offset<E:endian::EndianParse>(elf: &elf::ElfBytes<E>, addr: u64) -> Option<usize> {
    elf.segments().and_then(|segs| {
        segs.iter().find(|item| {
            item.p_type == abi::PT_LOAD && item.p_vaddr <= addr && addr < item.p_vaddr + item.p_memsz
        })
    }).map(|seg| {
        (addr - seg.p_vaddr + seg.p_offset) as usize
    })
}