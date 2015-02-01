
#[macro_export]
pub macro_rules! read_u8 {
    ($elf:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $elf.file.read_le_u8() }
            types::ELFDATA2MSB => { $elf.file.read_be_u8() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

#[macro_export]
pub macro_rules! read_u16 {
    ($elf:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $elf.file.read_le_u16() }
            types::ELFDATA2MSB => { $elf.file.read_be_u16() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

#[macro_export]
pub macro_rules! read_u32 {
    ($elf:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $elf.file.read_le_u32() }
            types::ELFDATA2MSB => { $elf.file.read_be_u32() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

#[macro_export]
pub macro_rules! read_u64 {
    ($elf:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $elf.file.read_le_u64() }
            types::ELFDATA2MSB => { $elf.file.read_be_u64() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

use std;
pub fn get_string(mut data: Vec<u8>, start: usize) -> Result<String, std::string::FromUtf8Error> {
    let mut str_data = data.split_off(start);
    let mut end: usize = 0;
    for i in 0..str_data.len() {
        if str_data[i] == 0u8 {
            end = i;
            break;
        }
    }
    str_data.truncate(end);
    String::from_utf8(str_data)
}

