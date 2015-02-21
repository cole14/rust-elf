
#[macro_export]
macro_rules! read_u8 {
    ($elf:ident, $io:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $io.read_le_u8() }
            types::ELFDATA2MSB => { $io.read_be_u8() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

#[macro_export]
macro_rules! read_u16 {
    ($elf:ident, $io:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $io.read_le_u16() }
            types::ELFDATA2MSB => { $io.read_be_u16() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

#[macro_export]
macro_rules! read_u32 {
    ($elf:ident, $io:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $io.read_le_u32() }
            types::ELFDATA2MSB => { $io.read_be_u32() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

#[macro_export]
macro_rules! read_u64 {
    ($elf:ident, $io:ident) => (
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $io.read_le_u64() }
            types::ELFDATA2MSB => { $io.read_be_u64() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    );
}

use std;
pub fn get_string(data: &Vec<u8>, start: usize) -> Result<String, std::string::FromUtf8Error> {
    let mut end: usize = 0;
    for i in start..data.len() {
        if data[i] == 0u8 {
            end = i;
            break;
        }
    }
    let mut rtn = String::with_capacity(end - start);
    for i in start..end {
        rtn.push(data[i] as char);
    }
    Ok(rtn)
}

