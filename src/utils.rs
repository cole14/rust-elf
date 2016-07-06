#[macro_export]
macro_rules! read_u16 {
    ($elf:ident, $io:ident) => ({
        use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $io.read_u16::<LittleEndian>() }
            types::ELFDATA2MSB => { $io.read_u16::<BigEndian>() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    });
}

#[macro_export]
macro_rules! read_u32 {
    ($elf:ident, $io:ident) => ({
        use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $io.read_u32::<LittleEndian>() }
            types::ELFDATA2MSB => { $io.read_u32::<BigEndian>() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    });
}

#[macro_export]
macro_rules! read_u64 {
    ($elf:ident, $io:ident) => ({
        use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
        match $elf.ehdr.data {
            types::ELFDATA2LSB => { $io.read_u64::<LittleEndian>() }
            types::ELFDATA2MSB => { $io.read_u64::<BigEndian>() }
            types::ELFDATANONE => { panic!("Unable to resolve file endianness"); }
            _ => { panic!("Unable to resolve file endianness"); }
        }
    });
}

use std;
pub fn get_string(data: &[u8], start: usize) -> Result<String, std::string::FromUtf8Error> {
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
