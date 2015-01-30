
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

