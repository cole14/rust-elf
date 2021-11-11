#[macro_export]
macro_rules! read_u16 {
    ($elf:ident, $io:ident) => {{
        use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
        match $elf.ehdr.data {
            types::ELFDATA2LSB => $io.read_u16::<LittleEndian>(),
            types::ELFDATA2MSB => $io.read_u16::<BigEndian>(),
            types::ELFDATANONE => {
                return Err(ParseError::EndianError);
            }
            _ => {
                return Err(ParseError::EndianError);
            }
        }
    }};
}

#[macro_export]
macro_rules! read_u32 {
    ($elf:ident, $io:ident) => {{
        use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
        match $elf.ehdr.data {
            types::ELFDATA2LSB => $io.read_u32::<LittleEndian>(),
            types::ELFDATA2MSB => $io.read_u32::<BigEndian>(),
            types::ELFDATANONE => {
                return Err(ParseError::EndianError);
            }
            _ => {
                return Err(ParseError::EndianError);
            }
        }
    }};
}

#[macro_export]
macro_rules! read_u64 {
    ($elf:ident, $io:ident) => {{
        use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
        match $elf.ehdr.data {
            types::ELFDATA2LSB => $io.read_u64::<LittleEndian>(),
            types::ELFDATA2MSB => $io.read_u64::<BigEndian>(),
            types::ELFDATANONE => {
                return Err(ParseError::EndianError);
            }
            _ => {
                return Err(ParseError::EndianError);
            }
        }
    }};
}

pub fn get_string(data: &[u8], start: usize) -> Result<String, std::string::FromUtf8Error> {
    let mut end: usize = 0;

    for (i, item) in data.iter().enumerate().skip(start) {
        if *item == 0u8 {
            end = i;
            break;
        }
    }

    let mut rtn = String::with_capacity(end - start);
    for item in data.iter().take(end).skip(start) {
        rtn.push(*item as char);
    }
    Ok(rtn)
}
