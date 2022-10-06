use std::fs;
use std::io;
use std::path::Path;
use std::io::{Read, Seek};

pub mod file;
pub mod gabi;
pub mod segment;
pub mod section;
pub mod symbol;
pub mod parse;

use parse::Parse;

mod utils;

pub struct File {
    pub ehdr: file::FileHeader,
    pub phdrs: Vec<segment::ProgramHeader>,
    pub sections: Vec<Section>,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?} {:?} {:?}", self.ehdr, self.phdrs, self.sections)
    }
}

impl std::fmt::Display for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{{ {} }}", self.ehdr)?;
        write!(f, "{{ ")?;
        for phdr in self.phdrs.iter() {
            write!(f, "{}", phdr)?;
        }
        write!(f, " }} {{ ")?;
        for shdr in self.sections.iter() {
            write!(f, "{}", shdr)?;
        }
        write!(f, " }}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

impl std::convert::From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError(e.to_string())
    }
}

impl std::convert::From<std::string::FromUtf8Error> for ParseError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        ParseError(e.to_string())
    }
}

impl File {
    pub fn open_path<T: AsRef<Path>>(path: T) -> Result<File, ParseError> {
        // Open the file for reading
        let mut io_file = fs::File::open(path)?;

        File::open_stream(&mut io_file)
    }

    pub fn open_stream<T: Read + Seek>(io_file: &mut T) -> Result<File, ParseError> {
        let ehdr = file::FileHeader::parse(file::Endian(gabi::ELFDATANONE), file::Class(gabi::ELFCLASSNONE), io_file)?;

        // Parse the program headers
        io_file.seek(io::SeekFrom::Start(ehdr.e_phoff))?;
        let mut phdrs = Vec::<segment::ProgramHeader>::default();

        for _ in 0..ehdr.e_phnum {
            let phdr = segment::ProgramHeader::parse(ehdr.endianness, ehdr.class, io_file)?;
            phdrs.push(phdr);
        }

        let mut sections = Vec::<Section>::default();

        // Parse the section headers
        io_file.seek(io::SeekFrom::Start(ehdr.e_shoff))?;
        for _ in 0..ehdr.e_shnum {
            let shdr = section::SectionHeader::parse(ehdr.endianness, ehdr.class, io_file)?;
            sections.push(
                Section {
                    name: String::new(),
                    shdr: shdr,
                    data: Vec::new(),
                });
        }

        // Read the section data
        for section in sections.iter_mut() {
            if section.shdr.sh_type == section::SectionType(gabi::SHT_NOBITS) {
                continue;
            }

            io_file.seek(io::SeekFrom::Start(section.shdr.sh_offset))?;
            section.data.resize(section.shdr.sh_size as usize, 0u8);
            io_file.read_exact(&mut section.data)?;
        }

        // Parse the section names from the section header string table
        for i in 0..sections.len() {
            let shstr_data = &sections[ehdr.e_shstrndx as usize].data;
            sections[i].name = utils::get_string(shstr_data, sections[i].shdr.sh_name as usize)?;
        }

        Ok(File {
            ehdr: ehdr,
            phdrs: phdrs,
            sections: sections
        })
    }

    pub fn get_symbols(&self, section: &Section) -> Result<Vec<symbol::Symbol>, ParseError> {
        let mut symbols = Vec::new();
        if section.shdr.sh_type == section::SectionType(gabi::SHT_SYMTAB) || section.shdr.sh_type == section::SectionType(gabi::SHT_DYNSYM) {
            let link = &self.sections[section.shdr.sh_link as usize].data;
            let mut io_section = io::Cursor::new(&section.data);
            while (io_section.position() as usize) < section.data.len() {
                self.parse_symbol(&mut io_section, &mut symbols, link)?;
            }
        }
        Ok(symbols)
    }

    fn parse_symbol<T: Read + Seek>(&self, io_section: &mut T, symbols: &mut Vec<symbol::Symbol>, link: &[u8]) -> Result<(), ParseError> {
        let name: u32;
        let value: u64;
        let size: u64;
        let shndx: u16;
        let mut info: [u8; 1] = [0u8];
        let mut other: [u8; 1] = [0u8];

        if self.ehdr.class == gabi::ELFCLASS32 {
            name = utils::read_u32(self.ehdr.endianness, io_section)?;
            value = utils::read_u32(self.ehdr.endianness, io_section)? as u64;
            size = utils::read_u32(self.ehdr.endianness, io_section)? as u64;
            io_section.read_exact(&mut info)?;
            io_section.read_exact(&mut other)?;
            shndx = utils::read_u16(self.ehdr.endianness, io_section)?;
        } else {
            name = utils::read_u32(self.ehdr.endianness, io_section)?;
            io_section.read_exact(&mut info)?;
            io_section.read_exact(&mut other)?;
            shndx = utils::read_u16(self.ehdr.endianness, io_section)?;
            value = utils::read_u64(self.ehdr.endianness, io_section)?;
            size = utils::read_u64(self.ehdr.endianness, io_section)?;
        }

        symbols.push(symbol::Symbol {
                name:    utils::get_string(link, name as usize)?,
                value:   value,
                size:    size,
                shndx:   shndx,
                symtype: symbol::SymbolType(info[0] & 0xf),
                bind:    symbol::SymbolBind(info[0] >> 4),
                vis:     symbol::SymbolVis(other[0] & 0x3),
            });
        Ok(())
    }

    pub fn get_section<T: AsRef<str>>(&self, name: T) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.name == name.as_ref() )
    }
}

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub shdr: section::SectionHeader,
    pub data: Vec<u8>,
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.shdr)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use File;

    #[test]
    fn test_open_path() {
        let file = File::open_path(PathBuf::from("tests/samples/test1"))
            .expect("Open test1");
        let bss = file.get_section(".bss").expect("Get .bss section");
        assert!(bss.data.iter().all(|&b| b == 0));
    }
}