use std::fs;
use std::io;
use std::path::Path;
use std::io::{Read, Seek};

pub mod types;

#[macro_use]
pub mod utils;

pub struct File {
    pub ehdr: types::FileHeader,
    pub phdrs: Vec<types::ProgramHeader>,
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

#[derive(Debug)]
pub enum ParseError {
    EndianError,
    IoError(io::Error),
    InvalidMagic,
    InvalidFormat(Option<std::string::FromUtf8Error>),
    NotImplemented,
}

impl std::convert::From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::IoError(e)
    }
}

impl std::convert::From<std::string::FromUtf8Error> for ParseError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        ParseError::InvalidFormat(Some(e))
    }
}

impl File {
    pub fn open_path<T: AsRef<Path>>(path: T) -> Result<File, ParseError> {
        // Open the file for reading
        let mut io_file = fs::File::open(path)?;

        File::open_stream(&mut io_file)
    }

    pub fn open_stream<T: Read + Seek>(io_file: &mut T) -> Result<File, ParseError> {
        // Read the platform-independent ident bytes
        let mut ident = [0u8; types::EI_NIDENT];
        let nread = io_file.read(ident.as_mut())?;

        if nread != types::EI_NIDENT {
            return Err(ParseError::InvalidFormat(None));
        }

        // Verify the magic number
        if ident[0] != types::ELFMAG0 || ident[1] != types::ELFMAG1
                || ident[2] != types::ELFMAG2 || ident[3] != types::ELFMAG3 {
            return Err(ParseError::InvalidMagic);
        }

        // Fill in file header values from ident bytes
        let mut elf_f = File::new();
        elf_f.ehdr.class = types::Class(ident[types::EI_CLASS]);
        elf_f.ehdr.data = types::Data(ident[types::EI_DATA]);
        elf_f.ehdr.osabi = types::OSABI(ident[types::EI_OSABI]);
        elf_f.ehdr.abiversion = ident[types::EI_ABIVERSION];
        elf_f.ehdr.elftype = types::Type(utils::read_u16(elf_f.ehdr.data, io_file)?);
        elf_f.ehdr.machine = types::Machine(utils::read_u16(elf_f.ehdr.data, io_file)?);
        elf_f.ehdr.version = types::Version(utils::read_u32(elf_f.ehdr.data, io_file)?);

        let phoff: u64;
        let shoff: u64;

        // Parse the platform-dependent file fields
        if elf_f.ehdr.class == types::ELFCLASS32 {
            elf_f.ehdr.entry = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
            phoff = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
            shoff = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
        } else {
            elf_f.ehdr.entry = utils::read_u64(elf_f.ehdr.data, io_file)?;
            phoff = utils::read_u64(elf_f.ehdr.data, io_file)?;
            shoff = utils::read_u64(elf_f.ehdr.data, io_file)?;
        }

        let _flags = utils::read_u32(elf_f.ehdr.data, io_file)?;
        let _ehsize = utils::read_u16(elf_f.ehdr.data, io_file)?;
        let _phentsize = utils::read_u16(elf_f.ehdr.data, io_file)?;
        let phnum = utils::read_u16(elf_f.ehdr.data, io_file)?;
        let _shentsize = utils::read_u16(elf_f.ehdr.data, io_file)?;
        let shnum = utils::read_u16(elf_f.ehdr.data, io_file)?;
        let shstrndx = utils::read_u16(elf_f.ehdr.data, io_file)?;

        // Parse the program headers
        io_file.seek(io::SeekFrom::Start(phoff))?;
        for _ in 0..phnum {
            let progtype: types::ProgType;
            let offset: u64;
            let vaddr: u64;
            let paddr: u64;
            let filesz: u64;
            let memsz: u64;
            let flags: types::ProgFlag;
            let align: u64;

            progtype = types::ProgType(utils::read_u32(elf_f.ehdr.data, io_file)?);
            if elf_f.ehdr.class == types::ELFCLASS32 {
                offset = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                vaddr = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                paddr = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                filesz = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                memsz = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                flags = types::ProgFlag(utils::read_u32(elf_f.ehdr.data, io_file)?);
                align = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
            } else {
                flags = types::ProgFlag(utils::read_u32(elf_f.ehdr.data, io_file)?);
                offset = utils::read_u64(elf_f.ehdr.data, io_file)?;
                vaddr = utils::read_u64(elf_f.ehdr.data, io_file)?;
                paddr = utils::read_u64(elf_f.ehdr.data, io_file)?;
                filesz = utils::read_u64(elf_f.ehdr.data, io_file)?;
                memsz = utils::read_u64(elf_f.ehdr.data, io_file)?;
                align = utils::read_u64(elf_f.ehdr.data, io_file)?;
            }

            elf_f.phdrs.push(types::ProgramHeader {
                    progtype: progtype,
                    offset:   offset,
                    vaddr:    vaddr,
                    paddr:    paddr,
                    filesz:   filesz,
                    memsz:    memsz,
                    flags:    flags,
                    align:    align,
                });
        }

        // Parse the section headers
        let mut name_idxs: Vec<u32> = Vec::new();
        io_file.seek(io::SeekFrom::Start(shoff))?;
        for _ in 0..shnum {
            let name: String = String::new();
            let shtype: types::SectionType;
            let flags: types::SectionFlag;
            let addr: u64;
            let offset: u64;
            let size: u64;
            let link: u32;
            let info: u32;
            let addralign: u64;
            let entsize: u64;

            name_idxs.push(utils::read_u32(elf_f.ehdr.data, io_file)?);
            shtype = types::SectionType(utils::read_u32(elf_f.ehdr.data, io_file)?);
            if elf_f.ehdr.class == types::ELFCLASS32 {
                flags = types::SectionFlag(utils::read_u32(elf_f.ehdr.data, io_file)? as u64);
                addr = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                offset = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                size = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                link = utils::read_u32(elf_f.ehdr.data, io_file)?;
                info = utils::read_u32(elf_f.ehdr.data, io_file)?;
                addralign = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
                entsize = utils::read_u32(elf_f.ehdr.data, io_file)? as u64;
            } else {
                flags = types::SectionFlag(utils::read_u64(elf_f.ehdr.data, io_file)?);
                addr = utils::read_u64(elf_f.ehdr.data, io_file)?;
                offset = utils::read_u64(elf_f.ehdr.data, io_file)?;
                size = utils::read_u64(elf_f.ehdr.data, io_file)?;
                link = utils::read_u32(elf_f.ehdr.data, io_file)?;
                info = utils::read_u32(elf_f.ehdr.data, io_file)?;
                addralign = utils::read_u64(elf_f.ehdr.data, io_file)?;
                entsize = utils::read_u64(elf_f.ehdr.data, io_file)?;
            }

            elf_f.sections.push(Section {
                    shdr: types::SectionHeader {
                        name:      name,
                        shtype:    shtype,
                        flags:     flags,
                        addr:      addr,
                        offset:    offset,
                        size:      size,
                        link:      link,
                        info:      info,
                        addralign: addralign,
                        entsize:   entsize,
                    },
                    data: Vec::new(),
                });
        }

        // Read the section data
        let mut s_i: usize = 0;
        loop {
            if s_i == shnum as usize { break; }

            let off = elf_f.sections[s_i].shdr.offset;
            let size = elf_f.sections[s_i].shdr.size;
            io_file.seek(io::SeekFrom::Start(off))?;
            let mut data = vec![0; size as usize];
            if elf_f.sections[s_i].shdr.shtype != types::SHT_NOBITS {
                io_file.read_exact(&mut data)?;
            }
            elf_f.sections[s_i].data = data;

            s_i += 1;
        }

        // Parse the section names from the string header string table
        s_i = 0;
        loop {
            if s_i == shnum as usize { break; }

            elf_f.sections[s_i].shdr.name = utils::get_string(
                &elf_f.sections[shstrndx as usize].data,
                name_idxs[s_i] as usize)?;

            s_i += 1;
        }

        Ok(elf_f)
    }

    pub fn get_symbols(&self, section: &Section) -> Result<Vec<types::Symbol>, ParseError> {
        let mut symbols = Vec::new();
        if section.shdr.shtype == types::SHT_SYMTAB || section.shdr.shtype == types::SHT_DYNSYM {
            let link = &self.sections[section.shdr.link as usize].data;
            let mut io_section = io::Cursor::new(&section.data);
            while (io_section.position() as usize) < section.data.len() {
                self.parse_symbol(&mut io_section, &mut symbols, link)?;
            }
        }
        Ok(symbols)
    }

    fn parse_symbol<T: Read + Seek>(&self, io_section: &mut T, symbols: &mut Vec<types::Symbol>, link: &[u8]) -> Result<(), ParseError> {
        let name: u32;
        let value: u64;
        let size: u64;
        let shndx: u16;
        let mut info: [u8; 1] = [0u8];
        let mut other: [u8; 1] = [0u8];

        if self.ehdr.class == types::ELFCLASS32 {
            name = utils::read_u32(self.ehdr.data, io_section)?;
            value = utils::read_u32(self.ehdr.data, io_section)? as u64;
            size = utils::read_u32(self.ehdr.data, io_section)? as u64;
            io_section.read_exact(&mut info)?;
            io_section.read_exact(&mut other)?;
            shndx = utils::read_u16(self.ehdr.data, io_section)?;
        } else {
            name = utils::read_u32(self.ehdr.data, io_section)?;
            io_section.read_exact(&mut info)?;
            io_section.read_exact(&mut other)?;
            shndx = utils::read_u16(self.ehdr.data, io_section)?;
            value = utils::read_u64(self.ehdr.data, io_section)?;
            size = utils::read_u64(self.ehdr.data, io_section)?;
        }

        symbols.push(types::Symbol {
                name:    utils::get_string(link, name as usize)?,
                value:   value,
                size:    size,
                shndx:   shndx,
                symtype: types::SymbolType(info[0] & 0xf),
                bind:    types::SymbolBind(info[0] >> 4),
                vis:     types::SymbolVis(other[0] & 0x3),
            });
        Ok(())
    }

    pub fn get_section<T: AsRef<str>>(&self, name: T) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.shdr.name == name.as_ref() )
    }

    pub fn new() -> File {
        File {
            ehdr: types::FileHeader::new(),
            phdrs: Vec::new(),
            sections: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct Section {
    pub shdr: types::SectionHeader,
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
