use std::fs;
use std::io;
use std::path::Path;
use std::io::Read;

extern crate byteorder;

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

    pub fn open_stream<T: io::Read + io::Seek>(io_file: &mut T) -> Result<File, ParseError> {
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
        elf_f.ehdr.elftype = types::Type(read_u16!(elf_f, io_file)?);
        elf_f.ehdr.machine = types::Machine(read_u16!(elf_f, io_file)?);
        elf_f.ehdr.version = types::Version(read_u32!(elf_f, io_file)?);

        let phoff: u64;
        let shoff: u64;

        // Parse the platform-dependent file fields
        if elf_f.ehdr.class == types::ELFCLASS32 {
            elf_f.ehdr.entry = read_u32!(elf_f, io_file)? as u64;
            phoff = read_u32!(elf_f, io_file)? as u64;
            shoff = read_u32!(elf_f, io_file)? as u64;
        } else {
            elf_f.ehdr.entry = read_u64!(elf_f, io_file)?;
            phoff = read_u64!(elf_f, io_file)?;
            shoff = read_u64!(elf_f, io_file)?;
        }

        let flags = read_u32!(elf_f, io_file)?;
        let ehsize = read_u16!(elf_f, io_file)?;
        let phentsize = read_u16!(elf_f, io_file)?;
        let phnum = read_u16!(elf_f, io_file)?;
        let shentsize = read_u16!(elf_f, io_file)?;
        let shnum = read_u16!(elf_f, io_file)?;
        let shstrndx = read_u16!(elf_f, io_file)?;

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

            progtype = types::ProgType(read_u32!(elf_f, io_file)?);
            if elf_f.ehdr.class == types::ELFCLASS32 {
                offset = read_u32!(elf_f, io_file)? as u64;
                vaddr = read_u32!(elf_f, io_file)? as u64;
                paddr = read_u32!(elf_f, io_file)? as u64;
                filesz = read_u32!(elf_f, io_file)? as u64;
                memsz = read_u32!(elf_f, io_file)? as u64;
                flags = types::ProgFlag(read_u32!(elf_f, io_file)?);
                align = read_u32!(elf_f, io_file)? as u64;
            } else {
                flags = types::ProgFlag(read_u32!(elf_f, io_file)?);
                offset = read_u64!(elf_f, io_file)?;
                vaddr = read_u64!(elf_f, io_file)?;
                paddr = read_u64!(elf_f, io_file)?;
                filesz = read_u64!(elf_f, io_file)?;
                memsz = read_u64!(elf_f, io_file)?;
                align = read_u64!(elf_f, io_file)?;
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

            name_idxs.push(read_u32!(elf_f, io_file)?);
            shtype = types::SectionType(read_u32!(elf_f, io_file)?);
            if elf_f.ehdr.class == types::ELFCLASS32 {
                flags = types::SectionFlag(read_u32!(elf_f, io_file)? as u64);
                addr = read_u32!(elf_f, io_file)? as u64;
                offset = read_u32!(elf_f, io_file)? as u64;
                size = read_u32!(elf_f, io_file)? as u64;
                link = read_u32!(elf_f, io_file)?;
                info = read_u32!(elf_f, io_file)?;
                addralign = read_u32!(elf_f, io_file)? as u64;
                entsize = read_u32!(elf_f, io_file)? as u64;
            } else {
                flags = types::SectionFlag(read_u64!(elf_f, io_file)?);
                addr = read_u64!(elf_f, io_file)?;
                offset = read_u64!(elf_f, io_file)?;
                size = read_u64!(elf_f, io_file)?;
                link = read_u32!(elf_f, io_file)?;
                info = read_u32!(elf_f, io_file)?;
                addralign = read_u64!(elf_f, io_file)?;
                entsize = read_u64!(elf_f, io_file)?;
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

    fn parse_symbol(&self, io_section: &mut dyn Read, symbols: &mut Vec<types::Symbol>, link: &[u8]) -> Result<(), ParseError> {
        let name: u32;
        let value: u64;
        let size: u64;
        let shndx: u16;
        let mut info: [u8; 1] = [0u8];
        let mut other: [u8; 1] = [0u8];

        if self.ehdr.class == types::ELFCLASS32 {
            name = read_u32!(self, io_section)?;
            value = read_u32!(self, io_section)? as u64;
            size = read_u32!(self, io_section)? as u64;
            io_section.read_exact(&mut info)?;
            io_section.read_exact(&mut other)?;
            shndx = read_u16!(self, io_section)?;
        } else {
            name = read_u32!(self, io_section)?;
            io_section.read_exact(&mut info)?;
            io_section.read_exact(&mut other)?;
            shndx = read_u16!(self, io_section)?;
            value = read_u64!(self, io_section)?;
            size = read_u64!(self, io_section)?;
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
