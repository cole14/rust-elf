
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

pub trait ReadExact {
    fn read_exact(&mut self, len: u64) -> io::Result<Vec<u8>>;
}
impl<T> ReadExact for T
    where T: io::Read
{
    fn read_exact(&mut self, len: u64) -> io::Result<Vec<u8>> {
        use std::io::{Error, ErrorKind};
        let mut buf = Vec::with_capacity(len as usize);
        let mut chunk = self.take(len);
        try!(chunk.read_to_end(&mut buf));
        return Ok(buf);
    }
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?} {:?} {:?}", self.ehdr, self.phdrs, self.sections)
    }
}

impl std::fmt::Display for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        try!(write!(f, "{{ {} }}", self.ehdr));
        try!(write!(f, "{{ "));
        for phdr in self.phdrs.iter() {
            try!(write!(f, "{}", phdr));
        }
        try!(write!(f, " }} {{ "));
        for shdr in self.sections.iter() {
            try!(write!(f, "{}", shdr));
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
impl std::convert::From<byteorder::Error> for ParseError {
    fn from(e: byteorder::Error) -> Self {
        match e {
            byteorder::Error::UnexpectedEOF => {
                ParseError::InvalidFormat(None)
            },
            byteorder::Error::Io(e) => {
                From::from(e)
            },
        }
    }
}

impl File {
    pub fn open_path<T: AsRef<Path>>(path: T) -> Result<File, ParseError> {
        // Open the file for reading
        let mut io_file = try!(fs::File::open(path));

        File::open_stream(&mut io_file)
    }

    pub fn open_stream<T: io::Read + io::Seek>(io_file: &mut T) -> Result<File, ParseError> {
        // Read the platform-independent ident bytes
        let mut ident = [0u8; types::EI_NIDENT];
        let nread = try!(io_file.read(ident.as_mut()));

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
        elf_f.ehdr.elftype = types::Type(try!(read_u16!(elf_f, io_file)));
        elf_f.ehdr.machine = types::Machine(try!(read_u16!(elf_f, io_file)));
        elf_f.ehdr.version = types::Version(try!(read_u32!(elf_f, io_file)));

        let mut phoff: u64;
        let mut shoff: u64;

        // Parse the platform-dependent file fields
        if elf_f.ehdr.class == types::ELFCLASS32 {
            elf_f.ehdr.entry = try!(read_u32!(elf_f, io_file)) as u64;
            phoff = try!(read_u32!(elf_f, io_file)) as u64;
            shoff = try!(read_u32!(elf_f, io_file)) as u64;
        } else {
            elf_f.ehdr.entry = try!(read_u64!(elf_f, io_file));
            phoff = try!(read_u64!(elf_f, io_file));
            shoff = try!(read_u64!(elf_f, io_file));
        }

        let flags = try!(read_u32!(elf_f, io_file));
        let ehsize = try!(read_u16!(elf_f, io_file));
        let phentsize = try!(read_u16!(elf_f, io_file));
        let phnum = try!(read_u16!(elf_f, io_file));
        let shentsize = try!(read_u16!(elf_f, io_file));
        let shnum = try!(read_u16!(elf_f, io_file));
        let shstrndx = try!(read_u16!(elf_f, io_file));

        // Parse the program headers
        try!(io_file.seek(io::SeekFrom::Start(phoff)));
        for _ in 0..phnum {
            let mut progtype: types::ProgType;
            let mut offset: u64;
            let mut vaddr: u64;
            let mut paddr: u64;
            let mut filesz: u64;
            let mut memsz: u64;
            let mut flags: types::ProgFlag;
            let mut align: u64;

            progtype = types::ProgType(try!(read_u32!(elf_f, io_file)));
            if elf_f.ehdr.class == types::ELFCLASS32 {
                offset = try!(read_u32!(elf_f, io_file)) as u64;
                vaddr = try!(read_u32!(elf_f, io_file)) as u64;
                paddr = try!(read_u32!(elf_f, io_file)) as u64;
                filesz = try!(read_u32!(elf_f, io_file)) as u64;
                memsz = try!(read_u32!(elf_f, io_file)) as u64;
                flags = types::ProgFlag(try!(read_u32!(elf_f, io_file)));
                align = try!(read_u32!(elf_f, io_file)) as u64;
            } else {
                flags = types::ProgFlag(try!(read_u32!(elf_f, io_file)));
                offset = try!(read_u64!(elf_f, io_file));
                vaddr = try!(read_u64!(elf_f, io_file));
                paddr = try!(read_u64!(elf_f, io_file));
                filesz = try!(read_u64!(elf_f, io_file));
                memsz = try!(read_u64!(elf_f, io_file));
                align = try!(read_u64!(elf_f, io_file));
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
        try!(io_file.seek(io::SeekFrom::Start(shoff)));
        for _ in 0..shnum {
            let name: String = String::new();
            let mut shtype: types::SectionType;
            let mut flags: types::SectionFlag;
            let mut addr: u64;
            let mut offset: u64;
            let mut size: u64;
            let mut link: u32;
            let mut info: u32;
            let mut addralign: u64;
            let mut entsize: u64;

            name_idxs.push(try!(read_u32!(elf_f, io_file)));
            shtype = types::SectionType(try!(read_u32!(elf_f, io_file)));
            if elf_f.ehdr.class == types::ELFCLASS32 {
                flags = types::SectionFlag(try!(read_u32!(elf_f, io_file)) as u64);
                addr = try!(read_u32!(elf_f, io_file)) as u64;
                offset = try!(read_u32!(elf_f, io_file)) as u64;
                size = try!(read_u32!(elf_f, io_file)) as u64;
                link = try!(read_u32!(elf_f, io_file));
                info = try!(read_u32!(elf_f, io_file));
                addralign = try!(read_u32!(elf_f, io_file)) as u64;
                entsize = try!(read_u32!(elf_f, io_file)) as u64;
            } else {
                flags = types::SectionFlag(try!(read_u64!(elf_f, io_file)));
                addr = try!(read_u64!(elf_f, io_file));
                offset = try!(read_u64!(elf_f, io_file));
                size = try!(read_u64!(elf_f, io_file));
                link = try!(read_u32!(elf_f, io_file));
                info = try!(read_u32!(elf_f, io_file));
                addralign = try!(read_u64!(elf_f, io_file));
                entsize = try!(read_u64!(elf_f, io_file));
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
            try!(io_file.seek(io::SeekFrom::Start(off)));
            elf_f.sections[s_i].data = try!(io_file.read_exact(size));

            s_i += 1;
        }

        // Parse the section names from the string header string table
        s_i = 0;
        loop {
            if s_i == shnum as usize { break; }

            elf_f.sections[s_i].shdr.name = try!(utils::get_string(
                &elf_f.sections[shstrndx as usize].data,
                name_idxs[s_i] as usize));

            s_i += 1;
        }

        Ok(elf_f)
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
