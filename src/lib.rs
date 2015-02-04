#![feature(io)]
#![feature(core)]
#![feature(collections)]

pub mod types;

#[macro_use]
pub mod utils;

pub struct File {
    file: std::old_io::File,
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
    IoError,
    InvalidMagic,
    InvalidFormat,
    NotImplemented,
}

impl std::error::FromError<std::old_io::IoError> for ParseError {
    fn from_error(_: std::old_io::IoError) -> Self {
        ParseError::IoError
    }
}

impl std::error::FromError<std::string::FromUtf8Error> for ParseError {
    fn from_error(_: std::string::FromUtf8Error) -> Self {
        ParseError::InvalidFormat
    }
}

impl File {
    pub fn open(path: &std::path::Path) -> Result<File, ParseError> {
        // Open the file for reading
        let mut io_file = try!(std::old_io::File::open(path));

        // Read the platform-independent ident bytes
        let mut ident = [0u8; types::EI_NIDENT];
        let nread = try!(io_file.read(&mut ident));

        if nread != types::EI_NIDENT {
            return Err(ParseError::InvalidFormat);
        }

        // Verify the magic number
        if ident[0] != types::ELFMAGIC[0] || ident[1] != types::ELFMAGIC[1]
                || ident[2] != types::ELFMAGIC[2] || ident[3] != types::ELFMAGIC[3] {
            return Err(ParseError::InvalidMagic);
        }

        // Fill in file header values from ident bytes
        let mut elf_f = File::new(io_file);
        elf_f.ehdr.class = types::Class(ident[types::EI_CLASS]);
        elf_f.ehdr.data = types::Data(ident[types::EI_DATA]);
        elf_f.ehdr.osabi = types::OSABI(ident[types::EI_OSABI]);
        elf_f.ehdr.abiversion = ident[types::EI_ABIVERSION];
        elf_f.ehdr.elftype = types::Type(try!(read_u16!(elf_f)));
        elf_f.ehdr.machine = types::Machine(try!(read_u16!(elf_f)));
        elf_f.ehdr.version = types::Version(try!(read_u32!(elf_f)));

        let mut phoff: u64;
        let mut shoff: u64;

        // Parse the platform-dependent file fields
        if elf_f.ehdr.class == types::ELFCLASS32 {
            elf_f.ehdr.entry = try!(read_u32!(elf_f)) as u64;
            phoff = try!(read_u32!(elf_f)) as u64;
            shoff = try!(read_u32!(elf_f)) as u64;
        } else {
            elf_f.ehdr.entry = try!(read_u64!(elf_f));
            phoff = try!(read_u64!(elf_f));
            shoff = try!(read_u64!(elf_f));
        }

        let flags = try!(read_u32!(elf_f));
        let ehsize = try!(read_u16!(elf_f));
        let phentsize = try!(read_u16!(elf_f));
        let phnum = try!(read_u16!(elf_f));
        let shentsize = try!(read_u16!(elf_f));
        let shnum = try!(read_u16!(elf_f));
        let shstrndx = try!(read_u16!(elf_f));

        // Parse the program headers
        try!(elf_f.file.seek(phoff as i64, std::old_io::SeekStyle::SeekSet));
        for _ in 0..phnum {
            let mut progtype: types::ProgType;
            let mut offset: u64;
            let mut vaddr: u64;
            let mut paddr: u64;
            let mut filesz: u64;
            let mut memsz: u64;
            let mut flags: types::ProgFlag;
            let mut align: u64;

            progtype = types::ProgType(try!(read_u32!(elf_f)));
            if elf_f.ehdr.class == types::ELFCLASS32 {
                offset = try!(read_u32!(elf_f)) as u64;
                vaddr = try!(read_u32!(elf_f)) as u64;
                paddr = try!(read_u32!(elf_f)) as u64;
                filesz = try!(read_u32!(elf_f)) as u64;
                memsz = try!(read_u32!(elf_f)) as u64;
                flags = types::ProgFlag(try!(read_u32!(elf_f)));
                align = try!(read_u32!(elf_f)) as u64;
            } else {
                flags = types::ProgFlag(try!(read_u32!(elf_f)));
                offset = try!(read_u64!(elf_f));
                vaddr = try!(read_u64!(elf_f));
                paddr = try!(read_u64!(elf_f));
                filesz = try!(read_u64!(elf_f));
                memsz = try!(read_u64!(elf_f));
                align = try!(read_u64!(elf_f));
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
        try!(elf_f.file.seek(shoff as i64, std::old_io::SeekStyle::SeekSet));
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

            name_idxs.push(try!(read_u32!(elf_f)));
            shtype = types::SectionType(try!(read_u32!(elf_f)));
            if elf_f.ehdr.class == types::ELFCLASS32 {
                flags = types::SectionFlag(try!(read_u32!(elf_f)) as u64);
                addr = try!(read_u32!(elf_f)) as u64;
                offset = try!(read_u32!(elf_f)) as u64;
                size = try!(read_u32!(elf_f)) as u64;
                link = try!(read_u32!(elf_f));
                info = try!(read_u32!(elf_f));
                addralign = try!(read_u32!(elf_f)) as u64;
                entsize = try!(read_u32!(elf_f)) as u64;
            } else {
                flags = types::SectionFlag(try!(read_u64!(elf_f)));
                addr = try!(read_u64!(elf_f));
                offset = try!(read_u64!(elf_f));
                size = try!(read_u64!(elf_f));
                link = try!(read_u32!(elf_f));
                info = try!(read_u32!(elf_f));
                addralign = try!(read_u64!(elf_f));
                entsize = try!(read_u64!(elf_f));
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
        for s_i in 0..shnum {
            let off = elf_f.sections[s_i as usize].shdr.offset;
            let size = elf_f.sections[s_i as usize].shdr.size;
            try!(elf_f.file.seek(off as i64, std::old_io::SeekStyle::SeekSet));
            elf_f.sections[s_i as usize].data = try!(elf_f.file.read_exact(size as usize));
        }

        // Parse the section names from the string header string table
        for s_i in 0..shnum {
            elf_f.sections[s_i as usize].shdr.name = try!(utils::get_string(
                    elf_f.sections[shstrndx as usize].data.clone(),
                    name_idxs[s_i as usize] as usize));
        }

        Ok(elf_f)
    }

    pub fn get_section(&self, name: String) -> Option<&Section> {
        for s_i in 0..self.sections.len() {
            if self.sections[s_i].shdr.name == name {
                return Some(&self.sections[s_i])
            }
        }
        None
    }

    pub fn new(io_file: std::old_io::File) -> File {
        File { file: io_file,
            ehdr: std::default::Default::default(),
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

