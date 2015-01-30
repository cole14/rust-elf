#![feature(io)]
#![feature(core)]

pub mod types;

#[macro_use]
pub mod utils;

pub struct File {
    file: std::old_io::File,
    pub ehdr: types::FileHeader,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.ehdr)
    }
}

impl std::fmt::Display for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ehdr)
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
    fn from_error(err: std::old_io::IoError) -> Self {
        ParseError::IoError
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

        let mut phoff = 0u64;
        let mut shoff = 0u64;

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

        Ok(elf_f)
    }

    fn new(io_file: std::old_io::File) -> File {
        File { file: io_file, ehdr: std::default::Default::default() }
    }
}

