#![feature(io)]
#![feature(core)]

pub mod types;

pub struct File {
    file: std::old_io::File,
    pub ehdr: types::Elf32Ehdr,
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

#[derive(Show)]
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
        elf_f.ehdr.e_class = types::Class(ident[types::EI_CLASS]);
        elf_f.ehdr.e_data = types::Data(ident[types::EI_DATA]);
        elf_f.ehdr.e_osabi = types::OSABI(ident[types::EI_OSABI]);

        // Parse the platform-dependent file header
        if elf_f.ehdr.e_class == types::ELFCLASS32 {
            try!(elf_f.parse_ehdr32());
        } else {
            try!(elf_f.parse_ehdr64());
        }

        Ok(elf_f)
    }

    fn parse_ehdr32(self: &mut Self) -> Result<(), ParseError> {
        if self.ehdr.e_data == types::ELFDATA2LSB {
            self.ehdr.e_type = types::Type(try!(self.file.read_le_u16()));
            self.ehdr.e_machine = types::Machine(try!(self.file.read_le_u16()));
            self.ehdr.e_version = types::Version(try!(self.file.read_le_u32()));
            self.ehdr.e_entry = types::Elf32Addr(try!(self.file.read_le_u32()));
            self.ehdr.e_phoff = types::Elf32Off(try!(self.file.read_le_u32()));
            self.ehdr.e_shoff = types::Elf32Off(try!(self.file.read_le_u32()));
            self.ehdr.e_flags = try!(self.file.read_le_u32());
            self.ehdr.e_ehsize = try!(self.file.read_le_u16());
            self.ehdr.e_phentsize = try!(self.file.read_le_u16());
            self.ehdr.e_phnum = try!(self.file.read_le_u16());
            self.ehdr.e_shentsize = try!(self.file.read_le_u16());
            self.ehdr.e_shnum = try!(self.file.read_le_u16());
            self.ehdr.e_shstrndx = try!(self.file.read_le_u16());
        } else {
            self.ehdr.e_type = types::Type(try!(self.file.read_be_u16()));
            self.ehdr.e_machine = types::Machine(try!(self.file.read_be_u16()));
            self.ehdr.e_version = types::Version(try!(self.file.read_be_u32()));
            self.ehdr.e_entry = types::Elf32Addr(try!(self.file.read_be_u32()));
            self.ehdr.e_phoff = types::Elf32Off(try!(self.file.read_be_u32()));
            self.ehdr.e_shoff = types::Elf32Off(try!(self.file.read_be_u32()));
            self.ehdr.e_flags = try!(self.file.read_be_u32());
            self.ehdr.e_ehsize = try!(self.file.read_be_u16());
            self.ehdr.e_phentsize = try!(self.file.read_be_u16());
            self.ehdr.e_phnum = try!(self.file.read_be_u16());
            self.ehdr.e_shentsize = try!(self.file.read_be_u16());
            self.ehdr.e_shnum = try!(self.file.read_be_u16());
            self.ehdr.e_shstrndx = try!(self.file.read_be_u16());
        }
        Ok(())
    }

    fn parse_ehdr64(&mut self) -> Result<(), ParseError> {
        Err(ParseError::NotImplemented)
    }

    fn new(io_file: std::old_io::File) -> File {
        File { file: io_file, ehdr: std::default::Default::default() }
    }
}

