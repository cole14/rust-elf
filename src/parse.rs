use crate::file::Class;

/// Represents the ELF file data format (little-endian vs big-endian)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self {
            Endian::Little => "2's complement, little endian",
            Endian::Big => "2's complement, big endian",
        };
        write!(f, "{}", str)
    }
}

pub trait Parse<R>: Copy {
    fn parse(endian: Endian, class: Class, reader: &mut R) -> Result<Self, crate::ParseError>
    where
        R: std::io::Read;
}
