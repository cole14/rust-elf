use crate::file::{Class, Endian};

pub trait Parse<R>: Copy {
    fn parse(endian: Endian, class: Class, reader: &mut R) -> Result<Self, crate::ParseError>
    where
        R: std::io::Read;
}
