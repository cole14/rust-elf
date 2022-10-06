use types;

pub trait Parse<R>: Copy {
    fn parse(
        endian: types::Endian,
        class: types::Class,
        reader: &mut R,
    ) -> Result<Self, crate::ParseError>
    where
        R: std::io::Read;
}
