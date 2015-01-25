
pub const EI_NIDENT: usize = 16;

pub struct Elf32Ehdr {
    e_ident: [u8; EI_NIDENT]
}

