extern crate elf;

use std::default;

fn main() {
    let ehdr: elf::types::Elf32Ehdr = default::Default::default();
    println!("{:?}", ehdr);
    println!("{}", ehdr);
}
