extern crate elf;

use std::default;

fn main() {
    let ehdr: elf::Elf32Ehdr = default::Default::default();
    println!("{:?}", ehdr);
    println!("{}", ehdr);
}
