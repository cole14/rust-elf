#![feature(collections)]

extern crate elf;

use std::path::Path;

fn main() {
    let path = Path::new("stress");
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };
    println!("Debug-print ELF file:");
    println!("{:?}", file);
    println!("");
    println!("Pretty-print ELF file:");
    println!("{}", file);

    println!("Getting the .text section");
    let text = file.get_section(".text");
    match text {
        Some(s) => println!("shdr: {}", s),
        None => println!("Failed to look up .text section!"),
    }
}
