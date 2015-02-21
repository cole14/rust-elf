#![feature(old_path)]
#![feature(collections)]

extern crate elf;

use std::old_path::Path;

fn main() {
    let path = Path::new("stress");
    let file = match elf::File::open(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };
    println!("Debug-print ELF file:");
    println!("{:?}", file);
    println!("");
    println!("Pretty-print ELF file:");
    println!("{}", file);

    println!("Getting the .text section");
    let text = file.get_section(String::from_str(".text"));
    match text {
        Some(s) => println!("shdr: {}", s),
        None => println!("Failed to look up .text section!"),
    }
}
