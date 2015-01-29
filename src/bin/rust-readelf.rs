extern crate elf;

use std::path::Path;

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
}
