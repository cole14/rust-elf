extern crate elf;

use std::env;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();
    let paths: Vec<PathBuf> = if args.len() == 1 {
        vec!(From::from("stress"))
    } else {
        let mut i = args.into_iter();
        i.next();
        i.map(|arg| From::from(arg) )
            .collect()
    };
    for path in paths.into_iter() {
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
}
