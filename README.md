[![](https://img.shields.io/crates/v/elf.svg)](https://crates.io/crates/elf)
[![](https://img.shields.io/crates/d/elf.svg)](https://crates.io/crates/elf)
[![Build Status](https://github.com/cole14/rust-elf/actions/workflows/rust.yml/badge.svg)](https://github.com/cole14/rust-elf/actions)
[![](https://docs.rs/elf/badge.svg)](https://docs.rs/elf/)

# rust-elf
Pure-Rust library for parsing ELF files

[Documentation](https://docs.rs/elf/)

## Example:
```rust
extern crate elf;

fn main() {
    let path: std::path::PathBuf = From::from("some_file");
    let mut io = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let elf_file = match elf::File::open_stream(&mut io) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    println!("ELF: {}", elf_file.ehdr);

    let text_scn = match elf_file.sections.get_by_name(".text") {
        Some(s) => s,
        None => panic!("Failed to find .text section"),
    };

    println!("{:?}", text_scn.data);
}

```
